import net from "node:net";
import { randomBytes } from "node:crypto";

function normalize(call) {
  return {
    agent_id: call.agent_id || call.agentId || "agent",
    tool: call.tool,
    params: call.params || {},
    timestamp: call.timestamp ?? Date.now()/1000,
    trace_id: call.trace_id || call.traceId || randomBytes(8).toString("hex"),
    context: call.context || {},
    cost: call.cost ?? null
  };
}

export class RemoteGuardrailProvider {
  constructor(options={}) {
    this.socketPath=options.socketPath;
    this.host=options.host || (this.socketPath ? undefined : "127.0.0.1");
    this.port=options.port || 50051;
    this.timeoutMs=options.timeoutMs ?? 1500;
  }

  verify(call) {
    const command=normalize(call);
    return new Promise((resolve) => {
      let done=false, buffer="";
      const fail=(reason)=>{
        if (done) return;
        done=true;
        resolve({
          ok:false, allowed:false, verdict:"deny", retryable:false,
          error_code:-32000, block_reason:`verifier unavailable: ${reason}`, receipt:null
        });
      };
      const socket=this.socketPath
        ? net.createConnection({path:this.socketPath})
        : net.createConnection({host:this.host,port:this.port});
      socket.setTimeout(this.timeoutMs);
      socket.on("connect",()=>socket.write(JSON.stringify({command})+"\n"));
      socket.on("data",(chunk)=>{
        buffer += chunk.toString("utf8");
        const i=buffer.indexOf("\n");
        if (i>=0 && !done) {
          done=true;
          try {
            const r=JSON.parse(buffer.slice(0,i));
            resolve({...r,allowed:r.verdict==="allow"});
          } catch {
            resolve({ok:false,allowed:false,verdict:"deny",retryable:false,error_code:-32000,block_reason:"invalid verifier response",receipt:null});
          }
          socket.end();
        }
      });
      socket.on("timeout",()=>{ socket.destroy(); fail("timeout"); });
      socket.on("error",(e)=>fail(e.message));
      socket.on("close",()=>{ if(!done) fail("connection closed"); });
    });
  }
}

export function governRemote(fn, options={}) {
  const guard=options.guardrail || new RemoteGuardrailProvider(options);
  return async function governed(params,meta={}) {
    const v=await guard.verify({
      agent_id:meta.agent_id || meta.agentId || "agent",
      tool:options.tool || fn.name || "anonymous_tool",
      params,context:meta.context || {},cost:meta.cost
    });
    if (!v.allowed) {
      const e=new Error(v.block_reason || `CCS ${v.verdict}`);
      e.name="PermissionError";
      e.ccs=v;
      throw e;
    }
    return await fn(params);
  };
}

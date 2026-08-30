import { randomBytes } from "node:crypto";
import { defaultRules } from "./rules.js";
import { ReceiptManager } from "./receipt.js";

const dims=["structure","schema","latency","cost","identity","integrity","security"];

export class GuardrailProvider {
  constructor(config={}) {
    this.config=config;
    this.receipts=config.receiptManager || new ReceiptManager(config);
  }
  verify(call) {
    const normalized={
      agent_id:call.agent_id || call.agentId || "anonymous",
      tool:call.tool,
      params:call.params || {},
      timestamp:call.timestamp ?? Date.now()/1000,
      trace_id:call.trace_id || call.traceId || randomBytes(8).toString("hex"),
      context:call.context || {},
      cost:call.cost ?? null
    };
    let rr;
    try { rr=defaultRules(normalized,this.config); }
    catch (e) {
      rr=[{name:"guardrail_exception",dimension:"security",status:"fail",reason:String(e)}];
    }
    const dimensions=Object.fromEntries(dims.map(d => {
      const a=rr.filter(x=>x.dimension===d).map(x=>x.status);
      return [d,a.includes("fail")?"fail":a.includes("unknown")||a.length===0?"unknown":"pass"];
    }));
    const verdict=Object.values(dimensions).includes("fail") ? "deny"
      : Object.values(dimensions).includes("unknown") ? "escalate" : "allow";
    const block=rr.find(x=>x.status==="fail")?.reason || (verdict==="escalate"?"unknown dimension":null);
    const summary=rr.map(x=>`${x.name}=${x.status}`).join("|");
    const receipt=this.receipts.createAdmission(normalized,verdict,dimensions,summary,block,this.config);
    return {allowed:verdict==="allow",verdict,dimensions,block_reason:block,receipt};
  }
}

export function govern(fn, options={}) {
  const guard=options.guardrail || new GuardrailProvider(options);
  return async function governed(params, meta={}) {
    const v=guard.verify({
      agent_id:meta.agent_id || meta.agentId || "agent",
      tool:options.tool || fn.name || "anonymous_tool",
      params, context:meta.context || {}, cost:meta.cost
    });
    if (!v.allowed) {
      const e=new Error(v.block_reason || `CCS ${v.verdict}`);
      e.name="PermissionError";
      e.ccs=v;
      throw e;
    }
    let output;
    try { output=await fn(params); }
    catch (e) { throw e; }
    const finalized=guard.receipts.finalize(v.receipt,output);
    return options.returnEvidence ? {output,receipt:finalized} : output;
  };
}

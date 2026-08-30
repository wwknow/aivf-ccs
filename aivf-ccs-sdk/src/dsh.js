import { GuardrailProvider } from "./guardrail.js";

export function createDSHPlugin(config={}) {
  const guardrail=new GuardrailProvider(config);
  return {
    name:"dsh-aivf-ccs",
    version:"0.1.0",
    guardrail,
    beforeToolCall(call) {
      const r=guardrail.verify({
        agent_id:call.agentId || call.agent_id || "dsh-agent",
        tool:call.tool || call.name,
        params:call.params || call.arguments || {},
        context:{framework:"dsh",...(call.context||{})}
      });
      if (!r.allowed) {
        const e=new Error(r.block_reason || `CCS ${r.verdict}`);
        e.name="PermissionError";
        e.ccs=r;
        throw e;
      }
      return r;
    }
  };
}

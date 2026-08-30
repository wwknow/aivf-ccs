export type DimensionStatus = "pass" | "fail" | "unknown";
export type Verdict = "allow" | "deny" | "escalate";
export interface ToolCall {
  agent_id?: string; agentId?: string; tool: string;
  params?: Record<string,unknown>; context?: Record<string,unknown>;
  timestamp?: number; trace_id?: string; traceId?: string; cost?: number;
}
export interface Verification {
  allowed: boolean; verdict: Verdict;
  dimensions: Record<string,DimensionStatus>;
  block_reason: string | null; receipt: Record<string,unknown>;
}
export class ReceiptManager {
  constructor(opts?: Record<string,unknown>);
  createAdmission(call:ToolCall,verdict:Verdict,dimensions:Record<string,string>,ruleSummary:string,blockReason:string|null,config?:Record<string,unknown>):Record<string,unknown>;
  finalize(receipt:Record<string,unknown>,response:unknown):Record<string,unknown>;
  validate(receipt:Record<string,unknown>,opts?:Record<string,unknown>):boolean;
  consume(receipt:Record<string,unknown>):Record<string,unknown>;
}
export class GuardrailProvider {
  constructor(config?:Record<string,unknown>);
  verify(call:ToolCall):Verification;
}
export function govern<T,U>(fn:(params:T)=>Promise<U>|U, options?:Record<string,unknown>):(params:T,meta?:Record<string,unknown>)=>Promise<U|{output:U,receipt:Record<string,unknown>}>;
export function createDSHPlugin(config?:Record<string,unknown>):Record<string,unknown>;

export class RemoteGuardrailProvider {
  constructor(options?:Record<string,unknown>);
  verify(call:ToolCall):Promise<Verification>;
}
export function governRemote<T,U>(
  fn:(params:T)=>Promise<U>|U,
  options?:Record<string,unknown>
):(params:T,meta?:Record<string,unknown>)=>Promise<U>;

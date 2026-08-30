import { generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify, randomBytes } from "node:crypto";
import { canonicalJSON, sha256Hex, sha256URI } from "./canonical.js";

export const SIGNING_FIELDS = [
  "trace_id","verdict","timestamp","tool","params_hash","rule_summary",
  "verified_at","block_reason","request_hash","response_hash",
  "runtime_context_hash","action","issuer","audience","nonce","sequence",
  "expires_at","config_hash","dimensions","receipt_status","key_id"
];

function signingObject(r) {
  return Object.fromEntries(SIGNING_FIELDS.map(k => [k,r[k]]));
}
export function signingBytes(r) {
  return Buffer.from(canonicalJSON(signingObject(r)),"utf8");
}

export class ReceiptManager {
  constructor(opts={}) {
    const kp=opts.keyPair || generateKeyPairSync("ed25519");
    this.privateKey=kp.privateKey;
    this.publicKey=kp.publicKey;
    this.issuer=opts.issuer || "urn:wwknow:aivf:verifier:node";
    this.audience=opts.audience || "urn:wwknow:aivf:executor:node";
    this.ttlSeconds=opts.ttlSeconds ?? 30;
    this.keyId=opts.keyId || "node-ed25519-1";
    this.sequence=0;
    this.consumed=new Set();
  }
  signReceipt(r) {
    const out={...r};
    out.signature=cryptoSign(null,signingBytes(out),this.privateKey).toString("hex");
    return out;
  }
  createAdmission(call, verdict, dimensions, ruleSummary, blockReason, config={}) {
    const now=Date.now()/1000;
    const paramsHash=sha256Hex(call.params);
    const wire={
      agent_id:call.agent_id,tool:call.tool,params:call.params,
      timestamp:call.timestamp,trace_id:call.trace_id
    };
    return this.signReceipt({
      trace_id:call.trace_id, verdict, timestamp:now, tool:call.tool,
      params_hash:paramsHash, rule_summary:ruleSummary, verified_at:now,
      block_reason:blockReason ?? null, request_hash:sha256URI(wire),
      response_hash:null, runtime_context_hash:sha256URI(call.context || {}),
      action:`ccs:tool-invoke:${call.tool}:${paramsHash}`,
      issuer:this.issuer, audience:this.audience,
      nonce:randomBytes(16).toString("hex"), sequence:++this.sequence,
      expires_at:now+this.ttlSeconds, config_hash:sha256URI(config),
      dimensions, receipt_status:"admission", key_id:this.keyId, signature:""
    });
  }
  finalize(r,response) {
    return this.signReceipt({...r,response_hash:sha256URI(response),receipt_status:"finalized"});
  }
  validate(r,opts={}) {
    const pub=opts.publicKey || this.publicKey;
    if (!cryptoVerify(null,signingBytes(r),pub,Buffer.from(r.signature,"hex")))
      throw new Error("signature verification failed");
    if (opts.audience && r.audience!==opts.audience) throw new Error("audience mismatch");
    if ((opts.fresh ?? true) && Date.now()/1000>r.expires_at) throw new Error("receipt expired");
    if (["consumed","unavailable"].includes(r.receipt_status)) throw new Error(`receipt status ${r.receipt_status} is non-authorizing`);
    if (opts.requireAuthorizing && r.verdict!=="allow") throw new Error("native deny/escalate cannot authorize");
    if (opts.call) {
      const ph=sha256Hex(opts.call.params);
      if (r.params_hash!==ph) throw new Error("parameter substitution detected");
      if (r.action!==`ccs:tool-invoke:${opts.call.tool}:${ph}`) throw new Error("exact-action mismatch");
    }
    return true;
  }
  consume(r) {
    this.validate(r,{audience:this.audience,requireAuthorizing:true});
    const k=`${r.issuer}:${r.nonce}`;
    if (this.consumed.has(k)) throw new Error("receipt replay/consumed");
    this.consumed.add(k);
    return this.signReceipt({...r,receipt_status:"consumed"});
  }
}

function flatten(v) {
  try { return JSON.stringify(v).toLowerCase(); } catch { return String(v).toLowerCase(); }
}
const pass = (name, dimension, reason="") => ({name,dimension,status:"pass",reason});
const fail = (name, dimension, reason) => ({name,dimension,status:"fail",reason});

export function structureRule(call) {
  return call?.agent_id && call?.tool && call.params && typeof call.params === "object"
    ? pass("structure","structure")
    : fail("structure","structure","missing/invalid command structure");
}
export function schemaRule(call, schemas={}) {
  const s=schemas[call.tool];
  if (!s) return pass("schema","schema");
  for (const k of (s.required || [])) if (!(k in call.params))
    return fail("schema","schema",`missing required param: ${k}`);
  return pass("schema","schema");
}
export function latencyRule(call, maxAgeSeconds=30) {
  const age=Math.max(0,Date.now()/1000-(call.timestamp ?? Date.now()/1000));
  return age>maxAgeSeconds ? fail("latency","latency",`command too old: ${age.toFixed(3)}s`) : pass("latency","latency");
}
export function costRule(call, maxCost=null) {
  if (maxCost == null || call.cost == null) return pass("cost","cost");
  return call.cost>maxCost ? fail("cost","cost","cost limit exceeded") : pass("cost","cost");
}
export function identityRule(call, allowedAgents=[]) {
  return allowedAgents.length && !allowedAgents.includes(call.agent_id)
    ? fail("identity","identity","agent identity not allowed") : pass("identity","identity");
}
export function integrityRule(call) {
  try { JSON.stringify(call.params); return pass("integrity","integrity"); }
  catch { return fail("integrity","integrity","params not canonicalizable"); }
}
export function ssrfRule(call) {
  const b=flatten(call.params);
  if (/file:\/\/|gopher:\/\//.test(b) || /169\.254\.169\.254|metadata\.google\.internal/.test(b) ||
      /https?:\/\/(?:localhost|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/.test(b))
    return fail("ssrf_protection","security","SSRF target detected");
  return pass("ssrf_protection","security");
}
export function rceRule(call) {
  const b=flatten(call.params);
  if (/\bcurl\b[\s\S]{0,200}\|\s*(?:ba)?sh\b/i.test(b) ||
      /\bwget\b[\s\S]{0,200}\|\s*(?:ba)?sh\b/i.test(b) ||
      /\brm\s+-rf\s+\//i.test(b))
    return fail("rce_protection","security","RCE pattern detected");
  return pass("rce_protection","security");
}
export function credentialLeakRule(call) {
  const b=(call.tool+" "+flatten(call.params)).toLowerCase();
  if (/(api[_-]?key|secret|password|authorization|bearer|private[_-]?key)/i.test(b) &&
      /(http|fetch|request|send|upload|webhook|curl)/i.test(b))
    return fail("credential_leak","security","possible credential exfiltration");
  return pass("credential_leak","security");
}

export function defaultRules(call, config={}) {
  return [
    structureRule(call),
    schemaRule(call,config.schemas||{}),
    latencyRule(call,config.maxAgeSeconds ?? 30),
    costRule(call,config.maxCost ?? null),
    identityRule(call,config.allowedAgents||[]),
    integrityRule(call),
    ssrfRule(call),
    rceRule(call),
    credentialLeakRule(call)
  ];
}

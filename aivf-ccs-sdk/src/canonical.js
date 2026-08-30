import { createHash } from "node:crypto";

function normalize(value) {
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === "object" && value.constructor === Object) {
    return Object.fromEntries(Object.keys(value).sort().map(k => [k, normalize(value[k])]));
  }
  if (typeof value === "number" && !Number.isFinite(value)) throw new TypeError("non-finite number");
  return value;
}

export function canonicalJSON(value) {
  return JSON.stringify(normalize(value));
}
export function sha256Hex(value) {
  const b = Buffer.isBuffer(value) ? value : Buffer.from(canonicalJSON(value), "utf8");
  return createHash("sha256").update(b).digest("hex");
}
export function sha256URI(value) { return `sha256:${sha256Hex(value)}`; }

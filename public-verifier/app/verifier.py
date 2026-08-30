from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SIGNING_FIELDS = [
    "trace_id", "verdict", "timestamp", "tool", "params_hash", "rule_summary",
    "verified_at", "block_reason", "request_hash", "response_hash",
    "runtime_context_hash", "action", "issuer", "audience", "nonce", "sequence",
    "expires_at", "config_hash", "dimensions", "receipt_status", "key_id",
]
ALL_FIELDS = SIGNING_FIELDS + ["signature"]
DIMENSIONS = ["structure", "schema", "latency", "cost", "identity", "integrity", "security"]
STATUS_VALUES = {"pass", "fail", "unknown"}
VERDICTS = {"allow", "deny", "escalate"}
RECEIPT_STATUSES = {"admission", "finalized", "consumed", "unavailable"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
SHA256_URI = re.compile(r"^sha256:[0-9a-f]{64}$")


def canonical_json(value: Any) -> str:
    # This intentionally matches the v0.1 verifier's canonical subset exactly.
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def signing_bytes(receipt: dict[str, Any]) -> bytes:
    payload = {k: receipt[k] for k in SIGNING_FIELDS}
    return canonical_json(payload).encode("utf-8")


def load_public_key_hex(path: str | Path) -> str:
    value = Path(path).read_text(encoding="utf-8").strip().lower()
    if not HEX64.fullmatch(value):
        raise ValueError("public key must be exactly 32 bytes encoded as 64 lowercase hex characters")
    return value


def public_key_fingerprint(public_key_hex: str) -> str:
    return "sha256:" + hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    level: str = "required"

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "detail": self.detail, "level": self.level}


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def profile_checks(receipt: Any) -> list[Check]:
    checks: list[Check] = []
    if not isinstance(receipt, dict):
        return [Check("JSON object", False, "Receipt must be a JSON object")]

    keys = set(receipt)
    missing = [k for k in ALL_FIELDS if k not in receipt]
    extra = sorted(keys - set(ALL_FIELDS))
    checks.append(Check(
        "CCS 22-field profile",
        not missing and not extra and len(receipt) == 22,
        "exactly 22 signed-profile fields" if not missing and not extra and len(receipt) == 22
        else f"missing={missing or 'none'}, extra={extra or 'none'}, count={len(receipt)}",
    ))
    if missing:
        return checks

    checks.extend([
        Check("trace_id", isinstance(receipt["trace_id"], str) and len(receipt["trace_id"]) >= 16, "non-empty trace identifier"),
        Check("verdict", receipt["verdict"] in VERDICTS, f"{receipt['verdict']!r}"),
        Check("timestamp", _is_number(receipt["timestamp"]), "numeric Unix time"),
        Check("tool", isinstance(receipt["tool"], str) and bool(receipt["tool"]), f"{receipt['tool']!r}"),
        Check("params_hash", isinstance(receipt["params_hash"], str) and bool(HEX64.fullmatch(receipt["params_hash"])), "64-hex SHA-256 digest"),
        Check("rule_summary", isinstance(receipt["rule_summary"], str), "string"),
        Check("verified_at", _is_number(receipt["verified_at"]), "numeric Unix time"),
        Check("block_reason", receipt["block_reason"] is None or isinstance(receipt["block_reason"], str), "null or string"),
        Check("request_hash", isinstance(receipt["request_hash"], str) and bool(SHA256_URI.fullmatch(receipt["request_hash"])), "sha256:<64 hex>"),
        Check("response_hash", receipt["response_hash"] is None or (isinstance(receipt["response_hash"], str) and bool(SHA256_URI.fullmatch(receipt["response_hash"]))), "null or sha256:<64 hex>"),
        Check("runtime_context_hash", isinstance(receipt["runtime_context_hash"], str) and bool(SHA256_URI.fullmatch(receipt["runtime_context_hash"])), "sha256:<64 hex>"),
        Check("action", isinstance(receipt["action"], str) and receipt["action"].startswith("ccs:tool-invoke:"), "CCS tool-invoke action"),
        Check("issuer", isinstance(receipt["issuer"], str) and bool(receipt["issuer"]), f"{receipt['issuer']!r}"),
        Check("audience", isinstance(receipt["audience"], str) and bool(receipt["audience"]), f"{receipt['audience']!r}"),
        Check("nonce", isinstance(receipt["nonce"], str) and len(receipt["nonce"]) >= 16, "anti-replay nonce"),
        Check("sequence", isinstance(receipt["sequence"], int) and not isinstance(receipt["sequence"], bool) and receipt["sequence"] >= 0, f"{receipt['sequence']!r}"),
        Check("expires_at", _is_number(receipt["expires_at"]), "numeric Unix time"),
        Check("config_hash", isinstance(receipt["config_hash"], str) and bool(SHA256_URI.fullmatch(receipt["config_hash"])), "sha256:<64 hex>"),
        Check("receipt_status", receipt["receipt_status"] in RECEIPT_STATUSES, f"{receipt['receipt_status']!r}"),
        Check("key_id", isinstance(receipt["key_id"], str) and bool(receipt["key_id"]), f"{receipt['key_id']!r}"),
        Check("signature encoding", isinstance(receipt["signature"], str) and bool(HEX128.fullmatch(receipt["signature"])), "64-byte Ed25519 signature encoded as 128 hex chars"),
    ])

    dims = receipt["dimensions"]
    dims_ok = isinstance(dims, dict) and set(dims) == set(DIMENSIONS) and all(dims[d] in STATUS_VALUES for d in DIMENSIONS)
    checks.append(Check("seven dimensions", dims_ok, "structure/schema/latency/cost/identity/integrity/security"))

    if isinstance(receipt["params_hash"], str) and isinstance(receipt["tool"], str):
        expected_action = f"ccs:tool-invoke:{receipt['tool']}:{receipt['params_hash']}"
        checks.append(Check("action binding shape", receipt["action"] == expected_action, "action exactly binds tool + full params_hash"))

    return checks


def verify_receipt(receipt: Any, public_key_hex: str, now: float | None = None) -> dict[str, Any]:
    now = time.time() if now is None else now
    checks = profile_checks(receipt)
    profile_valid = all(c.ok for c in checks if c.level == "required")

    signature_valid = False
    signature_detail = "not checked because required profile fields are invalid"
    if profile_valid:
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
            pub.verify(bytes.fromhex(receipt["signature"]), signing_bytes(receipt))
            signature_valid = True
            signature_detail = "Ed25519 signature matches the mounted AIVF CCS verifier public key"
        except Exception:
            signature_detail = "Ed25519 signature does not match this receipt/public key"
    checks.append(Check("Ed25519 signature", signature_valid, signature_detail))

    authentic = profile_valid and signature_valid
    fresh = bool(authentic and _is_number(receipt.get("expires_at")) and now <= float(receipt["expires_at"]))
    if authentic:
        checks.append(Check(
            "freshness",
            fresh,
            "receipt has not expired" if fresh else "receipt is cryptographically authentic but expired",
            level="informational",
        ))

    status = receipt.get("receipt_status") if isinstance(receipt, dict) else None
    verdict = receipt.get("verdict") if isinstance(receipt, dict) else None
    authorizing_now = bool(authentic and fresh and status == "admission" and verdict == "allow")

    if authentic:
        headline = "AUTHENTIC RECEIPT"
        if verdict == "deny":
            headline = "AUTHENTIC DENY EVIDENCE"
        elif verdict == "escalate":
            headline = "AUTHENTIC ESCALATION EVIDENCE"
        elif status == "finalized":
            headline = "AUTHENTIC FINALIZED EVIDENCE"
    else:
        headline = "INVALID / UNVERIFIED RECEIPT"

    display = {}
    if isinstance(receipt, dict):
        for k in [
            "trace_id", "verdict", "tool", "action", "issuer", "audience", "sequence",
            "receipt_status", "block_reason", "expires_at", "key_id", "dimensions",
            "request_hash", "response_hash", "params_hash", "config_hash",
        ]:
            if k in receipt:
                display[k] = receipt[k]

    return {
        "ok": True,
        "headline": headline,
        "authentic": authentic,
        "profile_valid": profile_valid,
        "signature_valid": signature_valid,
        "fresh": fresh,
        "authorizing_now": authorizing_now,
        "public_key": public_key_hex,
        "public_key_fingerprint": public_key_fingerprint(public_key_hex),
        "checks": [c.to_dict() for c in checks],
        "receipt": display,
    }

import copy
import hashlib
import json
import time
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from app.verifier import SIGNING_FIELDS, canonical_json, verify_receipt


def make_receipt(verdict="allow", expires_at=None):
    seed = bytes.fromhex("42" * 32)
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    now = 1_800_000_000.0
    params_hash = hashlib.sha256(b'{}').hexdigest()
    receipt = {
        "trace_id": "1234567890abcdef",
        "verdict": verdict,
        "timestamp": now,
        "tool": "web_fetch" if verdict == "allow" else "shell_exec",
        "params_hash": params_hash,
        "rule_summary": "security=pass" if verdict == "allow" else "rce_protection=fail",
        "verified_at": now,
        "block_reason": None if verdict == "allow" else "RCE pattern detected",
        "request_hash": "sha256:" + "11" * 32,
        "response_hash": None,
        "runtime_context_hash": "sha256:" + "22" * 32,
        "action": "",
        "issuer": "urn:test:verifier",
        "audience": "urn:test:executor",
        "nonce": "33" * 16,
        "sequence": 7,
        "expires_at": expires_at if expires_at is not None else now + 30,
        "config_hash": "sha256:" + "44" * 32,
        "dimensions": {d: "pass" for d in ["structure","schema","latency","cost","identity","integrity","security"]},
        "receipt_status": "admission",
        "key_id": "test-key",
        "signature": "",
    }
    if verdict == "deny":
        receipt["dimensions"]["security"] = "fail"
    receipt["action"] = f"ccs:tool-invoke:{receipt['tool']}:{receipt['params_hash']}"
    payload = canonical_json({k: receipt[k] for k in SIGNING_FIELDS}).encode()
    receipt["signature"] = priv.sign(payload).hex()
    return receipt, pub, now


def test_valid_allow_receipt():
    r, pub, now = make_receipt()
    out = verify_receipt(r, pub, now=now + 1)
    assert out["authentic"] is True
    assert out["fresh"] is True
    assert out["authorizing_now"] is True


def test_deny_receipt_is_authentic_but_not_authorizing():
    r, pub, now = make_receipt("deny")
    out = verify_receipt(r, pub, now=now + 1)
    assert out["authentic"] is True
    assert out["headline"] == "AUTHENTIC DENY EVIDENCE"
    assert out["authorizing_now"] is False


def test_mutating_signed_field_breaks_signature():
    r, pub, now = make_receipt("deny")
    bad = copy.deepcopy(r)
    bad["verdict"] = "allow"
    out = verify_receipt(bad, pub, now=now + 1)
    assert out["signature_valid"] is False
    assert out["authentic"] is False


def test_extra_unsigned_field_is_rejected():
    r, pub, now = make_receipt()
    bad = copy.deepcopy(r)
    bad["trusted"] = True
    out = verify_receipt(bad, pub, now=now + 1)
    assert out["profile_valid"] is False
    assert out["authentic"] is False


def test_expired_receipt_remains_authentic_evidence():
    r, pub, now = make_receipt(expires_at=1_700_000_000.0)
    out = verify_receipt(r, pub, now=now)
    assert out["authentic"] is True
    assert out["fresh"] is False
    assert out["authorizing_now"] is False


if __name__ == "__main__":
    tests = [
        test_valid_allow_receipt,
        test_deny_receipt_is_authentic_but_not_authorizing,
        test_mutating_signed_field_breaks_signature,
        test_extra_unsigned_field_is_rejected,
        test_expired_receipt_remains_authentic_evidence,
    ]
    for fn in tests:
        fn()
        print("PASS:", fn.__name__)
    print("PUBLIC VERIFIER TESTS PASSED: 5/5")

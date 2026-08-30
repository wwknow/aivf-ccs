from __future__ import annotations
import secrets, time
from typing import Any, Dict
from .canonical import canonical_bytes, sha256_hex, sha256_uri
from .crypto import public_key, sign, verify
from .models import Command
from .key_manager import load_or_create_seed

SIGNING_FIELDS = [
    "trace_id","verdict","timestamp","tool","params_hash","rule_summary",
    "verified_at","block_reason","request_hash","response_hash",
    "runtime_context_hash","action","issuer","audience","nonce","sequence",
    "expires_at","config_hash","dimensions","receipt_status","key_id"
]

class ReceiptValidationError(ValueError):
    pass

class ReceiptManager:
    def __init__(
        self,
        seed: bytes | None = None,
        *,
        key_file: str | None = None,
        store=None,
        issuer: str = "urn:wwknow:aivf:verifier:local",
        audience: str = "urn:wwknow:aivf:executor:local",
        ttl_seconds: float = 30.0,
        key_id: str = "aivf-ed25519-1",
    ):
        if seed is None:
            if not key_file:
                raise ValueError("ReceiptManager requires seed or key_file")
            seed = load_or_create_seed(key_file)
        self.seed = seed
        self.public_key = public_key(self.seed)
        self.issuer=issuer
        self.audience=audience
        self.ttl_seconds=ttl_seconds
        self.key_id=key_id
        self.store=store
        self._sequence=0
        self._consumed=set()

    def signing_payload(self, receipt: Dict[str, Any]) -> bytes:
        return canonical_bytes({k: receipt[k] for k in SIGNING_FIELDS})

    def _persist(self, receipt):
        if self.store is not None:
            self.store.save_receipt(receipt)

    def _sign(self, receipt, *, persist=True):
        receipt["signature"] = sign(self.seed, self.signing_payload(receipt)).hex()
        if persist:
            self._persist(receipt)
        return receipt

    def _next_sequence(self):
        if self.store is not None:
            return self.store.next_sequence()
        self._sequence += 1
        return self._sequence

    def create_admission(
        self, command: Command, verdict: str, dimensions: dict, rule_summary: str,
        block_reason: str | None, config: dict
    ) -> dict:
        now=time.time()
        params_full=sha256_hex(command.params)
        command_wire={
            "agent_id": command.agent_id,
            "tool": command.tool,
            "params": command.params,
            "timestamp": command.timestamp,
            "trace_id": command.trace_id,
        }
        receipt={
            "trace_id": command.trace_id,
            "verdict": verdict,
            "timestamp": now,
            "tool": command.tool,
            "params_hash": params_full,
            "rule_summary": rule_summary,
            "verified_at": now,
            "block_reason": block_reason,
            "request_hash": sha256_uri(command_wire),
            "response_hash": None,
            "runtime_context_hash": sha256_uri(command.context),
            "action": f"ccs:tool-invoke:{command.tool}:{params_full}",
            "issuer": self.issuer,
            "audience": self.audience,
            "nonce": secrets.token_hex(16),
            "sequence": self._next_sequence(),
            "expires_at": now + self.ttl_seconds,
            "config_hash": sha256_uri(config),
            "dimensions": dimensions,
            "receipt_status": "admission",
            "key_id": self.key_id,
            "signature": "",
        }
        return self._sign(receipt)

    def finalize(self, receipt: dict, response: Any) -> dict:
        out=dict(receipt)
        out["response_hash"]=sha256_uri(response)
        out["receipt_status"]="finalized"
        return self._sign(out)

    def mark_unavailable(self, receipt: dict) -> dict:
        out=dict(receipt)
        out["receipt_status"]="unavailable"
        return self._sign(out)

    def consume(self, receipt: dict) -> dict:
        self.validate(receipt, expected_audience=self.audience, require_authorizing=True)
        if self.store is not None:
            try:
                self.store.mark_consumed(receipt["issuer"], receipt["nonce"])
            except ValueError as e:
                raise ReceiptValidationError(str(e))
        else:
            replay_key=(receipt["issuer"],receipt["nonce"])
            if replay_key in self._consumed:
                raise ReceiptValidationError("receipt replay/consumed")
            self._consumed.add(replay_key)
        out=dict(receipt)
        out["receipt_status"]="consumed"
        return self._sign(out)

    def validate(
        self, receipt: dict, *,
        public: bytes | None = None,
        expected_audience: str | None = None,
        expected_command: Command | None = None,
        require_fresh: bool = True,
        require_authorizing: bool = False,
    ) -> bool:
        for k in SIGNING_FIELDS + ["signature"]:
            if k not in receipt:
                raise ReceiptValidationError(f"missing field: {k}")
        pub=public or self.public_key
        try:
            sig=bytes.fromhex(receipt["signature"])
        except Exception:
            raise ReceiptValidationError("invalid signature encoding")
        if not verify(pub, self.signing_payload(receipt), sig):
            raise ReceiptValidationError("signature verification failed")
        if expected_audience and receipt["audience"] != expected_audience:
            raise ReceiptValidationError("audience mismatch")
        if require_fresh and time.time() > receipt["expires_at"]:
            raise ReceiptValidationError("receipt expired")
        if receipt["receipt_status"] in {"consumed","unavailable"}:
            raise ReceiptValidationError(f"receipt status {receipt['receipt_status']} is non-authorizing")
        if self.store is not None and self.store.is_consumed(receipt["issuer"], receipt["nonce"]):
            raise ReceiptValidationError("receipt replay/consumed")
        if require_authorizing and receipt["verdict"] != "allow":
            raise ReceiptValidationError("native deny/escalate cannot authorize")
        if expected_command:
            expected_params=sha256_hex(expected_command.params)
            if receipt["params_hash"] != expected_params:
                raise ReceiptValidationError("parameter substitution detected")
            if receipt["action"] != f"ccs:tool-invoke:{expected_command.tool}:{expected_params}":
                raise ReceiptValidationError("exact-action mismatch")
            wire={
                "agent_id": expected_command.agent_id,
                "tool": expected_command.tool,
                "params": expected_command.params,
                "timestamp": expected_command.timestamp,
                "trace_id": expected_command.trace_id,
            }
            if receipt["request_hash"] != sha256_uri(wire):
                raise ReceiptValidationError("request binding mismatch")
        return True

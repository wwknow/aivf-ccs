from __future__ import annotations
import json, hashlib
from typing import Any

def canonical_json(value: Any) -> str:
    # Deterministic JSON/JCS-compatible subset used by this rebuild.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)

def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")

def sha256_hex(value: Any) -> str:
    b = value if isinstance(value, (bytes, bytearray)) else canonical_bytes(value)
    return hashlib.sha256(bytes(b)).hexdigest()

def sha256_uri(value: Any) -> str:
    return "sha256:" + sha256_hex(value)

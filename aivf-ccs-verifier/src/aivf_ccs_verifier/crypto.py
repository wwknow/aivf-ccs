from __future__ import annotations
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

def _private(seed: bytes) -> Ed25519PrivateKey:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed)

def public_key(seed: bytes) -> bytes:
    return _private(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

def sign(seed: bytes, message: bytes) -> bytes:
    return _private(seed).sign(message)

def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
        return True
    except Exception:
        return False

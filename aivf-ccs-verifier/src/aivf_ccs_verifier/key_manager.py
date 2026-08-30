from __future__ import annotations
from pathlib import Path
import os, secrets

def load_or_create_seed(path: str) -> bytes:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        data = p.read_bytes()
        if len(data) != 32:
            raise ValueError(f"invalid Ed25519 seed length in {p}: {len(data)}")
        return data
    data = secrets.token_bytes(32)
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return data

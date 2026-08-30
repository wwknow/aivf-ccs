from __future__ import annotations
import argparse, json, os
from pathlib import Path
from .key_manager import load_or_create_seed
from .crypto import public_key, verify
from .canonical import canonical_bytes
from .receipt import SIGNING_FIELDS
from .storage import SQLiteStore

def main():
    p=argparse.ArgumentParser(description="CCS admin CLI")
    sub=p.add_subparsers(dest="cmd",required=True)

    pk=sub.add_parser("public-key")
    pk.add_argument("--key-file",default=os.getenv("CCS_KEY_FILE","/var/lib/aivf-ccs/keys/ed25519.seed"))

    vr=sub.add_parser("verify-receipt")
    vr.add_argument("receipt")
    vr.add_argument("--public-key-hex",required=True)

    db=sub.add_parser("evidence")
    db.add_argument("--db",default=os.getenv("CCS_DB","/var/lib/aivf-ccs/evidence.db"))
    db.add_argument("--limit",type=int,default=10)

    a=p.parse_args()
    if a.cmd=="public-key":
        seed=load_or_create_seed(a.key_file)
        print(public_key(seed).hex())
    elif a.cmd=="verify-receipt":
        r=json.loads(Path(a.receipt).read_text(encoding="utf-8"))
        payload=canonical_bytes({k:r[k] for k in SIGNING_FIELDS})
        ok=verify(bytes.fromhex(a.public_key_hex),payload,bytes.fromhex(r["signature"]))
        print("VALID" if ok else "INVALID")
        raise SystemExit(0 if ok else 2)
    elif a.cmd=="evidence":
        store=SQLiteStore(a.db)
        for r in store.latest_receipts(a.limit):
            print(json.dumps({
                "trace_id":r["trace_id"],"sequence":r["sequence"],"verdict":r["verdict"],
                "status":r["receipt_status"],"tool":r["tool"],"issuer":r["issuer"]
            },ensure_ascii=False))

if __name__=="__main__":
    main()

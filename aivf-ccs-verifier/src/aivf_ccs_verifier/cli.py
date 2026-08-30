from __future__ import annotations
import argparse, asyncio, os
from .server import VerifierServer
from .storage import SQLiteStore
from .receipt import ReceiptManager
from .verifier import Verifier

def env(name, default=None):
    return os.environ.get(name, default)

def main():
    p=argparse.ArgumentParser(description="CCS verifier production-test service")
    p.add_argument("--transport",choices=["unix","tcp"],default=env("CCS_TRANSPORT","unix"))
    p.add_argument("--socket",default=env("CCS_SOCKET","/run/aivf-ccs/ccs-verifier.sock"))
    p.add_argument("--host",default=env("CCS_HOST","127.0.0.1"))
    p.add_argument("--port",type=int,default=int(env("CCS_PORT","50051")))
    p.add_argument("--health-host",default=env("CCS_HEALTH_HOST","127.0.0.1"))
    p.add_argument("--health-port",type=int,default=int(env("CCS_HEALTH_PORT","8080")))
    p.add_argument("--db",default=env("CCS_DB","/var/lib/aivf-ccs/evidence.db"))
    p.add_argument("--key-file",default=env("CCS_KEY_FILE","/var/lib/aivf-ccs/keys/ed25519.seed"))
    p.add_argument("--issuer",default=env("CCS_ISSUER","urn:wwknow:aivf:verifier:prod"))
    p.add_argument("--audience",default=env("CCS_AUDIENCE","urn:wwknow:aivf:executor:prod"))
    p.add_argument("--ttl",type=float,default=float(env("CCS_TTL","30")))
    p.add_argument("--key-id",default=env("CCS_KEY_ID","aivf-ed25519-1"))
    a=p.parse_args()

    store=SQLiteStore(a.db)
    rm=ReceiptManager(
        key_file=a.key_file, store=store, issuer=a.issuer,
        audience=a.audience, ttl_seconds=a.ttl, key_id=a.key_id
    )
    config={"issuer":a.issuer,"audience":a.audience,"ttl_seconds":a.ttl}
    verifier=Verifier(receipt_manager=rm,config=config)
    server=VerifierServer(verifier,store=store)
    asyncio.run(server.serve(
        transport=a.transport,socket_path=a.socket,host=a.host,port=a.port,
        health_host=a.health_host,health_port=a.health_port
    ))

if __name__=="__main__":
    main()

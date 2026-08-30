from __future__ import annotations
import asyncio, json, os
from .models import Command

class VerifierServer:
    def __init__(self, verifier, *, store=None):
        self.verifier=verifier
        self.store=store

    async def _handle(self, reader, writer):
        try:
            while not reader.at_eof():
                line=await reader.readline()
                if not line:
                    break
                try:
                    req=json.loads(line)
                    cmd=Command(**req["command"])
                    result=self.verifier.verify(cmd)
                    body={
                        "ok":True,
                        "verdict":result.verdict,
                        "dimensions":result.dimensions,
                        "block_reason":result.block_reason,
                        "error_code":result.error_code,
                        "retryable":result.retryable,
                        "receipt":result.receipt,
                    }
                except Exception as e:
                    body={"ok":False,"verdict":"deny","error":str(e),"error_code":-32000,"retryable":False}
                writer.write((json.dumps(body,separators=(",",":"),ensure_ascii=False)+"\n").encode())
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def _health(self, reader, writer):
        try:
            first=(await reader.readline()).decode("latin-1","replace").strip()
            while True:
                line=await reader.readline()
                if not line or line in (b"\r\n",b"\n"):
                    break
            if first.startswith("GET /healthz "):
                count=self.store.count_evidence() if self.store else 0
                body=json.dumps({"status":"ok","evidence_count":count},separators=(",",":")).encode()
                status=b"HTTP/1.1 200 OK\r\n"
            else:
                body=b'{"status":"not_found"}'
                status=b"HTTP/1.1 404 Not Found\r\n"
            writer.write(status+b"Content-Type: application/json\r\nContent-Length: "+str(len(body)).encode()+b"\r\nConnection: close\r\n\r\n"+body)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def serve(self, *, transport="unix", socket_path="/run/aivf-ccs/ccs-verifier.sock",
                    host="127.0.0.1", port=50051, health_host="127.0.0.1", health_port=8080):
        if transport=="unix":
            os.makedirs(os.path.dirname(socket_path), exist_ok=True)
            try: os.unlink(socket_path)
            except FileNotFoundError: pass
            main=await asyncio.start_unix_server(self._handle,socket_path)
            os.chmod(socket_path,0o660)
        else:
            main=await asyncio.start_server(self._handle,host,port)
        health=await asyncio.start_server(self._health,health_host,health_port)
        async with main, health:
            await asyncio.gather(main.serve_forever(),health.serve_forever())

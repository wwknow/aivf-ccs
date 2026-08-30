from __future__ import annotations
import asyncio, json
from dataclasses import asdict
from .models import Command

class VerifierClient:
    def __init__(self, *, socket_path="/tmp/ccs-verifier.sock", host=None, port=50051):
        self.socket_path=socket_path
        self.host=host
        self.port=port

    async def verify(self, command: Command) -> dict:
        if self.host:
            reader,writer=await asyncio.open_connection(self.host,self.port)
        else:
            reader,writer=await asyncio.open_unix_connection(self.socket_path)
        try:
            writer.write((json.dumps({"command":asdict(command)},ensure_ascii=False)+"\n").encode())
            await writer.drain()
            line=await reader.readline()
            if not line:
                return {"ok":False,"verdict":"deny","error":"verifier unavailable","error_code":-32000}
            return json.loads(line)
        except Exception as e:
            # Fail closed.
            return {"ok":False,"verdict":"deny","error":str(e),"error_code":-32000,"retryable":False}
        finally:
            writer.close()
            await writer.wait_closed()

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .verifier import load_public_key_hex, public_key_fingerprint, verify_receipt

BASE = Path(__file__).resolve().parent
PUBLIC_KEY_PATH = os.environ.get("CCS_PUBLIC_KEY_PATH", "/app/keys/ed25519.pub")
MAX_BODY_BYTES = int(os.environ.get("CCS_MAX_BODY_BYTES", str(256 * 1024)))

app = FastAPI(
    title="AIVF CCS Receipt Verifier",
    version="0.2.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE / "templates"))


def key_hex() -> str:
    try:
        return load_public_key_hex(PUBLIC_KEY_PATH)
    except Exception as exc:
        raise RuntimeError(f"public key unavailable: {exc}") from exc


@app.middleware("http")
async def security_headers_and_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_BODY_BYTES:
                return JSONResponse({"ok": False, "error": "request too large"}, status_code=413)
        except ValueError:
            return JSONResponse({"ok": False, "error": "invalid content-length"}, status_code=400)

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    return response


@app.get("/healthz")
def healthz():
    try:
        pub = key_hex()
        return {
            "status": "ok",
            "service": "aivf-ccs-public-verifier",
            "version": "0.2.0",
            "public_key_fingerprint": public_key_fingerprint(pub),
        }
    except Exception as exc:
        return JSONResponse({"status": "error", "detail": str(exc)}, status_code=503)


@app.get("/api/public-key")
def public_key():
    try:
        pub = key_hex()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return {"public_key": pub, "fingerprint": public_key_fingerprint(pub), "algorithm": "Ed25519"}


@app.post("/api/verify")
async def api_verify(request: Request):
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="request too large")
    try:
        receipt: Any = json.loads(raw)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"invalid JSON: {exc}")
    try:
        return verify_receipt(receipt, key_hex())
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    try:
        pub = key_hex()
        fingerprint = public_key_fingerprint(pub)
        key_error = None
    except Exception as exc:
        pub = ""
        fingerprint = "unavailable"
        key_error = str(exc)
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"public_key": pub, "fingerprint": fingerprint, "key_error": key_error},
    )

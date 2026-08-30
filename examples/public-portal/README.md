# AIVF CCS v0.2-C r1 — Public Hardening

This is the public-facing aggregation layer for the frozen working components:

```text
v0.1   CCS Core              127.0.0.1:50051
v0.2-A Receipt Verifier      127.0.0.1:18050
v0.2-B Agent Runtime Demo    127.0.0.1:18051
v0.2-C Public Portal         127.0.0.1:18052
```

The portal does not hold the Ed25519 private key or evidence database.

## Deploy

Upload the ZIP to `/root/`, then:

```bash
mkdir -p /opt/aivf-ccs/aivf-ccs-v0.2c
cd /opt/aivf-ccs/aivf-ccs-v0.2c

unzip -o /root/aivf-ccs-v0.2c-public-portal.zip

./scripts/preflight.sh

docker compose build
docker compose up -d
sleep 10
docker compose ps

./scripts/smoke.sh
```

Expected final output:

```text
PASS: unified portal health
PASS: homepage renders verifier + demo
PASS: safe ALLOW through portal
PASS: attack DENY through portal
PASS: signed evidence verifies through portal
```

## Browser test before DNS

From Windows PowerShell:

```powershell
ssh -L 18052:127.0.0.1:18052 root@YOUR_VPS_IP
```

Then open:

```text
http://127.0.0.1:18052/
```

## Verify a saved receipt

```bash
./scripts/verify-file.sh /root/ccs-sequence-2-deny.json
```

## Production reverse proxy target

After local tests pass, configure OpenLiteSpeed:

```text
aivf.wwknow.com
    -> HTTPS :443
    -> http://127.0.0.1:18052
```

Keep 50051, 18050, 18051, and 18052 bound to localhost. Do not open them in the firewall.


## Public hardening in r1

- Implements HTTP `HEAD /` so `curl -I` and common monitors return 200 instead of 501.
- Adds an in-memory sliding-window rate limit:
  - demo endpoints: 10 requests/minute/client
  - receipt verification: 60 requests/minute/client
- Client identity prefers Cloudflare `CF-Connecting-IP`, then `X-Forwarded-For`.
- Keeps all internal services bound to localhost.

After deployment:

```bash
curl -I https://aivf.wwknow.com/
./scripts/public-hardening-smoke.sh
```

`curl -I` should return HTTP 200.

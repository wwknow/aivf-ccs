# AIVF CCS Public Receipt Verifier

This service independently verifies AIVF CCS signed evidence receipts using
only the Ed25519 public key. It does not mount the private signing seed or the
evidence database.

From the repository root, the public key is exported with:

```bash
mkdir -p public
docker compose exec -T aivf-ccs-verifier   aivf-ccs-admin public-key   | tr -d '\r\n' > public/ed25519.pub
chmod 644 public/ed25519.pub
```

Then:

```bash
cd public-verifier
docker compose build
docker compose up -d
sleep 5
bash scripts/smoke.sh
```

Local endpoint:

```text
http://127.0.0.1:18050/
```

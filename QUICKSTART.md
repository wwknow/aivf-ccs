# Quick Start — Clean Rebuild

Requirements: Linux, Docker, Docker Compose.

This repository can run the complete local stack:

```text
AIVF CCS core        127.0.0.1:50051
Core health          127.0.0.1:8080
Public verifier      127.0.0.1:18050
Agent demo           127.0.0.1:18051
Public portal        127.0.0.1:18052
```

The default namespace is:

```text
issuer   urn:wwknow:aivf:verifier:prod
audience urn:wwknow:aivf:executor:prod
key_id   aivf-ed25519-1
```

## One-command deployment

From the repository root:

```bash
bash scripts/fresh-deploy.sh
```

The script creates a new Ed25519 signing key and a new evidence database if
`data/` is empty. It then exports only the public key to `public/`, starts the
public verifier, agent demo, and portal, and runs smoke tests.

Never commit:

```text
data/
public/ed25519.pub  # runtime-generated public material; publish separately if desired
```

## Manual public-key export

If needed:

```bash
mkdir -p public
docker compose exec -T aivf-ccs-verifier   aivf-ccs-admin public-key   | tr -d '\r\n' > public/ed25519.pub
chmod 644 public/ed25519.pub
```

## Tests

```bash
bash scripts/secret-scan.sh
bash scripts/oss-boundary-scan.sh
bash scripts/namespace-scan.sh
bash scripts/oss-test-all.sh
```

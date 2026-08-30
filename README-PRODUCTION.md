# AIVF CCS — Production-Oriented Deployment Notes

AIVF CCS uses a fail-closed core verifier plus public verification/demo
surfaces. The reference deployment keeps all service ports on loopback.

## Runtime namespace

```text
CCS_ISSUER=urn:wwknow:aivf:verifier:prod
CCS_AUDIENCE=urn:wwknow:aivf:executor:prod
CCS_KEY_ID=aivf-ed25519-1
```

## Persistent private data

The core stores:

```text
data/evidence.db
data/keys/ed25519.seed
```

These files are private runtime state and must not be committed or exposed by a
public web service.

The public verifier receives only:

```text
public/ed25519.pub
```

## Deploy

```bash
bash scripts/fresh-deploy.sh
```

## Administrative commands

```bash
docker compose exec -T aivf-ccs-verifier aivf-ccs-admin public-key
docker compose exec -T aivf-ccs-verifier aivf-ccs-admin evidence --limit 20
docker compose exec -T aivf-ccs-verifier   aivf-ccs-admin verify-receipt receipt.json --public-key-hex <PUBLIC_KEY_HEX>
```

## Security boundary

- The signing seed and evidence database stay with the core.
- The public verifier mounts only the Ed25519 public key.
- Demo tool execution is simulated and never invokes a real shell.
- Public-facing services bind to loopback and are intended to sit behind a
  reverse proxy such as OpenLiteSpeed.

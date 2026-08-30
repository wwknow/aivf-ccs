# AIVF CCS Quick Start

This guide starts the complete local reference stack from a clean checkout.

## Requirements

- Linux
- Git
- Docker
- Docker Compose

## 1. Clone

```bash
git clone https://github.com/wwknow/aivf-ccs.git
cd aivf-ccs
```

## 2. Deploy

```bash
bash scripts/fresh-deploy.sh
```

The script:

1. runs the release-safety and conformance tests;
2. creates runtime directories;
3. creates a fresh Ed25519 signing key and evidence database when needed;
4. starts the AIVF CCS core;
5. exports only the public key to the public-verifier side;
6. starts the public verifier, agent demo, and public portal;
7. runs the smoke and hardening checks.

## 3. Local endpoints

```text
127.0.0.1:50051  AIVF CCS verifier protocol
127.0.0.1:8080   Core health
127.0.0.1:18050  Public receipt verifier
127.0.0.1:18051  Agent demo
127.0.0.1:18052  Public portal
```

Check health:

```bash
curl -sS http://127.0.0.1:8080/healthz
curl -sS http://127.0.0.1:18050/healthz
curl -sS http://127.0.0.1:18051/healthz
curl -sS http://127.0.0.1:18052/healthz
```

## Runtime namespace

Default production configuration:

```text
CCS_ISSUER=urn:wwknow:aivf:verifier:prod
CCS_AUDIENCE=urn:wwknow:aivf:executor:prod
CCS_KEY_ID=aivf-ed25519-1
CCS_TTL=30
```

For local-only experiments, change the environment suffix rather than reusing a
production identity.

## Runtime data

Private runtime state is stored under:

```text
data/evidence.db
data/keys/ed25519.seed
```

Do not commit or expose these files.

The public verifier receives only:

```text
public/ed25519.pub
```

The repository `.gitignore` excludes these runtime outputs.

## Minimal SDK example

```bash
node examples/sdk-minimal.mjs
```

Expected output includes an `allow` decision for a safe governed function and a
blocked RCE-pattern example.

## Run tests without deploying

```bash
bash scripts/secret-scan.sh
bash scripts/oss-boundary-scan.sh
bash scripts/namespace-scan.sh
bash scripts/oss-test-all.sh
```

## Manual public-key export

```bash
mkdir -p public
docker compose exec -T aivf-ccs-verifier \
  aivf-ccs-admin public-key \
  | tr -d '\r\n' > public/ed25519.pub
chmod 644 public/ed25519.pub
```

## Stop the AIVF CCS containers

```bash
bash scripts/fresh-teardown.sh
```

`fresh-teardown.sh` removes the reference containers but intentionally leaves
runtime files intact.

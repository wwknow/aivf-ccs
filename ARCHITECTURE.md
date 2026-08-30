# Architecture

AIVF CCS is an execution-boundary verification and evidence layer for AI agents.

```text
AI Agent / LLM
    |
    v
AIVF CCS SDK
    |
    v
CCS Verifier
    |
    +-- Structure
    +-- Schema
    +-- Latency
    +-- Cost
    +-- Identity
    +-- Integrity
    +-- Security
    |
    v
ALLOW / DENY / ESCALATE
    |
    +--> signed CCS evidence receipt
    |
    v
Privileged tool (only after ALLOW)
```

## Components

- `ccs-verifier/`: Python reference verifier and durable evidence service.
- `aivf-ccs-sdk/`: Node.js SDK and fail-closed wrappers.
- `standards/`: receipt schema and 14 conformance checks.
- `public-verifier/`: read-only receipt verification web service; no private key access.
- `examples/agent-demo/`: simulated runtime enforcement demo; never starts a real shell.
- `examples/public-portal/`: unified portal and public hardening/rate limiting example.

## Trust boundaries

The signing private key belongs only to the CCS verifier. Public verification needs only the public key. The public verifier and portal must never mount the private seed or the evidence database.

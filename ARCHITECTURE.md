# Architecture

AIVF CCS is an execution-boundary verification and signed-evidence layer for AI
agents.

```text
AI Agent / LLM
    |
    v
AIVF CCS SDK
    |
    v
AIVF CCS Verifier
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

- `aivf-ccs-verifier/` — Python reference verifier and durable evidence service.
- `aivf-ccs-sdk/` — Node.js SDK, local guardrail, and fail-closed remote wrapper.
- `standards/` — receipt schema and 14-point conformance material.
- `public-verifier/` — read-only receipt verification service; no private-key access.
- `examples/sdk-minimal.mjs` — smallest governed-function example.
- `examples/real-agent-integration/` — OpenAI-compatible tool-calling agent connected to the remote verifier.
- `examples/agent-demo/` — simulated runtime enforcement demo; never starts a real shell.
- `examples/public-portal/` — unified public portal with hardening/rate limiting.

## Trust boundaries

The signing private key belongs only to the core verifier. Public verification
requires only the public key. The public verifier and portal must never mount the
private seed or evidence database.

The remote SDK is fail-closed: verifier timeout, connection failure, malformed
response, or an explicit non-ALLOW verdict prevents the wrapped privileged tool
from executing.

## Evidence flow

Admission receipts bind the intended tool invocation before execution. A local
SDK flow may finalize an admitted receipt after the wrapped tool returns, adding
a response hash while preserving the original decision context.

The core profile binds the decision to:

```text
request
parameters
runtime context
configuration
tool/action
issuer + audience
nonce + sequence
expiry
seven verification dimensions
Ed25519 signature
```

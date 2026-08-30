# CCS v1.3 reconstruction profile

CCS is modeled here as an evidence protocol for AI-agent tool calls.

A command is evaluated across seven dimensions:

1. Structure
2. Schema
3. Latency
4. Cost
5. Identity
6. Integrity
7. Security

Each dimension returns `pass`, `fail`, or `unknown`. The enforcement verdict is:

- any `fail` -> `deny`
- otherwise any `unknown` -> `escalate`
- otherwise -> `allow`

## Evidence receipt lifecycle

1. Admission receipt is generated and persisted before tool execution.
2. The tool executes only if the admission receipt authorizes it.
3. The receipt is finalized with `response_hash`.
4. The finalized receipt is signed again.

The signing input is canonical JSON of fields 1-21. Field 22 (`signature`) is
detached and excluded from its own signing input.

## Bindings

The reconstructed profile binds evidence to:

- request bytes (`request_hash`)
- response bytes (`response_hash`)
- runtime context (`runtime_context_hash`)
- exact action (`action`)
- canonical parameters (`params_hash`)
- verifier identity (`issuer`)
- intended consumer (`audience`)
- anti-replay nonce and monotonic sequence
- freshness (`expires_at`)
- verifier configuration (`config_hash`)
- signing key (`key_id`)

# Threat Model

## Protected assets

- authorization decision integrity
- Ed25519 signing key
- evidence receipt integrity
- evidence/replay database
- privileged tool execution path

## Primary threats

1. **Receipt tampering** — changing `deny` to `allow`, sequence, action, block reason, hashes, or other signed fields.
2. **Parameter substitution** — approving one parameter set and executing another.
3. **Replay** — reusing a previously consumed authorization receipt.
4. **Verifier bypass** — exposing a second unguarded path to the privileged tool.
5. **Verifier outage** — an agent attempts execution when verification is unavailable.
6. **SSRF/RCE/credential exfiltration** — dangerous tool parameters pass through an agent.
7. **Public endpoint abuse** — repeated demo or verification requests exhaust resources/evidence sequence space.

## Current mitigations

- Ed25519 detached signatures over the signed receipt profile.
- request/params/action/context/config/audience bindings.
- freshness and nonce/sequence fields.
- durable consumed-receipt state in SQLite.
- fail-closed remote SDK behavior.
- local-only core ports by default.
- read-only public verifier with no private key/database access.
- request-size limits and public portal rate limits.

## Out of scope / not yet high-assurance production

- compromise of the host/root account
- HSM/KMS-backed key custody
- multi-node HA consensus for sequence/replay state
- formal verification of canonicalization
- independent third-party security audit
- cross-host transport without mTLS

Do not place high-value production tools behind this alpha release without an independent security review and deployment-specific hardening.

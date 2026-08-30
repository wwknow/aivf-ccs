# Security Policy

Please do not open a public issue containing an exploitable vulnerability, private key, token, credential, or production receipt containing sensitive data.

For a public repository, configure a private GitHub Security Advisory channel before announcing the project and direct vulnerability reports there.

## Never commit

- `data/keys/ed25519.seed`
- `data/evidence.db`
- `.env`
- cloud/CDN/API tokens
- SSH keys
- production credentials

## Supported status

This repository is an alpha/reference implementation. It is suitable for interoperability testing, development, demos, and controlled pilots. It has not undergone an independent security audit.

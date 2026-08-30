# Contributing

1. Create a focused branch.
2. Add or update tests for behavior changes.
3. Run `./scripts/oss-test-all.sh` before opening a pull request.
4. Never include runtime keys, databases, credentials, or production evidence.
5. Protocol/profile changes should update `standards/` and conformance tests together.

Security-sensitive changes should explain the threat being addressed and the fail-open/fail-closed behavior.


## Contributor licensing

Before a third-party contribution is accepted, the contributor must agree to
the project's Contributor License Agreement (CLA). See
`CONTRIBUTOR_LICENSE_AGREEMENT.md`.

Until the Project Steward and CLA acceptance workflow are finalized, external
pull requests may be reviewed but should not be merged into a release branch.

The CLA is intended to preserve the project's long-term licensing flexibility
while keeping contributor permissions explicit.

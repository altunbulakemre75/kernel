# Security policy

Kyvern exists to make tampering with a decision record detectable. A flaw that
lets a changed, deleted, reordered or forged record pass `kyvern-verify` is a
security issue, and so is anything that makes the auditor tools give a wrong
answer on a crafted chain.

## Reporting a vulnerability

Report it privately through GitHub: on this repository, open **Security →
Report a vulnerability**. Please do not open a public issue or discussion.

Include the Kyvern version or commit, what you did and what you expected. A
minimal chain or receipt file that reproduces the problem helps most.

Kyvern has a single maintainer. Reports are acknowledged as soon as possible;
fixes are released with a note in [CHANGELOG.md](CHANGELOG.md) and in the
GitHub release, crediting you unless you prefer otherwise.

## In scope

- A modified, deleted, reordered or forged entry that `kyvern-verify` accepts,
  with the documented options (for deletion from the end of a chain:
  `--require-anchors`)
- RFC 3161 anchor receipts accepted when they should not be, including an
  anchored entry dated further from its receipt than `--max-lag` allows
- Crashes or wrong results on crafted chain or receipt files in
  `kyvern-verify`, `kyvern-report` or `kyvern-mcp`
- Handling of the signing key (`~/.kyvern/keys`)
- Untrusted input reaching the LLM advisor's prompt despite `sanitize.py`

## Out of scope

The non-defenses listed in [docs/threat-model.md](docs/threat-model.md), for
example an attacker who holds the signing key on a chain without anchors, or a
verifier given the attacker's public key.

## Supported versions

Security fixes go into the latest release.

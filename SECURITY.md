# Security Policy

## Supported versions

`ugallu` is currently in **pre-alpha**. No security backports to historical versions. All fixes land on `main`.

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories on this repository, or via email to **security@ninsun-labs.io** if private channel is not available.

**Do not open public issues for security disclosures.**

A coordinated disclosure timeline will be agreed on report. Default expectation:

| Severity | Initial response | Fix target |
|---|---|---|
| Critical | 24h | 7 days |
| High | 72h | 30 days |
| Medium / Low | 7 days | best-effort |

## Scope

- Code in this repository
- Released container images under `ghcr.io/ninsun-labs/ugallu/*`
- Helm charts published from this repository

Out of scope:
- Third-party dependencies (report upstream; we will track and update)
- Deployment misconfigurations (covered in operational documentation)

## Threat model

See [docs/architecture/threat-model.md](docs/architecture/threat-model.md) once published. The TCB explicit boundary, hardening checklist, and key-compromise recovery flows are documented there.

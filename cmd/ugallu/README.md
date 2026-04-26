# ugallu (CLI)

Standalone CLI binary for the ugallu platform. Used by operators (preflight, debugging) and by SREs / auditors (attestation verification).

## Planned subcommands

- `ugallu attest verify <bundle-uid>` — verify in-toto Statement signed via Fulcio keyless or OpenBao transit, validate Rekor inclusion proof, confirm against live CR or offline snapshot
- `ugallu doctor` — preflight check of the cluster: CRDs, ValidatingAdmissionPolicy, resolver/attestor/ttl Ready, WORM reachable, OpenBao reachable, Rekor reachable, SPIFFE workload API reachable
- `ugallu debug` — diagnostics for resolver indices, attestor pipeline state, TTL queue depth
- `ugallu version` — version information

Status: scaffold. Only `version` is wired.

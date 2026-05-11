# Changelog

All notable changes to ugallu land here. Format roughly follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); ugallu
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for public releases.

## [Unreleased]

### Added

- README + CHANGELOG aligned with the public docs site at
  [ugallu.io](https://ugallu.io).

## [v0.1.0-alpha.1]

First public release. Pre-`v1.0.0`; minor versions may break
compatibility. Breaking changes are called out at the top of each
release entry.

### Added

- **Closed CRD surface** under `security.ugallu.io/v1alpha1`:
  `SecurityEvent`, `EventResponse`, `AttestationBundle`, plus one
  `*Run` / `*Result` pair per workflow operator. 16
  ValidatingAdmissionPolicies guard the surface server-side.
- **92 SecurityEvent types** in a frozen catalog
  (`sdk/pkg/api/v1alpha1/types_catalog.go`). The catalog is
  enforced by a `ValidatingAdmissionPolicy` so a typo in an
  emitter is rejected at the API server before any consumer sees
  it.
- **11 operators**, all shipped in a multi-binary runtime image:
  - `audit-detection` - apiserver audit log → Sigma rule engine
    → SecurityEvent, with hot-swappable rules and per-rule rate
    limiting
  - `backup-verify` - Velero / etcd-snapshot integrity check with
    optional sandbox restore + diff
  - `compliance-scan` - kube-bench + Falco + CEL custom backends
    with a unified `ComplianceScanResult` contract
  - `confidential-attestation` - per-node TPM 2.0 / SEV-SNP / TDX
    quotes verified against an attestation policy
  - `dns-detect` - DaemonSet capture from CoreDNS plugin or
    Tetragon kprobe + 5 detectors (exfiltration, tunneling,
    blocklist, young-domain, anomalous-port)
  - `forensics` - IR-as-code pipeline (pod freeze + filesystem
    snapshot to WORM + unfreeze), every step sealed as an
    `EventResponse` by the attestor
  - `gitops-responder` - `EventResponse` -> PR/MR on the GitOps
    repo (GitHub App + GitLab providers; `noop` provider ships
    for dev / test environments)
  - `honeypot` - decoy `Secret` and `ServiceAccount` objects that
    fire `HoneypotTriggered` SEs the moment audit traffic
    touches them
  - `seccomp-gen` - generates OCI seccomp profiles by tracing a
    target Pod via the `tetragon-bridge` gRPC stream
  - `tenant-escape` - audit-bus + Tetragon network namespace
    events drive 4 cross-tenant detectors against the
    `TenantBoundary` index
  - `webhook-auditor` - continuously scores admission webhook
    configurations and fires a SecurityEvent when the risk
    threshold is crossed
- **SDK runtime singletons**: `resolver` (subject hydration),
  `attestor` (cosign keyless + Rekor + WORM seal),
  `ttl` (lifecycle GC + archive snapshots),
  `backpressure` (cluster-wide rate limiter for the emitter).
- **Backend-for-Frontend (`ugallu-bff`)** and **SvelteKit UI
  (`ugallu-ui`)** for the SOC view. OIDC + PKCE auth against any
  IdP (Keycloak is the reference) with an
  `--auth-disabled` lab/dev escape hatch. Read-only over the
  `security.ugallu.io` group; impersonates the OIDC subject so
  apiserver audit retains the human actor.
- **Helm umbrella chart** at `charts/ugallu`. One
  `helm install ugallu charts/ugallu` ships every operator,
  RBAC, admission policy, namespace and CRD. The `ugallu-ui`
  subchart adds a single Pod with the BFF + nginx-distroless
  serving the SPA bundle.
- **Cosign-keyless supply chain**: every operator image and every
  attestation bundle is signed via GitHub OIDC + Fulcio + Rekor.
  SBOM attached as a separate cosign attestation.
- **Public documentation site** at
  [ugallu.io](https://ugallu.io). Covers architecture,
  operators, the CRD reference, operations, and four recipes
  (detect a cluster-admin grant, verify a Velero backup,
  capture forensic evidence, generate a seccomp profile).

### Known limitations

- The `ValidatingAdmissionPolicy` CEL surface requires
  Kubernetes >= 1.30.
- Sigstore policy-controller is recommended for image signature
  enforcement but not bundled.
- The `gitops-responder`'s GitHub / GitLab providers are wired
  but the round-trip integration is still under hardening; the
  `noop` provider is the default for `v0.1.0-alpha.1`.
- The Linux kernel must be >= 5.8 for modern-eBPF features
  (Falco / Tetragon).

[Unreleased]: https://github.com/ninsun-labs/ugallu/compare/v0.1.0-alpha.1...HEAD
[v0.1.0-alpha.1]: https://github.com/ninsun-labs/ugallu/releases/tag/v0.1.0-alpha.1

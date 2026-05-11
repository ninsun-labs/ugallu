# sdk

Shared SDK for the ugallu platform. Consumed by every operator and SDK runtime singleton (resolver, attestor, ttl) plus the `ugallu` CLI.

## Subpackages (planned)

- `pkg/api/v1alpha1/` - CRD types (SecurityEvent, EventResponse, AttestationBundle, AttestorConfig, WORMConfig, TTLConfig, GitOpsResponderConfig) + per-kind `Subject` schema
- `pkg/runtime/` - controller-runtime helpers, leader election, lifecycle, `runtime/ttl/` controller
- `pkg/events/` - SecurityEvent emit/subscribe, correlation
- `pkg/evidence/` - `sign/`, `attestor/`, `worm/` (cosign + Rekor + S3 WORM)
- `pkg/identity/` - `openbao/`, `spiffe/`
- `pkg/resolver/server/` + `pkg/resolver/clientv1/` - gRPC subject resolver (eBPF cgroup tracker + informer cache)
- `pkg/sources/` - `tetragon/`, `audit/`, `hubble/`, `dns/` adapters
- `pkg/responders/` - `gitops/`, `netpol/`, `isolation/`
- `pkg/obs/` - metrics, tracing, slog
- `pkg/testing/` - envtest harness, fakes
- `proto/` - protobuf contracts (resolver/v1)

Implementation begins as scaffold; CRD types come first, then SDK runtime singletons, then operators.

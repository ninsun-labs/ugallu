<p align="center">
  <img src="docs/assets/ugallu-wordmark.svg" alt="ugallu" height="80">
</p>

# ugallu

Kubernetes security platform - apotropaic guardian for cluster ingress and runtime.

> **Status: pre-alpha.** Initial detection chain (audit-detection + forensics + monitoring) is functional; extension operators are landing.

## Overview

`ugallu` integrates detection, response, and attestation operators around a shared SDK and a CRD spine on `security.ugallu.io/v1alpha1`. The platform implements a closed loop **detect → reason → respond → attest** with cryptographically signed evidence stored in WORM.

## Architecture at a glance

| Layer | Component | Status |
|---|---|---|
| Core SDK runtime | `ugallu-resolver` (DaemonSet, eBPF cgroup tracker + informer cache, gRPC subject lookup) | shipped |
| Core SDK runtime | `ugallu-attestor` (Deployment singleton, in-toto pipeline: OpenBao transit + Rekor + WORM) | shipped |
| Core SDK runtime | `ugallu-ttl` (Deployment singleton, lifecycle GC + attestor watchdog) | shipped |
| Detection | [`audit-detection`](operators/audit-detection) (Sigma-style rules over K8s audit log) | shipped |
| Response | [`forensics`](operators/forensics) (IR-as-code workflow, content-addressed WORM evidence) | shipped |
| Telemetry | [`monitoring`](charts/ugallu/charts/monitoring) (PrometheusRule + Grafana dashboards) | shipped |
| Detection / Reason / Response | webhook-auditor, dns-detect, seccomp-gen, velero-verify, compliance, coco-kit, tenant-escape, honeypot | landing |

## Repository structure

Multi-module Go workspace (`go.work`). Each component is an independent module:

```
sdk/                  shared SDK (CRD types, runtime, evidence pipeline, resolver client, sources, responders)
resolver/             ugallu-resolver binary
attestor/             ugallu-attestor binary
ttl/                  ugallu-ttl binary
cmd/ugallu/           CLI standalone
operators/<name>/     per-operator binaries
charts/ugallu/        umbrella Helm chart with subcharts
crds/                 CRD bundle (kustomize base)
argocd/               ApplicationSet for deployment
docs/                 architecture + deploy + reference
```

## Designs

Complete design documents live in this Obsidian vault (private at design phase): see `docs/architecture/` for published versions once the repository goes public.

## License

Apache-2.0. See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All commits require Developer Certificate of Origin sign-off (`git commit -s`).

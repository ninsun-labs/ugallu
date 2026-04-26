# attestor

Wave 1 subchart for `ugallu-attestor` (Deployment singleton via leader-election).

## Status

**Pre-alpha placeholder.** Sleeps with `busybox`. Override `image.*` + clear `command` for the real binary.

## Resources

- `Deployment/ugallu-attestor` (replicas=2 default; one is leader, the rest are warm standby) in the system (non-privileged) namespace
- Uses the `ugallu-attestor` SA from the `rbac` subchart
- Restricted PSA: runAsNonRoot, no caps, readOnlyRootFilesystem, RuntimeDefault seccomp

## Override knobs

```yaml
attestor:
  placeholder: false
  image:
    repository: ghcr.io/ninsun-labs/ugallu/ugallu-attestor
    tag: v0.0.1-alpha.1
  command: []
  replicas: 2
```

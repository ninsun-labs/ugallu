# ttl

Subchart for `ugallu-ttl` (Deployment singleton via leader-election).

## Status

**Pre-alpha placeholder.** Sleeps with `busybox`. Override `image.*` + clear `command` for the real binary.

## Resources

- `Deployment/ugallu-ttl` (replicas=1, Recreate strategy - singleton) in the system (non-privileged) namespace
- Uses the `ugallu-ttl` SA from the `rbac` subchart
- Restricted PSA

## Override knobs

```yaml
ttl:
  placeholder: false
  image:
    repository: ghcr.io/ninsun-labs/ugallu/ugallu-ttl
    tag: v0.0.1-alpha.1
  command: []
```

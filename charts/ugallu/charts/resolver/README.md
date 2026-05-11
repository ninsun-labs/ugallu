# resolver

Subchart for `ugallu-resolver` (DaemonSet on every node).

## Status

**Pre-alpha placeholder.** The DaemonSet runs `busybox sleep infinity` for the deploy-contract validation while the real binary is implemented. Override `image.repository`/`image.tag` and clear `command` to switch to the production binary.

## Resources rendered

- `DaemonSet/ugallu-resolver` in the privileged namespace
- `Service/ugallu-resolver` (ClusterIP, gRPC + metrics ports)

The DaemonSet uses the `ugallu-resolver` SA (created by the `rbac` subchart) and lands in the privileged namespace (created by the `namespaces` subchart). Privileges and host paths:

- `hostPID: true` (PID resolution)
- caps: `BPF`, `PERFMON`, `SYS_ADMIN` (eBPF cgroup tracker + BTF)
- hostPath: `/sys/fs/cgroup`, `/proc`, `/sys/kernel/btf`, `/var/run/ugallu` (Unix socket)

## Override knobs

```yaml
resolver:
  placeholder: false
  image:
    repository: ghcr.io/ninsun-labs/ugallu/ugallu-resolver
    tag: v0.1.0-alpha.2
  command: []
  args: []
```

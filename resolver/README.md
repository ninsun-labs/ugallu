# ugallu-resolver

DaemonSet that hosts:

- eBPF cgroup tracker (CO-RE program on `cgroup_mkdir`/`cgroup_rmdir` raw tracepoints) for authoritative `cgroupID → PodUID` mapping
- informer caches for Pod / Node / ServiceAccount / Namespace / EndpointSlice
- secondary indices: `podByIP`, `podByUID`, `podByCgroupID`, `podByContainerID`, `saIndex`
- gRPC server on Unix socket (local node) + ClusterIP Service (cluster-wide)
- tombstone GC for late-arriving events

See vault `03 - Subject Resolver` for the locked design.

Status: scaffold. Implementation pending.

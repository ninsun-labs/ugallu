# audit-detection

Wave 1 operator. DaemonSet consumes the Kubernetes API server audit log via webhook backend, evaluates Sigma-style rules, and emits SecurityEvent CRs of class `Detection` or `Audit`.

## Rule examples (Wave 1 catalog)

`WildcardRBACBinding`, `ClusterAdminGranted`, `PrivilegedPodChange`, `HostPathMount`, `CapAddDangerous`, `AnonymousAccess`, `ImpersonationUsed`, `PrivilegeEscalationAttempt`, `FailOpenWebhook`, `CRDOverwrite`, `APIServiceInsecure`, `NamespacePSAWeakened`, `ExecIntoPod`, `PortForwardOpened`, ...

See vault `11 - Type taxonomy (Wave 1)` for the full catalog and `02 - SecurityEvent (v1alpha1)` for the schema.

Status: scaffold. Implementation pending.

# forensics

Wave 1 operator. Deployment that orchestrates `IncidentResponse` workflows in reaction to high-severity SecurityEvent. Each workflow expands into multiple atomic EventResponse steps:

1. `PodFreeze` — apply CiliumNetworkPolicy deny-all to isolate the subject pod
2. `FilesystemSnapshot` — capture rootfs as `tar.zst` to WORM
3. `MemorySnapshot` — capture process memory (CRIU or equivalent) to WORM
4. `EvidenceUpload` — persist additional logs/events to WORM
5. attestation chain: each EventResponse and the IncidentResponse umbrella triggers AttestationBundle

See vault `04 - EventResponse` for the workflow pattern and `13 - RBAC Bundle` for the elevated permissions required (CAP_SYS_PTRACE, ephemeral container insert, CiliumNetworkPolicy create).

Status: scaffold. Implementation pending.

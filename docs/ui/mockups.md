# Ugallu UI — ASCII mockups (v0.1.0-alpha.1)

Three reference views: **Dashboard**, **SecurityEvent list**,
**SecurityEvent detail**. Plus the unified Run list. Used to anchor
the SvelteKit + ShadCN-Svelte component tree before any code is
written.

---

## /  Dashboard

```
┌─ ugallu  cluster: rke2-lab ────────────────  alice@example.com  [⏻]─┐
│                                                                     │
│  ┌─ Posture (last 24h) ────┐  ┌─ Top severities ──────────────────┐ │
│  │                          │  │  critical  ▆▆▆▆▆▆▆ 7              │ │
│  │   ✔ 124 pass             │  │  high      ▆▆▆▆▆▆▆▆▆▆▆▆▆ 21       │ │
│  │   ✘   8 fail             │  │  medium    ▆▆▆▆ 4                 │ │
│  │   ◯   3 indeterminate    │  │  low       ▆ 1                    │ │
│  │                          │  │  info      ▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆ 32    │ │
│  └──────────────────────────┘  └──────────────────────────────────┘ │
│                                                                     │
│  ┌─ Recent incidents ─────────────────────────────────────────────┐ │
│  │  TIME      TYPE                       SUBJECT          SEV    │ │
│  │  2m ago    DNSToBlocklistedFQDN      pod/team-a/cli   high  ▶ │ │
│  │  9m ago    HoneypotTriggered         secret/decoy     critic │ │
│  │  17m ago   IncidentCaptureCompleted  pod/team-a/cli   info   │ │
│  │  31m ago   ComplianceScanCompleted   cluster          info   │ │
│  │                                                ⋯ 12 more     │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  ┌─ Run state ─────────────┐  ┌─ Attestation chain ──────────────┐ │
│  │  backup-verify   2 ✔ 0 ✘ │  │  fulcio  rekor   sealed   stale  │ │
│  │  compliance      1 ✔ 1 ✘ │  │    ✔      ✔        ✔       0     │ │
│  │  attestation     3 ✔ 0 ✘ │  └──────────────────────────────────┘ │
│  │  seccomp         0 ✔ 0 ✘ │                                       │
│  └──────────────────────────┘                                       │
└─────────────────────────────────────────────────────────────────────┘
```

Components used: `Card`, `Badge`, `Progress`, `Table`, `Sparkline` (custom).

---

## /events  list

```
┌─ ugallu / events ──────────────────────────  alice@example.com [⏻]─┐
│                                                                    │
│  ┌─ Filters ──────────────────────────────────────────────────────┐│
│  │ class:[Detection ▾] severity:[≥ high ▾] ns:[any]   ⌕ qname:    ││
│  └────────────────────────────────────────────────────────────────┘│
│                                                                    │
│  ┌────────────┬──────────────────────────┬───────────────┬────────┐│
│  │ TIME       │ TYPE                     │ SUBJECT       │ SEV    ││
│  ├────────────┼──────────────────────────┼───────────────┼────────┤│
│  │ 2m ago     │ DNSToBlocklistedFQDN     │ pod/team-a/c1 │ high  ▶││
│  │ 9m ago     │ HoneypotTriggered        │ secret/decoy  │ crit  ▶││
│  │ 17m ago    │ IncidentCaptureCompleted │ pod/team-a/c1 │ info  ▶││
│  │ 25m ago    │ DNSExfiltration          │ pod/team-a/c1 │ high  ▶││
│  │ 31m ago    │ CrossTenantSecretAccess  │ sa/team-b/bot │ high  ▶││
│  │   …                                                            ││
│  └────────────┴──────────────────────────┴───────────────┴────────┘│
│                              ⌜ ‹ 1 2 3 4 5 › ⌝   page size [50 ▾] │
└────────────────────────────────────────────────────────────────────┘
```

Click on a row → `/events/<name>`. The right ▶ marker hints at
"this SE shares a CorrelationID with at least one other" — clicking
it filters the list to the incident.

---

## /events/<name>  detail

```
┌─ ugallu / events / se-2eef2bfbc0e91023 ──────────────────  [⏻]─────┐
│                                                                    │
│  DNSToBlocklistedFQDN                                       high   │
│  emitted 2m ago by ugallu-dns-detect v0.0.1-alpha.1                │
│  correlation: a8f8fb55…  ⤷ 3 related events  [open incident view] │
│                                                                    │
│  ┌─ Subject ──────────────────────────────────────────────────────┐│
│  │  Kind: Pod                                                     ││
│  │  Name: client-pod-1777473010-920392                            ││
│  │  Namespace: dns-smoke                                          ││
│  │  UID: 701cdd19-0ee6-461e-96e7-3bd2fb9b8741                     ││
│  │  Status: unresolved (resolver miss)                            ││
│  └────────────────────────────────────────────────────────────────┘│
│                                                                    │
│  ┌─ Signals ──────────────────────────────────────────────────────┐│
│  │ qname:           evil.bit                                      ││
│  │ src_ip:          10.244.7.7                                    ││
│  │ src_cgroup:      4242                                          ││
│  │ blocklist_match: ugallu-dns-blocklists/default                 ││
│  └────────────────────────────────────────────────────────────────┘│
│                                                                    │
│  ┌─ Attestation chain ────────────────────────────────────────────┐│
│  │  Phase: Sealed                                                 ││
│  │  Fulcio cert:  CN=ugallu-dns-detect    [✓ verified]            ││
│  │  Rekor entry:  rekor.ugallu/123456789  [✓ included]            ││
│  │  WORM object:  s3://ugallu-evidence/se-…/dsse.json             ││
│  └────────────────────────────────────────────────────────────────┘│
│                                                                    │
│  ┌─ Raw spec (yaml) ────────────────────────────  [copy]  [-]──┐  │
│  │ class: Detection                                            │  │
│  │ type:  DNSToBlocklistedFQDN                                 │  │
│  │ ⋯                                                           │  │
│  └─────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
```

Components: `Card`, `KeyValue`, `StatusBadge`, `CodeBlock`,
`Collapsible`. The "open incident view" CTA is a placeholder for the
Wave 6 incident-graph route.

---

## /runs  unified run list

```
┌─ ugallu / runs ────────────────────────────  alice@example.com [⏻]─┐
│                                                                    │
│  filter: kind:[any ▾]   phase:[any ▾]   namespace:[any ▾]    ⌕    │
│                                                                    │
│  ┌────────────┬────────────────────┬──────────────────┬───────────┐│
│  │ TIME       │ KIND                │ NAME             │ PHASE    ││
│  ├────────────┼─────────────────────┼──────────────────┼──────────┤│
│  │ 2m ago     │ BackupVerifyRun     │ velero-good      │ Succeed ▶││
│  │ 14m ago    │ ComplianceScanRun   │ cel-default      │ Succeed ▶││
│  │ 22m ago    │ ConfidentialAtt…Run │ tpm-cp-1         │ Succeed ▶││
│  │ 1h ago     │ SeccompTrainingRun  │ team-a-training  │ Succeed ▶││
│  │ 2h ago     │ BackupVerifyRun     │ velero-fullrest. │ Failed  ▶││
│  └────────────┴─────────────────────┴──────────────────┴──────────┘│
└────────────────────────────────────────────────────────────────────┘
```

Click → `/runs/<kind>/<ns>/<name>` → the Run detail (status conditions,
linked Result, framework mappings for compliance, etc).

---

## Visual language

- **Severity colour**: critical = red-600, high = orange-500,
  medium = yellow-400, low = blue-400, info = slate-400. Background
  `bg-foreground/5` per row, no hover-darken on dark mode.
- **Density**: ShadCN's default table density (medium). The SOC view
  needs at least 25 rows visible without scroll on a 1080p screen.
- **Theme**: dark mode default; light mode follows OS preference.
- **Typography**: Inter for UI, JetBrains Mono for code blocks.

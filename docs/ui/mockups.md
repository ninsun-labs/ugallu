# Ugallu UI — wireframe mockups (v0.1.0-alpha.1)

Reference views for the SvelteKit + ShadCN-Svelte component tree.

The wireframes below are a **layout contract**, not a fidelity
target — they pin where each card sits, which fields each detail
view exposes, and the table density. The rendered SvelteKit views
use the full ShadCN-Svelte palette (icons, badges, hover states,
transitions); these ASCII shells just keep the design honest.

Lists and table content are written as Markdown tables so they
render natively. ASCII boxes are kept short and used only where
the placement matters (split cards, panes side-by-side).

---

## /  Dashboard

Layout — three rows: top KPIs, recent incidents, run state +
attestation chain.

```
+----------------------------------------------------------------------+
|  ugallu / dashboard                       cluster: rke2-lab          |
+----------------------------+-----------------------------------------+
|  Posture (last 24h)        |  Severity counts                        |
|                            |                                         |
+----------------------------+-----------------------------------------+
|  Recent incidents (paged, last 24h, click to drill into the SE)      |
|                                                                      |
+--------------------------------+-------------------------------------+
|  Run state (4 kinds, OK/FAIL)  |  Attestation chain                  |
|                                |                                     |
+--------------------------------+-------------------------------------+
```

**Posture (last 24h)** — count of compliance check outcomes:

| outcome | count |
|---|---:|
| pass | 124 |
| fail | 8 |
| indeterminate | 3 |

**Severity counts** — emitted SE in the last 24h, by severity:

| severity | count |
|---|---:|
| critical | 7 |
| high | 21 |
| medium | 4 |
| low | 1 |
| info | 32 |

**Recent incidents** — last N SE rolled up by `correlationID`,
clicking a row drills into the incident view:

| time | type | subject | sev |
|---|---|---|---|
| 2m ago | DNSToBlocklistedFQDN | pod team-a/cli | high |
| 9m ago | HoneypotTriggered | secret/decoy | critical |
| 17m ago | IncidentCaptureCompleted | pod team-a/cli | info |
| 31m ago | ComplianceScanCompleted | cluster | info |

**Run state** — pass/fail by run kind, last 24h:

| kind | pass | fail |
|---|---:|---:|
| backup-verify | 2 | 0 |
| compliance-scan | 1 | 1 |
| confidential-attestation | 3 | 0 |
| seccomp-gen | 0 | 0 |

**Attestation chain** — supply-chain status:

| component | state |
|---|---|
| Fulcio | ok |
| Rekor | ok |
| Sealed bundles | ok |
| Stale bundles | 0 |

---

## /events  list

```
+----------------------------------------------------------------------+
|  ugallu / events                                                     |
+----------------------------------------------------------------------+
|  Filter row:  class | severity | ns | search-qname                   |
+----------------------------------------------------------------------+
|  Paged table — 50 rows per page, infinite scroll on Wave 6           |
|                                                                      |
+----------------------------------------------------------------------+
```

**Filter row**: `class` (multi-select), `severity` (range slider:
">= high"), `namespace` (autocomplete), free-text qname search.

**Result table**:

| time | type | subject | sev | related |
|---|---|---|---|:---:|
| 2m | DNSToBlocklistedFQDN | pod team-a/c1 | high | > |
| 9m | HoneypotTriggered | secret/decoy | critical | > |
| 17m | IncidentCaptureCompleted | pod team-a/c1 | info | > |
| 25m | DNSExfiltration | pod team-a/c1 | high | > |
| 31m | CrossTenantSecretAccess | sa team-b/bot | high | > |

The trailing `>` flag means "this SE shares a `correlationID`
with at least one other event"; clicking it filters the list to
that incident.

---

## /events/<name>  detail

```
+----------------------------------------------------------------------+
|  ugallu / events / se-2eef2bfbc0e91023                               |
+----------------------------------------------------------------------+
|  Header: type, severity, emitter, correlationID + related count      |
+----------------------+-----------------------------------------------+
|  Subject card        |  Signals card                                 |
|                      |                                               |
+----------------------+-----------------------------------------------+
|  Attestation chain card                                              |
+----------------------------------------------------------------------+
|  Raw spec (yaml, collapsible, copy button)                           |
+----------------------------------------------------------------------+
```

**Header** — fixed 3 lines:

```
DNSToBlocklistedFQDN                                              high
emitted 2m ago by ugallu-dns-detect v0.0.1-alpha.1
correlation: a8f8fb55...   3 related events   [open incident view]
```

**Subject card** — KeyValue rows:

| field | value |
|---|---|
| Kind | Pod |
| Name | client-pod-1777473010-920392 |
| Namespace | dns-smoke |
| UID | 701cdd19-0ee6-461e-96e7-3bd2fb9b8741 |
| Status | unresolved (resolver miss) |

**Signals card** — KeyValue rows from `spec.signals`:

| key | value |
|---|---|
| qname | evil.bit |
| src_ip | 10.244.7.7 |
| src_cgroup | 4242 |
| blocklist_match | ugallu-dns-blocklists/default |

**Attestation chain card**:

| field | value |
|---|---|
| Phase | Sealed |
| Fulcio cert | CN=ugallu-dns-detect [verified] |
| Rekor entry | rekor.ugallu/123456789 [included] |
| WORM object | s3://ugallu-evidence/se-.../dsse.json |

**Raw spec (yaml)** — collapsible code block with a copy-to-clipboard
button. Default state collapsed; default theme dark.

The "open incident view" CTA is a placeholder for the Wave 6
incident-graph route.

---

## /runs  unified run list

```
+----------------------------------------------------------------------+
|  ugallu / runs                                                       |
+----------------------------------------------------------------------+
|  Filter row:  kind | phase | namespace | search                      |
+----------------------------------------------------------------------+
|  Paged table — same density as /events                               |
+----------------------------------------------------------------------+
```

| time | kind | name | phase |
|---|---|---|---|
| 2m | BackupVerifyRun | velero-good | Succeeded |
| 14m | ComplianceScanRun | cel-default | Succeeded |
| 22m | ConfidentialAttestationRun | tpm-cp-1 | Succeeded |
| 1h | SeccompTrainingRun | team-a-training | Succeeded |
| 2h | BackupVerifyRun | velero-fullrestore-test | Failed |

Click on a row → `/runs/<kind>/<ns>/<name>` (Run detail with status
conditions, linked Result, framework mappings for compliance, etc).

---

## Visual language

- **Severity colour**: critical = red-600, high = orange-500,
  medium = yellow-400, low = blue-400, info = slate-400.
  Background `bg-foreground/5` per row, no hover-darken on dark mode.
- **Density**: ShadCN's default table density (medium). The SOC
  view needs at least 25 rows visible without scroll on 1080p.
- **Theme**: dark mode default; light mode follows OS preference.
- **Typography**: Inter for UI, JetBrains Mono for code blocks.
- **Empty states**: every list view ships an explicit empty state
  card with a "what creates this" sentence (e.g. /events empty →
  "No SecurityEvents yet — the operators emit them on incidents
  + on schedule. Try `kubectl apply -f hack/...`.").

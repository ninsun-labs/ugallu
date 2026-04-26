# ugallu-ttl

Leader-elected Deployment that:

- archives SecurityEvent / EventResponse / AttestationBundle CRs at TTL expiry (after snapshotting the CR YAML to WORM as evidence)
- enforces preconditions (parent bundle Sealed) before archiving SE/ER
- supports postpone, force, and frozen (legal hold) annotations
- doubles as the **attestor watchdog**: emits `AttestorUnavailable` and toggles cluster-wide backpressure when the attestor heartbeat goes stale

See vault `09 - TTL & Archive Controller`.

Status: scaffold. Implementation pending.

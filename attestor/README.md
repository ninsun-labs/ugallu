# ugallu-attestor

Leader-elected Deployment that watches SecurityEvent and EventResponse, builds in-toto Statements, signs (Fulcio keyless or OpenBao transit), uploads to Rekor, and archives the DSSE envelope in WORM.

Pipeline: `Pending → Signed → Logged → Sealed` (or `Failed` recoverable).

See vault `05 - AttestationBundle` and `06 - Signing Strategy`.

Status: scaffold. Implementation pending.

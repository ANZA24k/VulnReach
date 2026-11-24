# Security model

VulnReach assesses a specific advisory against specific submitted documents. It does not provide exploitation instructions, attack a target, or certify that software is secure.

## Trust boundaries

OSV is the authoritative vulnerability metadata source for this workflow. The fixed endpoint is constructed only from a validated GHSA ID; callers cannot provide arbitrary fetch URLs. An exact expected canonical JSON SHA-256 and the advisory's identity must match before locking. Retrieval occurs inside strict-equality consensus. The current API response must be at most 60,000 bytes; advisory prose at most 18,000 bytes.

Manifest and configuration documents are submitter-attested. Hash, byte count, and provenance labels are validated; URL ownership and runtime deployment identity are not. Frontend text is rendered through React escaping; evidence is never inserted as HTML. Users must redact secrets before submitting immutable public evidence.

For AI decisions the leader and validators execute the same analysis independently. Validators validate the leader's exact quote grounding and independently reproduce its decision field. They do not merely check a JSON shape or approve the leader's explanation. Definite findings require contiguous quotations from both locked documents. Ambiguous or ungrounded findings normalize to UNKNOWN. Invalid provider JSON or provider failures can revert, rather than create a misleading successful assessment.

Documents and challenges are untrusted data in the prompt. Prompt-injection instructions are explicitly prohibited, and contradictory or injected documents should yield UNKNOWN. AI remains fallible; independent consensus and quotation checks do not eliminate correlated model failures or false submitter assertions.

## Deterministic safeguards

- Case creation is immutable; duplicate identifiers and unknown fields are rejected.
- Owner-only lock and assessment operations. Finalization is permissionless after the deadline.
- Exact v2/v3 package-lock identity, official npm tarball prefix, exact dependency path, no aliases or links.
- Stable SemVer interval union, inclusive `last_affected`, exclusive `fixed`, conservative `limit`, unsupported data remains unknown.
- One challenge per case, during a five-minute window; bounded reassessment, no evidence replacement or deletion.
- Global receipts contain monotonic sequence, actor, time, prior hash, evidence/decision payload and their own SHA-256.
- No contracts transfer funds or hold escrow. Studionet transactions use development-network currency.

A public challenge can delay a case and consume the case's single challenge slot. It cannot alter its inputs or erase prior findings. A malicious owner can abandon a challenged case; it remains visibly CHALLENGED. A dishonest submitter can create a misleading documentary case; readers must verify submitter identity and actual deployment scope independently.

## Application protections

No private keys, API secrets or signing relays are included. Browser-wallet chain and account are checked; network/account changes clear the signing connection. Transactions use full consensus. The monitor distinguishes provisional acceptance, execution failure, cancellation, and verified final success, and saves a pending hash to avoid accidental duplicate submission. Wallet tests use mocked providers; live Studio signatures are separately recorded as network evidence.

Report issues through a GitHub issue without including secrets, personal data or exploit payloads. Rotate any accidentally disclosed credential outside this system. Development-network state may reset; export the evidence needed for long-term audit.

# VulnReach

**Evidence before urgency.** Intelligent vulnerability applicability verification on GenLayer.

VulnReach connects an exact npm dependency version to a published GitHub advisory and scoped configuration evidence. Deterministic contract code evaluates OSV affected-version intervals. For a matching version, the leader and validators independently assess the advisory's necessary conditions, producing a grounded, documentary applicability finding. Every state transition appends a hash-linked receipt.

A scanner alert identifies a potentially vulnerable dependency. Teams still disagree about whether the relevant feature is used, whether an exploitation condition is present, and which evidence supported a remediation decision. VulnReach gives that review a reproducible scope, independently validated reasoning, an explicit uncertainty outcome, and a durable challenge trail.

## Links

- Source: https://github.com/ANZA24k/VulnReach
- Website and deployed contract: see [DEPLOYMENT.md](DEPLOYMENT.md).
- Real network transactions and verification: [EVIDENCE.md](EVIDENCE.md).
- Submission text: [SUBMISSION.md](SUBMISSION.md).

## Run locally

Requires Node.js 22.12+ or 24, Python 3.12+, and network access to OSV and Studionet.

```sh
npm ci
python -m pip install -r requirements-dev.txt
npm test
npm run test:wallet
npm run build
npm run dev -- --host 127.0.0.1
```

Frontend: React, TypeScript, Vite, GenLayerJS 2.0.0. Contract: standalone `contracts/vuln_reach.py`, using the pinned GenVM Python dependency in its header. No backend, database, paid API key, or server-held wallet is required.

## Use it

1. Connect a browser wallet on Studionet, or select **GenLayer Studio** to sign with its built-in wallet. The site never requests a private key.
2. Open **Review workbench**. Supply an npm `package-lock.json` v2/v3, the exact path under `packages`, a GHSA identifier, and public, scoped configuration evidence. The synthetic examples make the input format easy to inspect.
3. Fetch the current OSV advisory. Review its canonical JSON SHA-256 and create an immutable case. A new case ID is required for changed evidence.
4. **Lock authoritative advisory**. The contract independently retrieves the fixed OSV API URL, verifies the expected canonical JSON hash and GHSA identity, and stores the snapshot. If OSV changed, create a new case using the new hash.
5. **Request consensus assessment**. Version exclusion is deterministic; in-range conditions are reviewed by the leader and independently re-derived by validators. Full consensus is always requested.
6. Read the finding and exact quotes. A reviewed case has a five-minute challenge window. Any wallet can raise one challenge. The owner can resolve it through another assessment of the same immutable evidence plus the challenge.
7. Finalize after the window expires. Export the case and receipt chain for audit. Prior receipts cannot be overwritten.

With Studio mode, each site action downloads the exact contract method and JSON inputs. Open Studio, import the deployed address, select the method, and paste the `inputs` object in JSON mode. Execute in **Normal (Full Consensus)**, then paste the resulting hash into the website's transaction monitor. Browser-wallet mode submits directly using `writeContract`; Studio mode is an explicit signing handoff, not a wallet connection across origins.

## Outcomes and limits

| Outcome | Contract rule |
|---|---|
| `AFFECTED` | Version in an affected range; independent AI consensus finds all stated necessary conditions evidenced, with exact advisory and configuration quotes. |
| `NOT_AFFECTED` | Exact version outside every supported affected range, or consensus establishes a necessary condition is explicitly absent across the documented scope. |
| `INCONCLUSIVE` | Unsupported/unknown version evidence, withdrawn advisory, missing package match, or unestablished/contradictory conditions. |

`NOT_AFFECTED` applies only to the selected advisory and locked documentary scope. Configuration and lockfile provenance are **submitter-attested**, even if a source URL is provided; the contract does not authenticate a running system, detect omitted services, verify supplied source ownership, or execute exploit tests. Exact quotations prove grounding in the documents, not truth of those documents. Hashes bind bytes, not authenticity. This is not a security certification or a replacement for patching and security review.

The first release deliberately supports only npm package-lock v2/v3 and stable three-component SemVer ranges from OSV. npm aliases, symlink dependencies, non-registry artifacts, prereleases, build metadata, and other ecosystems are not interpreted as safe. `limit` boundaries cannot establish exclusion beyond the limit. All matching OSV affected records are considered as a union. Missing/unsupported interval data prevents a negative version finding.

No findings are computed by a frontend LLM. The website reads finalized contract state. `ACCEPTED` is provisional; execution failures are never displayed as successful finalization. Network/provider failures can revert or leave a transaction unresolved; they do not become a safe verdict. The development network can reset and does not provide production persistence guarantees.

## Architecture

- `contracts/vuln_reach.py`: immutable cases, authoritative OSV fetch, deterministic interval evaluator, independently reproduced AI findings, scoped challenges, timed finalization, hash-linked receipts.
- `web/`: responsive interface, direct SDK reads/writes, EIP-1193 wallet connection, Studio inputs, transaction lifecycle monitoring, JSON exports.
- `tests/`: deterministic rules and lifecycle tests using an explicit GenLayer shim; wallet/provider and transaction-state tests. These do not replace real GenVM/network tests.
- `fixtures/`: clearly labeled synthetic evidence for affected, fixed, and undocumented dependency scenarios; advisory information is real OSV data.
- `evidence/`: deployment, real transaction summaries, exported state and receipts.
- `scripts/verify-live.mjs`: verifies deployed source, finalized successful full-consensus transactions, case outcomes and receipt chain.

## Continued use

A practical adoption path is an npm CI step that exports a bounded review packet for disputed scanner findings, then links the resulting case receipt from a ticket or VEX document. Future work includes authenticated build attestations, commit-pinned retrieval, SBOM ingestion, ecosystem-specific range parsers, and signed VEX exports. These are extensions, not existing guarantees.

## Primary references

- https://docs.genlayer.com/developers/intelligent-contracts/equivalence-principle
- https://docs.genlayer.com/api-references/genlayer-js/contracts
- https://docs.genlayer.com/developers/networks
- https://ossf.github.io/osv-schema/
- https://google.github.io/osv.dev/api/
- https://github.com/github/advisory-database

MIT licensed. See [SECURITY.md](SECURITY.md) for the threat model.

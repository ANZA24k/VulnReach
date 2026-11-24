# VulnReach — Intelligent Software Vulnerability Applicability Verification

**Category: Projects** (complete application with a contract-backed frontend).

## Submission description

VulnReach helps teams resolve disputed dependency vulnerability alerts with immutable evidence and independently validated reasoning. An npm package-lock, configuration evidence, and authoritative OSV advisory are hash-locked. The GenLayer contract checks affected versions deterministically, then independent AI validators interpret the advisory’s necessary conditions against the documented deployment scope. Grounded findings produce AFFECTED, NOT_AFFECTED, or INCONCLUSIVE. A timed challenge workflow preserves every assessment in append-only, hash-linked receipts. The frontend reads real finalized state, submits browser-wallet transactions, supports Studio built-in signing, tracks execution status, and exports evidence. Findings are documentary assessments; runtime configuration is not authenticated.

## Review links

- Website: https://vulnreach.vercel.app
- Repository: https://github.com/ANZA24k/VulnReach
- Contract: https://explorer-studio.genlayer.com/address/0x65329695921c877b8371f2F60084fb55bCF1523C
- Deployment transaction: https://explorer-studio.genlayer.com/transactions/0x1f2f00d924a7dd4eec6a105abc2e97dc6572095a59051ab7939c391a73b01bcc
- Validation evidence and full lifecycle transactions: [EVIDENCE.md](EVIDENCE.md).

## How reviewers can use it

Open the website and inspect `VR-LODASH-001` from the overview. Open Review workbench to inspect the exact locked documents and quotes, export the record, or prepare a new case using a clearly labeled synthetic example. Connect MetaMask to Studionet for direct signing, or choose GenLayer Studio to download method inputs for its built-in wallet. Every state mutation uses the deployed contract. The contract’s authoritative data retrieval and AI assessment run through real GenLayer consensus, not an off-chain frontend model.

## Why GenLayer is central

Affected-version math is objective and remains deterministic. Advisory phrases describe conditional feature use and deployment assumptions that do not reduce to version arithmetic. The leader and validators independently derive whether those conditions are evidenced, compare their decision, and require exact quotation grounding. The resulting immutable decision and its challenges can be linked from a remediation ticket or future VEX export.

## Verification boundary

First release: npm package-lock v2/v3, stable SemVer, bounded public evidence, OSV GHSA advisories. Manifest/configuration sources are submitter-attested. Provenance authentication, signed runtime attestations, more ecosystems and SBOM import are future work. No public social post has been made. Only recorded, successfully verified network operations should be represented as complete.

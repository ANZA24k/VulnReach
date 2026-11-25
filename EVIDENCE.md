# Verification evidence

Release contract: [0x65329695921c877b8371f2F60084fb55bCF1523C](https://explorer-studio.genlayer.com/address/0x65329695921c877b8371f2F60084fb55bCF1523C), GenLayer Studionet 61999.

The deployed Python source is `contracts/vuln_reach.py`. `evidence/deployment.json` is the transaction index. `scripts/verify-live.mjs` checks remote source bytes, successful finalized full-consensus execution, document hashes and the complete receipt chain. Provider execution failures and idle validators cancelled after quorum are distinguished from successful leader execution.

## Confirmed behavior

- Real OSV GHSA-35jh-r3h4-6jhm data is independently retrieved and bound by canonical JSON SHA-256 `7cf722323e4190b84d050dcf0565c0e9dc949fe6bdb63d9df46f9a14507c8498`.
- `VR-LODASH-001` records an **AFFECTED** finding for lodash 4.17.20. Its submitted synthetic configuration states that attacker-controlled template strings are compiled and executed in the scoped Node.js service. The leader and independent validators assessed the actual locked advisory and evidence, with exact quotes.
- A challenge was submitted and resolved through a second real assessment. Finalized state was read back as REVIEWED, AFFECTED, attempts 2.
- Empty case identifiers are rejected without creating an assessment. Rejected and superseded prerelease calls are retained separately; they are not counted as successful lifecycle operations.
- Manifest and configuration documents are synthetic, explicitly labeled fixtures. The vulnerability advisory is real authoritative OSV data. No claim is made that the fixture represents a real deployed service.

## Automated checks

52 Python tests cover stable SemVer boundaries and interval unions, unsupported formats, hash/byte binding, identity, authorization, immutable case IDs, exact quote grounding, conservative outcomes, challenge timing, finalization and receipt integrity. The explicit test shim reproduces the SDK's JSON-mode object return type; real GenVM schema and network checks are separate.

21 JavaScript tests cover canonical advisory commitments and Unicode encoding, plus browser-provider and transaction handling. They cover MetaMask-compatible EIP-1193 connection, chain addition/switching, rejected connections, provisional acceptance, execution errors, final success, idle validators, saved-status semantics and bounded read-only RPC retries. Writes are never automatically resent.

`npm run build` checks TypeScript and builds production assets. No runtime dependency vulnerabilities were found in the audited installed dependencies during implementation.

## Browser checks

The public Vercel site was opened without authentication. Real finalized case state, receipt data and the deployed explorer link were read through the frontend. An actual OSV advisory was fetched in the workbench; the resulting hash matched the contract snapshot. The site prepared and downloaded exact Studio inputs, which were used with the built-in Studio account. No private key was exported.

A compact CSS viewport of 545 pixels was exercised through browser zoom. Overview, mobile navigation, workbench and wallet dialog had no horizontal document overflow (client width and scroll width both 539 pixels). This is a CSS responsiveness check, not a physical-device certification. Desktop layout was also visually inspected.

## Limits and reproduction

Run `npm test`, `npm run test:wallet`, `npm run build`, and `npm run verify:live`. The latter uses the live public RPC and can be temporarily blocked by its shared request or execution-slot limits. These failures do not become safe findings. The frontend queues reads and retries transient congestion; no write is silently resubmitted.

Only live operations listed as successfully verified in the exported evidence should be represented as complete. No live MetaMask signature is claimed: actual signatures used the Studio built-in wallet; browser-wallet integration has provider tests. No public social post has been made.

## Netlify handoff

The requested hosting target is Netlify. The delivery ZIP includes a prebuilt static website, the complete source, Netlify headers and SPA fallback, and upload instructions. Publication will be performed by the owner; no Netlify live URL is claimed before it is supplied. Final package validation: 52 Python tests and 21 JavaScript tests passed; TypeScript and production build passed. Live finalization and the patched/insufficient-evidence comparison assessments remain unconfirmed because Studio returned request-limit, occupied execution-slot, and database errors during the last verification attempts.

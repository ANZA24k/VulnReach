# Deployment

- Public website: https://vulnreach.vercel.app
- GitHub: https://github.com/ANZA24k/VulnReach
- Network: GenLayer Studionet, chain ID **61999**
- RPC: https://studio.genlayer.com/api
- Contract: **0x65329695921c877b8371f2F60084fb55bCF1523C**
- Contract explorer: https://explorer-studio.genlayer.com/address/0x65329695921c877b8371f2F60084fb55bCF1523C
- Deployment transaction: https://explorer-studio.genlayer.com/transactions/0x1f2f00d924a7dd4eec6a105abc2e97dc6572095a59051ab7939c391a73b01bcc

The contract was deployed through GenLayer Studio using its built-in development account and **Normal (Full Consensus)**. No private key was exported or placed in the application. The frontend uses `genlayer-js@2.0.0`, the stable `studionet` preset, and `latest-final` reads. It does not relabel the Studio development-preview network.

## Reproduce the application

```sh
npm ci
npm run build
npm run dev -- --host 127.0.0.1
```

`web/deployment.json` contains the public address, explorer origin and initial case ID. No `.env` is needed. The Vercel project is `vulnreach`, owned by team `anza0x`; Node.js 22.x, install `npm ci`, build `npm run build`, output `dist`. `vercel.json` defines static security headers. The application is publicly readable without a Vercel account.

## Reproduce the contract

1. Open https://studio.genlayer.com.
2. Upload `contracts/vuln_reach.py`. Keep its pinned GenVM Python dependency.
3. Use **Normal (Full Consensus)** and deploy with no constructor inputs.
4. Verify finalized successful execution, not only a displayed FINALIZED status.
5. Update `web/deployment.json` and `evidence/deployment.json` for the new instance.
6. Use the site workbench to prepare method inputs. Sign in Studio or connect an EIP-1193 browser wallet.
7. Run `npm run verify:live` to compare deployed source, execution receipts and the receipt chain.

The original prerelease address `0xcD612C7fdABFE74C2Ded614366Cc53c594BA5399` is superseded. Live testing there exposed a raw HTTP whitespace difference in OSV data. The release commits **canonical JSON**, using sorted object keys, compact separators and ASCII escapes, while preserving array order and string values. This removes transport-format sensitivity without accepting semantic changes. The original rejected calls remain documented in `evidence/pre-release.json`.

## Network limitations

Studionet is a hosted development network and may reset. Public node calls may be rate-limited. The website retains pending transaction hashes for later verification and does not automatically resubmit writes. Full AI reviews depend on network validators and model availability; failures are not safe verdicts. Export receipts for durable audit. No production-chain deployment or live MetaMask signature is implied by a Studio signing test; browser-provider connection and lifecycle logic have separate automated tests.

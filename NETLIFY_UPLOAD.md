# Publish VulnReach on Netlify

The delivery ZIP contains the prebuilt website at its root: `index.html`, `assets/`, `_headers`, `_redirects`, and the logo. It also includes the complete project in `project-source/`.

1. Extract `VulnReach-Netlify-Ready.zip`.
2. Open your Netlify dashboard and select **Add new project → Deploy manually** (or https://app.netlify.com/drop).
3. Drag in the extracted folder that directly contains `index.html`. Do not upload only `project-source/` and do not run a build for this manual upload.
4. Open the generated HTTPS address and send that address back for a published-site check and final link updates.

No API key, environment variable, database, or backend setup is needed. The app already targets GenLayer Studionet contract `0x65329695921c877b8371f2F60084fb55bCF1523C`.

For Git-based deployment instead, import `ANZA24k/VulnReach`; build command `npm run build`, publish directory `dist`, Node.js 22. The repository's `netlify.toml` supplies these settings.

To edit the included source, open `project-source`, run `npm ci`, then `npm run build`. Upload that source folder's generated `dist` directory to Netlify for the updated website.

The real AFFECTED case, its resolved challenge, and its finalization are verified on Studionet. The two comparison-case assessments remain unconfirmed after earlier shared request-limit, execution-slot, and database errors. These limits are independent of Netlify hosting. See `project-source/EVIDENCE.md` for the verification boundary.

Published URL supplied and checked on 2026-11-25: https://earnest-choux-399835.netlify.app/

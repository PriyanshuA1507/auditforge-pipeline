# AuditForge — Audit Report Parser

A small frontend + scan proxy that ingests PDF/DOCX audit reports, validates, hashes, and performs a VirusTotal scan.

Quick start

1. Server (scan proxy)

- Create a `.env` or set the `VIRUSTOTAL_API_KEY` environment variable. Example in `.env.example`.

Windows PowerShell:

```powershell
$env:VIRUSTOTAL_API_KEY = "your_api_key_here"
cd server
npm install
npm start
```

2. Frontend

```bash
npm install
npm run dev
# open http://localhost:3001/ in your browser
```

Notes

- The VirusTotal API key must be set on the server only — never expose it in the browser.
- The frontend can be pointed to a different scan proxy via the `VITE_SCAN_API_URL` env var.

Security

- This project is a demo. For production, add stricter validation, rate-limiting, request authentication, and secure secret storage.

Full project summary
-------------------

- Components:
	- Frontend: Vite + React (in `src/`). Key components: `ScanPanel.jsx` (file ingestion pipeline), `ScanResults.jsx` (per-engine VT display), `Dashboard.jsx` (analytics), `JsonOutput.jsx` (export).
	- Server: Express scan proxy (in `server/`) using `multer` for uploads, forwards files to VirusTotal API, polls analysis, and returns `{ analysis, vt_meta, extracted_cves }`.

- Pipeline implemented:
	1. Secure ingestion — client file drop/browse + server upload endpoint (`POST /scan`).
	2. File validation — allowed types: PDF/DOCX, max 50 MB, filename validation.
	3. SHA-256 hashing — computed and re-verified in the browser using Web Crypto API.
	4. Malware scanning — file forwarded to VirusTotal; server polls `/api/v3/analyses/{id}` and fetches `/api/v3/files/{id}` for `last_analysis_stats`.

- Extra features:
	- Best-effort DOCX CVE extraction on server using `adm-zip`.
	- Client-side synthesis of `vt_meta.stats` when the server doesn't provide it.
	- Per-engine CVE extraction from VT engine results (regex `CVE-YYYY-NNNN`) merged into final `extraction.cve_ids`.
	- JSON / CSV export from the UI.

Environment variables
---------------------

- Server (create `server/.env` or set env vars):
	- `VIRUSTOTAL_API_KEY` — your VirusTotal API key (server-side only). Restart server after changing.
	- `PORT` — optional server port (default `4000`).

- Frontend (Vite):
	- `VITE_SCAN_API_URL` — optional override for scan API (default `http://localhost:4000/scan`).

How to run locally
-------------------

1. Server (scan proxy)

```powershell
cd server
npm install
# add server/.env with VIRUSTOTAL_API_KEY
npm start
```

2. Frontend

```bash
npm install
npm run dev
# open http://localhost:3001/ (or the port Vite selects)
```

Security & operational notes
----------------------------

- Do NOT paste API keys into chat or commit them. If a key was exposed, rotate it immediately.
- For production, put the `VIRUSTOTAL_API_KEY` in a secure secrets store (Azure Key Vault, AWS Secrets Manager, etc.) and authenticate requests to the scan proxy.
- Consider rate-limiting and request-level authentication to prevent abuse of the VirusTotal key.

Pushing to GitHub
------------------

I can initialize a git repo and push this workspace to a new GitHub repository for you. To proceed I need one of:

- A GitHub repository remote URL you created and permission to push (e.g. `https://github.com/yourname/repo.git`), OR
- A GitHub personal access token (PAT) with `repo` scopes so I can create a repo via the API and push.

If you prefer to push manually, run:

```bash
git init
git add .
git commit -m "Initial commit: AuditForge pipeline"
git remote add origin https://github.com/<yourname>/<repo>.git
git branch -M main
git push -u origin main
```

If you want me to create the repo and push, reply with your preferred repo name and whether it should be `public` or `private`. You can paste a PAT here if you want me to perform the push; otherwise I will stop after creating the local commit and show the exact push commands.

Need anything else?
-------------------

I can also:
- Enrich extracted CVEs with CVSS scores from NVD.
- Add PDF extraction and better NLP-based CVE location tagging.
- Add basic tests and CI workflow to run lint/tests on push.



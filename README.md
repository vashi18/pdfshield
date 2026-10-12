# PDFShield

PDFShield is a defensive, local-first workspace for static PDF malware analysis, OSINT investigation, and threat-intelligence correlation. It parses suspicious documents without executing scripts, attachments, or extracted URLs.

## Run locally

```bash
sudo pip3 install -r requirements.txt
cd frontend && npm ci && npm run build
cd ..
PYTHONPATH=. PDFSHIELD_USE_MANAGED_DB=false uvicorn backend.app.main:app --host 0.0.0.0 --port 3000
```

Open `http://localhost:3000`. The default database is SQLite at `pdfshield.db`. The project can be adapted to the managed database later by setting `PDFSHIELD_USE_MANAGED_DB=true` and providing a compatible `DATABASE_URL`; provider secrets belong in server-side environment variables only.

## API surface

The FastAPI OpenAPI document is available at `/docs`. The app exposes health, dashboard stats/activity, PDF upload/list/detail/report, IOC search/detail, OSINT lookup/history, trusted feed status/sync/history, case history/update, and persistent settings endpoints under `/api`.

## Security posture

Upload validation checks the extension, content signature, and configured byte limit. Temporary parsing stays in memory where practical. Uploaded files are never executed; PDF JavaScript, actions, embedded-file names, URI annotations, URLs, domains, and IPs are treated as untrusted evidence. No extracted URL is contacted automatically. External OSINT is disabled until both request-level consent and a Settings consent gate are enabled. Feed fetches use a hard-coded HTTPS allowlist and bounded timeouts.

The risk score is an explainable heuristic, not a malware verdict. A suspicious structural feature does not prove maliciousness, and a missing intelligence match does not prove safety. Demo mode is off by default; the dashboard reads its values from persisted records and shows zero states when no analyses exist.

## Verification

```bash
PYTHONPATH=. pytest -q
cd frontend && npm run typecheck && npm run build
```

# AnySend

Privacy‑oriented self‑hosted file drop with per‑user listing, owner‑only downloads, share tokens, short links, soft deletion, and optional expiry.

## Run locally (Windows PowerShell)

1. Install Node.js (v18+ recommended).
2. Install dependencies (only `express` + `multer` used):

```powershell
npm install
```

3. Start the server:

```powershell
npm start
```

4. Open:
	- http://localhost:3000 (site)
	- http://localhost:3000/api/health (health JSON)

## Features

* Upload multiple files (extension + MIME allowlist, no enforced size limits by default – be cautious)
* Per‑user (cookie id) recent listing – you only see your own uploads by default
* Owner‑only direct download route: `/api/download/:storedName`
* Share tokens for public one‑time style links (not consumed but guess‑resistant): `/api/share/:storedName` -> `/api/d/:token`
* Pretty short links: `/api/short/:storedName` -> `/f/:code` (wraps a share token)
* Soft delete with tombstone recorded in `index.jsonl` and file removed from disk
* Optional expiry via `ANYSEND_EXPIRE_DAYS` environment variable (expired files behave like 404)
* JSONL append‑only metadata (`uploads/index.jsonl`, `uploads/share_tokens.jsonl`, `uploads/short_links.jsonl`)

## Environment Variables

| Var | Purpose |
|-----|---------|
| PORT | Server port (default 3000) |
| ALLOWED_ORIGINS | Comma separated origins for CORS (default https://anyfile.uk) |
| ANYSEND_EXPIRE_DAYS | If set (>0), files older than N days are treated as deleted/404 |

## Key Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/health | Liveness probe |
| POST | /api/upload | Upload files (field name `files`) |
| GET | /api/files?limit=50 | Recent uploads (current user unless `?all=1`) |
| GET | /api/download/:id | Owner‑only download with original filename disposition |
| POST | /api/share/:id | Create / reuse short link -> returns `shortUrl` (/f/:code) |
| GET | /api/d/:token | (Legacy) token download still works for existing tokens |
| POST | /api/short/:id | (Legacy alias) same as /api/share/:id |
| GET | /f/:code | Public download via short code (wraps share token) |
| POST | /api/files/delete/:id | Soft delete (owner) – removes file, adds tombstone |

## Deletion & Expiry Semantics

* Deleting a file: file is unlinked from disk; a `{ storedName, deleted:true }` line is appended to `index.jsonl`.
* Listing filters out deleted or expired entries.
* Share tokens & short links remain in their JSONL logs but resolve to 404 once file deleted/expired.
* Expiry (if configured) is evaluated on each request; no background purge required.

## Data Files

| File | Purpose |
|------|---------|
| uploads/index.jsonl | Append‑only metadata lines (and deletion tombstones) |
| uploads/share_tokens.jsonl | Created share token records |
| uploads/short_links.jsonl | Short link mappings (code -> token -> storedName) |

## Frontend Notes

Plain vanilla JS automatically discovers API base (same origin, api.<host>, dev ports) and provides buttons: Share, Delete. Share copies a short /f/<code> URL (absolute). Short button removed after unification.

## Roadmap

* Token revocation & rate limiting
* Deduplicated storage by hash
* SQLite/LiteFS index instead of JSONL
* Quotas / total size pruning
* Optional authentication layer

## License

MIT (see repository root if added) – adjust as needed.


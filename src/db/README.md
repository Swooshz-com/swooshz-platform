# Database Scaffold

This folder contains the Drizzle schema scaffold for platform-owned persistence records.

Current scope:

- Drizzle schema definitions only.
- Reviewable SQL migration generation via `npm run db:generate`.
- Drizzle-backed repository adapter functions that accept an already-wired database object.
- No real database client or connection.
- No local, staging, or production database provisioning.
- No migration execution workflow.
- No auth provider integration.
- No frontend or backend routes.
- No KQAG adapter or KQAG data storage.

The pure domain core under `src/accounts`, `src/apps`, and `src/access` must remain storage-agnostic. Repository/service ports under `src/platform` also remain free of Drizzle and database implementation imports. Drizzle adapters under `src/db` map database rows to plain typed records before any domain access decision is made.

Generated migrations are review artifacts until an explicit database execution workflow is approved.

# Database Scaffold

This folder contains the Drizzle schema scaffold for platform-owned persistence records.

Current scope:

- Drizzle schema definitions only.
- Reviewable SQL migration generation via `npm run db:generate`.
- No real database client or connection.
- No local, staging, or production database provisioning.
- No auth provider integration.
- No frontend or backend routes.
- No KQAG adapter or KQAG data storage.

The pure domain core under `src/accounts`, `src/apps`, and `src/access` must remain storage-agnostic. Repository/service adapters can later load database records and pass plain typed objects into the domain core.

Generated migrations are review artifacts until an explicit database execution workflow is approved.

# Database Scaffold

This folder contains the Drizzle schema scaffold for platform-owned persistence records.

Current scope:

- Drizzle schema definitions only.
- Reviewable SQL migration generation via `npm run db:generate`.
- Drizzle-backed repository adapter functions that accept an already-wired database object.
- Auth state storage through hashed `state_hash`/`nonce_hash` references only; raw OIDC state and nonce values are not persisted.
- Lazy `pg`/Drizzle client construction via `src/db/client.ts`.
- Explicit migration execution via `npm run db:migrate`.
- No local, staging, or production database provisioning.
- No automatic migration execution.
- No committed `.env` or real `DATABASE_URL`.
- No auth provider integration.
- No frontend or backend routes.
- No KQAG adapter or KQAG data storage.

The pure domain core under `src/accounts`, `src/apps`, and `src/access` must remain storage-agnostic. Repository/service ports under `src/platform` also remain free of Drizzle and database implementation imports. Drizzle adapters under `src/db` map database rows to plain typed records before any domain access decision is made.

`DATABASE_URL` is required for live database connections and migration execution. `DATABASE_SSL_MODE` may be set to `disable` or `require`; unsupported values are rejected without printing the database URL.

`npm run db:migrate` is operator-controlled and requires `DATABASE_MIGRATIONS_CONFIRM=apply-reviewed-migrations`. It does not run during package install, app startup, default CI, or `npm test`.

Generated migrations remain reviewable artifacts and are applied only through the explicit migration command.

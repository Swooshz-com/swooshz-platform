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
- No SQAG adapter or SQAG data storage.

The pure domain core under `src/accounts`, `src/apps`, and `src/access` must remain storage-agnostic. Repository/service ports under `src/platform` also remain free of Drizzle and database implementation imports. Drizzle adapters under `src/db` map database rows to plain typed records before any domain access decision is made.

`DATABASE_URL` is the restricted long-running runtime connection. Production startup also requires the non-secret `DATABASE_EXPECTED_RUNTIME_ROLE` and fails before listening unless the connected role matches and has the restricted posture. `DATABASE_SSL_MODE` may be set to `disable` or `require`; unsupported values are rejected without printing connection details.

`npm run db:migrate` is operator-controlled, uses `DATABASE_OPERATOR_URL` in production, and requires `DATABASE_MIGRATIONS_CONFIRM=apply-reviewed-migrations`. It does not run during package install, app startup, default CI, or `npm test`.

`npm run platform:db-readiness-check` is a separate operator check for hosted Postgres readiness. It builds the app, validates `DATABASE_OPERATOR_URL` in production, opens a PostgreSQL connection, checks basic reachability, verifies required platform tables, and checks Drizzle migration metadata. It prints sanitized status only: no connection strings, credentials, hostnames with credentials, table data, or driver error details.

Generated migrations remain reviewable artifacts and are applied only through the explicit migration command.

## Durable database operations

`src/db/durable-operations.ts` is the single repository-owned boundary for durable database observation, typed mutation plans, inverse construction, migration identity checks, final readiness verification, restoration verification, and closed public receipts. It reuses the existing readiness, runtime posture, runtime grant, Drizzle journal, and migration authorities.

The observation API begins a PostgreSQL read-only transaction, verifies the target identity and PostgreSQL 17 posture, and exposes only the fixed query identifiers. Mutation plans accept only canonical objects, approved roles and principals, allowlisted privileges, the locked membership transition, canonical default ACLs, approved role posture, or contiguous journal entries. Arbitrary SQL, credentials, provider metadata, and recovery-database actions are outside this boundary.

`scripts/platform-db-operation.mjs` is the guarded operator entry point. It requires the explicit operator configuration and reviewed confirmation already used by the migration workflow. `scripts/db-migrate.mjs` continues to use the canonical Drizzle migration executor; the durable primitive adds identity and post-verification around that executor rather than creating another migration system.

`npm run test:disposable-durable-db-operations` builds the project and runs the production-shaped proof against a runner-owned, loopback-only `postgres:17` container. The runner rejects caller-supplied database URLs, owns cleanup, and is not a provider, recovery, staging, or production database. It is the required local proof for read-only enforcement, exact migration identity, drift and prewrite rejection, truthful first-write state, frozen inverse recovery, exact restoration, and canonical runtime posture.

# ADR 0005: Database Connection And Migration Execution

## Status

Accepted.

## Context

ADR 0003 selected Postgres-compatible relational persistence for platform account state. ADR 0004 selected Drizzle ORM and Drizzle Kit as the preferred TypeScript schema and migration tooling. Later implementation PRs added the first Drizzle schema, review-only migration artifacts, storage-agnostic repository/service ports, and Drizzle-backed repository adapters.

The repository still has no real database client, no `pg` dependency, no database provisioning, no migration execution workflow, no auth provider, no backend HTTP routes, no frontend, and no SQAG adapter. The next persistence decision is how database connection code and migration execution should be introduced safely when the platform is ready to connect to a real Postgres-compatible database.

This ADR defines that workflow before any live database connection exists.

## Decision

Future database connection code should use Drizzle with the `pg` Postgres client unless a later ADR supersedes this direction.

Do not install `pg` in this PR. Add it only in the future PR that implements actual connection code.

Future connection code should live behind the database adapter boundary, likely in `src/db/client.ts`. Domain code under `src/accounts`, `src/apps`, and `src/access` must remain storage-agnostic. Platform ports and services under `src/platform` must remain free of Drizzle, database client, schema, raw SQL, and migration implementation details. Only DB adapter modules under `src/db/**` may import Drizzle schema/table objects, database clients, or Drizzle implementation details.

Migration generation remains `npm run db:generate`. Migration execution must be added later as a separate explicit command only after real database wiring exists. Migration execution must require `DATABASE_URL`. Production or other real-data migration execution must also require explicit operator confirmation through an approved environment variable or CLI confirmation pattern.

Do not run migrations automatically on application startup. Do not run migrations in CI against a live database. Do not add Docker/Postgres provisioning in this PR.

Generated migrations remain review artifacts until an explicit database execution workflow is implemented and approved.

## Database Client Direction

Use `pg` with Drizzle for the first real Postgres connection implementation.

Rationale:

- It matches the Postgres-compatible direction from ADR 0003.
- It fits Drizzle's Postgres adapter model.
- It keeps database client wiring isolated in `src/db/**`.
- It avoids selecting a managed provider or auth vendor through the client choice.
- It is familiar operationally and works with many Postgres-compatible managed providers.

The package should be added only when implementing live connection code. This avoids introducing a runtime database dependency before the repository has a safe execution workflow and environment contract.

## Environment Variables

Future database connection code should use:

- `DATABASE_URL`: required for any real database connection or migration execution.

Optional future variables may include:

- `DATABASE_SSL_MODE`: only if the selected managed provider or deployment environment needs explicit SSL behavior.
- `DATABASE_MIGRATIONS_CONFIRM`: only if the migration execution command uses environment-variable confirmation rather than an interactive CLI confirmation.

This ADR does not add a populated `.env`, `.env.example`, real host, port, username, password, domain, or credential. Any future examples must use synthetic placeholders only.

Environment variables must not contain raw provider tokens, OIDC responses, auth codes, access tokens, refresh tokens, ID tokens, session secrets, raw invite tokens, payment details, customer data, SQAG runtime data, or private app payloads.

## Runtime Connection Boundary

Future connection code should be introduced in `src/db/client.ts` or a similarly explicit `src/db/**` module.

The intended layering is:

1. `src/db/client.ts` creates a Drizzle database object from approved environment configuration.
2. `src/db/repositories.ts` adapts that database object to `PlatformRepositories`.
3. `src/platform/**` services coordinate workflows through repository ports.
4. `src/accounts`, `src/apps`, and `src/access` remain pure domain code.

The app-access decision path must continue to receive plain domain records. It must not import database clients, Drizzle schema, migration artifacts, or generated table objects.

## Migration Execution Workflow

Migration generation remains:

```powershell
npm run db:generate
```

Future migration execution should be introduced as a separate command only when live database wiring exists. That future command should:

- Refuse to run without `DATABASE_URL`.
- Print no secret values.
- Make the target environment explicit.
- Apply committed migration files in deterministic order.
- Run only as an operator-controlled action.
- Require explicit confirmation for production or any real-data environment.
- Require separate operator approval for destructive changes after real data exists.

Destructive changes include dropping tables, dropping columns, deleting records, rewriting account/customer state, narrowing constraints that may reject existing records, or backfills that can permanently alter user/workspace/app-access behavior.

Do not run migrations automatically:

- On app startup.
- During ordinary unit tests.
- In pull request CI against a live database.
- As part of package install.
- As part of schema generation.

Future integration tests that require a database must be separately introduced, clearly named, and isolated from the default DB-free unit test workflow.

## Local Development Database Strategy

Local database setup remains deferred.

Do not add Docker/Postgres provisioning in this PR. A future local development database workflow should be introduced only when the project needs integration tests or local end-to-end persistence testing.

Future local setup should:

- Use synthetic data only.
- Avoid real customer/company/bank/payment/SQAG data.
- Keep reset commands explicit.
- Separate destructive local reset behavior from staging or production commands.
- Avoid relying on local setup for normal unit tests.

## Managed Postgres Provider

Managed Postgres provider selection remains deferred.

Compatible options may include managed Postgres providers such as Supabase database, Neon, RDS, Cloud SQL, or another Postgres-compatible provider. Mentioning Supabase here means managed Postgres only. This ADR does not select Supabase Auth or any other auth provider.

Provider selection should consider backups, restore testing, access control, migration execution ergonomics, environment isolation, logging, operational visibility, and cost.

## CI Policy

Existing CI must continue to run without a database.

Default validation remains:

- Typecheck.
- Unit tests.
- DB-free mapper, repository adapter, and domain tests.
- Review of generated migration files.

No live `DATABASE_URL` is required for `npm test`. Pull request CI must not require a staging or production database. Future database integration tests should use a separate, explicit workflow or script and should never run against production.

## Safety And Privacy Rules

Never commit:

- Secrets or populated `.env` files.
- Database URLs or credentials.
- Raw provider tokens.
- Raw OIDC/provider responses.
- Auth codes.
- Access tokens.
- Refresh tokens.
- ID tokens.
- Session secrets.
- Raw invite tokens.
- Customer/company/bank/payment data.
- Quote exports.
- Pricing files.
- Embedded logos or Base64 logo data.
- SQAG runtime data.
- Private app payloads.

Invitation token storage, if implemented, must store token hashes only. Audit metadata must remain privacy-minimized. Platform persistence must not store SQAG quote workflow payloads unless a later ADR explicitly changes that boundary.

## Consequences

Positive consequences:

- The project can add real database wiring later without revisiting connection ownership.
- Default development and CI remain DB-free.
- Migration execution is separated from migration generation.
- Production migration risk is handled deliberately before real data exists.
- Domain and platform port layers remain insulated from Drizzle and client details.

Tradeoffs:

- No integration test workflow exists yet.
- No local Postgres setup exists yet.
- Repository adapters remain unit-tested with fakes until a future DB workflow is approved.
- Operators will need one more implementation PR before migrations can be applied to any database.

## Future Implementation Checklist

Before adding real database connection or migration execution code:

- Add `pg` only in the PR that implements connection code.
- Add `src/db/client.ts` or equivalent under `src/db/**`.
- Require `DATABASE_URL` for live connections.
- Keep connection configuration from printing secrets.
- Decide whether `DATABASE_SSL_MODE` is needed.
- Add a migration execution command separate from `db:generate`.
- Require explicit confirmation for production or real-data migrations.
- Document destructive migration approval.
- Keep default CI and `npm test` DB-free.
- Add integration tests only in a clearly labelled DB-specific workflow.
- Confirm no auth provider, frontend, billing, or SQAG adapter behavior is bundled into the DB wiring PR unless separately approved.

## Deferred Decisions

- Exact managed Postgres provider.
- Local database provisioning approach.
- Whether Docker is used for local integration tests.
- Exact `pg` and Drizzle connection module implementation.
- Migration execution command name.
- Confirmation mechanism for production migrations.
- Backup, retention, restore testing, and operational runbooks.
- Auth provider selection.
- Deployment environment and secret-management mechanism.
- SQAG adapter runtime/session/history storage changes.

## Explicit Non-Goals

- No real database connection.
- No `src/db/client.ts` live connection module.
- No `pg` installation.
- No migration runner.
- No automatic migration execution.
- No Docker Postgres setup.
- No local, staging, or production database provisioning.
- No real `DATABASE_URL`.
- No populated `.env`.
- No seed data.
- No login, callback, or logout implementation.
- No auth provider integration.
- No Clerk, Auth0, Supabase Auth, custom OIDC, email/password auth, or public signup.
- No backend API routes.
- No HTTP server.
- No Next.js, Vite, React, frontend shell, or UI.
- No billing, credits, Stripe, or customer portal.
- No SQAG adapter.
- No SQAG repository changes.
- No quote exports, pricing files, embedded logos, bank details, customer/company private data, or private app payloads.

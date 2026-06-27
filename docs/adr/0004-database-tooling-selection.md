# ADR 0004: Database Tooling Selection

## Status

Accepted.

## Context

ADR 0003 selected Postgres-compatible relational persistence for platform account state and deferred the specific database tooling choice. The next backend implementation step needs a schema and migration tool direction before adding database packages, schema files, migrations, repository adapters, backend APIs, auth provider integration, or frontend UI.

The platform has a small TypeScript domain core that should remain pure and storage-agnostic. The database tool should support durable account records while keeping access decisions, role checks, and app entitlement logic easy to test without a live database.

## Decision

Use Postgres-compatible relational persistence for Swooshz Platform account state.

Prefer Drizzle ORM with Drizzle Kit for the first TypeScript schema and migration tooling implementation.

Keep the exact managed Postgres provider deferred. Supabase may be considered later as a managed Postgres provider, but this ADR does not select Supabase Auth or any other auth provider.

Do not implement database code in this PR. This ADR only selects the preferred direction for future work.

## Database Engine Direction

The platform should target Postgres-compatible relational storage because the account model depends on durable relationships, uniqueness rules, status transitions, audit history, and transactional updates across users, workspaces, memberships, sessions, invitations, apps, and entitlements.

Future implementation should use Postgres features conservatively at first: primary keys, unique constraints, foreign keys, indexes, timestamps, nullable revocation/acceptance fields, and transactional writes. Advanced provider-specific features should be introduced only when there is a clear product or operational need.

## ORM, Query Builder, And Direct SQL Direction

Drizzle is preferred because it fits a small TypeScript project that wants SQL-shaped control, typed schemas, reviewable generated SQL migrations, and relatively low framework lock-in.

The intended use is:

- Define database schema in TypeScript using Drizzle.
- Generate reviewable SQL migration files with Drizzle Kit.
- Keep repositories explicit and small.
- Use SQL-like query patterns where clarity matters.
- Allow raw SQL escape hatches for operations Drizzle does not express cleanly.

Prisma remains a viable alternative for teams that prefer its schema language, generated client, and migration workflow, but it is not selected as the first choice because Swooshz Platform currently benefits more from a lighter SQL-adjacent layer and a lower abstraction boundary around the relational model.

Direct SQL with a migration runner remains a fallback if Drizzle becomes a poor fit, but it is not selected now because the project would need to choose and maintain more TypeScript typing, query composition, and migration conventions manually.

## Migration Tooling Direction

Use Drizzle Kit as the preferred migration generation and migration management tool once database implementation begins.

Future migrations should be:

- Generated or written as SQL files.
- Source-controlled.
- Reviewed in pull requests.
- Applied in deterministic order.
- Paired with local validation.
- Explicit about destructive operations, backfills, locks, and data rewrites.

Do not use schema push workflows against staging or production as the normal migration path. Push-style workflows may be acceptable only for throwaway local prototypes before real data exists.

No destructive migration should run automatically without explicit operator approval once real data exists.

## Local Development Database Direction

Local development should later use a deterministic Postgres-compatible setup. The exact local setup is deferred.

Candidate local options include:

- Local Postgres service.
- Docker-managed Postgres if explicitly approved for local development.
- A managed branch/preview database if the provider supports safe isolated branches.
- A lightweight Postgres-compatible local approach if it supports the required constraints and migrations.

This PR does not add Docker, a database, seed data, reset scripts, Drizzle config, or migration files.

## Production And Staging Database Direction

Production and staging should use a managed Postgres-compatible provider with backups, access controls, operational visibility, and a migration workflow that can be run deliberately.

The exact provider remains deferred. Supabase can be evaluated later as a managed Postgres option, alongside other Postgres providers. Choosing Supabase as a database provider would not imply selecting Supabase Auth; auth provider selection remains governed by ADR 0002 and a future auth-provider decision.

## Fit With Pure Domain Core

The existing `src/` domain core must remain pure and storage-agnostic.

Future database code should live behind repository and service boundaries:

1. Repository adapters load records from Postgres.
2. Services coordinate workflows and audit behavior.
3. Pure domain functions receive explicit typed input objects.
4. Repository adapters persist approved changes.

Access decision logic must not import Drizzle, database clients, generated table objects, or raw SQL.

## Support For Platform Records

The selected direction should support:

- Sessions as server-side records with user id, expiry, revocation, and privacy-minimized metadata.
- Invitations with normalized email, status, hashed token storage if implemented, expiry, acceptance, and exactly-one-membership activation semantics.
- Provider identities stored separately from `User`, with provider key/name and provider subject.
- Audit events as append-only application records with privacy-minimized metadata.
- App registry records as platform-owned app definitions.
- App entitlements as workspace-owned app grants that combine with membership and role checks.

Provider tokens, raw provider claims, auth codes, refresh tokens, provider session secrets, and provider error payloads must not be stored unless a later ADR explicitly approves encrypted token storage.

## Options Considered

### Drizzle ORM / Drizzle Kit

Pros:

- Strong TypeScript fit.
- SQL-adjacent model that keeps relational behavior visible.
- Supports schema definition in TypeScript.
- Can generate SQL migration files for review.
- Lower abstraction boundary than heavier data frameworks.
- Fits the pure-domain-core direction because repositories can remain thin adapters.
- Fits a small internal startup project by avoiding a large data framework commitment.

Cons:

- Smaller ecosystem than Prisma.
- Team must stay comfortable with SQL concepts.
- Some advanced migration operations may still need hand-edited SQL.

Conclusion: preferred first choice.

### Prisma

Pros:

- Mature TypeScript ecosystem.
- Strong generated client experience.
- Prisma Migrate generates SQL migration history from a declarative schema and supports customizing generated SQL.
- Familiar to many TypeScript developers.

Cons:

- Heavier framework boundary.
- Schema language and generated client can become a stronger architectural center than desired.
- May abstract SQL behavior more than this account-domain project needs.

Conclusion: viable alternative, but not selected for the first platform persistence layer.

### Direct SQL With A Migration Runner

Pros:

- Maximum SQL clarity and low ORM lock-in.
- Migrations are directly reviewable.
- Easy to use database-specific features intentionally.

Cons:

- Requires separate decisions for migration runner, typed query patterns, validation conventions, and repository ergonomics.
- More manual work for a small TypeScript project.
- Higher risk of ad hoc query shape drift before the team has enough persistence code to justify the extra control.

Conclusion: keep as fallback if Drizzle becomes a poor fit.

### Supabase-First Approach

Pros:

- Supabase projects provide Postgres databases and operational conveniences.
- Supabase can support SQL migrations and local/remote workflows.
- May be useful later as a managed Postgres provider.

Cons:

- Selecting Supabase-first can blur database provider, auth provider, local tooling, and platform boundary decisions too early.
- Supabase Auth is explicitly not selected by ADR 0002.
- A provider-first approach may increase lock-in before the platform account model has real persistence needs.

Conclusion: consider later as a managed Postgres provider, but do not make the platform Supabase-first in this PR.

## Evaluation Summary

| Criterion | Drizzle / Drizzle Kit | Prisma | Direct SQL | Supabase-first |
| --- | --- | --- | --- | --- |
| TypeScript compatibility | Strong | Strong | Manual | Depends on chosen client/tooling |
| Migration reviewability | Strong with generated SQL | Strong with generated/custom SQL | Strong | Strong when using migration files |
| Operational simplicity | Good for small TS backend | Good but heavier | More manual | Good if Supabase is selected |
| Lock-in risk | Moderate-low | Moderate | Low | Higher provider coupling |
| Provider-agnostic auth fit | Strong | Strong | Strong | Mixed if coupled to Supabase Auth |
| Postgres-compatible fit | Strong | Strong | Strong | Strong |
| Small internal startup fit | Strong | Good | Mixed | Good only if provider is selected |
| Keeps domain core pure | Strong with repositories | Strong with discipline | Strong with discipline | Mixed if provider SDK leaks upward |

## Deferred Decisions

- Exact managed Postgres provider.
- Whether Supabase, Neon, RDS, Cloud SQL, self-hosted Postgres, or another provider is used.
- Exact Drizzle package versions and install timing.
- Drizzle project layout and config file paths.
- Local database setup.
- Migration naming conventions.
- Migration review checklist.
- Repository/service interface names and module layout.
- Test database strategy.
- Auth provider selection.
- Production migration execution workflow.
- Backup, retention, and restore testing policy.

## Explicit Non-Goals

- No database package installation.
- No Drizzle package installation.
- No Prisma package installation.
- No SQL files.
- No schema files.
- No migrations.
- No Docker or database setup.
- No backend API routes.
- No auth provider integration.
- No login, callback, or logout code.
- No Next.js, Vite, React, frontend shell, or UI.
- No email/password login implementation.
- No public signup.
- No OAuth/OIDC provider calls.
- No Clerk, Auth0, Supabase Auth, custom OIDC, or other auth provider integration.
- No Stripe, billing, or credits implementation.
- No customer portal.
- No deployment, VPS, Coolify, DNS, TLS, or firewall work.
- No secrets.
- No real customer, company, bank, quote, pricing, logo, or app workflow data.
- No KQAG repository changes.

# ADR 0003: Persistence And Migrations

## Status

Accepted.

## Context

Swooshz Platform now has account/app-access contracts, a pure TypeScript domain core, a CI baseline, and a provider-agnostic auth/session strategy. The next backend implementation step needs a persistence and migration direction before login routes, provider integration, database schemas, backend APIs, or frontend UI begin.

The platform account model needs durable relational state for users, workspaces, memberships, invitations, sessions, audit events, apps, and app entitlements. At the same time, the existing `src/` domain core should remain pure and storage-agnostic so access decisions can be tested without a database or provider.

## Persistence Goals

- Persist platform account and app-access state durably and consistently.
- Keep domain logic independent from database query details.
- Support auditable changes to membership, invitation, session, and entitlement state.
- Preserve the KQAG boundary by avoiding storage of quote workflow payloads in the platform database.
- Keep local development deterministic once a database is added.
- Keep production/staging operations reviewable, reversible or forward-safe where practical, and explicit about destructive risk.

## Storage Ownership Boundaries

The platform database owns:

- Users.
- Provider identities.
- Workspaces/accounts.
- Memberships.
- Invitations.
- Sessions.
- Audit events.
- App registry records.
- App entitlements.
- Later billing or credit metadata if explicitly approved.

KQAG owns quote workflow data until a later KQAG platform adapter phase explicitly changes runtime, session, or history storage boundaries.

The platform should not store raw quote exports, real pricing files, embedded logos, bank details, or app workflow payloads unless a later ADR explicitly approves that expanded storage scope.

## Relational Account Data Model Direction

Platform account state should use a relational database model compatible with Postgres-style persistence. This ADR does not choose a managed database provider, ORM, query builder, schema library, or migration tool.

The future data model should keep account concepts separate:

- Users are platform human identity records.
- Provider identities map provider name/key and provider subject to platform users.
- Workspaces/accounts own organization-level app access.
- Memberships connect users to workspaces with roles and status.
- Invitations target normalized email and resolve to membership creation or activation.
- Sessions are server-side records linked to users.
- Audit events are append-only application records.
- App registry records describe platform-known apps.
- App entitlements grant workspace access to apps.

Billing and credits may later influence entitlement status, but they must not be mixed into users or memberships.

## Repository And Service Boundary

Future persistence code should sit behind repository and service interfaces. Database queries must not leak into the pure access decision function or other domain core logic.

The intended flow is:

1. Repositories load platform records from storage.
2. Services apply application workflows, validations, and audit behavior.
3. Pure domain functions decide access from explicit input objects.
4. Repositories persist approved state changes.

This keeps `src/` domain decisions testable without a database while allowing future integration tests to cover persistence adapters.

## Migration Strategy Direction

Schema migrations should be versioned, reviewed, and committed as source-controlled artifacts once a database tool is selected.

Migrations should be:

- Ordered and deterministic.
- Reviewable in pull requests.
- Reversible when practical.
- Forward-safe when reversal is not practical.
- Paired with validation or smoke checks appropriate to the change.
- Explicit about backfills, data rewrites, locking risk, and destructive operations.

No destructive migration should run automatically without explicit operator approval once real data exists. Destructive operations include dropping columns or tables, deleting records, rewriting customer/account state, or narrowing constraints in ways that may reject existing data.

This PR does not add migration files, a migration runner, database packages, or an ORM.

## Local Development Strategy

Local development can later use a deterministic local database setup with documented reset and migration commands. The local setup should avoid secrets, private customer data, real payment data, provider tokens, and KQAG app payloads.

Synthetic fixtures may be used for tests. They must be clearly identified as fixtures, not production seed data.

This ADR does not add Docker, a local database, seed data, or reset scripts.

## Production And Staging Strategy

Production and staging database providers remain deferred. The future provider should support relational constraints, transactions, backups, controlled migrations, and operational visibility.

Staging should exercise migration behavior before production. Production migrations should be run through explicit operator-controlled workflows once real data exists.

Deployment, hosting, VPS, Coolify, DNS, TLS, firewall, and managed database provisioning are out of scope for this ADR.

## Session Persistence Requirements

Sessions should be server-side records with:

- Platform user id.
- Created timestamp.
- Expiry timestamp.
- Revoked timestamp.
- Privacy-minimized metadata only when needed.

Expired or revoked sessions must not launch apps. Session cookies should reference platform session state without exposing raw session data to the browser. Cookie names, expiry behavior, rotation, CSRF strategy, and provider handoff details are deferred to the implementation/provider phase.

Session storage must not contain raw provider tokens unless a later ADR explicitly approves encrypted token storage.

## Invitation Persistence Requirements

Invitation target email should be normalized before storage and lookup.

Invitation status should support:

- `pending`.
- `accepted`.
- `expired`.
- `revoked`.

Invitation tokens must be stored hashed if token storage is implemented. Accepting an invitation should create or activate exactly one membership for the target workspace and role. Expired or revoked invitations must not be accepted.

Public self-serve signup remains out of scope unless explicitly approved later.

## Provider Identity Persistence Requirements

Provider identities should be stored separately from `User` records.

Provider identity records should store:

- Platform user id.
- Provider name/key.
- Provider subject.
- Created and updated timestamps.

Do not store raw provider tokens, raw provider claims, auth codes, refresh tokens, provider session secrets, or provider error payloads unless a later ADR explicitly approves encrypted token storage.

Email should be normalized and used carefully for identity matching and invitations. Email address, email domain, display name, or provider identity alone must not grant app access.

## Audit Event Persistence Requirements

Audit events should be append-only from the application perspective.

Audit metadata must be privacy-minimized and must not store secrets, raw provider responses, payment details, bank details, quote exports, embedded logos, private app payloads, provider tokens, invitation tokens, auth headers, or session secrets.

Future implementation should emit audit events for sign-in, sign-out, session revocation, invitation acceptance, membership changes, and entitlement changes.

## App Entitlement Persistence Requirements

App registry and entitlement records are platform-owned.

Workspace app access should be controlled by entitlement records plus membership and role checks. Entitlement status should remain separate from membership status.

Suspended or disabled entitlement status should block app launch even for workspace owners. Billing and credits may later influence entitlement status, but billing state must not be stored on users or memberships as the source of access truth.

## Future Billing And Credits Placeholder

Billing and credits remain reserved concepts. If approved later, they should have dedicated relational records such as billing customers, subscriptions, invoices, credit pools, credit transactions, and usage events.

Payment provider ids, invoice metadata, credit balances, and usage records must not be added to users, memberships, or KQAG-owned workflow storage.

## Backup And Retention Considerations

Future production and staging persistence choices should define backup frequency, restoration testing, retention periods, access controls, and deletion/anonymization behavior.

Audit retention may differ from session retention, invitation retention, and user profile retention. These retention windows are deferred until compliance, operational, and product needs are clearer.

Backups must be treated as sensitive operational data and must not be committed to the repository.

## Privacy And Security Rules

- Never commit secrets, populated `.env` files, provider tokens, private customer files, bank data, payment details, database dumps, or provider responses.
- Do not store KQAG quote exports, real pricing files, embedded logos, bank details, or app workflow payloads in the platform database unless separately approved.
- Keep provider identifiers separate from business profile fields.
- Store invitation tokens hashed if token storage is implemented.
- Keep sessions server-side and avoid exposing raw session data to browsers.
- Keep audit metadata privacy-minimized.
- Use relational constraints where practical for ownership and uniqueness invariants.
- Require explicit operator approval for destructive migrations once real data exists.

## Deferred Decisions

- Managed database provider.
- ORM, query builder, or direct SQL approach.
- Migration tool and migration file format.
- Local database setup and reset workflow.
- Production/staging provisioning and operations.
- Backup, retention, restoration, and deletion policy.
- Session cookie details and CSRF strategy.
- Provider identity matching edge cases.
- KQAG runtime/history storage changes in the adapter phase.
- Billing and credits persistence if approved.

## Explicit Non-Goals

- No database package.
- No ORM.
- No SQL migration files.
- No backend API routes.
- No auth provider integration.
- No login, callback, or logout code.
- No Next.js, Vite, React, frontend shell, or UI.
- No email/password login implementation.
- No public signup.
- No OAuth/OIDC provider calls.
- No Clerk, Auth0, Supabase Auth, custom OIDC, or other provider integration.
- No Supabase setup.
- No Stripe, billing, or credits implementation.
- No customer portal.
- No deployment, VPS, Coolify, DNS, TLS, or firewall work.
- No secrets.
- No real customer, company, quote, pricing, logo, payment, or bank data.
- No KQAG repository changes.

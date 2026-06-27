# Swooshz Platform

Swooshz Platform is the future shared platform layer for Swooshz apps. It will own account identity, workspace membership, app access, app whitelisting, and eventually billing or credits when those are explicitly approved.

The current priority is not a frontend shell. The current priority is to define the account, workspace, and app-access contract clearly enough that backend scaffolding can start without reopening basic product boundaries.

## What This Platform Owns

- Users and sessions.
- Workspaces/accounts representing the organization or operating unit that uses Swooshz apps.
- Workspace memberships and roles.
- Invitations into a workspace.
- Audit events for account, access, and security-relevant actions.
- App registry records for Swooshz apps.
- App entitlements and app access decisions per workspace.
- Later billing, credits, subscriptions, or usage ledgers if approved in a future phase.
- Later shared platform shell and cross-app navigation after the backend contract is stable.

## What This Platform Does Not Own

- App-specific workflow logic.
- Quote generation, pricing reference import, quotation layout, or quote export logic.
- KQAG/SAQG runtime behavior until a platform adapter phase is explicitly started.
- Customer portal behavior.
- Public SaaS launch behavior.
- Deployment, VPS, Coolify, DNS, TLS, or firewall setup in this initial contract PR.
- Billing or credits implementation in this initial contract PR.

## Current Implementation State

Phase 0 defined the contract and architecture:

1. Define the account domain.
2. Define workspace app access.
3. Define the KQAG integration boundary.
4. Record the decision to build accounts/workspaces/app access before UI.

This repository now also includes the first executable TypeScript domain core for account, workspace, membership, app entitlement, and app access decisions. It is intentionally pure domain code and unit tests only. GitHub Actions CI guards the TypeScript domain core on pull requests and `main` pushes.

ADR 0002 defines the provider-agnostic auth/session strategy: the platform owns sessions and app launch decisions, while a future auth provider proves identity only.

ADR 0003 defines the persistence and migration strategy: platform account state should use relational persistence behind repository/service boundaries while the TypeScript domain core stays storage-agnostic.

ADR 0004 selects Postgres-compatible persistence with Drizzle ORM and Drizzle Kit as the preferred future TypeScript schema/migration tooling, while deferring the managed database provider.

The repo now includes the first Drizzle/Postgres database scaffold: schema definitions, Drizzle config, and a generated initial SQL migration for review.

The repo also includes storage-agnostic repository and service ports for loading platform account, workspace, session, app, and entitlement records before delegating app launch decisions to the pure domain core. The pure domain core remains independent of Drizzle and persistence details.

The first Drizzle-backed repository adapters now map database rows to plain platform/domain records behind those ports.

ADR 0005 defines the database connection and migration execution workflow. The repo now has a lazy `pg`/Drizzle client boundary and explicit `npm run db:migrate` command. `DATABASE_URL` is required for live connection or migration execution, no populated `.env` is committed, migrations do not run automatically, and default CI plus `npm test` remain DB-free.

ADR 0006 selects the auth provider strategy: start with a provider-agnostic OIDC adapter boundary. The auth provider proves identity only; Swooshz Platform continues to own users, provider identities, platform sessions, workspace membership, invitations, audit events, app entitlements, and app access decisions. No auth implementation exists yet.

The repo now includes the first auth foundation layer: environment/config parsing, provider-agnostic OIDC adapter contracts, callback parameter/state contracts, a DB-free callback service skeleton, and privacy-safe auth error types. These are contract-driven modules only. They do not perform real login route handling, logout, provider network calls, real token exchange, cookie issuance, DB writes, or frontend work.

The auth callback service consumes stored auth state by hash/reference, delegates provider exchange and identity verification to an injected OIDC adapter, applies configured email/domain allowlists, and now persists platform sessions through storage-agnostic repository ports. It resolves provider identity by provider key plus provider subject, creates or links platform users only through repository boundaries, and returns a safe platform identity plus persisted session record. Workspace membership and app access remain separate platform decisions.

The repo also includes a storage-agnostic session revocation service for logout/session lifecycle work. It can revoke active or expired sessions through repository ports, treats already revoked sessions idempotently, and returns privacy-safe results without issuing cookies or exposing HTTP routes.

The repo also includes a protected app-access decision service. It accepts a platform session id, selected workspace id, app key, and deterministic timestamp, gates missing/revoked/expired sessions first, and then delegates app-access rules to the existing repository-backed decision service. It does not issue cookies, create launch tokens, write platform records, or call KQAG.

The repo now includes framework-agnostic browser session cookie helpers and plain-object HTTP handler contracts for protected app-access decisions and logout. These contracts parse only platform session references from cookies, build secure default `Set-Cookie` headers, clear session cookies for logout, and return privacy-safe response bodies. They do not wire a real HTTP server, framework route, CSRF middleware, frontend, or KQAG adapter.

ADR 0007 defines the HTTP transport and CSRF strategy: keep handlers framework-agnostic for now, use the route manifest as the next wiring contract, require `SameSite=Lax` cookies with `Secure` in production, and require Origin/Referer validation plus a CSRF token strategy for future state-changing browser-cookie routes.

The HTTP scaffold now includes framework-agnostic Origin/Referer validation, CSRF token validation contracts, and a combined route-aware request security helper. These helpers prepare the logout route and future state-changing browser-cookie routes for real wiring without adding middleware or a real server.

The repo now includes a minimal Node HTTP adapter for the approved route manifest: `GET /healthz`, `GET /api/platform/session/app-access`, `GET /api/platform/session/csrf`, and `POST /api/platform/logout`. The adapter delegates business logic to the framework-agnostic handlers, uses the combined request security helper before logout, returns privacy-safe JSON, and does not start a listener or add a framework.

The repo now includes a minimal Node server runtime contract around that adapter. Runtime config parsing supports safe local defaults, requires explicit public base URL and allowed origins in production, and enforces secure cookies for production. The server factory uses Node's built-in HTTP module only in runtime-specific code and does not listen automatically on import.

The repo now includes storage-agnostic CSRF token lifecycle contracts, a framework-agnostic browser-session CSRF issuance route contract, secure Node crypto adapters for CSRF token generation and HMAC hashing, and a Drizzle/Postgres-compatible CSRF token repository adapter. `GET /api/platform/session/csrf` requires an active platform session cookie, issues a raw CSRF token only in the response body, and persists only token hashes. The CSRF token migration is generated for review.

The repo now includes an explicit runtime dependency composition contract for the approved Node HTTP adapter/server. It assembles Drizzle platform repositories, the Drizzle CSRF token repository, secure CSRF token factory/hash adapters, the repository-backed CSRF validator, CSRF issuer dependencies, cookie config, and origin config from injected inputs. It requires an injected `CSRF_TOKEN_HASH_SECRET`-style secret config and does not listen, connect, run migrations, invoke auth providers, or call KQAG by itself.

The repo now includes explicit Node bootstrap wiring for the approved platform routes. The bootstrap reads runtime config and secret config from injected environment values, creates the database client through the existing DB boundary only when `start()` is called, composes platform runtime dependencies, creates the Node server, and exposes explicit `start()`/`stop()` lifecycle methods. Importing or creating the bootstrap object does not start a server, run migrations, or invoke provider/KQAG flows.

The repo now includes framework-agnostic auth HTTP route contracts for browser login start and provider callback. `GET /api/platform/auth/start` stores only hashed state/nonce references through injected state-store dependencies and redirects through an injected OIDC authorization URL builder. `GET /api/platform/auth/callback` wraps the existing callback service and sets the platform browser session cookie only after successful platform session creation. These route contracts do not perform real provider networking, add auth SDKs, build frontend UI, create app launch tokens, or call KQAG.

No Next.js, Vite, React, frontend shell, real auth provider, public signup, database provisioning, deployment, Supabase setup, Stripe setup, billing implementation, KQAG adapter, or secrets are part of this scaffold.

The next likely platform PR should define real auth state persistence/adapter wiring or provider network verification behind the existing contracts before broadening browser routes. Frontend shell work should still wait until backend auth, session, persistence, CSRF, and app-access boundaries are stable.

## First App Integration Target

KQAG/SAQG is the first app integration target. It remains a separate app in `Swooshz-com/koncept-quote-auto-generator` and stays quote-workflow-specific.

The platform will eventually provide KQAG with platform-issued identity and workspace context. KQAG should not grow its own accounts, users, billing, workspace membership, app registry, customer portal, or platform shell.

## Contract Docs

- `docs/accounts-contract.md`
- `docs/app-access-contract.md`
- `docs/kqag-integration-contract.md`
- `docs/adr/0001-platform-accounts-first.md`
- `docs/adr/0002-auth-session-strategy.md`
- `docs/adr/0003-persistence-and-migrations.md`
- `docs/adr/0004-database-tooling-selection.md`
- `docs/adr/0005-database-connection-and-migration-execution.md`
- `docs/adr/0006-auth-provider-selection.md`
- `docs/adr/0007-http-transport-and-csrf-strategy.md`
- `docs/roadmap.md`

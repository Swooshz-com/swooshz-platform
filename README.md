# Swooshz Platform

Swooshz Platform is the future shared platform layer for Swooshz apps. It will own account identity, workspace membership, app access, app whitelisting, and eventually billing or credits when those are explicitly approved.

The current priority is a minimal internal platform shell over the existing backend contracts, not a polished dashboard or public product surface. The platform still prioritizes clear account, workspace, and app-access boundaries before broader UI or app integration work.

## What This Platform Owns

- Users and sessions.
- Workspaces/accounts representing the organization or operating unit that uses Swooshz apps.
- Workspace memberships and roles.
- Invitations into a workspace.
- Audit events for account, access, and security-relevant actions.
- App registry records for Swooshz apps.
- App entitlements and app access decisions per workspace.
- Later billing, credits, subscriptions, or usage ledgers if approved in a future phase.
- Shared platform shell and cross-app navigation, starting with a minimal internal browser shell over the stable backend contract.

## What This Platform Does Not Own

- App-specific workflow logic.
- Quote generation, pricing reference import, quotation layout, or quote export logic.
- KQAG/SAQG quote workflow behavior and app-owned runtime data.
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

ADR 0006 selects the auth provider strategy: start with a provider-agnostic OIDC adapter boundary. The auth provider proves identity only; Swooshz Platform continues to own users, provider identities, platform sessions, workspace membership, invitations, audit events, app entitlements, and app access decisions. Provider-specific SDKs and vendor-coupled account logic remain out of scope.

The repo now includes the first auth foundation layer: environment/config parsing, provider-agnostic OIDC adapter contracts, callback parameter/state contracts, a DB-free callback service skeleton, and privacy-safe auth error types. These are contract-driven modules only. They do not perform real login route handling, logout, provider network calls, real token exchange, cookie issuance, DB writes, or frontend work.

The auth callback service consumes stored auth state by hash/reference, delegates provider exchange and identity verification to an injected OIDC adapter, applies configured email/domain allowlists, and now persists platform sessions through storage-agnostic repository ports. It resolves provider identity by provider key plus provider subject, creates or links platform users only through repository boundaries, and returns a safe platform identity plus persisted session record. Workspace membership and app access remain separate platform decisions.

The repo also includes a storage-agnostic session revocation service for logout/session lifecycle work. It can revoke active or expired sessions through repository ports, treats already revoked sessions idempotently, and returns privacy-safe results without issuing cookies or exposing HTTP routes.

The repo also includes a protected app-access decision service. It accepts a platform session id, selected workspace id, app key, and deterministic timestamp, gates missing/revoked/expired sessions first, and then delegates app-access rules to the existing repository-backed decision service. It does not issue cookies, create launch tokens, write platform records, or call KQAG.

The repo now includes framework-agnostic browser session cookie helpers and plain-object HTTP handler contracts for protected app-access decisions and logout. These contracts parse only platform session references from cookies, build secure default `Set-Cookie` headers, clear session cookies for logout, and return privacy-safe response bodies. They do not wire a real HTTP server, framework route, CSRF middleware, frontend, or KQAG adapter.

ADR 0007 defines the HTTP transport and CSRF strategy: keep handlers framework-agnostic for now, use the route manifest as the next wiring contract, require `SameSite=Lax` cookies with `Secure` in production, and require Origin/Referer validation plus a CSRF token strategy for future state-changing browser-cookie routes.

The HTTP scaffold now includes framework-agnostic Origin/Referer validation, CSRF token validation contracts, and a combined route-aware request security helper. These helpers prepare the logout route and future state-changing browser-cookie routes for real wiring without adding middleware or a real server.

The repo now includes a minimal Node HTTP adapter for the approved route manifest: `GET /healthz`, `GET /api/platform/session/app-access`, `GET /api/platform/session/context`, `GET /api/platform/session/csrf`, and `POST /api/platform/logout`. The adapter delegates business logic to the framework-agnostic handlers, uses the combined request security helper before logout, returns privacy-safe JSON, and does not start a listener or add a framework.

The repo now includes a minimal Node server runtime contract around that adapter. Runtime config parsing supports safe local defaults, requires explicit public base URL and allowed origins in production, and enforces secure cookies for production. The server factory uses Node's built-in HTTP module only in runtime-specific code and does not listen automatically on import.

The repo now includes storage-agnostic CSRF token lifecycle contracts, a framework-agnostic browser-session CSRF issuance route contract, secure Node crypto adapters for CSRF token generation and HMAC hashing, and a Drizzle/Postgres-compatible CSRF token repository adapter. `GET /api/platform/session/csrf` requires an active platform session cookie, issues a raw CSRF token only in the response body, and persists only token hashes. The CSRF token migration is generated for review.

The repo now includes an explicit runtime dependency composition contract for the approved Node HTTP adapter/server. It assembles Drizzle platform repositories, the Drizzle CSRF token repository, secure CSRF token factory/hash adapters, the repository-backed CSRF validator, CSRF issuer dependencies, cookie config, and origin config from injected inputs. It requires an injected `CSRF_TOKEN_HASH_SECRET`-style secret config and does not listen, connect, run migrations, invoke auth providers, or call KQAG by itself.

The repo now includes explicit Node bootstrap wiring for the approved platform routes. The bootstrap reads runtime config and secret config from injected environment values, creates the database client through the existing DB boundary only when `start()` is called, composes platform runtime dependencies, creates the Node server, and exposes explicit `start()`/`stop()` lifecycle methods. Importing or creating the bootstrap object does not start a server, run migrations, or invoke provider/KQAG flows.

The repo now includes framework-agnostic auth HTTP route contracts for browser login start and provider callback. `GET /api/platform/auth/start` stores only hashed state/nonce references through injected state-store dependencies and redirects through an injected OIDC authorization URL builder. `GET /api/platform/auth/callback` wraps the existing callback service and sets the platform browser session cookie only after successful platform session creation. These route contracts do not directly perform provider networking, add auth SDKs, build frontend UI, create app launch tokens, or call KQAG; provider calls remain behind an injected OIDC adapter.

The repo now includes secure auth state/nonce crypto adapters and a Drizzle/Postgres-compatible auth state store. Browser auth start can use CSPRNG-generated state/nonce values, HMAC reference hashing with an injected secret, and review-only `auth_states` migration artifacts. Raw OIDC state and nonce values are never persisted; only hashes and lifecycle metadata are stored.

The approved Node runtime dependency composition can now wire the framework-agnostic auth start/callback routes when an OIDC provider adapter is injected or when the explicit `PLATFORM_AUTH_PROVIDER_MODE=generic_oidc` runtime mode is enabled. Auth composition reads the existing auth config contract, uses the Drizzle auth state store, secure state/nonce factories, and `AUTH_STATE_HASH_SECRET` for HMAC auth state references. `AUTH_STATE_HASH_SECRET` is required only when auth runtime composition is enabled. Generic OIDC runtime mode also requires configured issuer and JWKS URLs plus an injected HTTP client, composes the provider-agnostic adapter and JWT/JWKS verifier, and keeps provider HTTP behind injected route-time HTTP boundaries. Bootstrap creation still does not listen, connect, query, run migrations, or call provider/KQAG flows; `start()` remains explicit and provider calls occur only when an auth route request deliberately invokes the configured adapter.

The repo now includes a provider-agnostic generic OIDC provider adapter factory. It builds authorization URLs from the existing auth config values, exchanges authorization codes with an injected HTTP client using form-encoded token requests, keeps raw provider tokens inside adapter-private references only, and can call userinfo only after token verification succeeds. The repo also includes a generic JWT/JWKS token verifier behind the existing `GenericOidcTokenVerifier` interface. It fetches JWKS only during explicit verification, verifies RS256 signatures, validates issuer, audience, expiry, not-before, issued-at, and required subject claims, returns nonce for the adapter-side nonce hash comparison, and only trusts email when `email_verified === true`. No provider SDK, frontend login shell, KQAG launch/storage adapter, app launch token, billing, deployment, or fake-login shortcut is added.

The repo now includes platform-only internal workspace/app-access seed contracts. The seed service can idempotently prepare an internal workspace, the `kqag` app registry record, the workspace entitlement, and an owner/admin/member membership grant through storage-agnostic repository ports. It can grant access to an existing authenticated user by user id or normalized email. Creating a user and provider identity together is deferred until an explicit transactional identity seed boundary exists, so the seed refuses provider-identity user creation before any platform writes. It also refuses email-only user precreation for future provider linking, fake-login shortcuts, conflicting records, and viewer grants for KQAG.

The repo now includes a read-only current session context service and `GET /api/platform/session/context` route. It loads the current browser session from the platform session cookie, returns safe active-session status, user summary, accessible workspace memberships, and app access summaries based on existing app entitlement rules. Responses use no-store/no-cache headers. The endpoint does not launch apps, persist workspace selection, accept invitations, create grants, expose provider tokens/raw claims/session secrets, or call KQAG.

The repo now includes platform-only app launch token contracts. `POST /api/platform/apps/launch?workspaceId=...&appKey=...` requires the browser session cookie plus Origin/Referer and CSRF token validation, re-checks protected app access, and creates a short-lived launch token record that stores only an HMAC hash. The raw launch token is returned only once in the immediate no-store response for diagnostics. `POST /api/platform/apps/launch/consume?appKey=...` accepts the raw launch token only through the `x-app-launch-token` header, requires no browser cookie or CSRF token, hashes before lookup, rejects unknown/expired/consumed/revoked tokens safely, re-checks app access, consumes the token once, and returns safe user/workspace/app context for app integration. `APP_LAUNCH_TOKEN_HASH_SECRET` is required when runtime/bootstrap composes launch issuing and consume dependencies. This does not add KQAG storage, fake login, provider SDKs, billing, deployment, or migration execution.

The repo now includes a minimal framework-free browser shell. `GET /` renders an internal Swooshz Platform landing page with a login link to `GET /api/platform/auth/start`. `GET /app` renders a no-store HTML shell that loads the current session context, requests a CSRF token only for state-changing actions, and can start a browser-safe KQAG launch through `POST /api/platform/apps/launch/open?workspaceId=...&appKey=kqag`. The open route creates the platform launch intent server-side, sends the raw launch token to KQAG only in the server-side `x-app-launch-token` header, relays the safe KQAG session cookie response, and returns only a launch URL to the browser. The launch token is not placed in a URL, response body, cookie, or browser storage. The shell does not bypass service contracts, expose cookies or token hashes, add KQAG storage, or become a polished dashboard.

The repo now includes an explicit internal platform access seed CLI for already-authenticated platform users. After real OIDC login creates the platform user and provider identity, an admin/dev can run `npm run platform:seed-internal-access` with `PLATFORM_SEED_CONFIRM=seed-reviewed-internal-access` and `PLATFORM_SEED_USER_EMAIL` to create or reuse the internal workspace, `kqag` app record, workspace entitlement, and owner/admin/member membership. The CLI validates confirmation and email before opening a DB connection, requires the existing user to have a provider identity, closes the DB pool after completion, prints only a safe summary, and does not run migrations. It does not create users, provider identities, sessions, app launch tokens, fake login state, KQAG storage, private KQAG profile/pricing data, or deployment artifacts.

Safe internal setup flow:

1. Configure real OIDC and platform runtime env.
2. Build and run `npm run platform:start`.
3. Internal tester logs in once through `/api/platform/auth/start`.
4. Run `npm run platform:seed-internal-access` with the required seed env.
5. Visit `/app`.
6. Click the KQAG launch button.

The `platform:start` command is a narrow operator CLI over the existing Node bootstrap/runtime boundary. It does not run migrations, provision a database service, seed access, call provider endpoints on startup, call KQAG on startup, or add deployment behavior. Browser-safe KQAG handoff is disabled by default and requires explicit local UAT env such as `PLATFORM_KQAG_LAUNCH_MODE=server_handoff` and `PLATFORM_KQAG_APP_BASE_URL=<kqag-local-base-url>`.

No Next.js, Vite, React, provider SDK, provider-specific account model, public signup, database provisioning, deployment, Supabase setup, Stripe setup, billing implementation, KQAG-owned auth, KQAG storage, polished dashboard, broad app proxy, or secrets are part of this scaffold.

The internal smoke checklist is documented in `docs/internal-platform-smoke-runbook.md`. It covers the existing database/OIDC/runtime/seed/browser-launch path, keeps migrations explicit, and documents the local same-host KQAG handoff shape without putting launch tokens in browser URLs or storage.

The hosted internal-alpha runbook is documented in `docs/hosted-internal-alpha-runbook.md`. It covers hosted Platform/KQAG placeholders, the env checklist, manual migration/backup/rollback procedure, smoke checklist, and dry-run readiness check without deploying, provisioning, or exposing infrastructure. The readiness check is hardened for hosted review: it requires production mode, HTTPS browser/provider-facing URLs, origin-only allowed origins, callback path shape, KQAG handoff URL guardrails, value-safe output, and no migration/server/network imports.

The hosted operator decision record is documented in `docs/hosted-internal-alpha-operator-decisions.md`. It lists the host/provider, TLS/proxy, process/container, database/backup/restore, migration/rollback, OIDC, secret, log, first owner/admin, add-existing-user, KQAG handoff, cross-host session/cookie, incident, and go/no-go approvals that must happen outside the repo before any actual hosted execution.

External provider setup notes are documented in `docs/auth-provider-selection.md`, `docs/google-oidc-setup-runbook.md`, and `docs/workos-authkit-fit-notes.md`. Google OIDC is the first operational provider setup target for internal UAT. WorkOS/AuthKit remains documented as a likely future B2B/hosted-auth candidate, not runtime-wired. Platform-owned email/password auth, fake login, and active multi-provider login remain deferred.

The next likely platform PR should keep provider configuration operational review separate from broadening browser routes. Polished dashboard work, actual hosted deployment execution, and KQAG app-data changes should still wait for separately approved phases.

## First App Integration Target

KQAG/SAQG is the first app integration target. It remains a separate app in `Swooshz-com/koncept-quote-auto-generator` and stays quote-workflow-specific.

The platform provides KQAG with platform-issued identity and workspace context through the launch consume contract and the browser-safe handoff route. KQAG should not grow its own accounts, users, billing, workspace membership, app registry, customer portal, or platform shell.

## Contract Docs

- `docs/accounts-contract.md`
- `docs/app-access-contract.md`
- `docs/kqag-integration-contract.md`
- `docs/internal-alpha-platform-contract.md`
- `docs/adr/0001-platform-accounts-first.md`
- `docs/adr/0002-auth-session-strategy.md`
- `docs/adr/0003-persistence-and-migrations.md`
- `docs/adr/0004-database-tooling-selection.md`
- `docs/adr/0005-database-connection-and-migration-execution.md`
- `docs/adr/0006-auth-provider-selection.md`
- `docs/adr/0007-http-transport-and-csrf-strategy.md`
- `docs/auth-provider-selection.md`
- `docs/google-oidc-setup-runbook.md`
- `docs/workos-authkit-fit-notes.md`
- `docs/internal-platform-smoke-runbook.md`
- `docs/hosted-internal-alpha-runbook.md`
- `docs/hosted-internal-alpha-operator-decisions.md`
- `docs/roadmap.md`

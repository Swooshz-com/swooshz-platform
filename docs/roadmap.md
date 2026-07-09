# Platform Roadmap

This roadmap sequences Swooshz Platform work so account and app-access scope is settled before frontend implementation.

## Phase 0: Contracts And Architecture

Goal: define the platform account and app-access contract.

Deliverables:

- `README.md` platform ownership boundary.
- `docs/accounts-contract.md`.
- `docs/app-access-contract.md`.
- `docs/sqag-integration-contract.md`.
- `docs/adr/0001-platform-accounts-first.md`.
- Initial roadmap.

Non-goals:

- Frontend shell.
- Real auth provider.
- Database migrations.
- Billing.
- Deployment.
- SQAG code changes.

## Phase 1: Account/Workspace/App-Access Backend Scaffold

Goal: create the backend model and service skeleton that implements the contracts.

Candidate deliverables:

- Entity definitions for user, workspace, membership, role, invitation, session, audit event, app, and entitlement.
- Access decision service.
- Privacy-safe error/result types.
- Unit tests for invariants and app launch decisions.
- Local-only seed or fixture data using synthetic values.

Non-goals:

- Public signup.
- Billing.
- Production auth provider integration.
- Frontend shell.

## Phase 2: Auth Provider Decision And Login Backend

Goal: choose and implement the authentication backend boundary after persistence direction is settled.

Candidate deliverables:

- Provider-agnostic auth/session strategy ADR.
- Persistence and migration strategy ADR.
- Database/provider/tooling selection decision.
- First database scaffold behind repository/service boundaries.
- Storage-agnostic repository/service ports around the app-access decision boundary.
- Drizzle-backed repository adapters around the database scaffold.
- Database connection and migration execution workflow decision.
- Database connection and explicit migration execution implementation.
- Database provisioning or DB integration-test workflow if separately approved.
- Auth provider selection ADR or decision record.
- Auth config/env parser and callback contract tests.
- Provider-agnostic OIDC adapter interface.
- Auth callback service skeleton using a fake adapter and storage-agnostic service ports.
- Platform session creation through repository boundaries.
- Storage-agnostic session revocation service.
- Protected app-access decision service over repository ports.
- Framework-agnostic browser session cookie and HTTP handler contracts.
- HTTP transport and CSRF strategy ADR.
- Route contract manifest for first real HTTP endpoints.
- Framework-agnostic Origin/Referer and CSRF validation contracts.
- Minimal Node HTTP adapter for the approved platform route manifest.
- Node server runtime/config contract around the approved HTTP adapter.
- Storage-agnostic CSRF token lifecycle contracts and repository-backed validator.
- Framework-agnostic CSRF issuance route contract for active browser sessions.
- Drizzle/Postgres CSRF token storage adapter plus secure Node crypto token/hash adapters.
- Runtime dependency composition contract for the approved Node HTTP adapter/server.
- Explicit Node bootstrap wiring with start/stop lifecycle for the approved route set.
- Framework-agnostic browser auth HTTP route contracts for provider login start and callback.
- Node adapter wiring for `GET /api/platform/auth/start` and `GET /api/platform/auth/callback` using injected fake/test dependencies only.
- Drizzle/Postgres auth state storage adapter plus secure Node crypto state/nonce and HMAC reference adapters.
- Runtime auth dependency composition for `GET /api/platform/auth/start` and `GET /api/platform/auth/callback` using the Drizzle auth state store, secure state/nonce factories, `AUTH_STATE_HASH_SECRET`, existing auth config parsing, and an injected OIDC adapter.
- Explicit Node bootstrap wiring that can pass injected auth dependencies into the approved Node adapter without provider calls during creation or start.
- Platform-only internal access seed service and repository create ports for preparing an internal workspace, the `sqag` app record, app entitlement, and owner/admin/member membership grants without SQAG changes.
- Provider-agnostic generic OIDC adapter for authorization URL building, form-encoded token exchange, adapter-private token references, userinfo after verifier success, and normalized identity output through an injected verifier boundary.
- Provider-agnostic generic OIDC JWT/JWKS verifier for real RS256 signature verification, issuer/audience/time/subject validation, nonce return, verified-email handling, and safe metadata normalization through the existing verifier interface.
- Explicit generic OIDC runtime mode that composes the generic adapter and JWT/JWKS verifier from injected config and HTTP boundaries without provider calls during import, composition, bootstrap creation, or bootstrap start.
- Read-only current session context endpoint for future platform shell/dashboard UX, returning safe user, workspace membership, and app access summaries without app launch, persistent workspace selection, frontend, or SQAG integration.
- CSRF-protected app launch intent endpoint that re-checks platform app access, stores only short-lived launch token hashes, and returns the raw launch token only once.
- Platform-side app launch token consume endpoint that accepts raw launch tokens only by header, hashes before lookup, rejects unsafe token lifecycle states, re-checks app access, marks tokens consumed once, and returns safe user/workspace/app context without SQAG integration.
- Minimal framework-free internal browser shell at `GET /` and `GET /app` that uses the existing session context, CSRF issuance, SQAG browser launch handoff, and logout JSON APIs. The shell can launch SQAG through `POST /api/platform/apps/launch/open?workspaceId=...&appKey=sqag` without placing raw launch tokens in URLs, browser storage, cookies, logs, or response bodies. It does not add a frontend framework, SQAG-owned auth/storage, a broad app proxy, or the final dashboard design.
- Explicit internal access seed CLI for existing provider-backed platform users. It requires reviewed confirmation plus explicit workspace identity, refuses missing users and email-only users without provider identities, creates or reuses only reviewed platform-owned workspace/app/entitlement/membership records, does not run migrations, and does not create users, provider identities, sessions, app launch tokens, fake login state, SQAG storage, default production workspace data, billing, deployment, or provider network calls.
- Internal platform smoke runbook for verifying the existing database, OIDC, runtime, seed, browser shell, and SQAG browser launch path without adding database provisioning, deployment, migration automation, fake login, SQAG-owned auth, or SQAG app-data storage. Operational smoke remains the first gate before broader app integration work.
- Explicit `npm run platform:start` operator CLI over the existing Node bootstrap/runtime boundary. It starts the platform HTTP server, supports graceful shutdown, injects the generic OIDC HTTP boundary when configured, and does not run migrations, provision databases, seed access, call provider endpoints on startup, call SQAG on startup, or add deployment behavior. SQAG browser handoff is disabled by default and requires explicit local UAT configuration.
- Narrow SQAG browser-safe launch handoff. Platform creates the launch intent server-side, sends the raw launch token to SQAG only as `x-app-launch-token`, requires same browser cookie host for local UAT, rejects unsafe host mismatch, and returns only a safe launch URL to the browser.
- External provider setup docs: `docs/auth-provider-selection.md`, `docs/google-oidc-setup-runbook.md`, and `docs/workos-authkit-fit-notes.md`.
- Google OIDC as the first operational provider setup target for internal UAT against the existing generic OIDC runtime.
- WorkOS/AuthKit documented as a future B2B/hosted-auth candidate requiring a provider-fit check before runtime wiring.
- Hosted internal-alpha deployment runbook with Platform/SQAG placeholders, env checklist, manual migration/backup/rollback guidance, smoke checklist, and dry-run readiness check hardened for production mode, HTTPS browser/provider URLs, origin/callback shape, SQAG handoff guardrails, value-safe output, and no migration/server/network imports. Actual hosted deployment execution still requires reviewed infra/operator approval.
- Hosted operator decision record and approval checklist for the out-of-repo host/provider, TLS/proxy, process/container, database/backup/restore, migration/rollback, OIDC, secret, log, first owner/admin, add-existing-user, SQAG handoff, cross-host session/cookie, incident, and go/no-go decisions required before hosted execution.
- Auth/session security contract and pre-alpha gap inventory documenting implemented generic OIDC login, provider-backed users, server-side sessions, cookie security, fail-closed session context, CSRF/origin protections, app-launch token handling, read-only route posture, audit-event coverage, and deferred session-management UI/security surfaces.
- Consolidated internal-alpha go/no-go checklist that pulls together the platform contract, hosted runbook, operator decisions, readiness checker, internal smoke runbook, SQAG integration contract, roadmap, and auth/session security contract without approving hosted execution.
- HTTP logout route hardening after real CSRF storage and browser wiring are separately approved.
- Invitation acceptance path if compatible with selected auth provider.
- Tests for session, token, and provider-error privacy behavior.

Non-goals:

- Email/password auth unless explicitly approved.
- Platform-owned email/password auth in the external-provider setup phase.
- Public self-serve signup.
- Real auth provider network calls before the callback/service contract is tested.
- Provider SDKs or real provider networking before a live provider adapter PR is explicitly approved.
- Claiming live-login readiness before provider configuration, runtime deployment posture, observability, and operational approval are reviewed.
- Fake-login shortcuts or email-only user precreation for future provider linking.
- Active multi-provider runtime implementation before a separate architecture PR covers provider selection, callback disambiguation, and controlled account linking.
- User plus provider identity seeding before an explicit transactional identity seed boundary is approved.
- Customer portal.
- Polished dashboard or broad frontend shell beyond the minimal internal browser shell.
- SQAG-owned auth, SQAG storage, deployment routing, broad app proxying, or polished app launch UI before separately approved integration work.
- Database migrations before provider/tooling selection is approved.
- Auth-provider coupling in the database layer.
- Production, staging, or local database execution before an explicit DB workflow is approved.

## Phase 3: Minimal Admin/Internal Account Management

Goal: allow internal administrators to manage workspaces, memberships, and app entitlements safely.

Candidate deliverables:

- Workspace create/update backend operations.
- Membership and invitation backend operations.
- App entitlement enable/disable backend operations.
- Audit event recording.
- Internal-only admin API or minimal admin surface as approved.
- Optional explicit reviewed seed command after a safe operator-confirmation contract exists.

Non-goals:

- Full polished platform shell.
- Public account settings.
- Billing screens.
- SQAG-owned auth/storage adapter.
- Broad app redirect flow or polished app launch UI.

## Phase 4: SQAG Integration

Goal: connect platform identity and workspace access to SQAG through a defined adapter.

Candidate deliverables:

- Run the internal platform smoke runbook successfully against reviewed existing services before broadening SQAG integration work.
- Platform-side SQAG launch handoff contract finalized around the existing short-lived launch token issue, consume, and browser-safe open endpoints.
- SQAG launch context contract aligned to the platform consume response.
- App-side backend exchange using the platform launch token consume contract.
- SQAG workspace-scoped runtime/session boundary.
- Tests proving platform grants SQAG launch only for entitled workspaces and permitted roles.

Non-goals:

- Billing inside SQAG.
- SQAG-owned users or workspaces.
- Customer portal.

## Phase 5: Platform Frontend Shell

Goal: evolve the minimal internal shell into a fuller platform dashboard after backend and app-integration contracts are stable.

Candidate deliverables:

- Polished login entry.
- Workspace switcher.
- App launcher.
- Basic account/membership/admin surfaces.
- SQAG launch entry point.

Non-goals:

- Marketing site.
- Public SaaS onboarding.
- Billing UI unless Phase 6 is approved.

## Phase 6: Billing/Credits Later

Goal: add commercial controls only if approved later.

Candidate deliverables:

- Billing/credits ADR.
- Billing customer/subscription model.
- Credit pool and transaction model.
- Usage event contract.
- Entitlement impact rules for billing status.

Non-goals until approved:

- Stripe integration.
- Payment collection.
- Pricing plans.
- Customer billing portal.

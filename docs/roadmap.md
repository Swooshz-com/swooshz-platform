# Platform Roadmap

This roadmap sequences Swooshz Platform work so account and app-access scope is settled before frontend implementation.

## Phase 0: Contracts And Architecture

Goal: define the platform account and app-access contract.

Deliverables:

- `README.md` platform ownership boundary.
- `docs/accounts-contract.md`.
- `docs/app-access-contract.md`.
- `docs/kqag-integration-contract.md`.
- `docs/adr/0001-platform-accounts-first.md`.
- Initial roadmap.

Non-goals:

- Frontend shell.
- Real auth provider.
- Database migrations.
- Billing.
- Deployment.
- KQAG code changes.

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
- Platform-only internal access seed service and repository create ports for preparing an internal workspace, the `kqag` app record, app entitlement, and owner/admin/member membership grants without KQAG changes.
- Provider-agnostic generic OIDC adapter for authorization URL building, form-encoded token exchange, adapter-private token references, userinfo after verifier success, and normalized identity output through an injected verifier boundary.
- Provider-agnostic generic OIDC JWT/JWKS verifier for real RS256 signature verification, issuer/audience/time/subject validation, nonce return, verified-email handling, and safe metadata normalization through the existing verifier interface.
- Explicit generic OIDC runtime mode that composes the generic adapter and JWT/JWKS verifier from injected config and HTTP boundaries without provider calls during import, composition, bootstrap creation, or bootstrap start.
- Read-only current session context endpoint for future platform shell/dashboard UX, returning safe user, workspace membership, and app access summaries without app launch, persistent workspace selection, frontend, or KQAG integration.
- CSRF-protected app launch intent endpoint that re-checks platform app access, stores only short-lived launch token hashes, returns the raw launch token only once, and leaves launch-token consumption plus KQAG integration deferred.
- HTTP logout route hardening after real CSRF storage and browser wiring are separately approved.
- Invitation acceptance path if compatible with selected auth provider.
- Tests for session, token, and provider-error privacy behavior.

Non-goals:

- Email/password auth unless explicitly approved.
- Public self-serve signup.
- Real auth provider network calls before the callback/service contract is tested.
- Provider SDKs or real provider networking before a live provider adapter PR is explicitly approved.
- Claiming live-login readiness before provider configuration, runtime deployment posture, observability, and operational approval are reviewed.
- Fake-login shortcuts or email-only user precreation for future provider linking.
- User plus provider identity seeding before an explicit transactional identity seed boundary is approved.
- Customer portal.
- Frontend shell before provider and persistence decisions are stable.
- Launch-token consume/validation contract, KQAG launch/storage integration, app redirects, or app launch UI before separately approved integration work.
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
- KQAG launch/storage adapter.
- Launch-token consume/validation contract.

## Phase 4: KQAG Integration

Goal: connect platform identity and workspace access to KQAG through a defined adapter.

Candidate deliverables:

- KQAG launch context contract.
- Signed launch token or backend exchange mechanism.
- KQAG workspace-scoped runtime/session boundary.
- Tests proving platform grants KQAG launch only for entitled workspaces and permitted roles.

Non-goals:

- Billing inside KQAG.
- KQAG-owned users or workspaces.
- Customer portal.

## Phase 5: Platform Frontend Shell

Goal: build the smallest useful frontend after backend contracts are stable.

Candidate deliverables:

- Login entry.
- Workspace switcher.
- App launcher.
- Basic account/membership/admin surfaces.
- KQAG launch entry point.

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

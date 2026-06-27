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
- HTTP logout route after cookie/session handling is separately approved.
- Minimal protected session or app-access decision endpoint after session/cookie handling is separately approved.
- Login callback/session handling after HTTP routes and real provider verification are separately approved.
- Invitation acceptance path if compatible with selected auth provider.
- Tests for session, token, and provider-error privacy behavior.

Non-goals:

- Email/password auth unless explicitly approved.
- Public self-serve signup.
- Real auth provider network calls before the callback/service contract is tested.
- Customer portal.
- Frontend shell before provider and persistence decisions are stable.
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

Non-goals:

- Full polished platform shell.
- Public account settings.
- Billing screens.

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

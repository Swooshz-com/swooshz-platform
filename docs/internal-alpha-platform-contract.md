# Internal Alpha Platform Contract Audit

This audit defines what Swooshz Platform must own before Koncept Images internal team rollout. It is a product-contract and architecture-readiness document only. It does not approve UI implementation, Google Stitch implementation, auth behavior changes, live deployment, KQAG repository changes, secrets, or real staff email addresses.

## Executive Summary

KQAG / SAQG local UAT has a usable platform launch path: Google-compatible generic OIDC can create a platform session, an operator can seed an already-authenticated user into the internal workspace, `/app` can show the user's workspace/app access, and the KQAG browser launch handoff can send a one-time launch token server-to-server for same-host local UAT.

Before Koncept Images internal alpha, Platform still needs a complete team and access-management product surface. The current code supports platform-owned users, provider identities, sessions, workspaces, memberships, app records, app entitlements, hashed auth state, hashed CSRF tokens, hashed one-time app launch tokens, a local browser shell, protected owner/admin-only HTTP route foundations for workspace member and KQAG app-access administration, and a minimal functional `/app/admin` browser surface for internal alpha administration. It does not yet support invitation delivery/acceptance, polished product UI, audit browsing, security/session management, or hosted internal-alpha operations.

The next PRs should therefore implement team/user management and app-access administration before Google Stitch or visual dashboard work. Stitch should consume an approved page inventory from this document and should not invent business logic or product scope.

## Current State

### Current Architecture Map

| Area | Current source | Current state |
| --- | --- | --- |
| Server entrypoints | `src/index.ts`, `scripts/platform-start.mjs`, `src/runtime/node-bootstrap.ts`, `src/http/node-server.ts`, `src/http/node-adapter.ts` | `npm run platform:start` starts the explicit Node bootstrap/server. Importing modules does not listen. Startup composes DB, runtime, auth, CSRF, launch-token, and optional KQAG handoff dependencies. |
| HTTP route map | `src/http/route-contracts.ts`, `src/http/node-adapter.ts` | Routes exist for `/`, `/app`, `/app/admin`, `/healthz`, auth start/callback, session app access, session context, CSRF token issue, protected workspace admin member routes, protected KQAG entitlement admin routes, launch intent, KQAG launch open, launch consume, and logout. The route manifest marks adapter-wired routes as implemented. |
| Auth routes | `src/http/auth-handlers.ts`, `src/auth/*`, `src/runtime/platform-runtime-dependencies.ts` | `GET /api/platform/auth/start` stores hashed state/nonce references and redirects to the configured OIDC authorization URL. `GET /api/platform/auth/callback` consumes state, exchanges/verifies tokens through the adapter, resolves platform identity, creates a platform session, and sets the session cookie. |
| Session handling | `src/auth/session-revocation-service.ts`, `src/http/session-cookie.ts`, `src/http/handlers.ts`, `src/platform/session-context-service.ts` | Server-side session records are referenced by an HttpOnly SameSite cookie. Logout revokes/clears the session. Session context is read-only and no-store. Expired, revoked, missing, or inactive-user sessions fail closed. |
| Workspace model | `src/accounts/types.ts`, `src/db/schema.ts`, `docs/accounts-contract.md` | Workspaces have id, slug, display name, and status. Membership connects users to workspaces with owner/admin/member/viewer roles and active/disabled status. |
| App access model | `src/apps/types.ts`, `src/access/decide-app-access.ts`, `src/platform/app-access-service.ts`, `docs/app-access-contract.md` | App launch requires valid session, active user, selected active workspace, active membership, available/private-preview app, enabled/trial entitlement, and role permission. KQAG launch is owner/admin/member only. |
| Admin service foundation | `src/platform/workspace-admin-service.ts`, `src/platform/repositories.ts`, `src/db/repositories.ts`, `src/http/handlers.ts`, `src/http/node-adapter.ts` | Owner/admin service methods and protected HTTP routes can list workspace members, change roles, disable memberships, list app entitlements, and enable/disable KQAG app entitlement. Mutations preserve last-owner/self-change guardrails and write privacy-minimized audit events in the same transaction/unit-of-work. |
| KQAG launch handoff | `src/platform/app-launch-intent-service.ts`, `src/platform/app-launch-token-consume-service.ts`, `src/http/handlers.ts`, `docs/kqag-integration-contract.md` | Platform creates a short-lived launch token, stores only an HMAC hash, sends the raw token only server-side to KQAG in `x-app-launch-token`, and exposes only a safe launch URL to the browser. Consume accepts the raw token only by header and marks it consumed once. |
| Seed scripts | `scripts/platform-seed-internal-access.mjs`, `src/platform/internal-access-seed-service.ts` | The seed CLI can grant owner/admin/member KQAG access to an existing active provider-backed platform user after explicit confirmation. It refuses email-only user precreation and users without provider identity records. |
| DB migrations | `drizzle/migrations/*`, `src/db/schema.ts`, `scripts/db-migrate.mjs`, `src/db/client.ts` | Drizzle migrations are committed. `npm run db:migrate` builds first, requires `DATABASE_URL`, and requires `DATABASE_MIGRATIONS_CONFIRM=apply-reviewed-migrations`. Migrations are not automatic. |
| Local UAT scripts/runbooks | `docs/internal-platform-smoke-runbook.md`, `docs/google-oidc-setup-runbook.md`, `scripts/platform-start.mjs` | Local UAT is documented around explicit env, migration, start, login, seed, `/app`, and same-host KQAG handoff. It uses placeholders and forbids secrets/private data in docs. |
| Docs/runbooks | `README.md`, `docs/accounts-contract.md`, `docs/app-access-contract.md`, `docs/kqag-integration-contract.md`, `docs/adr/*.md`, `docs/internal-platform-smoke-runbook.md`, `docs/google-oidc-setup-runbook.md` | Existing docs establish platform ownership and local UAT flow. This audit adds the internal-alpha product contract and page inventory. |
| Tests | `tests/*.test.mjs` | Tests cover domain contracts, repositories, DB schema, auth callback/OIDC, HTTP handlers, CSRF, runtime config, launch tokens, launch handoff, seed CLI, platform start CLI, and smoke runbook text. Default `npm test` remains DB-free. |

### Current Product Shape

The platform currently behaves like a minimal internal shell plus backend contract and internal-alpha admin surface:

- A user can sign in through the configured OIDC provider.
- The platform creates and owns the session.
- An operator can seed an already-authenticated user into the internal workspace and grant KQAG access.
- The `/app` shell can list the current user's active workspaces and launchable apps.
- Owner/admin users can reach `/app/admin` from the app shell, review safe workspace/member/KQAG entitlement state, change member roles, disable memberships, and enable or disable the KQAG workspace entitlement through the protected PR #50 admin routes.
- KQAG launch works through an explicitly configured local same-host server handoff.

It is not yet a complete internal admin product. The minimal admin UI is functional internal-alpha scaffolding, not a polished dashboard. Invitation acceptance, add-user/invite workflow, audit browsing, security/session management, hosted deployment operations, and account settings remain missing.

## Internal Alpha Requirements

### Workspace Contract

The internal-alpha workspace should be:

- Workspace display name: `Koncept Images Pte Ltd`
- Workspace slug: `koncept-images-pte-ltd`
- Workspace status: `active`
- Initial app: `kqag` with display name `KQAG / SAQG`
- Initial app entitlement status: `enabled` for the workspace

No real staff emails, private domains, database URLs, OAuth values, tokens, cookies, callback URLs with query params, or KQAG private payloads belong in this repo.

### Role Contract

| Role | Internal-alpha meaning | Team management | SAQG app access management | SAQG launch |
| --- | --- | --- | --- | --- |
| `owner` | Account owner and final administrator for the workspace. | Can add, remove/deactivate, and change roles for admins, members, and operators; ownership transfer/destructive owner removal should be separately guarded. | Can grant/revoke SAQG access for the workspace. | Can launch SAQG when workspace and entitlement are active. |
| `admin` | Workspace administrator for internal operations. | Can add/remove/deactivate members and operators; should not remove the last owner or transfer ownership. | Can grant/revoke SAQG access unless a later policy makes entitlement changes owner-only. | Can launch SAQG when workspace and entitlement are active. |
| `member` | Normal internal staff user. | Cannot manage team members. | Cannot grant/revoke app access. | Can launch SAQG when workspace and entitlement are active. |
| `operator` | Proposed internal-alpha product role for users who perform quote operations but should not administer workspace settings. | Cannot manage team members. | Cannot grant/revoke app access. | Should be allowed to launch SAQG if the role is added to the domain model, or map to `member` for internal alpha. |

Current schema supports `owner`, `admin`, `member`, and `viewer`, but not `operator`. The first admin foundation keeps quote operators mapped to `member`; adding an explicit `operator` role remains a separate implementation PR with migration, access-decision tests, seed/admin handling, and UI copy.

### Access And Removal Rules

| Question | Internal-alpha contract |
| --- | --- |
| Who can add team members? | Owner/admin after admin surfaces exist. The current seed CLI is operator-only and not a product surface. |
| Who can remove team members? | Owner/admin after admin surfaces exist. Removing a user should disable membership rather than deleting the user record by default. |
| Who can change roles? | Owner/admin after admin surfaces exist, with guardrails for last-owner protection and self-demotion. |
| Who can grant/revoke SAQG access? | Owner/admin after app-access admin exists. Grant/revoke should mutate workspace app entitlement and write audit events. |
| Who can launch SAQG? | Owner/admin/member today, and operator later if added or mapped to member. Viewer launch is blocked for KQAG because no read-only KQAG mode exists. |
| Can admins see/manage app access? | Yes for internal alpha, except ownership-only controls if later added. |
| What happens when a user is removed? | Membership should become disabled, new session context should omit that workspace, app launch should fail closed, existing platform sessions may remain signed in for other workspaces, and audit events should record the action. If the user is disabled globally, new app launch must fail for all workspaces. |
| What should be logged/audited? | Sign-in, sign-out/session revocation, membership create/update/disable, invitation create/accept/revoke/expire, app entitlement grant/revoke/suspend, seed operations, auth callback failure category, and launch intent/consume lifecycle metadata. Audit metadata must be privacy-minimized. |

## User And Team Management Gap Audit

| Capability | Current status | Alpha classification | Evidence | Internal-alpha requirement |
| --- | --- | --- | --- | --- |
| Listing workspace users | Implemented partial | Partial admin surface shipped; add/invite remains blocker before broad rollout | Protected admin HTTP routes and `/app/admin` can list workspace members with safe user summaries. | Add invite/add-user workflow or reviewed alpha fallback; keep provider tokens/raw claims out of responses. |
| Adding user by email | Missing | Blocker before internal alpha | Invitation schema/ports exist, but no product flow to invite/add and no email delivery/acceptance path. Seed requires existing provider-backed user. | Add invite/add workflow or documented operator-controlled fallback for approved internal alpha. Avoid user enumeration in public responses. |
| Removing/deactivating user | Implemented partial | Partial admin surface shipped; global user disable remains a future decision | Protected admin HTTP routes and `/app/admin` can disable a workspace membership with audit events, last-owner protection, and self-removal guard. | Decide whether global user disable is needed for alpha. |
| Changing role | Implemented partial | Partial admin surface shipped; operator-role decision remains future scope | Protected admin HTTP routes and `/app/admin` can change membership role with audit events, last-owner protection, and self-demotion guard. | Keep `member` as quote-operator mapping until a first-class `operator` role PR is approved. |
| App access grant/revoke | Implemented partial | Partial admin surface shipped for KQAG entitlement only | Protected admin HTTP routes and `/app/admin` can list KQAG entitlements and enable/disable KQAG entitlement with audit events. | Keep future app support behind app-specific contracts. |
| Invited/pending users | Partial | Future production enhancement after alpha decision, unless invitations are selected for alpha | Invitation schema and repository create/update status exist; no invitation service, token flow, email delivery, or acceptance route. | Decide whether alpha uses invitation flow or admin adds only already-authenticated allowlisted users. Invitation tokens must be hashed. |
| Fail-closed access if role/app access is missing | Implemented | Implemented | `decideAppAccess` denies missing session, inactive user, missing workspace selection, missing membership, inactive workspace, missing/unavailable app, missing entitlement, disallowed role, and future billing block. | Preserve this behavior while adding admin surfaces. |
| Seeding first owner/admin | Partial | Blocker for hosted internal alpha operations | Seed CLI exists for an existing provider-backed user and uses explicit confirmation. It requires manual operator sequencing after first login. | Keep as bootstrap fallback, document hosted operator runbook, and do not use real staff emails in repo. |
| Audit event recording for admin actions | Partial | Blocker before internal alpha admin surfaces | Workspace admin services emit privacy-minimized audit events for membership role change, membership disable, KQAG entitlement enable, and KQAG entitlement disable. Audit browsing/export is missing. | Add audit browsing and ensure future admin routes use the same service/audit path. |
| Admin authorization checks | Implemented partial | Implemented for current admin routes and UI | Workspace admin services and protected HTTP routes check active session, active user, active workspace, active membership, and owner/admin role. Browser-cookie admin mutation routes use the existing CSRF/origin security helper before mutation. | Preserve fail-closed behavior for future admin routes. |

## Security Findings

| Area | Current finding | Internal-alpha action |
| --- | --- | --- |
| Google/OIDC configuration | Generic OIDC config supports Google endpoints through env, verifies state/nonce, RS256 JWKS, issuer, audience, expiry, subject, nonce, and verified email. Exact email allowlist is recommended for internal UAT. | For hosted alpha, configure Google redirect URI to the hosted HTTPS Platform callback and prefer exact `AUTH_ALLOWED_EMAILS` until a domain policy is approved. |
| Auth start/callback diagnostics | Failure reporters emit category-only diagnostics such as `auth_start_failure category=<category>`. Responses stay generic. | Preserve category-only diagnostics. Add request ids later if logs need support correlation. Do not log callback URLs with query params. |
| Session cookies | Session cookies are HttpOnly, SameSite=Lax by default, and production runtime requires secure cookies. | Hosted alpha must use HTTPS and `PLATFORM_COOKIE_SECURE=true` through production config. |
| Logout behavior | Logout is POST, CSRF/origin-protected in the adapter, revokes session when present, and clears the cookie with generic response. | Preserve POST-only logout and no-store behavior. |
| CSRF assumptions | State-changing browser-cookie routes use Origin/Referer plus CSRF token validation. CSRF tokens are stored as HMAC hashes. | All future admin POST/PATCH/DELETE routes must reuse the same security helper before mutations. |
| Allowed origins/CORS | Runtime config requires explicit allowed origins in production and includes public base URL in origin validation. There is no broad CORS layer. | Hosted alpha must set only the hosted Platform origin. Do not add wildcard CORS for KQAG. |
| App launch token handling | Launch tokens are raw only at creation time, stored as hashes, short-lived, consumed once, and accepted only by header on consume. | Preserve header-only consume and no token-in-URL/browser-storage policy. |
| KQAG server handoff | Browser-safe KQAG handoff is explicit, same-host checked, disabled by default, and restricted to `appKey=kqag`. | Hosted alpha needs an HTTPS KQAG URL and a reviewed cross-host cookie/session strategy before moving beyond local same-host UAT. |
| Role/app-access checks | Launch re-checks session, user, workspace, membership, app, entitlement, and role. KQAG viewer launch is blocked. | Add equivalent owner/admin authorization checks for team/app-access admin mutations. |
| Fail-closed behavior | Missing/invalid config, missing app launch dependencies, unsafe KQAG host mismatch, denied access, invalid tokens, and CSRF/origin failures fail closed. | Preserve fail-closed defaults; do not add demo or fallback auth shortcuts. |
| DB migration safety | Migration execution requires explicit confirmation and does not run on startup. | Hosted alpha needs a migration procedure with backup/rollback notes before first real-data migration. |
| Logging privacy | Docs and code avoid printing secrets, raw provider payloads, auth headers, cookies, DB URLs, and private KQAG payloads. | Add privacy-safe request/event ids for support later; do not log raw prompts, quote files, provider responses, or token material. |
| Audit events | Audit schema/repository exists, but product workflows for team/app-access management and consistent event emission are missing. | Treat audit event emission as a blocker for admin surfaces before internal alpha. |

## Admin Foundation Runbook

The current admin foundation includes service/repository operations, protected HTTP routes, and a minimal `/app/admin` product surface for internal-alpha administration. The UI is plain functional scaffolding, not Google Stitch visual polish.

Implemented service operations:

- `listWorkspaceMembersForAdmin`: Owner/admin service can list workspace members with safe user and membership summaries.
- `changeWorkspaceMemberRole`: Owner/admin service can change membership role with last-owner protection, self-demotion guard, and `workspace.membership.role_changed` audit event in the same transaction/unit-of-work.
- `disableWorkspaceMembership`: Owner/admin service can disable a workspace membership with last-owner protection, self-removal guard, and `workspace.membership.disabled` audit event in the same transaction/unit-of-work.
- `listWorkspaceAppEntitlementsForAdmin`: Owner/admin service can list KQAG entitlements and enable/disable KQAG entitlement through paired listing and mutation services.
- `setWorkspaceAppEntitlementStatus`: owner/admin-only KQAG entitlement enable/disable with `workspace.app_entitlement.enabled` or `workspace.app_entitlement.disabled` audit event in the same transaction/unit-of-work.

Implemented protected HTTP route operations:

- Protected admin HTTP routes can list workspace members and perform the mutation operations below through the service foundation.
- `GET /api/platform/workspaces/:workspaceId/members`: lists workspace members through the service foundation.
- `POST /api/platform/workspaces/:workspaceId/members/:membershipId/role?role=<role>`: changes a workspace member role through the service foundation.
- `POST /api/platform/workspaces/:workspaceId/members/:membershipId/disable`: disables a workspace membership through the service foundation.
- `GET /api/platform/workspaces/:workspaceId/app-entitlements`: lists workspace app entitlements through the service foundation.
- `POST /api/platform/workspaces/:workspaceId/app-entitlements/kqag/status?status=<enabled|disabled>`: enables or disables the KQAG entitlement through the service foundation.

Implemented browser/admin UI surface:

- `GET /app/admin`: minimal no-store admin shell reachable from `/app` for users with an owner/admin workspace.
- The shell loads safe workspace identity from the session context route, then calls the protected workspace members and app-entitlement routes above.
- Role changes, membership disables, and KQAG entitlement toggles use the existing CSRF token route and send the required `x-csrf-token` header to the PR #50 protected routes.

Operational notes:

- Quote operators remain mapped to `member` until an explicit `operator` role migration is approved.
- Removed users are blocked from KQAG launch because disabled membership fails the existing app-access decision.
- Membership and app-entitlement mutation audit append failure cannot leave membership or entitlement state changed without the matching audit event.
- Protected admin HTTP routes follow the existing adapter convention of path parameters plus required query parameters for mutation inputs; there is no request-body parser in this foundation PR.
- State-changing admin HTTP routes require active browser session, allowed Origin/Referer, and valid CSRF token before mutation.
- Audit metadata uses internal ids and status/category values only. Do not add raw emails, provider claims, OAuth payloads, tokens, cookies, DB URLs, KQAG quote contents, or callback URLs with query params.
- No polished product UI exists yet; `/app/admin` is a plain functional internal-alpha surface.
- The minimal admin UI and routes use active session checks, active workspace membership checks, owner/admin authorization, CSRF/origin validation for browser-cookie mutations, and generic user-facing errors. They do not add invitation, audit browsing, global user disable, operator role, billing, KQAG app-data editing, or Google Stitch implementation.
- The former blocker phrase "No product HTTP route or UI exists yet" is resolved only for the minimal `/app/admin` member/app-entitlement controls; add/invite, audit browsing, and polished product UI remain out of scope.
- No KQAG app data responsibilities move into Platform. Platform manages access; KQAG still owns quote data.

Remaining internal-alpha blockers after this foundation:

- Add/invite user workflow or a reviewed operator-controlled alpha fallback.
- Audit/activity browsing.
- Hosted internal-alpha deployment runbook and smoke checklist.
- Product decision on whether `operator` remains mapped to `member` or becomes a first-class role.

## Production And Deployment Readiness Audit

| Hosted internal-alpha blocker | Current state | Required before hosted alpha |
| --- | --- | --- |
| Hosted HTTPS Platform URL | Local/runtime config supports public base URL; no hosted deployment runbook exists. | Choose host, HTTPS termination, process manager/container plan, and `PLATFORM_PUBLIC_BASE_URL`. |
| Hosted HTTPS KQAG URL | Local UAT handoff supports same-host local shape only. | Define hosted KQAG launch/session handoff and cookie strategy before cross-host rollout. |
| Google OAuth hosted redirect URI | Google runbook documents placeholder callback URL. | Add exact hosted callback URI in Google OAuth configuration outside the repo. |
| Persistent shared Postgres | Code expects existing Postgres through `DATABASE_URL`; no provider is selected here. | Select managed/owner-hosted Postgres, credentials handling, SSL mode, access controls, backups, and restore test. |
| Migration procedure | `npm run db:migrate` is explicit and confirmation-gated. | Write hosted migration runbook with review, backup, apply, smoke, and rollback/fix-forward steps. |
| Backup/restore | Deferred in ADRs. | Define backup cadence, restore test, retention, and who can access backups. |
| Rollback | Deferred. | Define app rollback, migration rollback/fix-forward, and KQAG handoff rollback. |
| Health checks | `GET /healthz` exists. | Add hosted health check target, uptime monitor, and expected response policy. |
| Process manager/container plan | `npm run platform:start` exists; no deployment wrapper. | Choose process manager/container, restart policy, env injection, log collection, and graceful stop handling. |
| Logs/monitoring | Category diagnostics and startup summary exist; no hosted observability plan. | Add metadata-only logs, request ids, auth failure categories, launch outcome counts, error rate, and alert thresholds. |
| Environment variable checklist | Local smoke runbook lists placeholders. | Create hosted alpha env checklist with secret owner, rotation plan, and no committed values. |
| Seeding first owner/admin | Seed CLI can seed an existing provider-backed user. | Hosted operator must login first, then run seed for the exact allowlisted placeholder email value outside repo. |
| Smoke checklist | Local smoke runbook exists. | Add hosted smoke checklist covering login, seed, `/app`, CSRF logout, KQAG launch, launch token non-exposure, and logs. |

## Platform And KQAG Boundary

### Platform Owns

- Auth provider configuration and identity-proof boundary.
- Platform users, provider identities, and platform sessions.
- Workspaces/accounts, roles, memberships, invitations, and admin authorization.
- App registry records, app entitlements, and app launch decisions.
- CSRF/session protection and browser-cookie route security.
- App launch token issue/consume and KQAG handoff boundary.
- Audit events for account, access, and security-relevant actions.
- Organization/account settings.
- Billing/credits later only if approved.

### KQAG Owns

- Quote generation workflow.
- Quote-company profiles.
- Pricing references.
- Quote sessions and quote workflow state.
- Generated quote artifacts.
- Dashboard quote history and app-specific runtime/history once scoped by platform context.

### Boundary Confusion To Resolve

- The platform shell is currently minimal and launch-focused; it should not become the source of KQAG quote history or pricing/profile administration.
- KQAG should consume platform context but must not grow separate Swooshz accounts, workspace membership, app entitlement, or billing concepts.
- Platform admin pages may display app access state, but they should not edit KQAG-owned quote data.
- The route manifest marks adapter-wired routes as implemented; keep future route inventory changes aligned with adapter tests before docs or tooling derive readiness from it.
- Hosted KQAG handoff may require a different cookie/session strategy than same-host local UAT; do not assume the local handoff is production-ready.

## UI And IA Requirements Before Google Stitch

| Page | Purpose | Visible data | Allowed actions | Required role | Blocker status |
| --- | --- | --- | --- | --- | --- |
| App Hub / Dashboard | Give signed-in users a workspace-aware entry to apps. | Current user, active workspace, launchable apps, access status, safe launch errors. | Launch SAQG, switch workspace when multiple workspaces exist, logout. | Any active member with app entitlement for launch; owner/admin/member for SAQG launch today. | Partially present as `/app`; needs product polish after contract approval. |
| Workspace Settings | Show internal workspace identity and non-secret configuration. | Workspace name, slug, status, app entitlement summary, safe metadata. | Edit display name/status only if approved later; no destructive ownerless state. | Owner/admin. | Minimal identity summary appears in `/app/admin`; editable settings remain future scope. |
| Team Members | Manage people in the workspace. | User display name, placeholder email, role, membership status, last login if safe, invitation status if used. | Add/invite user, remove/deactivate membership, change role, resend/revoke invite if invitations ship. | Owner/admin with last-owner guardrails. | Minimal list, role change, and membership disable are implemented in `/app/admin`; add/invite remains blocker. |
| App Access | Manage workspace entitlement to SAQG and future apps. | App key/name/status, entitlement status, who granted it if available, launch eligibility summary. | Grant/revoke/suspend SAQG access, view denied reason, future app enablement. | Owner/admin. | Minimal KQAG entitlement list and enable/disable controls are implemented in `/app/admin`; future app support remains contract-specific. |
| Audit / Activity | Review security and access changes. | Sign-in/out, membership changes, entitlement changes, seed operations, launch lifecycle metadata, actor/target ids, timestamps. | Filter/export later; no mutation except retention workflow later. | Owner/admin; maybe owner-only for export. | Audit events exist for admin services/routes; browsing/export still blocker for admin surfaces. |
| Security / Sessions | Review active sessions and security posture. | Current session, recent auth failure categories, session expiry, allowed auth provider. | Logout current session now; revoke other sessions later. | Current user for own session; owner/admin for workspace-wide security later. | Partial logout exists; management page is future production enhancement. |
| Deployment / Health | Internal operator page or runbook-only status. | Health check, app/runtime version, KQAG handoff mode, non-secret config presence checks. | Run smoke checklist manually; no secret display. | Operator/owner/admin, or runbook-only. | Future; hosted runbook is blocker before hosted alpha, UI is not. |
| Billing / Credits | Reserve commercial concepts. | Placeholder only; no balances or payment provider ids. | None until billing is approved. | Owner later. | Future only; not an internal-alpha blocker. |

## Google Stitch Recommendation

Do not start visual Stitch implementation until the Platform product contract and IA are approved.

Once approved, Stitch should generate screens based on the page inventory above, not invent product scope. Stitch prompts should provide exact page names, role rules, visible data, and allowed actions from this document.

Stitch output should be treated as UI reference only. It is not the source of truth for business logic, authorization, route contracts, audit rules, migrations, KQAG boundaries, or security behavior.

## Recommended PR Sequence

1. Add/invite user workflow or reviewed operator-controlled alpha fallback.
2. Audit/activity browsing.
3. Hosted internal-alpha deployment runbook.
4. Platform security/readiness guard checks.
5. Google Stitch UI exploration based on approved IA and current functional admin surfaces.
6. Implement Platform UI polish.
7. Billing/credits later.

## Acceptance Checklist For Internal Alpha

- Platform has a real `Koncept Images Pte Ltd` workspace contract without real emails or secrets in repo.
- Owner/admin/member/operator role decision is approved, including whether operator maps to member or becomes a schema role.
- Owner/admin can list, add/invite, remove/deactivate, and change roles for workspace users.
- Owner/admin can grant/revoke SAQG access.
- Removed users fail closed for SAQG launch.
- App launch remains token-hash, one-time, header-only, no-store, and server-side for browser handoff.
- Audit events exist for team and app-access changes.
- Hosted Platform, hosted KQAG, Google redirect URI, Postgres, migrations, backups, rollback, logs, health checks, env, seed, and smoke runbooks are approved.
- Google Stitch starts only after this contract and IA are approved.

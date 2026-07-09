# Internal Alpha Platform Contract Audit

This audit defines what Swooshz Platform must own before Koncept Images internal team rollout. It is a product-contract and architecture-readiness document only. It does not approve UI implementation, Google Stitch implementation, auth behavior changes, live deployment, SQAG repository changes, secrets, or real staff email addresses.

## Executive Summary

SQAG local UAT has a usable platform launch path: Google-compatible generic OIDC can create a platform session, an operator can seed a reviewed first-owner pending approval or an already-authenticated provider-backed user into the internal workspace, `/app` can show the user's workspace/app access, and the SQAG browser launch handoff can send a one-time launch token server-to-server for same-host local UAT.

Before Koncept Images internal alpha, Platform still needs a complete team and access-management product surface. The current code supports platform-owned users, provider identities, sessions, workspaces, memberships, DB-backed pending workspace membership approvals, app records, app entitlements, hashed auth state, hashed CSRF tokens, hashed one-time app launch tokens, a local browser shell, protected owner/admin-only HTTP route foundations for workspace member and SQAG app-access administration, a minimal functional `/app/admin` browser surface, minimal owner/admin audit/activity browsing for internal alpha administration, hosted internal-alpha runbook/readiness documentation, a hosted operator decision record/checklist, an auth/session security contract with a pre-alpha gap inventory, and hardened hosted-readiness guardrails for production mode, HTTPS URLs, origin/callback shape, SQAG handoff configuration, and value-safe output. Owner/admin users can add a teammate by normalized email and role before sign-in: existing active provider-backed Platform users are added immediately, while unknown or not-yet-provider-backed users create a pending workspace membership approval that activates only after real OIDC sign-in with the matching normalized email. It does not yet support full invitation delivery/acceptance, polished product UI, audit export/filtering/retention management, session-management UI, workspace-wide active-session review, revoke-other-sessions, or actual hosted internal-alpha deployment execution.

The next PRs should therefore finish the remaining team/user management and operations gaps before Google Stitch or visual dashboard work. Stitch should consume an approved page inventory from this document and should not invent business logic or product scope.

## Current State

### Current Architecture Map

| Area | Current source | Current state |
| --- | --- | --- |
| Server entrypoints | `src/index.ts`, `scripts/platform-start.mjs`, `src/runtime/node-bootstrap.ts`, `src/http/node-server.ts`, `src/http/node-adapter.ts` | `npm run platform:start` starts the explicit Node bootstrap/server. Importing modules does not listen. Startup composes DB, runtime, auth, CSRF, launch-token, and optional SQAG handoff dependencies. |
| HTTP route map | `src/http/route-contracts.ts`, `src/http/node-adapter.ts` | Routes exist for `/`, `/app`, `/app/admin`, `/healthz`, auth start/callback, session app access, session context, CSRF token issue, protected workspace admin member routes, pending member approval list/revoke routes, protected SQAG entitlement admin routes, protected workspace audit-event routes, launch intent, SQAG launch open, launch consume, and logout. The route manifest marks adapter-wired routes as implemented. |
| Auth routes | `src/http/auth-handlers.ts`, `src/auth/*`, `src/runtime/platform-runtime-dependencies.ts` | `GET /api/platform/auth/start` stores hashed state/nonce references and redirects to the configured OIDC authorization URL. `GET /api/platform/auth/callback` consumes state, exchanges/verifies tokens through the adapter, resolves platform identity, creates a platform session, and sets the session cookie. |
| Session handling | `src/auth/session-revocation-service.ts`, `src/http/session-cookie.ts`, `src/http/handlers.ts`, `src/platform/session-context-service.ts`, `docs/auth-session-security-contract.md` | Server-side session records are referenced by an HttpOnly SameSite cookie. Logout revokes/clears the current session. Session context is read-only and no-store. Expired, revoked, missing, or inactive-user sessions fail closed. The auth/session security contract now documents the implemented posture and pre-alpha gap inventory. This PR does not add a session-management UI. |
| Workspace model | `src/accounts/types.ts`, `src/db/schema.ts`, `docs/accounts-contract.md` | Workspaces have id, slug, display name, and status. Membership connects users to workspaces with owner/admin/member/viewer roles and active/disabled status. Pending workspace membership approvals store normalized email, workspace, role, status, nullable actor for first-owner bootstrap only, acceptance/revocation timestamps, and no invitation token material. Admin-created teammate approvals remain non-owner. |
| App access model | `src/apps/types.ts`, `src/access/decide-app-access.ts`, `src/platform/app-access-service.ts`, `docs/app-access-contract.md` | App launch requires valid session, active user, selected active workspace, active membership, available/private-preview app, enabled/trial entitlement, and role permission. SQAG launch is owner/admin/member only. |
| Admin service foundation | `src/platform/workspace-admin-service.ts`, `src/platform/repositories.ts`, `src/db/repositories.ts`, `src/http/handlers.ts`, `src/http/node-adapter.ts` | Owner/admin service methods and protected HTTP routes can list workspace members, add existing active provider-backed users by normalized email, create/list/revoke pending workspace membership approvals, change roles, disable and reactivate non-owner memberships, list app entitlements, and enable/disable SQAG app entitlement. They can also browse recent workspace audit events. Mutations preserve last-owner/self-change guardrails and write privacy-minimized audit events in the same transaction/unit-of-work. |
| SQAG launch handoff | `src/platform/app-launch-intent-service.ts`, `src/platform/app-launch-token-consume-service.ts`, `src/http/handlers.ts`, `docs/sqag-integration-contract.md` | Platform creates a short-lived launch token, stores only an HMAC hash, sends the raw token only server-side to SQAG in `x-app-launch-token`, and exposes only a safe launch URL to the browser. Consume accepts the raw token only by header and marks it consumed once. |
| Seed scripts | `scripts/platform-seed-internal-access.mjs`, `src/platform/internal-access-seed-service.ts` | The seed CLI can prepare a fresh hosted DB by creating reviewed workspace/app entitlement records plus a pending first-owner approval, then real OIDC sign-in creates/links the provider-backed user and activates the approval. Without first-owner bootstrap mode, it can grant owner/admin/member SQAG access to an existing active provider-backed platform user after explicit confirmation. It refuses email-only user precreation and users without provider identity records. |
| DB migrations/readiness | `drizzle/migrations/*`, `src/db/schema.ts`, `src/db/client.ts`, `src/db/readiness.ts`, `scripts/db-migrate.mjs`, `scripts/platform-db-readiness-check.mjs` | Drizzle migrations are committed. `npm run db:migrate` builds first, requires `DATABASE_URL`, and requires `DATABASE_MIGRATIONS_CONFIRM=apply-reviewed-migrations`. `npm run platform:db-readiness-check` verifies hosted Postgres reachability plus required schema/migration state with sanitized output. Migrations are not automatic. |
| Local UAT scripts/runbooks | `docs/internal-platform-smoke-runbook.md`, `docs/google-oidc-setup-runbook.md`, `scripts/platform-start.mjs` | Local UAT is documented around explicit env, migration, start, login, seed, `/app`, and same-host SQAG handoff. It uses placeholders and forbids secrets/private data in docs. |
| Hosted alpha runbooks/tooling | `docs/hosted-internal-alpha-runbook.md`, `docs/hosted-internal-alpha-operator-decisions.md`, `scripts/platform-readiness-check.mjs`, `scripts/platform-db-readiness-check.mjs` | Hosted deployment runbook and smoke checklist are now documented with placeholders only, alongside a hosted operator decision record, approval checklist, and readiness gate alignment. The dry-run readiness checker is hardened for production mode, HTTPS browser/provider URLs, origin-only allowed origins, callback path shape, SQAG handoff base URL shape, valid Postgres-shaped `DATABASE_URL`, value-safe output, and no migration/server/network imports. The DB readiness checker is a separate operator command that connects to hosted Postgres and reports only sanitized config, reachability, schema, and migration status. Actual hosted deployment execution still requires reviewed infra/operator approval. |
| Docs/runbooks | `README.md`, `docs/accounts-contract.md`, `docs/app-access-contract.md`, `docs/sqag-integration-contract.md`, `docs/auth-session-security-contract.md`, `docs/internal-alpha-go-no-go-checklist.md`, `docs/adr/*.md`, `docs/internal-platform-smoke-runbook.md`, `docs/hosted-internal-alpha-runbook.md`, `docs/hosted-internal-alpha-operator-decisions.md`, `docs/google-oidc-setup-runbook.md` | Existing docs establish platform ownership, local UAT flow, hosted internal-alpha operations guidance, operator approval gates, the auth/session security contract and gap inventory, the consolidated go/no-go checklist, and the internal-alpha product contract/page inventory. |
| Tests | `tests/*.test.mjs` | Tests cover domain contracts, repositories, DB schema, auth callback/OIDC, HTTP handlers, CSRF, runtime config, launch tokens, launch handoff, seed CLI, platform start CLI, and smoke runbook text. Default `npm test` remains DB-free. |

### Current Product Shape

The platform currently behaves like a minimal internal shell plus backend contract and internal-alpha admin surface:

- A user can sign in through the configured OIDC provider.
- The platform creates and owns the session.
- An operator can prepare a reviewed first-owner pending approval for a fresh hosted DB or seed an already-authenticated provider-backed user into the internal workspace and grant SQAG access.
- The `/app` shell can list the current user's active workspaces and launchable apps.
- Owner/admin users can reach `/app/admin` from the app shell, review safe workspace/member/pending-approval/SQAG entitlement/activity state, add a teammate by email and role, list/revoke pending approvals, change member roles, disable and reactivate non-owner memberships, and enable or disable the SQAG workspace entitlement through protected admin routes.
- SQAG launch works through an explicitly configured local same-host server handoff.

It is not yet a complete internal admin product. The minimal admin UI is functional internal-alpha scaffolding, not a polished dashboard. Full invitation delivery/acceptance, owner transfer, audit export/filtering/retention management, session-management UI, workspace-wide active-session review, revoke-other-sessions, actual hosted deployment execution, and account settings remain missing.

## Internal Alpha Requirements

### Workspace Contract

The internal-alpha workspace should be:

- Workspace display name: `Koncept Images Pte Ltd`
- Workspace slug: `koncept-images-pte-ltd`
- Workspace status: `active`
- Initial app: `sqag` with display name `SQAG`
- Initial app entitlement status: `enabled` for the workspace

No real staff emails, private domains, database URLs, OAuth values, tokens, cookies, callback URLs with query params, or SQAG private payloads belong in this repo.

### Role Contract

| Role | Internal-alpha meaning | Team management | SQAG app access management | SQAG launch |
| --- | --- | --- | --- | --- |
| `owner` | Account owner and final administrator for the workspace. | Can add, remove/deactivate, and change roles for admins, members, and operators; ownership transfer/destructive owner removal should be separately guarded. | Can grant/revoke SQAG access for the workspace. | Can launch SQAG when workspace and entitlement are active. |
| `admin` | Workspace administrator for internal operations. | Can add/remove/deactivate members and operators; should not remove the last owner or transfer ownership. | Can grant/revoke SQAG access unless a later policy makes entitlement changes owner-only. | Can launch SQAG when workspace and entitlement are active. |
| `member` | Normal internal staff user. | Cannot manage team members. | Cannot grant/revoke app access. | Can launch SQAG when workspace and entitlement are active. |
| `viewer` | Read-only Platform workspace visibility. | Cannot manage team members. | Cannot grant/revoke app access. | Cannot launch SQAG because no read-only SQAG mode exists. |
| `operator` | Proposed internal-alpha product role for users who perform quote operations but should not administer workspace settings. | Cannot manage team members. | Cannot grant/revoke app access. | Should be allowed to launch SQAG if the role is added to the domain model, or map to `member` for internal alpha. |

Current schema supports `owner`, `admin`, `member`, and `viewer`, but not `operator`. The first admin foundation keeps quote operators mapped to `member`; adding an explicit `operator` role remains a separate implementation PR with migration, access-decision tests, seed/admin handling, and UI copy.

### Access And Removal Rules

| Question | Internal-alpha contract |
| --- | --- |
| Who can add team members? | Owner/admin can add a teammate by normalized email and role before sign-in. Existing active provider-backed Platform users are added immediately. Unknown or not-yet-provider-backed users create a pending workspace membership approval and real OIDC sign-in with the matching normalized email activates the membership. Full invitation delivery remains future scope. The current seed CLI is operator-only and remains a bootstrap fallback. |
| Who can remove team members? | Owner/admin can remove non-owner memberships from the workspace without deleting the platform user, provider identities, or other workspace memberships. Removal revokes the removed user's active platform sessions. Disable/reactivate remains the reversible membership deactivation path. |
| Who can change roles? | Owner/admin after admin surfaces exist, with guardrails for last-owner protection and self-demotion. |
| Who can grant/revoke SQAG access? | Owner/admin after app-access admin exists. Grant/revoke should mutate workspace app entitlement and write audit events. |
| Who can launch SQAG? | Owner/admin/member today, and operator later if added or mapped to member. Viewer launch is blocked for SQAG because no read-only SQAG mode exists. Future products inherit the same blocked viewer launch default until an explicit per-product read-only policy is approved. |
| Can admins see/manage app access? | Yes for internal alpha, except ownership-only controls if later added. |
| What happens when a user is removed? | The workspace membership row is removed, the removed user's active platform sessions are revoked, new session context should omit that workspace, app launch should fail closed, future sign-in is rejected until the user is re-added to an active workspace or receives a matching pending approval, and audit events should record the action. If the user is disabled globally, new app launch must fail for all workspaces. |
| What should be logged/audited? | Sign-in, sign-out/session revocation, membership create/update/disable, membership approval create/revoke/accept, invitation create/accept/revoke/expire if a future invitation flow ships, app entitlement grant/revoke/suspend, seed operations, auth callback failure category, and launch intent/consume lifecycle metadata. Audit metadata must be privacy-minimized. |

## User And Team Management Gap Audit

| Capability | Current status | Alpha classification | Evidence | Internal-alpha requirement |
| --- | --- | --- | --- | --- |
| Listing workspace users | Implemented partial | Partial admin surface shipped; full invite remains blocker before broad rollout | Protected admin HTTP routes and `/app/admin` can list workspace members with safe user summaries. | Keep private provider material out of responses. Audit browsing is now covered by the Activity row. |
| Adding user by email | Implemented partial | Reviewed pending-approval onboarding shipped; full email invitation delivery remains future scope | `/app/admin` and the protected add route can add an existing active provider-backed user by normalized email immediately or create a pending workspace membership approval for an unknown/not-yet-provider-backed teammate. Real OIDC sign-in with the matching normalized email accepts the approval and creates the active membership. The route returns safe guidance for pending approval created, duplicate pending approval, existing membership, disabled users, invalid roles, and audit failures. No invitation delivery occurs. | Keep full invitation delivery/acceptance for a separate reviewed PR. Avoid user enumeration in public responses. |
| Removing/deactivating user | Implemented partial | Partial admin surface shipped; global user disable remains a future decision | Protected admin HTTP routes and `/app/admin` can disable a workspace membership, reactivate a disabled non-owner membership, and remove a non-owner workspace membership with audit events, last-owner protection, self-removal guard, owner protection, and transaction rollback on audit failure. | Decide whether global user disable is needed for alpha. |
| Changing role | Implemented partial | Partial admin surface shipped; operator-role decision remains future scope | Protected admin HTTP routes and `/app/admin` can change membership role with audit events, last-owner protection, and self-demotion guard. | Keep `member` as quote-operator mapping until a first-class `operator` role PR is approved. |
| App access grant/revoke | Implemented partial | Partial admin surface shipped for SQAG entitlement only | Protected admin HTTP routes and `/app/admin` can list SQAG entitlements and enable/disable SQAG entitlement with audit events. The service-level entitlement mutation is generic by `appKey` for future registered products, but the current browser/admin route remains SQAG-scoped. | Keep future app route/UI support behind app-specific contracts. |
| Invited/pending users | Partial | Pending approval onboarding implemented; full invitation delivery remains future scope | DB-backed pending workspace membership approvals exist for invite-less onboarding, including list/revoke in `/app/admin` and acceptance during real OIDC callback. Legacy invitation schema and repository create/update status still exist; no invitation service, email delivery, token flow, or invitation acceptance route is added. | Use pending approvals for day-to-day teammate onboarding. Keep full invitation delivery/acceptance for a separate reviewed PR if needed. |
| Fail-closed access if role/app access is missing | Implemented | Implemented | `decideAppAccess` denies missing session, inactive user, missing workspace selection, missing membership, inactive workspace, missing/unavailable app, missing entitlement, disallowed role, and future billing block. | Preserve this behavior while adding admin surfaces. |
| Seeding first owner/admin | Implemented partial | Needs hosted smoke evidence before internal alpha | Seed CLI first-owner bootstrap mode creates reviewed workspace/app entitlement records and a pending owner approval without users, provider identities, sessions, or fake login state. Real OIDC sign-in activates the owner membership transactionally. | Run only as a reviewed one-off, keep real staff emails outside repo notes, and require hosted smoke evidence before readiness changes. |
| Audit event recording and browsing for admin actions | Implemented partial | Minimal browsing shipped; export/filtering/retention remains future scope | Workspace admin services emit privacy-minimized audit events for membership add, membership role change, membership disable, membership reactivation, membership removal, SQAG entitlement enable, and SQAG entitlement disable. `/app/admin` can browse recent owner/admin-only workspace audit events through a read-only protected route. | Keep future admin routes on the same service/audit path and add export/filtering/retention only in a separate reviewed PR. |
| Admin authorization checks | Implemented partial | Implemented for current admin routes and UI | Workspace admin services and protected HTTP routes check active session, active user, active workspace, active membership, and owner/admin role. Browser-cookie admin mutation routes use the existing CSRF/origin security helper before mutation. | Preserve fail-closed behavior for future admin routes. |

## Security Findings

| Area | Current finding | Internal-alpha action |
| --- | --- | --- |
| Google/OIDC configuration | Generic OIDC config supports Google endpoints through env, verifies state/nonce, RS256 JWKS, issuer, audience, expiry, subject, nonce, and verified email. Exact email allowlist can remain a bootstrap/emergency provider-entry guard while pending approvals handle workspace authorization. | For hosted alpha, configure Google redirect URI to the hosted HTTPS Platform callback. Keep `AUTH_ALLOWED_EMAILS` as an entry filter for the first owner/admin and emergency guard unless a domain policy is approved; it does not create users or ownership. Pending approvals must not bypass real OIDC. |
| Auth start/callback diagnostics | Failure reporters emit category-only diagnostics such as `auth_start_failure category=<category>`. Responses stay generic. | Preserve category-only diagnostics. Add request ids later if logs need support correlation. Do not log callback URLs with query params. |
| Session cookies | Session cookies are HttpOnly, SameSite=Lax by default, and production runtime requires secure cookies. | Hosted alpha must use HTTPS and `PLATFORM_COOKIE_SECURE=true` through production config. |
| Logout behavior | Logout is POST, CSRF/origin-protected in the adapter, revokes session when present, and clears the cookie with generic response. | Preserve POST-only logout and no-store behavior. |
| CSRF assumptions | State-changing browser-cookie routes use Origin/Referer plus CSRF token validation. CSRF tokens are stored as HMAC hashes. | All future admin POST/PATCH/DELETE routes must reuse the same security helper before mutations. |
| Allowed origins/CORS | Runtime config requires explicit allowed origins in production and includes public base URL in origin validation. There is no broad CORS layer. | Hosted alpha must set only the hosted Platform origin. Do not add wildcard CORS for SQAG. |
| Hosted readiness guard | `npm run platform:readiness-check` is dry-run only and now fails hosted readiness for non-production `NODE_ENV`, plain HTTP browser/provider URLs, malformed origins, callback URLs with query/fragment or the wrong path, missing `server_handoff` SQAG base URL, SQAG handoff base URLs with query/fragment, or malformed `DATABASE_URL`. `npm run platform:db-readiness-check` is the separate live DB reachability and schema/migration check. | Keep env readiness as validation/tooling only. It must not run migrations, start servers, connect to databases, call OIDC, call SQAG, seed access, or print env values. DB readiness may connect to the configured Postgres only when the operator deliberately runs it, and it must print sanitized statuses only. Actual hosted deployment execution still requires reviewed infra/operator approval. |
| App launch token handling | Launch tokens are raw only at creation time, stored as hashes, short-lived, consumed once, and accepted only by header on consume. | Preserve header-only consume and no token-in-URL/browser-storage policy. |
| SQAG server handoff | Browser-safe SQAG handoff is explicit, same-host checked, disabled by default, and restricted to `appKey=sqag`. | Hosted alpha needs an HTTPS SQAG URL and a reviewed cross-host cookie/session strategy before moving beyond local same-host UAT. |
| Role/app-access checks | Launch re-checks session, user, workspace, membership, app, entitlement, and role. Viewer product launch is blocked by default, including SQAG, unless a future product-specific read-only launch policy is approved. | Preserve least-privilege viewer behavior and owner/admin authorization checks for team/app-access admin mutations. |
| Fail-closed behavior | Missing/invalid config, missing app launch dependencies, unsafe SQAG host mismatch, denied access, invalid tokens, and CSRF/origin failures fail closed. | Preserve fail-closed defaults; do not add demo or fallback auth shortcuts. |
| DB migration safety | Migration execution requires explicit confirmation and does not run on startup. DB readiness checks reachability, required tables, and Drizzle migration metadata after manual migration. | Hosted alpha needs the Neon target, backup/rollback notes, restore owner, and `ready` DB readiness result before first hosted server start. |
| Logging privacy | Docs and code avoid printing secrets, raw provider payloads, auth headers, cookies, DB URLs, and private SQAG payloads. | Add privacy-safe request/event ids for support later; do not log raw prompts, quote files, provider responses, or token material. |
| Audit events | Audit schema/repository exists, admin mutations emit audit events, and `/app/admin` can browse recent owner/admin-only activity. | Export/filtering/retention workflows remain future scope. Preserve privacy-minimized summaries. |
| Auth/session management contract | `docs/auth-session-security-contract.md` documents implemented auth/session behavior, intentionally deferred controls, and the pre-alpha gap inventory. | Treat the contract as documentation only. This PR does not add a session-management UI, password auth, 2FA, hosted deployment approval, or runtime auth changes. |

## Admin Foundation Runbook

The current admin foundation includes service/repository operations, protected HTTP routes, and a minimal `/app/admin` product surface for internal-alpha administration. The UI is plain functional scaffolding, not Google Stitch visual polish.

Implemented service operations:

- `listWorkspaceMembersForAdmin`: Owner/admin service can list workspace members with safe user and membership summaries.
- `addWorkspaceMemberByEmail`: Owner/admin service can add an existing active provider-backed user by normalized email as `admin`, `member`, or `viewer`; otherwise it creates a pending workspace membership approval for the normalized email and role. Existing-user adds emit `workspace.membership.added`; pending approval creates emit `workspace.membership_approval.created`; both store only privacy-minimized audit metadata.
- `listWorkspaceMembershipApprovalsForAdmin`: Owner/admin service can list pending workspace membership approvals for a workspace.
- `revokeWorkspaceMembershipApproval`: Owner/admin service can revoke a pending workspace membership approval and emits `workspace.membership_approval.revoked` in the same transaction/unit-of-work.
- `changeWorkspaceMemberRole`: Owner/admin service can change membership role with last-owner protection, self-demotion guard, and `workspace.membership.role_changed` audit event in the same transaction/unit-of-work.
- `disableWorkspaceMembership`: Owner/admin service can disable a workspace membership with last-owner protection, self-removal guard, and `workspace.membership.disabled` audit event in the same transaction/unit-of-work.
- `reactivateWorkspaceMembership`: Owner/admin service can reactivate a disabled non-owner workspace membership with self-reactivation guard, owner-reactivation protection, and `workspace.membership.reactivated` audit event in the same transaction/unit-of-work.
- `removeWorkspaceMembership`: Owner/admin service can remove a non-owner workspace membership with last-owner protection, self-removal guard, owner protection, removed-user active session revocation, and `workspace.membership.removed` audit event in the same transaction/unit-of-work.
- `listWorkspaceAppEntitlementsForAdmin`: Owner/admin service can list workspace app entitlements with app key/name/status summaries.
- `setWorkspaceAppEntitlementStatus`: owner/admin-only app entitlement enable/disable by registered `appKey` with `workspace.app_entitlement.enabled` or `workspace.app_entitlement.disabled` audit event in the same transaction/unit-of-work. The service is product-generic; the current HTTP/admin route remains SQAG-scoped.
- `listWorkspaceAuditEventsForAdmin`: Owner/admin service can list recent workspace audit events newest first with safe limits and privacy-minimized metadata.

Implemented protected HTTP route operations:

- Protected admin HTTP routes can list workspace members, list pending approvals, and perform the mutation operations below through the service foundation.
- `GET /api/platform/workspaces/:workspaceId/members`: lists workspace members through the service foundation.
- `POST /api/platform/workspaces/:workspaceId/members/add`: reads `email` and `role` from the JSON request body, adds an existing active provider-backed Platform user immediately, or creates a pending workspace membership approval through the service foundation. Allowed roles are `admin`, `member`, and `viewer`; `owner` is not accepted by this route.
- `GET /api/platform/workspaces/:workspaceId/member-approvals`: lists pending workspace membership approvals through the service foundation. It is read-only and does not require CSRF.
- `POST /api/platform/workspaces/:workspaceId/member-approvals/:approvalId/revoke`: revokes a pending workspace membership approval through the service foundation.
- `POST /api/platform/workspaces/:workspaceId/members/:membershipId/role?role=<role>`: changes a workspace member role through the service foundation.
- `POST /api/platform/workspaces/:workspaceId/members/:membershipId/disable`: disables a workspace membership through the service foundation.
- `POST /api/platform/workspaces/:workspaceId/members/:membershipId/reactivate`: reactivates a disabled non-owner workspace membership through the service foundation.
- `POST /api/platform/workspaces/:workspaceId/members/:membershipId/remove`: removes a non-owner membership from the workspace through the service foundation and revokes the removed user's active platform sessions without deleting the platform user, provider identities, or other workspace memberships.
- `GET /api/platform/workspaces/:workspaceId/app-entitlements`: lists workspace app entitlements through the service foundation.
- `POST /api/platform/workspaces/:workspaceId/app-entitlements/sqag/status?status=<enabled|disabled>`: enables or disables the SQAG entitlement through the service foundation.
- `GET /api/platform/workspaces/:workspaceId/audit-events?limit=<number>`: lists recent workspace audit events through the service foundation. It is read-only and does not require CSRF.

Implemented browser/admin UI surface:

- `GET /app/admin`: minimal no-store admin shell reachable from `/app` for users with an owner/admin workspace.
- The shell loads safe workspace identity from the session context route, then calls the protected workspace members, pending approval, app-entitlement, and audit-event routes above.
- The add-existing-user form posts by calling the protected add route with the existing CSRF token/header. The teammate does not need to sign in before an owner/admin creates the pending approval, but activation still requires real provider-backed OIDC sign-in with the matching normalized email. No invitation delivery or fake provider account creation happens.
- The Pending Approvals section lists pending approvals and lets owner/admin users revoke them through the CSRF-protected revoke route.
- Role changes, membership disables, membership reactivations, membership removals, and SQAG entitlement toggles use the existing CSRF token route and send the required `x-csrf-token` header to the protected routes.
- The Activity section shows recent workspace audit events with event type, target, actor user id, timestamp, and allowlisted safe metadata only, including membership approval create/revoke/accept events.
- Activity rows must identify the affected user or pending email safely. Membership events resolve a safe display label from the target user when available and fall back to `Unknown user`; pending approval events show the normalized pending email from the approval record. Activity keeps privacy-minimized metadata and must not show raw provider claims, tokens, cookies, database URLs, stack traces, or SQAG private payloads.
- State-changing admin actions use an internal modal and visible loading indicator instead of browser confirmation. The remove flow uses `Remove member?`, explains `This removes workspace access for this member. Their platform account is not deleted.`, disables modal buttons while pending, and shows safe success or failure copy.

Operational notes:

- Quote operators remain mapped to `member` until an explicit `operator` role migration is approved.
- For local UAT, set role to `member` for quote operators unless the user is explicitly administering the workspace.
- Removed users are blocked from SQAG launch because the workspace membership is absent; disabled memberships are blocked because inactive membership fails the existing app-access decision.
- Viewer users keep read-only workspace visibility in Platform but are blocked from product launch by default, including future registered apps, unless a future app-specific read-only launch contract is deliberately designed and tested.
- Membership, pending approval, and app-entitlement mutation audit append failure cannot leave membership, approval, or entitlement state changed without the matching audit event.
- Membership add audit append failure cannot leave a new membership without the matching `workspace.membership.added` audit event.
- Pending approvals do not grant app launch or admin access before activation creates an active membership through real provider-backed sign-in.
- Pending approval activation emits `workspace.membership_approval.accepted` with privacy-minimized metadata and must fail closed if the approval is revoked, the workspace is inactive, the role is invalid, the user is inactive, or an active membership already exists.
- Existing disabled memberships are not reactivated by the add route; owners/admins use the explicit membership reactivation action in `/app/admin`.
- Protected admin HTTP routes keep path parameters for resource identity. The add-member mutation reads teammate email and role from a JSON request body so private email/role values are not placed in the URL. Other current admin mutations keep short non-email controls in path/query parameters until separately reviewed.
- State-changing admin HTTP routes require active browser session, allowed Origin/Referer, and valid CSRF token before mutation.
- Audit metadata uses internal ids and status/category values only. Do not add raw emails, provider claims, OAuth payloads, tokens, cookies, DB URLs, SQAG quote contents, or callback URLs with query params.
- No polished product UI exists yet; `/app/admin` is a plain functional internal-alpha surface.
- The minimal admin UI and routes use active session checks, active workspace membership checks, owner/admin authorization, CSRF/origin validation for browser-cookie mutations, and generic user-facing errors. They do not add invitation delivery, audit export/filtering/retention, global user disable, operator role, billing, SQAG app-data editing, or Google Stitch implementation.
- The former blocker phrase "No product HTTP route or UI exists yet" is resolved only for the minimal `/app/admin` member/pending-approval/app-entitlement/activity controls; full invitations, audit export/filtering/retention, and polished product UI remain out of scope.
- No SQAG app data responsibilities move into Platform. Platform manages access; SQAG still owns quote data.

Remaining internal-alpha blockers after this foundation:

- Full email invitation delivery/acceptance, if selected beyond DB-backed pending approvals.
- Owner transfer, if approved.
- Audit export/filtering/retention workflows.
- Session-management UI, workspace-wide active-session review, revoke-other-sessions, account security page, auth failure dashboard, device/session metadata enrichment, and rate limiting/lockout controls.
- Product decision on whether `operator` remains mapped to `member` or becomes a first-class role.
- Hosted operator decision approvals documented in `docs/hosted-internal-alpha-operator-decisions.md`.
- Actual hosted deployment execution still requires reviewed infra/operator approval.

## Production And Deployment Readiness Audit

| Hosted internal-alpha blocker | Current state | Required before hosted alpha |
| --- | --- | --- |
| Hosted HTTPS Platform URL | Local/runtime config supports public base URL; hosted placeholder is documented in `docs/hosted-internal-alpha-runbook.md`. | Choose real host, HTTPS termination, process manager/container plan, and `PLATFORM_PUBLIC_BASE_URL` outside the repo. |
| Hosted HTTPS SQAG URL | Local UAT handoff supports same-host local shape; hosted SQAG placeholder and handoff caveat are documented. | Define hosted SQAG launch/session handoff and cookie strategy before cross-host rollout. |
| Google OAuth hosted redirect URI | Google runbook and hosted runbook document placeholder callback URI shape. | Add exact hosted callback URI in Google OAuth configuration outside the repo. |
| Persistent shared Postgres | Code expects existing Postgres through `DATABASE_URL`; hosted runbook documents the recommended Neon target, pooled runtime connection, backup, restore, and secret-store expectations. | Create and approve Neon project/database/role outside the repo, keep credentials in the secret store, decide SSL mode/access controls, and complete backup plus restore test. |
| Migration procedure | `npm run db:migrate` is explicit and confirmation-gated; hosted runbook documents manual review, backup, apply, DB readiness re-check, smoke, and rollback/fix-forward steps. | Apply only after reviewed infra/operator approval. Migrations remain explicit/manual only, never startup-automatic. |
| Backup/restore | Hosted runbook documents backup/restore operator checks. | Choose provider-specific cadence, restore target, retention, and access approvals outside the repo. |
| Rollback | Hosted runbook documents app rollback, database restore/fix-forward posture, and SQAG handoff rollback to manual mode. | Approve operator-specific rollback targets outside the repo. |
| Health checks | `GET /healthz` exists and hosted runbook documents its limited meaning. | Add hosted monitor target, expected response policy, and alerting outside the repo. |
| Process manager/container plan | `npm run platform:start` exists; hosted runbook documents process manager/container expectations without adding deployment code. | Choose process manager/container, restart policy, env injection, log collection, and graceful stop handling outside the repo. |
| Logs/monitoring | Category diagnostics and startup summary exist; hosted runbook documents privacy-safe log review. | Add request ids, launch outcome counts, error rate, alert thresholds, and retention policy outside the repo. |
| Environment variable checklist | Hosted env checklist is documented with secret vs non-secret classification and placeholders only; the dry-run readiness checker enforces production mode, HTTPS URL requirements, origin/callback shape, SQAG handoff guardrails, valid Postgres-shaped `DATABASE_URL`, and value-safe output. | Populate real hosted values through the secret/process manager outside the repo, then run env readiness before manual migrations or startup and DB readiness before server start. |
| Hosted operator approvals | Hosted operator decision record/checklist is documented with required owners, evidence placeholders, repo impact, and status placeholders. | Approve host/provider, TLS/proxy, process/container, database/backup/restore, migrations/rollback, OIDC, secrets, logs, first owner/admin identity, pending approval process, SQAG handoff mode, cross-host session/cookie strategy, incident path, and go/no-go outside repo before execution. |
| Seeding first owner/admin | Seed CLI can prepare a pending first-owner approval on a fresh hosted DB; hosted runbook documents seed first, then real OIDC login activation. | Hosted operator must run the reviewed first-owner bootstrap mode for the exact private value outside repo notes, then complete real OIDC login. |
| Smoke checklist | Hosted smoke checklist is documented for login, `/app`, `/app/admin`, pending approval create/revoke/activation, role/membership/SQAG entitlement changes, audit/activity, token privacy, logout, and fail-closed access. | Run after actual hosted deployment execution with reviewed infra/operator approval. |

## Platform And SQAG Boundary

### Platform Owns

- Auth provider configuration and identity-proof boundary.
- Platform users, provider identities, and platform sessions.
- Workspaces/accounts, roles, memberships, pending workspace approvals, invitations if later approved, and admin authorization.
- App registry records, app entitlements, and app launch decisions.
- CSRF/session protection and browser-cookie route security.
- App launch token issue/consume and SQAG handoff boundary.
- Audit events for account, access, and security-relevant actions.
- Organization/account settings.
- Billing/credits later only if approved.

### SQAG Owns

- Quote generation workflow.
- Quote-company profiles.
- Pricing references.
- Quote sessions and quote workflow state.
- Generated quote artifacts.
- Dashboard quote history and app-specific runtime/history once scoped by platform context.

### Boundary Confusion To Resolve

- The platform shell is currently minimal and launch-focused; it should not become the source of SQAG quote history or pricing/profile administration.
- SQAG should consume platform context but must not grow separate Swooshz accounts, workspace membership, app entitlement, or billing concepts.
- Platform admin pages may display app access state, but they should not edit SQAG-owned quote data.
- The route manifest marks adapter-wired routes as implemented; keep future route inventory changes aligned with adapter tests before docs or tooling derive readiness from it.
- Hosted SQAG handoff may require a different cookie/session strategy than same-host local UAT; do not assume the local handoff is production-ready.

## UI And IA Requirements Before Google Stitch

| Page | Purpose | Visible data | Allowed actions | Required role | Blocker status |
| --- | --- | --- | --- | --- | --- |
| App Hub / Dashboard | Give signed-in users a workspace-aware entry to apps. | Current user, active workspace, launchable apps, access status, safe launch errors. | Launch SQAG, switch workspace when multiple workspaces exist, logout. | Any active member with app entitlement for launch; owner/admin/member for SQAG launch today. | Partially present as `/app`; needs product polish after contract approval. |
| Workspace Settings | Show internal workspace identity and non-secret configuration. | Workspace name, slug, status, app entitlement summary, safe metadata. | Edit display name/status only if approved later; no destructive ownerless state. | Owner/admin. | Minimal identity summary appears in `/app/admin`; editable settings remain future scope. |
| Team Members | Manage people in the workspace. | User display name, placeholder email, role, membership status, last login if safe, pending approval status, invitation status if used later. | Add existing provider-backed user, create/revoke pending approval, remove/deactivate/reactivate membership, change role, resend/revoke invite if invitations ship. | Owner/admin with last-owner guardrails. | Minimal list, existing-user add, pending approval list/revoke/activation, role change, membership disable, non-owner membership reactivation, and non-owner membership removal are implemented in `/app/admin`; full invitations remain future scope. |
| App Access | Manage workspace entitlement to SQAG and future apps. | App key/name/status, entitlement status, who granted it if available, launch eligibility summary. | Grant/revoke/suspend SQAG access, view denied reason, future app enablement. | Owner/admin. | Minimal SQAG entitlement list and enable/disable controls are implemented in `/app/admin`; future app support remains contract-specific. |
| Audit / Activity | Review security and access changes. | Recent workspace admin audit events: membership changes, entitlement changes, actor/target ids, timestamps, and safe metadata. | Browse recent events now; filter/export later; no mutation except retention workflow later. | Owner/admin; maybe owner-only for export. | Minimal Activity browsing is implemented in `/app/admin`; export/filtering/retention remains future scope. |
| Security / Sessions | Review active sessions and security posture. | Current session, recent auth failure categories, session expiry, allowed auth provider. | Logout current session now; revoke other sessions later. | Current user for own session; owner/admin for workspace-wide security later. | Partial logout exists; management page is future production enhancement. |
| Deployment / Health | Internal operator page or runbook-only status. | Health check, app/runtime version, SQAG handoff mode, non-secret config presence checks. | Run smoke checklist manually; no secret display. | Operator/owner/admin, or runbook-only. | Runbook is documented; a UI remains future and actual hosted execution still requires reviewed infra/operator approval. |
| Billing / Credits | Reserve commercial concepts. | Placeholder only; no balances or payment provider ids. | None until billing is approved. | Owner later. | Future only; not an internal-alpha blocker. |

## Google Stitch Recommendation

Do not start visual Stitch implementation until the Platform product contract and IA are approved.

Once approved, Stitch should generate screens based on the page inventory above, not invent product scope. Stitch prompts should provide exact page names, role rules, visible data, and allowed actions from this document.

Stitch output should be treated as UI reference only. It is not the source of truth for business logic, authorization, route contracts, audit rules, migrations, SQAG boundaries, or security behavior.

## Recommended PR Sequence

1. Full email invitation delivery/acceptance, if needed for alpha beyond DB-backed pending approvals.
2. Audit export/filtering/retention.
3. Further Platform security/readiness checks beyond the hardened dry-run readiness checker, if a reviewed alpha blocker identifies them.
4. Reviewed hosted internal-alpha deployment execution, after infra/operator approval.
5. Google Stitch UI exploration based on approved IA and current functional admin surfaces.
6. Implement Platform UI polish.
7. Billing/credits later.

## Acceptance Checklist For Internal Alpha

- Platform has a real `Koncept Images Pte Ltd` workspace contract without real emails or secrets in repo.
- Owner/admin/member/operator role decision is approved, including whether operator maps to member or becomes a schema role.
- Owner/admin can list members, add existing provider-backed users, create/revoke pending approvals before sign-in, remove/deactivate, and change roles for workspace users; full invite delivery remains a separate decision.
- Owner/admin can grant/revoke SQAG access.
- Removed users fail closed for SQAG launch.
- App launch remains token-hash, one-time, header-only, no-store, and server-side for browser handoff.
- Audit events exist for team and app-access changes.
- Hosted Platform, hosted SQAG, Google redirect URI, Postgres, migrations, backups, rollback, logs, health checks, env, seed, and smoke runbooks are documented with placeholders and approved before execution; hosted readiness also fails closed on non-production mode, non-HTTPS browser/provider URLs, malformed origins, callback shape failures, unsafe SQAG handoff base URL shape, or value-leaking output.
- Google Stitch starts only after this contract and IA are approved.

# Auth/Session Security Contract

This contract documents the current Swooshz Platform auth/session security posture for pre-alpha review. It is documentation and test coverage only. For clarity: no password auth or 2FA added, no session-management UI added, and no hosted deployment approval.

Related docs:

- `docs/internal-alpha-platform-contract.md`
- `docs/hosted-internal-alpha-runbook.md`
- `docs/hosted-internal-alpha-operator-decisions.md`
- `docs/roadmap.md`

Platform owns auth, users, sessions, workspaces, roles, memberships, app entitlements, app launch checks, and audit events.

Platform does not own KQAG quote data. KQAG owns quote generation, profiles, pricing references, quote sessions, generated artifacts, and quote dashboard/history. KQAG deployment/runtime/data decisions remain outside this Platform PR except for Platform handoff placeholders. No KQAG app-data editing, KQAG profiles/pricing, quote history, generated artifacts, or quote sessions move into Platform.

## Current Implemented Behavior

- Generic OIDC login path: `GET /api/platform/auth/start` stores only hashed auth references, redirects through the configured OIDC adapter, and `GET /api/platform/auth/callback` exchanges and verifies identity through injected provider boundaries before creating a Platform session.
- Provider-backed user requirement: sign-in resolves a provider-backed Platform identity, and add-existing-user requires the target user to already be active and provider-backed after signing in once.
- Server-side session records: Platform sessions are persisted as server-side records and the browser cookie carries only the platform session reference.
- HttpOnly/SameSite cookie usage: session Set-Cookie helpers emit HttpOnly browser cookies with SameSite=Lax by default.
- Secure cookie requirement for production: production runtime config requires secure browser cookies, and hosted readiness requires production-mode secure cookie configuration.
- Session expiry behavior: session context, admin authorization, and launch checks reject missing, expired, revoked, or inactive-user sessions.
- Logout/session revocation behavior: logout is POST-only, CSRF/origin protected in the Node adapter, revokes the current session when present, and clears the browser session cookie.
- Fail-closed session context behavior: the session context endpoint returns safe unauthenticated results for missing, expired, revoked, inactive-user, or missing-user cases.
- CSRF token handling for browser state-changing routes: state-changing browser-cookie routes require Origin/Referer validation plus an `x-csrf-token` header; CSRF service stores only token hashes and lifecycle metadata.
- Origin/Referer checks for state-changing admin routes: member add, role change, membership disable, membership reactivation, and KQAG entitlement status mutation routes call the shared request-security helper before mutation.
- App-launch token properties: app launch tokens are one-time, hashed at rest, short-lived, consumed once, and accepted by consume only as a header-only raw token. The browser-safe KQAG launch path keeps no browser URL/storage token.
- Read-only browser-session routes that do not require CSRF: session context, session app-access checks, workspace member listing, app-entitlement listing, and workspace audit browsing do not require CSRF because they are read-only no-store routes that do not mutate Platform records.
- Header-token app launch consume route: `POST /api/platform/apps/launch/consume` does not require browser CSRF because it does not use the browser session cookie; it requires the raw one-time launch token in the request header and consumes it once.
- Audit events for workspace/app-access admin actions: membership add, role change, membership disable, membership reactivation, KQAG entitlement enable, and KQAG entitlement disable append privacy-minimized audit events through the workspace admin service.

## Explicitly Deferred Items

- Workspace-wide active-session viewer: deferred. There is no owner/admin UI for all active sessions.
- Revoke other sessions: deferred. Current logout handles current-session revocation only.
- Account security page: deferred. No user-facing account security page is added in this PR.
- Auth failure dashboard: deferred. Auth diagnostics are category-only, but no dashboard or reporting surface is added.
- Full invitation acceptance flow: deferred. Add-existing-user remains the internal-alpha fallback after a teammate signs in once.
- Password auth and 2FA: deferred. No password auth or 2FA added; external-provider-backed auth remains the current posture.
- SSO/SAML/AuthKit/WorkOS runtime integration: deferred. WorkOS/AuthKit remains documented as a future candidate, not runtime-wired.
- Device/session metadata enrichment: deferred. Session records carry the current lifecycle fields, not enriched device or geolocation data.
- Rate limiting/lockout: deferred unless a future implementation proves it exists. Do not treat auth throttling, lockout, or abuse dashboards as implemented by this contract.

## Internal-Alpha Minimum Acceptable Posture

Before hosted internal alpha, the minimum acceptable posture is:

- single provider-backed login.
- allowlisted users.
- secure cookie in hosted production.
- fail-closed sessions.
- owner/admin audit browsing.
- no raw token exposure.
- manual/operator incident process.

This posture does not approve hosted execution. Actual hosted execution still requires the hosted operator decision record, reviewed infrastructure/operator approval, and hosted smoke testing. This PR does not add a session-management UI and does not approve hosted deployment.

## Gap Inventory

| Security/session capability | Current status | Evidence/source file/doc | Alpha requirement | Future production enhancement |
| --- | --- | --- | --- | --- |
| Generic OIDC login path | Implemented | `src/http/auth-handlers.ts`; `src/auth/callback-service.ts`; `tests/auth-http-handlers.test.mjs`; `tests/auth-callback-service.test.mjs` | Use one reviewed external provider configuration; keep provider calls behind explicit auth requests. | Add richer provider support only after account-linking and operational review. |
| Provider-backed user requirement | Implemented partial | `src/auth/platform-identity-resolver.ts`; `src/platform/workspace-admin-service.ts`; `tests/auth-callback-service.test.mjs`; `tests/workspace-admin-service.test.mjs` | Allow only active provider-backed users; teammates must sign in once before add-existing-user. | Full invitation acceptance flow and controlled account-linking workflow. |
| Server-side session records | Implemented | `src/accounts/types.ts`; `src/auth/platform-identity-resolver.ts`; `src/platform/session-context-service.ts`; `tests/auth-callback-service.test.mjs` | Browser carries only the session reference; session state remains server-side. | Add session metadata enrichment and admin review surfaces. |
| HttpOnly/SameSite cookie usage | Implemented | `src/http/session-cookie.ts`; `tests/http-session-cookie.test.mjs`; `docs/adr/0007-http-transport-and-csrf-strategy.md` | Keep HttpOnly and SameSite=Lax defaults for browser sessions. | Revisit cookie policy only with a reviewed cross-host strategy. |
| Secure cookie requirement for production | Implemented | `src/http/runtime-config.ts`; `tests/http-node-server-runtime.test.mjs`; `docs/hosted-internal-alpha-runbook.md` | Hosted production must use secure browser cookies over HTTPS. | Add deployment-specific verification outside the repo after operator approval. |
| Session expiry behavior | Implemented | `src/platform/session-context-service.ts`; `src/platform/workspace-admin-service.ts`; `tests/session-context-service.test.mjs`; `tests/workspace-admin-service.test.mjs` | Expired sessions fail closed for context, admin, and launch checks. | Add user/admin visibility into session expiry and recent activity. |
| Logout/session revocation behavior | Implemented partial | `src/auth/session-revocation-service.ts`; `src/http/handlers.ts`; `src/http/node-adapter.ts`; `tests/session-revocation-service.test.mjs` | Current-session logout must revoke and clear the browser session safely. | Revoke other sessions and workspace-wide active-session viewer. |
| Fail-closed session context behavior | Implemented | `src/platform/session-context-service.ts`; `tests/session-context-service.test.mjs` | Missing, revoked, expired, inactive-user, or missing-user session state returns safe unauthenticated context. | Add support-facing category counts without exposing private values. |
| CSRF token handling for browser state-changing routes | Implemented | `src/http/request-security.ts`; `src/http/csrf-token-service.ts`; `src/http/route-contracts.ts`; `tests/http-request-security.test.mjs`; `tests/csrf-token-service.test.mjs` | All browser-cookie mutations use Origin/Referer plus CSRF token validation before mutation. | Add broader security telemetry and abuse controls if approved. |
| Origin/Referer checks for state-changing admin routes | Implemented | `src/http/node-adapter.ts`; `src/http/request-security.ts`; `tests/http-admin-routes.test.mjs`; `tests/http-request-security.test.mjs` | Admin mutations must validate Origin/Referer and CSRF before service calls. | Add centralized policy reporting and request identifiers. |
| App-launch token properties | Implemented | `src/platform/app-launch-intent-service.ts`; `src/platform/app-launch-token-consume-service.ts`; `src/http/handlers.ts`; `tests/app-launch-intent-service.test.mjs`; `tests/app-launch-token-consume-service.test.mjs` | Tokens remain one-time, hashed at rest, header-only raw token on consume, and no browser URL/storage token. | Hosted cross-host handoff needs reviewed session/cookie strategy before `server_handoff`. |
| Read-only browser-session routes that do not require CSRF | Implemented | `src/http/route-contracts.ts`; `tests/http-route-contracts.test.mjs`; `tests/http-request-security.test.mjs` | Read-only browser-session routes remain no-store and do not mutate Platform records. | Reassess if a route becomes state-changing. |
| Header-token app launch consume route | Implemented | `src/http/route-contracts.ts`; `src/platform/app-launch-token-consume-service.ts`; `tests/app-launch-token-consume-service.test.mjs`; `tests/http-route-contracts.test.mjs` | `POST /api/platform/apps/launch/consume` is state-changing because it consumes a one-time launch token. It is CSRF-exempt because it uses header-token auth and no browser session cookie. | Preserve replay resistance, header-only raw token handling, and privacy-safe consume diagnostics. |
| Audit events for workspace/app-access admin actions | Implemented partial | `src/platform/workspace-admin-service.ts`; `tests/workspace-admin-service.test.mjs`; `docs/internal-alpha-platform-contract.md` | Owner/admin audit browsing must show admin actions with privacy-minimized metadata. | Audit export/filtering/retention workflows. |
| Workspace-wide active-session viewer | Deferred | `docs/internal-alpha-platform-contract.md`; this contract | Not required for narrow internal alpha if manual/operator incident process is approved. | Build owner/admin session viewer with privacy limits. |
| Revoke other sessions | Deferred | `src/auth/session-revocation-service.ts`; this contract | Current-session logout is acceptable for pre-alpha with manual incident handling. | Add revoke-other-sessions workflow and audit events. |
| Account security page | Deferred | `docs/internal-alpha-platform-contract.md`; this contract | Not required before narrow hosted internal alpha. | Add account security page with current session and auth posture. |
| Auth failure dashboard | Deferred | `src/http/auth-handlers.ts`; `tests/auth-http-handlers.test.mjs`; this contract | Category-only diagnostics plus manual/operator incident process. | Add dashboard or alerting after observability owner approval. |
| Full invitation acceptance flow | Deferred | `docs/internal-alpha-platform-contract.md`; `src/platform/workspace-admin-service.ts`; this contract | Use add-existing-user only after provider-backed login unless invitations are selected later. | Invitation delivery, acceptance, revoke, expire, and audit workflows. |
| Password auth and 2FA | Deferred | `docs/adr/0006-auth-provider-selection.md`; this contract | No password auth or 2FA added; use provider-backed login. | Reconsider only after explicit security/product approval. |
| SSO/SAML/AuthKit/WorkOS runtime integration | Deferred | `docs/workos-authkit-fit-notes.md`; `docs/auth-provider-selection.md`; this contract | Generic OIDC remains the current runtime path. | Provider migration or enterprise SSO after architecture review. |
| Device/session metadata enrichment | Deferred | `src/accounts/types.ts`; this contract | Not required for narrow alpha if manual incident process is approved. | Capture reviewed device/session metadata with privacy rules. |
| Rate limiting/lockout | Deferred | this contract | Do not overclaim; manual/operator incident process covers alpha until a reviewed control exists. | Rate limiting, lockout, abuse telemetry, and alert thresholds. |

## Runbook Alignment

This contract complements `docs/hosted-internal-alpha-runbook.md` and `docs/hosted-internal-alpha-operator-decisions.md`. PR #55 readiness checks validate environment shape and dry-run safety only. They do not prove OIDC, database, backups, rollback, logs, session cookies, cross-host handoff, or actual hosted security behavior.

This PR does not add a session-management UI. It also does not approve hosted deployment. Actual hosted execution still needs operator approval, placeholder-to-real-value review outside this repo, and smoke testing after a reviewed execution window.

Security/session management remains a known future product/admin surface. The contract is now documented so pre-alpha reviewers can separate implemented minimum posture from deferred production controls.

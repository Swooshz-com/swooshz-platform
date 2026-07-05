# Hosted Internal Alpha Runbook

This runbook prepares Swooshz Platform for a reviewed hosted internal-alpha handoff. It is documentation, guardrails, and dry-run readiness tooling only. It does not deploy, provision, expose, sync, restart, or configure hosted infrastructure.

Before using this runbook for a real hosted execution window, review the operator briefing in `docs/hosted-internal-alpha-operator-briefing.md` and the operator decision record in `docs/hosted-internal-alpha-operator-decisions.md`. The briefing summarizes the human go/no-go context; the decision record tracks the required out-of-repo hosting, approval, ownership, handoff, incident, and go/no-go decisions. This runbook does not approve deployment by itself.

Also review the auth/session security contract in `docs/auth-session-security-contract.md`. That contract documents the implemented auth/session posture, the pre-alpha gap inventory, and the deferred security/session-management surfaces. This PR does not approve hosted deployment.

Use placeholders in this repo and in shared notes:

- Platform hosted base URL placeholder: `<hosted-platform-base-url>`.
- KQAG hosted base URL placeholder: `<hosted-kqag-base-url>`.
- Google/OIDC hosted redirect URI placeholder: `<hosted-oidc-redirect-uri>`.

The hosted redirect URI should resolve to the platform callback route, end with `/api/platform/auth/callback`, and avoid query parameters or fragments. Real domains, real staff addresses, database URLs, OAuth values, cookies, tokens, provider identity material, callback URLs with query parameters, and KQAG private app data do not belong in this repository, tickets, screenshots, or shared logs.

## Hosted Scope

Platform owns auth, users, sessions, workspaces, roles, memberships, app entitlements, app launch checks, and audit events.

KQAG owns quote-generation behavior, app-specific profiles, pricing references, generated files, app runtime state, and app dashboard/history. This runbook does not move any KQAG app data responsibility into Platform.

Platform local/internal alpha can proceed only with production-grade security expectations around provider-backed login, server-side sessions, role checks, app entitlements, one-time launch tokens, and privacy-safe audit events. That local/internal posture does not approve hosted execution.

No hosted internal-alpha operator should treat this document as deployment approval. Actual hosted deployment execution still requires reviewed infra/operator approval outside this PR.

SAQG/KQAG production readiness is separate from this Platform repository and is not claimed by this runbook. Hosted KQAG handoff, quote workflow readiness, app runtime data, and generated-artifact behavior need their own reviewed evidence outside this Platform PR.

This PR does not add a session-management UI. Security/session management remains a known future product/admin surface, while the current minimum posture and gaps are documented in `docs/auth-session-security-contract.md`.

## Deployment Plan

1. Choose the reviewed host for `<hosted-platform-base-url>` and the reviewed KQAG host for `<hosted-kqag-base-url>`.
2. Configure a PostgreSQL database service that Platform can reach through `DATABASE_URL`.
3. Configure the OIDC client outside the repo with `<hosted-oidc-redirect-uri>`.
4. Store secrets and runtime env outside the repo in the hosting secret manager or process manager secret store.
5. Build the platform application with `npm run build`.
6. Run `npm run platform:readiness-check` as a dry-run env checklist before migration or server start. Hosted readiness requires `NODE_ENV=production`, HTTPS browser/provider-facing URLs, origin-only allowed origins, and the reviewed callback path shape.
7. Take and verify a database backup before applying reviewed migrations.
8. Apply reviewed migrations manually with `npm run db:migrate` only after setting `DATABASE_MIGRATIONS_CONFIRM=apply-reviewed-migrations`.
9. Start the platform process through the reviewed process manager or container entrypoint that runs `npm run platform:start`.
10. Run the hosted smoke checklist before inviting broader internal-alpha use.

Migrations are never automatic on app startup. `npm run platform:start`, Node bootstrap creation, auth routes, app routes, seed commands, and readiness checks must not run migrations.

## Process Manager And Container Notes

Use a reviewed process manager or container scheduler that can inject environment variables without committing `.env` files. The process should run one explicit command: `npm run platform:start`.

Recommended hosted operator checks:

- Restart policy is explicit and bounded.
- Graceful stop sends a normal termination signal and allows the platform bootstrap to close its server and database pool.
- Build artifacts are produced before process start.
- Runtime env is injected by the host, not baked into source control.
- Logs are collected from stdout/stderr without printing secret values.
- Readiness checks are run as a dry-run command, not as a long-running service.

## TLS And Reverse Proxy Notes

The hosted platform must be served over HTTPS before internal-alpha browser testing. The reverse proxy or load balancer should terminate TLS for `<hosted-platform-base-url>` and forward only the reviewed platform origin.

Operator checks:

- `PLATFORM_PUBLIC_BASE_URL` uses the HTTPS platform placeholder value.
- `PLATFORM_PUBLIC_BASE_URL` does not include query parameters or fragments.
- `PLATFORM_ALLOWED_ORIGINS` contains only the hosted Platform origin, with no path, query, or fragment.
- `PLATFORM_COOKIE_SECURE=true` in production.
- OIDC issuer, authorization, token, JWKS, optional userinfo, and redirect URLs use HTTPS.
- `AUTH_REDIRECT_URI` ends with `/api/platform/auth/callback` and has no query parameters or fragments.
- The proxy preserves the original host/protocol values required by the reviewed hosting setup.
- No wildcard CORS rule is added for KQAG.
- KQAG handoff stays explicit through `PLATFORM_KQAG_LAUNCH_MODE` and `PLATFORM_KQAG_APP_BASE_URL`.

## Migration Procedure

1. Confirm the branch and migration files under review.
2. Confirm no migration was added for this runbook-only PR.
3. If a future reviewed PR adds migrations, review generated SQL before applying it.
4. Take a database backup and confirm restore access before migration execution.
5. Set the migration guard only for the manual migration command:

```powershell
$env:DATABASE_MIGRATIONS_CONFIRM="apply-reviewed-migrations"
npm run db:migrate
```

6. Remove the migration guard from the operator shell after the manual command if it is not needed for the next command.
7. Run `/healthz`, auth, `/app`, `/app/admin`, KQAG entitlement, and audit/activity smoke checks.

Do not add startup hooks, package install hooks, deployment hooks, or background jobs that run migrations automatically.

## Backup And Restore Procedure

Before the first hosted internal-alpha migration or seed operation:

1. Take a provider-approved PostgreSQL backup.
2. Record only the backup id, timestamp, and retention class in operator notes.
3. Perform a restore test into a separate reviewed restore target when the provider process supports it.
4. Confirm who can request backup access and who can approve restore.
5. Confirm backup retention and deletion policy outside the repo.

Do not paste database URLs, connection credentials, table dumps, private staff data, provider identity material, or KQAG private app data into this repo or shared tickets.

## Rollback Procedure

Rollback is an operator decision, not an automatic script in this repo.

Application rollback:

1. Stop new traffic at the hosting layer if needed.
2. Revert the process manager or container image to the last reviewed build.
3. Restart through the same reviewed command path.
4. Run `/healthz`, login, `/app`, `/app/admin`, KQAG entitlement, and audit/activity smoke checks.

Database rollback:

1. Prefer fix-forward for reviewed additive migrations when practical.
2. If restore is required, stop the platform process, restore from the approved backup, and rerun smoke checks before reopening access.
3. Do not run ad hoc destructive SQL from this repo.

KQAG handoff rollback:

1. Set `PLATFORM_KQAG_LAUNCH_MODE=manual` to stop browser handoff while keeping Platform access checks available.
2. Confirm `/app` reports a safe launch failure rather than exposing tokens.
3. Re-enable `server_handoff` only after the KQAG hosted base URL and cross-host session strategy are reviewed. The readiness checker validates the KQAG base URL shape only; cross-host session and cookie behavior remains an operator review and smoke-test item.

## Health Check Procedure

Use `GET /healthz` against `<hosted-platform-base-url>`. A healthy response means the HTTP adapter is reachable; it does not prove OIDC, database migrations, session cookies, admin authorization, KQAG handoff, or audit integrity by itself.

Minimum checks:

- `GET /healthz` returns a successful HTTP response.
- The response does not include secrets, database URLs, cookies, provider material, or KQAG private data.
- Health checks are rate-limited or scoped by the hosting layer if exposed beyond the internal operator network.

## Log Review Procedure

Review logs after migration, startup, login, admin mutations, KQAG handoff, and logout.

Expected log shape:

- Startup summary may include host, port, environment, and auth mode.
- Auth diagnostics should be category-only.
- Admin actions should be visible through audit/activity, not by logging private request details.
- KQAG handoff should not log raw app launch tokens, token hashes, cookies, or browser storage values.
- Database and provider failures should use safe categories, not raw connection or provider details.

Stop and redact the log collection process if a log includes secret values, database connection values, cookies, OAuth values, unredacted provider identity material, real staff addresses, or KQAG private app data.

## Secrets And Env Checklist

| Env var | Purpose | Required | Safe example | Secret | Validation / failure behavior |
| --- | --- | --- | --- | --- | --- |
| `NODE_ENV` | Runtime mode for hosted config. | Required | `production` | No | Hosted readiness requires `production`; development and test fail readiness. |
| `PLATFORM_HTTP_HOST` | Host/interface the reviewed process binds. | Required | `<host-to-bind>` | No | Empty value fails readiness; hosting decides the real bind address. |
| `PLATFORM_HTTP_PORT` | Port the reviewed process binds. | Required | `<port-to-bind>` | No | Must be an integer port; invalid values fail startup/readiness. |
| `PLATFORM_PUBLIC_BASE_URL` | Public HTTPS Platform base URL. | Required | `<hosted-platform-base-url>` | No | Hosted readiness requires HTTPS and no query parameters or fragments. |
| `PLATFORM_ALLOWED_ORIGINS` | Allowed browser origin list for CSRF/origin checks. | Required | `<hosted-platform-base-url>` | No | Hosted readiness requires HTTPS origins only: scheme, host, optional port, and no path, query, or fragment. |
| `PLATFORM_COOKIE_SECURE` | Forces secure browser session cookies. | Required | `true` | No | Production requires `true`; false fails startup/readiness. |
| `DATABASE_URL` | PostgreSQL connection string from the secret store. | Required | `<database-url-from-secret-store>` | Yes | Required for live DB connection and migrations; never printed by readiness. |
| `DATABASE_SSL_MODE` | Optional DB SSL mode override. | Optional | `<require-or-disable-if-needed>` | No | When set, must be `require` or `disable`; invalid value fails readiness/startup. |
| `DATABASE_MIGRATIONS_CONFIRM` | Manual migration confirmation guard. | Required for migrations only | `apply-reviewed-migrations` | No | Required only for `npm run db:migrate`; app startup never requires it. |
| `SESSION_SECRET` | Session signing/encryption secret boundary. | Required | `<strong-random-placeholder>` | Yes | Must be strong and at least 32 characters; short/missing value fails readiness/auth config. |
| `CSRF_TOKEN_HASH_SECRET` | HMAC secret for CSRF token hashes. | Required | `<strong-random-placeholder>` | Yes | Required by runtime secret config; short/missing value fails startup/readiness. |
| `AUTH_STATE_HASH_SECRET` | HMAC secret for OIDC state/nonce references. | Required | `<strong-random-placeholder>` | Yes | Required when auth is enabled; short/missing value fails startup/readiness. |
| `APP_LAUNCH_TOKEN_HASH_SECRET` | HMAC secret for one-time app launch token hashes. | Required | `<strong-random-placeholder>` | Yes | Required for launch issue/consume; short/missing value fails startup/readiness. |
| `PLATFORM_AUTH_PROVIDER_MODE` | Selects explicit auth provider runtime mode. | Required | `generic_oidc` | No | Hosted internal alpha uses `generic_oidc`; other values fail startup/readiness. |
| `AUTH_PROVIDER_KEY` | Stable provider key for linked identities. | Required | `<provider-key>` | No | Must match the auth config parser rules; invalid values fail auth config. |
| `AUTH_ISSUER_URL` | OIDC issuer URL. | Required | `<provider-issuer-url>` | No | Hosted readiness requires HTTPS; called only during explicit auth verification paths. |
| `AUTH_AUTHORIZATION_URL` | OIDC authorization endpoint. | Required | `<provider-authorization-url>` | No | Hosted readiness requires HTTPS; called only during auth start. |
| `AUTH_TOKEN_URL` | OIDC token endpoint. | Required | `<provider-token-url>` | No | Hosted readiness requires HTTPS; called only during auth callback. |
| `AUTH_JWKS_URL` | OIDC JWKS endpoint. | Required | `<provider-jwks-url>` | No | Hosted readiness requires HTTPS; called only during token verification. |
| `AUTH_USERINFO_URL` | Optional OIDC userinfo endpoint. | Optional | `<provider-userinfo-url-if-used>` | No | Hosted readiness requires HTTPS when set; called only after token verification succeeds. |
| `AUTH_CLIENT_ID` | OIDC client id. | Required | `<oidc-client-id-placeholder>` | No | Missing value fails auth config/readiness. |
| `AUTH_CLIENT_SECRET` | OIDC client secret. | Required | `<oidc-client-secret-placeholder>` | Yes | Missing value fails auth config/readiness; never print it. |
| `AUTH_REDIRECT_URI` | Hosted callback URI configured with the provider. | Required | `<hosted-oidc-redirect-uri>` | No | Hosted readiness requires HTTPS, no query parameters or fragments, and a path ending in `/api/platform/auth/callback`. |
| `AUTH_ALLOWED_EMAILS` | Exact allowlist for internal-alpha users. | Required | `<comma-separated-allowlisted-emails>` | No | Preferred for hosted alpha; malformed values fail auth config. Treat as private. |
| `AUTH_ALLOWED_DOMAINS` | Optional reviewed domain allowlist. | Optional | `<comma-separated-allowed-domains-if-approved>` | No | Leave unset unless broad domain allow is reviewed; malformed values fail auth config. |
| `PLATFORM_KQAG_LAUNCH_MODE` | Controls KQAG browser handoff behavior. | Required | `manual` or `server_handoff` | No | Unsupported value fails startup/readiness. Use `manual` until hosted handoff is reviewed. |
| `PLATFORM_KQAG_APP_BASE_URL` | KQAG hosted base URL for browser handoff. | Required when server_handoff | `<hosted-kqag-base-url>` | No | Omit when launch mode is `manual`; when `server_handoff`, hosted readiness requires HTTPS and no query parameters or fragments. |
| `PLATFORM_SEED_CONFIRM` | Explicit first owner/admin bootstrap confirmation. | Required for bootstrap only | `seed-reviewed-internal-access` | No | Required only for `npm run platform:seed-internal-access`; unexpected value fails seed config. |
| `PLATFORM_SEED_USER_EMAIL` | Already-authenticated owner/admin user for bootstrap. | Required for bootstrap only | `<hosted-owner-admin-email-after-login>` | No | Required only for seed; treat as private and do not commit real values. |
| `PLATFORM_SEED_MEMBERSHIP_ROLE` | Bootstrap role for the existing user. | Optional | `owner` | No | When set, must be `owner`, `admin`, or `member`; `viewer` is rejected for KQAG launch. |

## Readiness Check

Run the dry-run checker after env injection and before manual migrations or server start:

```powershell
npm run platform:readiness-check
```

The checker reports only env names, categories, missing/invalid status, and safe guidance. It enforces hosted-only production mode, HTTPS browser/provider-facing URLs, origin-only `PLATFORM_ALLOWED_ORIGINS`, callback URL shape, and KQAG handoff base URL shape. It does not print values, connect to PostgreSQL, run migrations, start the server, call OIDC, call KQAG, read provider endpoints, or seed access.

Passing readiness does not approve deployment. It only confirms the current shell has the required categories and safe URL shapes present for hosted internal-alpha review.

## First Owner/Admin Bootstrap Sequence

Use this sequence after hosted auth and migrations are reviewed:

1. Confirm `AUTH_ALLOWED_EMAILS` contains the placeholder value that will become the first owner/admin address outside repo notes.
2. Start Platform through the reviewed hosted process.
3. The first owner/admin signs in once through Platform so a real provider-backed Platform user exists.
4. Stop if the user has not completed real OIDC login; the seed must not create users, provider identities, sessions, or fake login state.
5. In the operator shell, set `PLATFORM_SEED_CONFIRM=seed-reviewed-internal-access`.
6. Set `PLATFORM_SEED_USER_EMAIL=<hosted-owner-admin-email-after-login>` outside the repo.
7. Set `PLATFORM_SEED_MEMBERSHIP_ROLE=owner` for the first bootstrap unless a separate reviewed owner assignment exists.
8. Run `npm run platform:seed-internal-access`.
9. Confirm `/app` shows the workspace and KQAG app access.
10. Confirm `/app/admin` is reachable only for the owner/admin.

## Add Existing User Sequence

Use this after a teammate signs in once through hosted Platform:

1. Teammate signs in once through OIDC and reaches the platform shell.
2. Owner/admin opens `/app/admin`.
3. Use add-existing-user with the teammate's placeholder address outside repo notes.
4. Use `member` for quote operators unless the teammate needs workspace administration.
5. Confirm the new active membership appears in the team list.
6. Confirm the teammate can reach `/app` after refresh.
7. Confirm member/viewer users are denied admin access to `/app/admin`.
8. Confirm Activity shows the membership add event with safe metadata only.

No invitation email is sent by this fallback. Add-existing-user does not reactivate disabled memberships; owners/admins must use the explicit Reactivate action for disabled non-owner memberships.

## KQAG Entitlement Check

1. Owner/admin opens `/app/admin`.
2. Confirm the KQAG entitlement row is present.
3. Disable the KQAG entitlement in a reviewed smoke workspace.
4. Confirm KQAG launch fails closed and does not create a browser-visible raw token.
5. Re-enable the entitlement.
6. Confirm owner/admin/member launch eligibility is restored.
7. Confirm viewer launch remains denied while KQAG has no read-only mode.

## Audit/Activity Verification

Confirm `/app/admin` Activity shows recent admin events for:

- add-existing-user membership creation.
- role change.
- membership disable.
- membership reactivation.
- KQAG entitlement enable/disable.

Audit/activity verification should show event type, target type/id, actor user id, timestamp, and allowlisted status/category metadata only. It must not display raw provider material, cookies, DB connection values, app launch tokens, or KQAG private app data.

## Smoke Checklist

Run this checklist after hosted startup and before broader internal-alpha use:

1. Confirm server starts without importing/listening side effects by using only `npm run platform:start` as the hosted process command.
2. Call `GET /healthz` on `<hosted-platform-base-url>` and confirm a successful response.
3. Start auth through `/api/platform/auth/start` and confirm auth start/callback shape without printing secrets or callback query details.
4. Complete login and confirm the callback returns to `/app`.
5. Fetch login session context through the platform shell and confirm no provider tokens, cookies, or secrets are rendered.
6. Visit `/app` and confirm the workspace/app access summary is present.
7. Visit `/app/admin` as owner/admin and confirm the admin surface loads.
8. Add existing user by email after teammate signs in once.
9. Change a non-owner member role and confirm last-owner/self-demotion guardrails still fail closed.
10. Run membership disable on a non-owner membership and confirm the disabled user cannot launch KQAG.
11. Run membership reactivation on the disabled non-owner membership and confirm access is restored only according to role, entitlement, and app-status gates.
12. Run KQAG entitlement enable/disable and confirm app access updates.
13. Confirm audit/activity shows admin events for add-user, role-change, membership-disable, membership-reactivation, and entitlement-change actions.
14. Launch KQAG through the browser-safe path and confirm no raw token in browser URL, storage, or logs.
15. Logout through the platform route and confirm the browser session is cleared.
16. Confirm denied member/viewer admin access for `/app/admin` and admin APIs.
17. Confirm missing, expired, or disabled session fail closed behavior for `/app`, `/app/admin`, launch, and logout.
18. Review logs for category-only diagnostics and no secret values.

## What Not To Paste Into Tickets/Screenshots/Logs

Do not paste:

- real staff addresses or private domains.
- database URLs, usernames, passwords, hostnames, backup dumps, or restore output.
- OAuth values, authorization responses, callback URLs with query parameters, token responses, or provider identity material.
- browser cookies, session ids, CSRF values, app launch tokens, token hashes, or storage contents.
- raw request/response headers from auth, admin mutation, or KQAG handoff routes.
- KQAG private app data or generated business outputs.

Use safe categories instead: auth failure category, route name, HTTP status class, event type, target type/id, actor user id, timestamp, and readiness category.

## Remaining Hosted Approval Items

Before actual hosted internal-alpha execution, operators still need reviewed decisions for:

- hosting provider/process manager/container target.
- PostgreSQL provider, backup cadence, restore test, and retention.
- TLS/reverse proxy configuration.
- OIDC client registration outside the repo.
- hosted KQAG handoff and cross-host session/cookie strategy.
- log retention and incident review process.
- first owner/admin identity outside repo notes.
- any infrastructure change approval required by the operator team.

Track these approvals in `docs/hosted-internal-alpha-operator-decisions.md` using placeholders only. Do not deploy until every required decision is approved outside repo.

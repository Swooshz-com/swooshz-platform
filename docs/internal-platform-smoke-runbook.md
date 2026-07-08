# Internal Platform Smoke Runbook

This runbook verifies the current internal Swooshz Platform flow using already-approved platform services and routes. It is an operator checklist, not a product feature, deployment guide, or database provisioning guide.

SQAG-side PR #122 landed at merge commit `6f93180023636306fe10f0d6250ea2df71d486a0` and requires Platform launch and consume payloads to use `appKey=sqag`. Platform PR #79 landed at merge commit `c65bf67078031921f5b4ce73f03455804eb2fd07` and migrated Platform-owned SQAG registry, entitlement, launch/open, consume, seed/bootstrap, docs, tests, and admin surfaces to the canonical app key. Live Platform-to-SQAG smoke remains pending until an operator deliberately runs the hosted/live smoke; this runbook must not be used to claim production readiness before that operator smoke is actually performed.

## Sanitized Local Smoke Evidence

Operator-provided sanitized evidence for the local-only Platform-to-SQAG smoke on 2026-07-08 records:

- Platform local main SHA checked: `58efef2dd2a80e9d9452678f0c397fc55212bdfd`.
- SQAG local main SHA checked: `6f93180023636306fe10f0d6250ea2df71d486a0`.
- `synthetic_gate_passed=true`.
- `local_real_smoke_ran=true`.
- `sqag_launch_success=true`.
- `kqag_rejected=true`.
- `token_header_only=true`.
- `browser_token_exposed=false`.
- `sqag_safe_context_established=true`.
- `hosted_platform_sqag_smoke_passed=false`.
- `production_ready=false`.
- Platform and SQAG local smoke processes were stopped after the run.
- Local smoke ports `127.0.0.1:4317` and `127.0.0.1:8765` were no longer listening after cleanup.
- No repo code changes were made during the smoke.

This evidence is local-only smoke evidence. It does not record hosted smoke evidence, does not approve hosted execution, and does not claim production readiness. Hosted Platform-to-SQAG smoke remains pending.

## Existing Services Assumption

The platform uses an existing Postgres-compatible database service through `DATABASE_URL`. This repo does not create or host its own database service, does not provision a database service, and does not run migrations automatically.

The platform also uses an existing OIDC provider through the existing auth environment contract. The repo does not add a fake login, provider SDK, provider-owned account model, or provider provisioning flow.

Migrations must be reviewed and run explicitly with the existing `npm run db:migrate` flow. The migration command has an operator confirmation guard: `DATABASE_MIGRATIONS_CONFIRM=apply-reviewed-migrations`.

The internal access seed CLI writes records into the already-configured platform database. It requires an already-authenticated platform user and provider identity, then seeds only platform-owned workspace, app registry, entitlement, and membership records.

## Smoke Sequence

### A. Build

Run the DB-free local validation first:

```powershell
npm run build
npm run typecheck
npm test
npm run platform:sqag-smoke-readiness
```

The synthetic SQAG smoke readiness command runs deterministic launch/open,
consume, seed/bootstrap, contract-doc, and app-key migration tests without real
OAuth, hosted database, hosted SQAG, Coolify, Hostinger, or secrets. Its output
is sanitized booleans, counts, status, and blocker identifiers only. Passing it
does not claim the live Platform-to-SQAG smoke or production readiness.

### B. Configure Env

Use placeholders only in local notes and shared docs. Do not paste real secrets, database credentials, staff emails, provider tokens, auth codes, provider subjects, callback payloads, or production domains.

Use `127.0.0.1` consistently for local browser UAT examples and operator notes. Do not mix alternate loopback hostnames with `127.0.0.1` in the same local session, because browser cookies and same-host SQAG handoff checks are host-sensitive.

Database:

```text
DATABASE_URL=<database-url-from-existing-service>
DATABASE_SSL_MODE=<ssl-mode-if-needed>
```

Platform HTTP runtime:

```text
NODE_ENV=<runtime-environment>
PLATFORM_HTTP_HOST=<host-to-bind>
PLATFORM_HTTP_PORT=<port-to-bind>
PLATFORM_PUBLIC_BASE_URL=<platform-base-url>
PLATFORM_ALLOWED_ORIGINS=<comma-separated-platform-origins>
PLATFORM_COOKIE_SECURE=<true-or-false-for-this-environment>
```

Platform secrets:

```text
SESSION_SECRET=<strong-random-placeholder>
CSRF_TOKEN_HASH_SECRET=<strong-random-placeholder>
APP_LAUNCH_TOKEN_HASH_SECRET=<strong-random-placeholder>
AUTH_STATE_HASH_SECRET=<strong-random-placeholder>
```

OIDC auth:

```text
AUTH_PROVIDER_KEY=<provider-key>
AUTH_ISSUER_URL=<provider-issuer-url>
AUTH_AUTHORIZATION_URL=<provider-authorization-url>
AUTH_TOKEN_URL=<provider-token-url>
AUTH_USERINFO_URL=<provider-userinfo-url-if-used>
AUTH_JWKS_URL=<provider-jwks-url>
AUTH_CLIENT_ID=<provider-client-id>
AUTH_CLIENT_SECRET=<provider-client-secret-placeholder>
AUTH_REDIRECT_URI=<platform-auth-callback-url>
AUTH_ALLOWED_EMAILS=<optional-comma-separated-allowed-emails>
AUTH_ALLOWED_DOMAINS=<optional-comma-separated-allowed-domains>
```

Generic OIDC runtime mode, if used:

```text
PLATFORM_AUTH_PROVIDER_MODE=generic_oidc
AUTH_ISSUER_URL=<provider-issuer-url>
AUTH_JWKS_URL=<provider-jwks-url>
```

Internal seed:

```text
PLATFORM_SEED_CONFIRM=seed-reviewed-internal-access
PLATFORM_SEED_USER_EMAIL=<email-used-for-login>
PLATFORM_SEED_WORKSPACE_SLUG=<optional-workspace-slug>
PLATFORM_SEED_WORKSPACE_NAME=<optional-workspace-name>
PLATFORM_SEED_MEMBERSHIP_ROLE=<optional-owner-admin-or-member>
PLATFORM_SEED_APP_LAUNCH_URL=<optional-app-launch-url>
```

The seed always targets the canonical SQAG app identity: app key `sqag`, app
name `SQAG`. `PLATFORM_SEED_APP_KEY` and `PLATFORM_SEED_APP_NAME` are not
supported bootstrap inputs; setting either one fails closed before any database
connection.

SQAG browser launch handoff, for same-host local UAT only:

```text
PLATFORM_SQAG_LAUNCH_MODE=server_handoff
PLATFORM_SQAG_APP_BASE_URL=<sqag-local-base-url>
```

Leave `PLATFORM_SQAG_LAUNCH_MODE` unset or set it to `manual` to keep the
safe default: the Platform shell will not complete a browser handoff to SQAG.
`server_handoff` is intended for local UAT where Platform and SQAG are visited
through the same browser cookie host, for example the same `127.0.0.1` host on
different ports. If the configured SQAG URL uses a different host from the
Platform request host, the handoff fails closed instead of forwarding cookies
across an unsafe boundary.

### C. Apply Reviewed Migrations

Review generated migration SQL before applying it. Then run the existing explicit migration command against the already-configured database:

```powershell
$env:DATABASE_MIGRATIONS_CONFIRM="apply-reviewed-migrations"
npm run db:migrate
```

This command should be run deliberately by an operator. It is not called by bootstrap, server creation, auth routes, the browser shell, or the seed CLI.

### D. Start Platform Server

Start the existing Node runtime through the explicit operator CLI:

```powershell
npm run platform:start
```

The start CLI calls the existing Node bootstrap/runtime boundary and then listens on the configured host and port. It uses the already-configured database service through the existing DB boundary, but it does not run migrations, does not provision a database service, does not seed access, does not create users or platform records by itself, does not issue or consume app launch tokens on startup, and does not call SQAG.

When `PLATFORM_AUTH_PROVIDER_MODE=generic_oidc` is configured, the CLI injects the generic OIDC HTTP client boundary required by runtime composition. It does not call provider token, JWKS, or userinfo endpoints during startup; provider HTTP happens only when an auth route is deliberately invoked.

When `PLATFORM_SQAG_LAUNCH_MODE=server_handoff` is configured, the CLI injects
the SQAG server-side HTTP boundary required by the browser launch route. It does not call SQAG during startup; SQAG HTTP happens only when an authenticated
browser deliberately opens SQAG from `/app`.

### E. Login Once

1. Visit `/`.
2. Click the sign-in link for `/api/platform/auth/start`.
3. Complete the configured OIDC flow.
4. Confirm the callback redirects to `/app`.

At this point the user should exist with a provider identity and platform session, but may not yet have workspace or app access.

### F. Seed Access

Run the seed command for the email address that just completed real OIDC login:

```powershell
$env:PLATFORM_SEED_CONFIRM="seed-reviewed-internal-access"
$env:PLATFORM_SEED_USER_EMAIL="<email-used-for-login>"
npm run platform:seed-internal-access
```

Optional workspace overrides use the `PLATFORM_SEED_WORKSPACE_*` env names
listed above. `PLATFORM_SEED_APP_LAUNCH_URL` may set a launch URL, but the app
key and app name are fixed to canonical SQAG.

The seed requires the user already exists and has a provider identity. It does not create users, provider identities, or sessions. It seeds workspace, app registry, entitlement, and membership records only.

### G. Verify `/app`

1. Refresh `/app`.
2. Confirm the workspace appears.
3. Confirm the SQAG app appears.
4. Confirm the launch button appears only when access is allowed.
5. Click the SQAG launch button.
6. Confirm the browser reaches `<sqag-local-base-url>/` without any launch
   token in the URL.
7. Confirm the SQAG session loads under the Platform workspace context.

The browser launch route creates the Platform launch token server-side, forwards
it to SQAG only in the `x-app-launch-token` header, copies SQAG's session cookie
back to the same browser cookie host, and returns only the safe SQAG launch URL.
The raw launch token must never appear in URL query parameters, URL fragments,
browser local/session storage, cookies, logs, screenshots, docs, telemetry, or
test snapshots.

### H. Verify `/app/admin` Add Existing User

Use this internal-alpha fallback only for a teammate who has completed real OIDC login at least once. That means the teammate is already an existing active provider-backed Platform user. The admin UI does not create provider accounts, does not create provider identities, and no invitation email is sent.

1. Have the teammate sign in once through `/` and confirm they reach `/app`.
2. As an owner/admin, open `/app/admin`.
3. Use the Add Existing User form with the placeholder email value the teammate used for login.
4. For this check, set role to `member` for quote operators unless the teammate should administer the workspace.
5. Submit the form and confirm the member appears in the team list with active membership status.
6. Change a non-owner member role when appropriate, disable a non-owner membership when appropriate, reactivate a disabled non-owner membership when appropriate, and enable or disable the SQAG entitlement only for this local smoke workspace.
7. Confirm the Activity section shows recent add-user, role-change, membership-disable, membership-reactivation, and entitlement-change audit events with event type, target type/id, actor user id, created timestamp, and safe metadata only.
8. If the form shows a generic failure, confirm the teammate completed real OIDC login, has an active provider-backed Platform user, is not already a workspace member, and that the browser request has a fresh CSRF token.

Activity browsing is a minimal internal-alpha check only. Export, filtering, and retention workflows remain future scope.

Do not paste real staff emails, private provider identity values, provider payloads, invitation secrets, cookies, or callback URLs with query params into local notes or shared screenshots.

### I. Optional Consume API Check

Use the lower-level consume route only when debugging the Platform consume
contract directly. A one-time token belongs only in the header accepted by the
app-side consume route:

```powershell
Invoke-RestMethod -Method Post `
  -Uri "<platform-base-url>/api/platform/apps/launch/consume?appKey=<app-key>" `
  -Headers @{ "x-app-launch-token" = "<launch-token-from-immediate-handoff>" }
```

The raw token belongs in `x-app-launch-token`, not in the query string. It is one-time, short-lived, and should not be stored.

For SQAG-side storage and generated XLSX artifact validation, see the SQAG
runbook `docs/platform-uat-smoke-runbook.md`.

## Troubleshooting

- `DATABASE_URL is required`: configure `DATABASE_URL` from the existing database service before live DB operations.
- `missing migrations` or missing table errors: review migration files and run the explicit `npm run db:migrate` command with `DATABASE_MIGRATIONS_CONFIRM=apply-reviewed-migrations`.
- `auth config invalid`: check required OIDC env names, callback URL alignment, and strong platform secrets. Do not paste raw secret values into tickets or docs.
- auth start failure: copy only the safe console diagnostic line `auth_start_failure category=<category>` into troubleshooting notes; do not copy surrounding URLs, cookies, provider payloads, state, nonce, auth codes, secrets, database URLs, or staff emails.
- `callback state/nonce failures`: retry the login flow from `/`; stale browser callbacks, mismatched auth state storage, or nonce mismatch can fail safely.
- no session in `/app`: confirm the callback completed, the platform session cookie was set by the auth callback route, and the browser is visiting the same platform origin.
- `user not found`: the seed command was run before the user completed real OIDC login.
- `missing provider identity`: the seed command found a platform user without a linked provider identity; rerun real login or inspect the auth callback path before seeding.
- `/app` shows no workspace: run the internal access seed for the provider-backed user and refresh `/app`.
- `launch denied`: verify the workspace entitlement, membership role, app key, and session are active.
- `CSRF/origin failure`: fetch a fresh CSRF token through the browser shell and confirm the request origin matches configured allowed origins.
- `consumed/expired launch token`: create a new launch intent; launch tokens are one-time and short-lived.
- `SQAG browser launch is not configured`: set `PLATFORM_SQAG_LAUNCH_MODE=server_handoff` and `PLATFORM_SQAG_APP_BASE_URL=<sqag-local-base-url>`, and confirm Platform and SQAG use the same browser cookie host.
- `SQAG browser launch could not be completed`: confirm SQAG is running in `SQAG_PLATFORM_LAUNCH_MODE=platform`, accepts `POST /api/platform/launch`, and can consume Platform launch tokens through the header-only contract.

## Out Of Scope

This runbook covers the internal smoke path only.

- no fake login
- no SQAG-owned auth
- no broad app proxy or open proxy
- no database provisioning
- no automatic migration execution
- does not deploy and adds no deployment script
- no server auto-start on import or bootstrap creation
- no provider SDK
- no billing or credits work
- no real secrets, provider responses, provider subjects, staff emails, private domains, or database credentials

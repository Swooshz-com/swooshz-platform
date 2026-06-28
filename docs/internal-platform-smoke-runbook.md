# Internal Platform Smoke Runbook

This runbook verifies the current internal Swooshz Platform flow using already-approved platform services and routes. It is an operator checklist, not a product feature, deployment guide, or database provisioning guide.

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
```

### B. Configure Env

Use placeholders only in local notes and shared docs. Do not paste real secrets, database credentials, staff emails, provider tokens, auth codes, provider subjects, callback payloads, or production domains.

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
PLATFORM_SEED_APP_KEY=<optional-app-key>
PLATFORM_SEED_APP_NAME=<optional-app-name>
PLATFORM_SEED_MEMBERSHIP_ROLE=<optional-owner-admin-or-member>
PLATFORM_SEED_APP_LAUNCH_URL=<optional-app-launch-url>
```

### C. Apply Reviewed Migrations

Review generated migration SQL before applying it. Then run the existing explicit migration command against the already-configured database:

```powershell
$env:DATABASE_MIGRATIONS_CONFIRM="apply-reviewed-migrations"
npm run db:migrate
```

This command should be run deliberately by an operator. It is not called by bootstrap, server creation, auth routes, the browser shell, or the seed CLI.

### D. Start Platform Server

There is not yet a committed runnable start CLI in `package.json` or `scripts/`. The existing Node runtime exposes the bootstrap contract and explicit `start()` lifecycle for callers and tests, but this repo does not yet ship a safe operator command for starting it.

For an internal smoke run, use the approved local harness or operator wrapper that calls the existing Node bootstrap. The next PR should add a narrow start script if the team wants a committed operator command. Do not invent an undocumented start command for this runbook.

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

Optional workspace and app overrides use the `PLATFORM_SEED_WORKSPACE_*` and `PLATFORM_SEED_APP_*` env names listed above.

The seed requires the user already exists and has a provider identity. It does not create users, provider identities, or sessions. It seeds workspace, app registry, entitlement, and membership records only.

### G. Verify `/app`

1. Refresh `/app`.
2. Confirm the workspace appears.
3. Confirm the KQAG/SAQG app appears.
4. Confirm the launch button appears only when access is allowed.
5. Create a launch intent for the accessible app.
6. Confirm the launch token appears only in the temporary handoff area.

The launch token is shown only once as an internal handoff. Do not store it in browser storage, paste it into logs, or put it in a URL.

### H. Optional Consume API Check

Use the one-time token only through the header accepted by the app-side consume route:

```powershell
Invoke-RestMethod -Method Post `
  -Uri "<platform-base-url>/api/platform/apps/launch/consume?appKey=<app-key>" `
  -Headers @{ "x-app-launch-token" = "<launch-token-from-immediate-handoff>" }
```

The raw token belongs in `x-app-launch-token`, not in the query string. It is one-time, short-lived, and should not be stored.

## Troubleshooting

- `DATABASE_URL is required`: configure `DATABASE_URL` from the existing database service before live DB operations.
- `missing migrations` or missing table errors: review migration files and run the explicit `npm run db:migrate` command with `DATABASE_MIGRATIONS_CONFIRM=apply-reviewed-migrations`.
- `auth config invalid`: check required OIDC env names, callback URL alignment, and strong platform secrets. Do not paste raw secret values into tickets or docs.
- `callback state/nonce failures`: retry the login flow from `/`; stale browser callbacks, mismatched auth state storage, or nonce mismatch can fail safely.
- no session in `/app`: confirm the callback completed, the platform session cookie was set by the auth callback route, and the browser is visiting the same platform origin.
- `user not found`: the seed command was run before the user completed real OIDC login.
- `missing provider identity`: the seed command found a platform user without a linked provider identity; rerun real login or inspect the auth callback path before seeding.
- `/app` shows no workspace: run the internal access seed for the provider-backed user and refresh `/app`.
- `launch denied`: verify the workspace entitlement, membership role, app key, and session are active.
- `CSRF/origin failure`: fetch a fresh CSRF token through the browser shell and confirm the request origin matches configured allowed origins.
- `consumed/expired launch token`: create a new launch intent; launch tokens are one-time and short-lived.

## Out Of Scope

This runbook adds no product feature and no runtime behavior. It documents the existing smoke path only.

- no fake login
- no KQAG integration
- no app redirect integration into KQAG
- no database provisioning
- no automatic migration execution
- does not deploy and adds no deployment script
- no committed server auto-start command
- no provider SDK
- no billing or credits work
- no real secrets, provider responses, provider subjects, staff emails, private domains, or database credentials

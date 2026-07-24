# Hosted Internal Alpha Runbook

This runbook prepares Swooshz Platform for a reviewed hosted internal-alpha handoff. It is documentation, guardrails, and readiness tooling only. It does not deploy, provision, expose, sync, restart, or configure hosted infrastructure. This PR is readiness only, not full production readiness.

SQAG-side PR #122 and Platform PR #79 established the historical `appKey=sqag` baseline only. Before hosted execution, record and jointly review the exact companion Platform and SQAG revisions that implement header-only finalization, host-only SQAG cookies, and live Platform access validation. Hosted Platform-to-SQAG smoke remains pending until an operator runs the smoke deliberately; do not claim production readiness from this documentation alone.

Before using this runbook for a real hosted execution window, review the operator briefing in `docs/hosted-internal-alpha-operator-briefing.md` and the operator decision record in `docs/hosted-internal-alpha-operator-decisions.md`. The briefing summarizes the human go/no-go context; the decision record tracks the required out-of-repo hosting, approval, ownership, handoff, incident, and go/no-go decisions. This runbook does not approve deployment by itself.

Also review the auth/session security contract in `docs/auth-session-security-contract.md`. That contract documents the implemented auth/session posture, the pre-alpha gap inventory, and the deferred security/session-management surfaces. This PR does not approve hosted deployment.

Use the canonical public routing contract in this repo and shared notes:

- Platform canonical origin: `https://swooshz.com`.
- Platform redirect-only origin: `https://www.swooshz.com`.
- SQAG canonical origin: `https://quote.swooshz.com`.
- Google/OIDC redirect URI: `https://swooshz.com/api/platform/auth/callback`.

The hosted redirect URI should resolve to the platform callback route, end with `/api/platform/auth/callback`, and avoid query parameters or fragments. Real configured domains, real staff addresses, database URLs, OAuth values, cookies, tokens, provider identity material, callback URLs with query parameters, and SQAG private app data do not belong in this repository, tickets, screenshots, or shared logs.

## Hosted Scope

Platform owns auth, users, sessions, workspaces, roles, memberships, app entitlements, app launch checks, and audit events.

SQAG owns quote-generation behavior, app-specific profiles, pricing references, generated files, app runtime state, and app dashboard/history. This runbook does not move any SQAG app data responsibility into Platform.

Platform local/internal alpha can proceed only with production-grade security expectations around provider-backed login, server-side sessions, role checks, app entitlements, one-time launch tokens, and privacy-safe audit events. That local/internal posture does not approve hosted execution.

No hosted internal-alpha operator should treat this document as deployment approval. Actual hosted deployment execution still requires reviewed infra/operator approval outside this PR.

SQAG production readiness is separate from this Platform repository and is not claimed by this runbook. Hosted SQAG handoff, quote workflow readiness, app runtime data, and generated-artifact behavior need their own reviewed evidence outside this Platform PR.

This PR does not add a session-management UI. Security/session management remains a known future product/admin surface, while the current minimum posture and gaps are documented in `docs/auth-session-security-contract.md`.

## Deployment Plan

1. Configure the reviewed Platform route for `https://swooshz.com`, the redirect-only `https://www.swooshz.com` route, and the SQAG route for `https://quote.swooshz.com`.
2. Configure the reviewed Neon PostgreSQL database service outside the repo, using the non-secret target in the Neon Hosted Postgres Readiness section.
3. Configure the OIDC client outside the repo with `https://swooshz.com/api/platform/auth/callback`.
4. Store secrets and runtime env outside the repo in the hosting secret manager or process manager secret store.
5. Build the platform application with `npm run build`.
6. Run `npm run platform:readiness-check` as a dry-run env checklist before migration or server start. Hosted readiness requires `NODE_ENV=production`, HTTPS browser/provider-facing URLs, origin-only allowed origins, the reviewed callback path shape, a valid Postgres-shaped `DATABASE_URL`, and a safe `DATABASE_EXPECTED_RUNTIME_ROLE`; it does not connect to the database.
7. Optionally run `npm run platform:db-readiness-check` before migrations to verify that the configured database is reachable. A new or unmigrated database should report `schema_not_ready`, not `ready`.
8. Take and verify a database backup before applying reviewed migrations.
9. Apply reviewed migrations manually with `npm run db:migrate` only after setting `DATABASE_MIGRATIONS_CONFIRM=apply-reviewed-migrations`.
10. Run `npm run platform:db-readiness-check` after migrations and require `ready` before hosted server start.
11. Start the platform process through the reviewed process manager or container entrypoint that runs `npm run platform:start`.
12. Run the hosted smoke checklist before inviting broader internal-alpha use.

Migrations are never automatic on app startup. `npm run platform:start`, Node bootstrap creation, auth routes, app routes, seed commands, and readiness checks must not run migrations.

## Process Manager And Container Notes

Use a reviewed process manager or container scheduler that can inject environment variables without committing `.env` files. The process should run one explicit command: `npm run platform:start`.

Recommended hosted operator checks:

- Restart policy is explicit and bounded.
- Graceful stop sends a normal termination signal and allows the platform bootstrap to close its server and database pool.
- Build artifacts are produced before process start.
- Runtime env is injected by the host, not baked into source control.
- Logs are collected from stdout/stderr without printing secret values.
- Env readiness is run as a dry-run command, and DB readiness is run as a one-off operator check. Neither runs as a long-running service.

## Hostinger VPS And Coolify Deployment Readiness

This section is a deployment-readiness checklist for a future Hostinger VPS plus Coolify execution window. It does not buy or create VPS resources, configure DNS, deploy the app, configure OAuth, run migrations, seed access, or approve hosted production readiness.

Use the exact public origins; keep private configuration values as placeholders only:

- Canonical Platform origin: `https://swooshz.com`. `https://www.swooshz.com` is redirect-only and must issue a path plus safe-query preserving permanent 308 to the apex. It must never serve UI, auth callbacks, session cookies, OAuth entry, or third-party redirects.
- SQAG canonical origin: `https://quote.swooshz.com`.
- OIDC callback: `https://swooshz.com/api/platform/auth/callback`.

Coolify app/service shape:

- Create one Node app/service for Swooshz Platform from the reviewed repo branch or release reference.
- Do not create a Coolify-managed database for Platform runtime; the runtime database is the already migrated Neon target, injected through pooled `DATABASE_URL`.
- Build command: `npm run build`.
- Start command: `npm run platform:start`.
- Health check path: `/healthz`.
- Do not add Coolify build hooks, deploy hooks, startup hooks, cron jobs, or sidecars that run `npm run db:migrate`, `npm run platform:seed-internal-access`, or product workflow commands.
- Keep SQAG runtime hosting and product workflow data outside this Platform service.

Deploy-time env categories:

| Category | Env names | Coolify handling | Notes |
| --- | --- | --- | --- |
| Non-secret operator choices | `NODE_ENV`, `PLATFORM_HTTP_HOST`, `PLATFORM_HTTP_PORT`, `PLATFORM_PUBLIC_BASE_URL`, `PLATFORM_ALLOWED_ORIGINS`, `PLATFORM_COOKIE_SECURE`, `DATABASE_SSL_MODE`, `DATABASE_EXPECTED_RUNTIME_ROLE`, `PLATFORM_AUTH_PROVIDER_MODE`, `AUTH_PROVIDER_KEY`, `AUTH_ISSUER_URL`, `AUTH_AUTHORIZATION_URL`, `AUTH_TOKEN_URL`, `AUTH_JWKS_URL`, `AUTH_USERINFO_URL`, `AUTH_CLIENT_ID`, `AUTH_REDIRECT_URI`, `AUTH_ALLOWED_DOMAINS`, `PLATFORM_SQAG_LAUNCH_MODE`, `PLATFORM_SQAG_APP_BASE_URL` | Set as reviewed environment entries. | Hosted runtime uses `NODE_ENV=production`, the exact canonical origins, HTTPS provider URLs, `PLATFORM_COOKIE_SECURE=true`, and `server_handoff` for the implemented separate-origin SQAG flow. |
| Secret values | `DATABASE_URL`, `SESSION_SECRET`, `CSRF_TOKEN_HASH_SECRET`, `AUTH_STATE_HASH_SECRET`, `APP_LAUNCH_TOKEN_HASH_SECRET`, `PLATFORM_SQAG_SERVICE_SECRET`, `AUTH_CLIENT_SECRET` | Inject through Coolify secret/env storage only. | Platform and SQAG receive the same service secret through their separate secret stores. Do not commit, print, screenshot, paste, or expose values in build logs, app logs, tickets, shell history, or PRs. |
| Private allowlist values | `AUTH_ALLOWED_EMAILS` | Treat as private operational data, even though it is not a credential. | Keep real staff addresses outside the repo; use placeholders in docs and tickets. |
| Operator-only database values | `DATABASE_OPERATOR_URL`, `DATABASE_MIGRATIONS_CONFIRM` | Do not keep on the long-running Coolify app service. Set only in a separately controlled operator process for readiness or a reviewed migration. | The migrated Neon database should already return `ready` from `npm run platform:db-readiness-check` before app start. |
| Bootstrap-only values | `PLATFORM_SEED_CONFIRM`, `PLATFORM_SEED_USER_EMAIL`, `PLATFORM_SEED_WORKSPACE_SLUG`, `PLATFORM_SEED_WORKSPACE_NAME`, `PLATFORM_SEED_MEMBERSHIP_ROLE` | Do not keep on the long-running Coolify app service. Set only for a reviewed one-off bootstrap after real hosted auth creates the user. | These values must not become env-controlled business/admin state, default production data, or a fake login path. |
| Product handoff configuration | `PLATFORM_SQAG_LAUNCH_MODE`, `PLATFORM_SQAG_APP_BASE_URL`, `PLATFORM_SQAG_SERVICE_SECRET` | Use `server_handoff`, exact `https://quote.swooshz.com`, and a shared secret injected separately into both services. | Platform stores launch checks/tokens and entitlements only; product workflow/runtime data remains outside Platform. |

Coolify readiness sequence:

1. Confirm the repo branch or release reference includes the reviewed Neon migration evidence and this runbook.
2. Configure Coolify env/secret entries using placeholders and secret injection only; do not commit `.env` files.
3. Run `npm run platform:readiness-check` as a one-off preflight in the same env shape the app will use.
4. Run `npm run platform:db-readiness-check` against the already migrated Neon database and require sanitized status `ready`.
5. Confirm no migration command is configured in build, start, deploy, restart, health check, or scheduled jobs.
6. Start the service with `npm run platform:start` only after readiness and operator decisions pass.

Reverse proxy and TLS expectations:

- Hostinger/Coolify must terminate TLS for the reviewed hosted Platform origin before browser testing.
- `PLATFORM_PUBLIC_BASE_URL`, `PLATFORM_ALLOWED_ORIGINS`, provider URLs, hosted redirect URI, and SQAG handoff URL when used must be HTTPS in production.
- Allowed origins must be explicit origins, not wildcard values and not URLs with path, query, or fragment.
- Session cookies must be secure in production through `PLATFORM_COOKIE_SECURE=true`.
- Database, provider, Coolify admin, VPS admin, and backup interfaces must not be exposed as public Platform routes.

Hosted smoke checklist after deployment:

1. Confirm Coolify health check reaches `GET /healthz` without rendering secrets.
2. Confirm startup logs show only safe summary fields and category-only diagnostics.
3. Confirm `npm run platform:db-readiness-check` still reports sanitized status `ready` from an operator shell when live DB recheck is intentionally run.
4. Confirm auth start/callback shape only after hosted OAuth is configured outside this PR.
5. Confirm `/app`, `/app/admin`, session logout, admin denial, entitlement denial, and audit/activity checks follow the Smoke Checklist below.
6. Verify the `server_handoff` finalization and live-validation flow with host-only cookies; do not broaden either cookie to `.swooshz.com`.

Rollback and fix-forward notes:

- Prefer redeploying the previous reviewed app build for application rollback.
- Prefer fix-forward for reviewed additive database migrations when practical.
- Use database restore only after backup/restore owner approval and restore-target evidence are available outside this repo.
- If SQAG handoff fails, switch back to `PLATFORM_SQAG_LAUNCH_MODE=manual` and keep Platform access checks available without exposing launch tokens.
- Do not troubleshoot by pasting secrets, database hostnames with credentials, cookies, OAuth callback query values, provider console screenshots, backup exports, or table data into tickets or PRs.

## TLS And Reverse Proxy Notes

The hosted platform must be served over HTTPS before internal-alpha browser testing. The reverse proxy or load balancer should terminate TLS for `https://swooshz.com`, route only that host to Platform, and give `www.swooshz.com` only the redirect handler.

Operator checks:

- `PLATFORM_PUBLIC_BASE_URL` is exactly `https://swooshz.com`.
- `PLATFORM_PUBLIC_BASE_URL` does not include query parameters or fragments.
- `PLATFORM_ALLOWED_ORIGINS` contains only the hosted Platform origin, with no path, query, or fragment.
- `PLATFORM_COOKIE_SECURE=true` in production.
- OIDC issuer, authorization, token, JWKS, optional userinfo, and redirect URLs use HTTPS.
- `AUTH_REDIRECT_URI` ends with `/api/platform/auth/callback` and has no query parameters or fragments.
- The proxy preserves the original host/protocol values required by the reviewed hosting setup.
- No wildcard CORS rule is added for SQAG.
- SQAG handoff stays explicit through `PLATFORM_SQAG_LAUNCH_MODE` and `PLATFORM_SQAG_APP_BASE_URL`.

## Neon Hosted Postgres Readiness

Recommended Neon target, for operator setup outside this repo:

- Project: `swooshz-platform`.
- Region: `Singapore / aws-ap-southeast-1`.
- Database: `swooshz_platform`.
- Owner/migration role: `platform_app`.
- Runtime role: the separately approved restricted role named by `DATABASE_EXPECTED_RUNTIME_ROLE`.
- Runtime connection: pooled restricted-role `DATABASE_URL` from the host secret store.
- Operator connection: separately controlled `DATABASE_OPERATOR_URL`; never keep it on the long-running Coolify application.
- Use an unpooled/direct owner connection for `DATABASE_OPERATOR_URL` when required by reviewed migration tooling; keep it outside source control and the long-running application.

The platform runtime app code uses only `DATABASE_URL` as the pooled restricted-role app connection and validates it against `DATABASE_EXPECTED_RUNTIME_ROLE` before listening. Migration and operator readiness commands use `DATABASE_OPERATOR_URL` in production. Do not add multiple database URL aliases for day-to-day runtime behavior. Do not commit `.env` files, connection strings, usernames with passwords, database hostnames with credentials, backup exports, table dumps, or provider console screenshots.

The pre-listen runtime-posture gate begins from the exact PostgreSQL `session_user` catalog identity and recursively follows only PostgreSQL 17 membership edges with `pg_auth_members.set_option = true`. Recursive `UNION` de-duplicates catalog OIDs and terminates cycles. The gate evaluates the login role and every role it can assume through `SET ROLE`, including through `NOINHERIT` memberships, for the same prohibited administrative attributes, Neon membership, database/schema/ledger privileges, and ownership conditions. A `SET FALSE` edge blocks traversal, but `ADMIN OPTION` on any membership reachable from the login or an already assumable role is itself rejected because it could be used to re-grant `SET TRUE`. Missing or inconclusive catalog evidence fails closed through the existing aggregate `database_posture_failed` behavior without exposing role or ACL details.

### Restricted Runtime Role Activation Contract

Runtime-role activation is a separately authorised operator operation. This
runbook does not authorise activation, password creation, provider changes, or
deployment. A future activation wrapper must use the secret-safe primitives in
`scripts/platform-runtime-activation-contract.mjs` rather than copying the
former ad hoc PowerShell pipeline.

The activation journal has exactly these ordered phases:

1. `dormant_role_preflight`
2. `password_installation`
3. `login_enablement`
4. `runtime_connection_construction`
5. `runtime_connection_establishment`
6. `runtime_identity`
7. `recursive_set_role_posture`
8. `grants_and_ownership_verification`
9. `success_finalisation`
10. `mandatory_rollback`

Only phase names and `pending`, `in_progress`, `passed`, `failed`, or
`not_required` may appear in operator evidence. Preserve the first failed
phase before starting rollback. Rollback reporting must never overwrite that
phase. Passwords, hashes, URLs, hosts embedded in secret URLs, role catalog
details, ACLs, OIDs, and driver output remain excluded.

For hidden `psql \password` input, do not merge native stderr into a Windows
PowerShell 5.1 pipeline while `$ErrorActionPreference = "Stop"`. `psql` writes
its hidden prompt to stderr; treating that prompt as a terminating PowerShell
error aborts a valid password-installation phase. Windows PowerShell 5.1 also
uses US-ASCII for native pipeline input by default, which can silently corrupt
a non-ASCII password. The reviewed Node helper avoids both defects by:

- spawning the official `postgres:17` Docker client directly;
- passing the operator URL to the child by environment name, never an argument;
- writing the `\password` exchange as explicit UTF-8 bytes on stdin;
- ignoring prompt stdout/stderr and deciding success only from the child exit;
- using a unique Docker container name for each password operation;
- on timeout, requesting termination, waiting through a bounded grace period,
  escalating with forced container removal when necessary, and waiting for
  both confirmed container removal and child close before returning;
- leaving the operation unsettled and blocking database rollback if
  termination remains inconclusive;
- clearing the password input buffer only after confirmed child termination;
  and
- returning only `runtime_activation_failed` on failure.

The activation wrapper must keep immutable target identity separate from
renewable provider attestation.

The immutable target is created once with `createRuntimeActivationTarget`. Its
canonical identity contains provider `neon`, exact project ID, exact branch ID,
expected database, approved compute endpoint IDs, direct or pooled connection
variants, provider-observed hosts, effective PostgreSQL ports, endpoint
`read_write` capability, and enabled/available state. Observation and expiry
timestamps are not part of this identity. The target also binds the exact
runtime role and the direct/operator and Docker/psql paths. Password
installation, LOGIN enablement, runtime URL construction, runtime identity
validation, success finalisation, rollback, and dormant-baseline verification
must retain that same opaque target object.

Each provider observation is reduced separately with
`createNeonProviderAttestation`. During a separately authorised activation
window, the operator must perform official read-only Neon API observations:

- retrieve each approved compute endpoint with
  `GET /api/v2/projects/{project_id}/endpoints/{endpoint_id}`;
- retain only endpoint `id`, `project_id`, `branch_id`, `host`, `type`,
  `current_state`, and `disabled`;
- verify the expected database through the official branch database listing;
  and
- attach only the reviewed direct/pooled variant and effective PostgreSQL port
  used by the corresponding operator path.

The reducer accepts only its strict reviewed shape. Do not pass a raw API response object.
Raw response bodies, bearer tokens, API credentials,
connection strings, usernames, endpoint credentials, and passwords must never
enter the attestation, arguments, logs, safe reports, or public errors.
Provider IDs and timestamps are non-secret metadata only when deliberately
classified as such. Missing, malformed, future-dated, expired, overlong,
duplicate, conflicting, disabled, unavailable, read-only, or inconclusive
evidence fails closed.

The planning attestation may create the immutable target, but it cannot
authorise a later mutation phase. Immediately before password installation,
LOGIN enablement, success finalisation, and rollback, obtain a new official
observation and create a new opaque attestation. Each phase attestation must:

- have the exact canonical immutable identity;
- still be valid and no more than 60 seconds old;
- be strictly newer than the previously accepted planning or phase
  observation; and
- preserve branch, database, endpoint ID, variant, host, effective port,
  write capability, enabled state, and availability.

Object identity is not reused or compared. A fresh equivalent attestation is
accepted; an older or equal observation is rejected even if unexpired. A
changed endpoint mapping is rejected even if endpoint ID, hostname,
connection authority, system identifier, and database OID remain stable.

Successful phase validation issues a single-use opaque capability bound to the
exact target and phase. `installRuntimePasswordWithDocker` cannot spawn without
the password-phase capability and the fixture identity it carries.
`buildRuntimeRoleStatement` cannot generate LOGIN or rollback SQL without the
matching capability. Success finalisation consumes its own capability.
Rollback SQL is generated only after the unchanged SQL fixture and a fresh
matching rollback attestation issue the rollback capability. A missing,
substituted, reused, cross-target, or wrong-phase capability fails before the
executable boundary.

Before mutation, prove through the trusted binding that both the
direct/operator connection path and Docker/psql path use approved compute
endpoint identities associated with the exact same Neon project, branch, and
database. Distinct direct and pooled endpoint variants are permitted only when
that binding maps both exact endpoint IDs to the same target. Hostnames,
connection strings, database names, role names, PostgreSQL versions, system
identifiers, and database OIDs are not branch identity by themselves; endpoint
transfer during restore can preserve a hostname or connection-string authority
while changing branches.

Retain the database-side comparison as secondary evidence. The operator
connection and Docker/psql connection must also return the same PostgreSQL
control-system identifier plus current database OID. Provider mismatch or
inconclusive provider evidence stops first; a SQL identity mismatch, malformed
response, query error, or cardinality error also stops before password
installation. SQL fingerprint values must stay out of logs and evidence.

The read-only Docker identity probe uses the same confirmed-termination
boundary as the password operation. Each probe has a unique exact container
name. Success requires child close plus an anchored all-container query proving
daemon-side absence. Timeout, stdin failure, excessive output, child or spawn
failure, and any inconclusive state request graceful termination, wait through
a bounded grace period, escalate to `SIGKILL` where applicable, run exact-name
`docker rm --force`, and re-check absence with bounded retries. The probe stays
unsettled and activation remains blocked unless both local child close and
daemon-side absence are proven. Operator URLs remain environment-only, output
is bounded, stderr is ignored, and public failures remain generic.

Cleanup is forbidden before complete provider and fixture validation. Track
whether password installation began or may have begun. If dormant-role or fixture
identity validation fails, teardown is read-only and must execute no
`ALTER ROLE`, password reset, LOGIN change, or cleanup SQL. If mutation may
have begun, cleanup must use only the immutable provider-bound target and the
exact fixture proven through both connection paths. Bind the provider target
and SQL identities to the mutation tracker with `fixtureValidated` before it
can issue a password-installation capability from a fresh attestation.
Immediately before cleanup, re-read the operator-side SQL fixture identity,
obtain another strictly newer official observation, and require both to pass
`assertRollbackFixture`. A changed database identity, project, branch,
database association, endpoint identity, variant, host, effective port, write
capability, enabled/available state, stale attestation, or substituted target
refuses rollback. The safe outcome remains inconclusive/manual cleanup. Never retarget rollback
to the newly observed branch.

The complete dormant preflight uses the same reviewed PostgreSQL 17 recursive
SET-assumable posture query as application startup, anchored to the exact
validated target role OID. Before password installation it requires exact role
identity, `NOLOGIN`, password null, no administrative attributes, no prohibited
Neon membership, no unsafe direct or indirect SET-assumable role, no reachable
`ADMIN OPTION`, reviewed grants, zero ownership, and the expected ledger,
schema, table, and index state. Missing or inconclusive evidence fails before
mutation.

Runtime URL construction rejects identity- or endpoint-overriding connection parameters,
aliases, duplicates, conflicts, arbitrary parameters, and options that can
change role or session state. It preserves only the reviewed
transport/security allowlist: `sslmode` with `require`, `verify-ca`, or
`verify-full`, and `channel_binding=require`. The validated runtime role and
password replace URL authority credentials while the reviewed host, port, and
database remain unchanged.

A separately authorised second attempt must use this order:

1. Reconfirm the exact repository, database, operator, PostgreSQL 17, recovery
   branches, grant matrix, ownership, schema, ledger, table, and index state.
2. Obtain a planning observation with the official read-only endpoint and
   branch-database API reads above. Reduce only the reviewed fields to one
   opaque attestation and create one immutable `activationTarget` for the exact
   project, branch, database, endpoint IDs, variants, hosts, effective ports,
   write capability, availability, and `platform_runtime` role. Compare the
   opaque control-system/database identity from the operator connection with
   the Docker connection as secondary evidence.
3. Run the shared operator-side recursive authority inspection and pass
   `dormant_role_preflight` only when complete fixture identity, `NOLOGIN`,
   password null, all prohibited-attribute and SET-assumable-role checks,
   reviewed grants, ownership, and database-shape assertions are conclusive
   and safe.
4. Only after step 3, perform a new official read-only control-plane
   observation. Require an exact, valid, at-most-60-second-old attestation that
   is strictly newer than planning, then issue the single-use password-phase
   capability. Obtain one fresh password through an approved hidden mechanism
   and pass it in protected process memory to
   `installRuntimePasswordWithDocker` with the same target, fixture identity,
   and capability. The helper marks mutation as possible only when it consumes
   that capability. Do not use a PowerShell string-to-native pipeline.
5. If password installation times out, wait for confirmed child termination
   and container removal before any rollback. Never start database rollback
   while the mutation process may still be alive.
6. Verify password-present plus `NOLOGIN`, obtain another strictly newer fresh
   official observation, and execute only the LOGIN statement generated from
   the same target and its single-use LOGIN capability.
7. Build the restricted URL with `buildRuntimeDatabaseUrl` and the same target,
   preserving only the reviewed endpoint, port, database, and allowlisted
   transport/security parameters.
8. Start a runtime-only child with `DATABASE_URL` and
   `DATABASE_EXPECTED_RUNTIME_ROLE`; explicitly remove
   `DATABASE_OPERATOR_URL`.
9. Require the same provider-bound target, expected database, exact runtime
   connection, `current_user`, `session_user`, recursive SET-assumable posture,
   grant matrix, ownership, ledger, table, index, and schema invariants before
   success finalisation. Then obtain another strictly newer fresh provider
   attestation and consume the resulting success capability. Never reuse the
   planning, password, or LOGIN observation.
10. On the first failed or inconclusive phase after mutation, record that
    phase. If and only if the mutation process is confirmed stopped and the
    mutation tracker requires rollback, revalidate the operator-side SQL
    fixture, obtain another strictly newer official observation, and require
    an exact fresh attestation before issuing a rollback capability. Execute
    only the rollback statement generated from that capability and the same
    immutable target. If provider lookup fails or shows any identity or
    write-capability drift, do not run rollback against the changed target;
    report only an inconclusive/manual-cleanup state and stop without retry.
    Otherwise verify the complete dormant baseline and stop without retry.

The disposable PostgreSQL integration test
`tests/platform-runtime-activation-postgres.test.mjs` exercises the same
phase contract with synthetic credentials. It is skipped unless both
lab-specific URLs and `RUNTIME_ACTIVATION_TEST_CONFIRM=disposable-only` are
provided. Passing that lab does not authorise or prove a production activation.

The readiness path is split deliberately:

- `npm run platform:readiness-check` validates hosted env shape only. It fails missing or malformed `DATABASE_URL` without printing the value and does not connect to Neon.
- `npm run platform:db-readiness-check` builds the app, opens a PostgreSQL connection through `DATABASE_OPERATOR_URL`, runs a basic reachability query, checks required platform tables, and checks the committed Drizzle migration journal against `drizzle.__drizzle_migrations`.
- DB readiness can report `db_config_missing`, `db_config_invalid`, `db_unreachable`, `schema_not_ready`, or `ready`.
- `db_config_missing` means the operator process has no usable production `DATABASE_OPERATOR_URL`.
- `db_unreachable` means a configured database could not be reached; the output must not include host, username, password, connection string, or low-level driver details.
- `schema_not_ready` means the database is reachable but required platform tables or migration metadata are missing or behind the committed migration journal.
- `ready` means the configured database is reachable and the required platform schema/migration state matches the committed code.

Passing both readiness commands is still not hosted deployment approval. Operators must still approve backups, restore test, migration window, rollback owner, secrets, logs, OIDC, SQAG handoff, and go/no-go outside this repo.

## Sanitized Neon Migration Evidence

Operator-provided sanitized evidence for the reviewed Neon target records the current migration readiness sequence:

- Pre-migration DB readiness: `schema_not_ready`.
- Migration command: guarded manual migration through `npm run db:migrate` with `DATABASE_MIGRATIONS_CONFIRM=apply-reviewed-migrations`.
- Post-migration DB readiness: `ready`.

This evidence records only readiness categories and the guarded command path. It does not include database URLs, hostnames, usernames with passwords, table data, provider console values, backup exports, screenshots, OAuth values, cookies, tokens, or private SQAG data.

This evidence does not approve hosted deployment or full production readiness. Hosted execution still requires the remaining operator decisions, backup/restore evidence, OIDC configuration, hosted smoke evidence, SQAG handoff/session review, log/incident review, first owner/admin approval, and final go/no-go outside the repo.

## Migration Procedure

1. Confirm the branch and migration files under review.
2. Confirm the target database is the reviewed Neon database name `swooshz_platform` in project `swooshz-platform`, with runtime using the pooled restricted-role `DATABASE_URL` and the operator shell using `DATABASE_OPERATOR_URL`.
3. Confirm no migration was added for this readiness-only PR.
4. If a future reviewed PR adds migrations, review generated SQL before applying it.
5. Run `npm run platform:readiness-check` and fix missing or malformed env before any database operation.
6. Run `npm run platform:db-readiness-check` to confirm the database is reachable. For a new database before migrations, `schema_not_ready` is expected; `db_unreachable` blocks migration.
7. Take a database backup and confirm restore access before migration execution.
8. Set the migration guard only for the manual migration command:

```powershell
$env:DATABASE_OPERATOR_URL="<owner-migration-url-from-operator-secret-store>"
$env:DATABASE_MIGRATIONS_CONFIRM="apply-reviewed-migrations"
npm run db:migrate
```

9. Remove the migration guard from the operator shell after the manual command if it is not needed for the next command.
10. Run `npm run platform:db-readiness-check` again. It must report `ready` before server start.
11. Run `/healthz`, auth, `/app`, `/app/admin`, SQAG entitlement, and audit/activity smoke checks after startup.

Do not add startup hooks, package install hooks, deployment hooks, or background jobs that run migrations automatically.

## Backup And Restore Procedure

Before the first hosted internal-alpha migration or seed operation:

1. Take a provider-approved PostgreSQL backup.
2. Record only the backup id, timestamp, and retention class in operator notes.
3. Perform a restore test into a separate reviewed restore target when the provider process supports it.
4. Confirm who can request backup access and who can approve restore.
5. Confirm backup retention and deletion policy outside the repo.

Do not paste database URLs, connection credentials, table dumps, private staff data, provider identity material, or SQAG private app data into this repo or shared tickets.

## Rollback Procedure

Rollback is an operator decision, not an automatic script in this repo.

Application rollback:

1. Stop new traffic at the hosting layer if needed.
2. Revert the process manager or container image to the last reviewed build.
3. Restart through the same reviewed command path.
4. Run `/healthz`, login, `/app`, `/app/admin`, SQAG entitlement, and audit/activity smoke checks.

Database rollback:

1. Prefer fix-forward for reviewed additive migrations when practical.
2. If restore is required, stop the platform process, restore from the approved backup, and rerun smoke checks before reopening access.
3. Do not run ad hoc destructive SQL from this repo.

SQAG handoff rollback:

1. Set `PLATFORM_SQAG_LAUNCH_MODE=manual` to stop browser handoff while keeping Platform access checks available.
2. Confirm `/app` reports a safe launch failure rather than exposing tokens.
3. Restore `server_handoff` only after confirming `PLATFORM_SQAG_APP_BASE_URL=https://quote.swooshz.com`, the shared service secret is injected into both services, and the host-only cookie/finalization flow is smoke tested.

## Health Check Procedure

Use `GET https://swooshz.com/healthz`. A healthy response means the HTTP adapter is reachable; it does not prove OIDC, database migrations, session cookies, admin authorization, SQAG handoff, or audit integrity by itself.

Minimum checks:

- `GET /healthz` returns a successful HTTP response.
- The response does not include secrets, database URLs, cookies, provider material, or SQAG private data.
- Health checks are rate-limited or scoped by the hosting layer if exposed beyond the internal operator network.

## Log Review Procedure

Review logs after migration, startup, login, admin mutations, SQAG handoff, and logout.

Expected log shape:

- Startup summary may include host, port, environment, and auth mode.
- Auth diagnostics should be category-only.
- Admin actions should be visible through audit/activity, not by logging private request details.
- SQAG handoff should not log raw app launch tokens, token hashes, cookies, or browser storage values.
- Database and provider failures should use safe categories, not raw connection or provider details.

Stop and redact the log collection process if a log includes secret values, database connection values, cookies, OAuth values, unredacted provider identity material, real staff addresses, or SQAG private app data.

## Secrets And Env Checklist

| Env var | Purpose | Required | Safe example | Secret | Validation / failure behavior |
| --- | --- | --- | --- | --- | --- |
| `NODE_ENV` | Runtime mode for hosted config. | Required | `production` | No | Hosted readiness requires `production`; development and test fail readiness. |
| `PLATFORM_HTTP_HOST` | Host/interface the reviewed process binds. | Required | `<host-to-bind>` | No | Empty value fails readiness; hosting decides the real bind address. |
| `PLATFORM_HTTP_PORT` | Port the reviewed process binds. | Required | `<port-to-bind>` | No | Must be an integer port; invalid values fail startup/readiness. |
| `PLATFORM_PUBLIC_BASE_URL` | Public HTTPS Platform base URL. | Required | `https://swooshz.com` | No | Production readiness requires this exact apex origin. |
| `PLATFORM_ALLOWED_ORIGINS` | Allowed browser origin list for CSRF/origin checks. | Required | `https://swooshz.com` | No | Production readiness permits only the exact apex origin. |
| `PLATFORM_COOKIE_SECURE` | Forces secure browser session cookies. | Required | `true` | No | Production requires `true`; false fails startup/readiness. |
| `DATABASE_URL` | Pooled restricted-role PostgreSQL connection for the long-running app. | Required | `<runtime-database-url-from-secret-store>` | Yes | Used only by application runtime; production startup checks the connected role and privilege posture before listening. |
| `DATABASE_EXPECTED_RUNTIME_ROLE` | Expected restricted PostgreSQL runtime role. | Required in production | `platform_runtime` | No | Must be a safe PostgreSQL identifier and exactly match `current_user`; mismatch or unsafe posture fails before listen. |
| `DATABASE_OPERATOR_URL` | Owner/migration connection for operator readiness and migrations. | Required for production operator commands only | `<operator-database-url-from-secret-store>` | Yes | Never configure on the long-running Coolify app; production operator commands fail closed when absent. |
| `DATABASE_SSL_MODE` | Optional DB SSL mode override. | Optional | `<require-or-disable-if-needed>` | No | When set, must be `require` or `disable`; invalid value fails readiness/startup. Use only when the hosted connection string or provider settings do not already enforce the intended SSL behavior. |
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
| `AUTH_REDIRECT_URI` | Hosted callback URI configured with the provider. | Required | `https://swooshz.com/api/platform/auth/callback` | No | Production readiness requires this exact callback URI. |
| `AUTH_ALLOWED_EMAILS` | Bootstrap/emergency exact allowlist for internal-alpha users. | Required | `<comma-separated-allowlisted-emails>` | No | Provider-entry filter only. It does not create a Platform user, workspace, membership, or first owner by itself. Day-to-day teammate onboarding can use pending workspace approvals; malformed values fail auth config. Treat as private. |
| `AUTH_ALLOWED_DOMAINS` | Optional reviewed domain allowlist. | Optional | `<comma-separated-allowed-domains-if-approved>` | No | Leave unset unless broad domain allow is reviewed; malformed values fail auth config. |
| `PLATFORM_SQAG_LAUNCH_MODE` | Controls SQAG browser handoff behavior. | Required | `server_handoff` | No | Unsupported values fail startup/readiness; production cross-subdomain launch uses the implemented server handoff. |
| `PLATFORM_SQAG_APP_BASE_URL` | SQAG hosted base URL for browser handoff. | Required when server_handoff | `https://quote.swooshz.com` | No | Production `server_handoff` readiness requires this exact SQAG origin. |
| `PLATFORM_SQAG_SERVICE_SECRET` | Shared service authorization for Platform-to-SQAG calls. | Required when server_handoff | `<strong-random-placeholder>` | Yes | Must be at least 32 characters and injected separately into Platform and SQAG; never expose it to browser code or logs. |
| `PLATFORM_SEED_CONFIRM` | Explicit first owner/admin bootstrap confirmation. | Required for bootstrap only | `seed-reviewed-internal-access` | No | Required only for `npm run platform:seed-internal-access`; unexpected value fails seed config. |
| `PLATFORM_SEED_USER_EMAIL` | Reviewed owner/admin email for bootstrap. | Required for bootstrap only | `<hosted-owner-admin-email-after-login>` | No | Required only for seed; treat as private and do not commit real values. In first-owner mode this is the email that will complete real OIDC after the pending approval is prepared. |
| `PLATFORM_SEED_WORKSPACE_SLUG` | Reviewed bootstrap workspace slug. | Required for bootstrap only | `<reviewed-workspace-slug>` | No | Required only for seed; no default workspace is created when missing. |
| `PLATFORM_SEED_WORKSPACE_NAME` | Reviewed bootstrap workspace display name. | Required for bootstrap only | `<reviewed-workspace-name>` | No | Required only for seed; do not use placeholders as real hosted data. |
| `PLATFORM_SEED_BOOTSTRAP_MODE` | Explicit first-owner pending approval mode. | Optional bootstrap only | `first-owner-pending-approval` | No | Required for fresh hosted DB first-owner bootstrap before any Platform user exists. When omitted, the seed expects an existing provider-backed user. |
| `PLATFORM_SEED_MEMBERSHIP_ROLE` | Bootstrap role. | Optional | `owner` | No | First-owner pending approval mode requires `owner` when set. Existing-user seeding allows `owner`, `admin`, or `member`; `viewer` is rejected for SQAG launch. |

## Readiness Check

Run the dry-run checker after env injection and before manual migrations or server start:

```powershell
npm run platform:readiness-check
```

The checker reports only env names, categories, missing/invalid status, and safe guidance. It enforces hosted-only production mode, HTTPS browser/provider-facing URLs, origin-only `PLATFORM_ALLOWED_ORIGINS`, callback URL shape, SQAG handoff base URL shape, and valid Postgres-shaped `DATABASE_URL` plus a safe `DATABASE_EXPECTED_RUNTIME_ROLE`. It does not print values, connect to PostgreSQL, run migrations, start the server, call OIDC, call SQAG, read provider endpoints, or seed access.

Passing readiness does not approve deployment. It only confirms the current shell has the required categories and safe URL shapes present for hosted internal-alpha review.

Run the live DB readiness checker only when the operator intentionally wants to test the configured hosted database:

```powershell
npm run platform:db-readiness-check
```

This command uses `DATABASE_OPERATOR_URL` to reach PostgreSQL in production, checks required Platform tables, and checks Drizzle migration metadata. It prints sanitized status only. It must not print the database URL, host, user, password, driver error details, table data, provider console values, or backup details. It exits non-zero for `db_config_missing`, `db_config_invalid`, `db_unreachable`, and `schema_not_ready`.

## First Owner/Admin Bootstrap Sequence

Use this sequence after hosted auth, migrations, and the reviewed first owner/admin email are approved:

1. Confirm `AUTH_ALLOWED_EMAILS` contains the private reviewed first-owner email outside repo notes. This only allows the provider entry path; it does not create Platform ownership or workspace records.
2. In the operator shell, set `PLATFORM_SEED_CONFIRM=seed-reviewed-internal-access`.
3. Set `PLATFORM_SEED_BOOTSTRAP_MODE=first-owner-pending-approval`.
4. Set `PLATFORM_SEED_USER_EMAIL=<hosted-owner-admin-email-after-login>` outside the repo.
5. Set `PLATFORM_SEED_WORKSPACE_SLUG=<reviewed-workspace-slug>` and `PLATFORM_SEED_WORKSPACE_NAME=<reviewed-workspace-name>` outside the repo.
6. Leave `PLATFORM_SEED_MEMBERSHIP_ROLE` unset or set it to `owner`.
7. Run `npm run platform:seed-internal-access`.
8. Confirm the safe seed output says first-owner bootstrap is pending and does not print the email, workspace slug/name, database values, provider values, launch URLs, tokens, cookies, or secrets.
9. Start Platform through the reviewed hosted process.
10. The reviewed first owner/admin signs in once through Platform with real OIDC.
11. Stop if real OIDC sign-in does not complete; the seed must not create users, provider identities, sessions, or fake login state.
12. Confirm `/app` shows the workspace and SQAG app access.
13. Confirm `/app/admin` is reachable only for the owner/admin.

## Pending Workspace Approval Sequence

Use this before a teammate signs in through hosted Platform:

1. Owner/admin opens `/app/admin`.
2. Create pending workspace approval before teammate sign-in with the teammate placeholder address and approved role outside repo notes.
3. Use `member` for quote operators unless the teammate needs workspace administration.
4. Confirm the Pending Approvals list shows the normalized placeholder address, role, and pending status.
5. Confirm Activity shows `workspace.membership_approval.created` with safe metadata only.
6. The teammate completes real OIDC sign-in with the matching normalized email.
7. Confirm real OIDC sign-in activates the pending approval, creates an active membership, and removes it from the pending list.
8. Confirm the teammate can reach `/app` after refresh only according to normal role and entitlement gates.
9. Create a second pending approval in a reviewed smoke workspace and revoke it before sign-in.
10. Confirm revoked approval does not activate on sign-in and Activity shows `workspace.membership_approval.revoked`.
11. Confirm member/viewer users are denied admin access to `/app/admin`.
12. Confirm no invitation email, invitation link, invitation token, fake provider identity, or public signup path is used.

Existing active provider-backed users are still added immediately by the same add route. Pending approvals do not reactivate disabled memberships; owners/admins must use the explicit Reactivate action for disabled non-owner memberships.

## SQAG Entitlement Check

1. Owner/admin opens `/app/admin`.
2. Confirm the SQAG entitlement row is present.
3. Disable the SQAG entitlement in a reviewed smoke workspace.
4. Confirm SQAG launch fails closed and does not create a browser-visible raw token.
5. Re-enable the entitlement.
6. Confirm owner/admin/member launch eligibility is restored.
7. Confirm viewer launch remains denied while SQAG has no read-only mode.

## Audit/Activity Verification

Confirm `/app/admin` Activity shows recent admin events for:

- pending workspace approval creation, revocation, and acceptance.
- existing provider-backed user membership creation.
- role change.
- membership disable.
- membership reactivation.
- SQAG entitlement enable/disable.

Audit/activity verification should show event type, target type/id, actor user id, timestamp, and allowlisted status/category metadata only. It must not display raw provider material, cookies, DB connection values, app launch tokens, or SQAG private app data.

## Smoke Checklist

Run this checklist after hosted startup and before broader internal-alpha use:

1. Confirm server starts without importing/listening side effects by using only `npm run platform:start` as the hosted process command.
2. Call `GET https://swooshz.com/healthz` and confirm a successful response.
3. Start auth through `/api/platform/auth/start` and confirm auth start/callback shape without printing secrets or callback query details.
4. Complete login and confirm the callback returns to `/app`.
5. Fetch login session context through the platform shell and confirm no provider tokens, cookies, or secrets are rendered.
6. Visit `/app` and confirm the workspace/app access summary is present.
7. Visit `/app/admin` as owner/admin and confirm the admin surface loads.
8. Create pending workspace approval before teammate sign-in, then complete real OIDC sign-in and confirm activation.
9. Change a non-owner member role and confirm last-owner/self-demotion guardrails still fail closed.
10. Run membership disable on a non-owner membership and confirm the disabled user cannot launch SQAG.
11. Run membership reactivation on the disabled non-owner membership and confirm access is restored only according to role, entitlement, and app-status gates.
12. Run SQAG entitlement enable/disable and confirm app access updates.
13. Confirm audit/activity shows admin events for add-user, role-change, membership-disable, membership-reactivation, and entitlement-change actions.
14. Launch SQAG through the browser-safe path and confirm no raw token in browser URL, storage, or logs.
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
- raw request/response headers from auth, admin mutation, or SQAG handoff routes.
- SQAG private app data or generated business outputs.

Use safe categories instead: auth failure category, route name, HTTP status class, event type, target type/id, actor user id, timestamp, and readiness category.

## Remaining Hosted Approval Items

Before actual hosted internal-alpha execution, operators still need reviewed decisions for:

- hosting provider/process manager/container target.
- Coolify/VPS deployment target, if used, including process command, env injection, restart policy, logs, network exposure, and rollback owner.
- Neon PostgreSQL provider target, backup cadence, restore test, and retention.
- TLS/reverse proxy configuration.
- OIDC client registration outside the repo.
- hosted SQAG handoff and host-only session-cookie/finalization evidence.
- log retention and incident review process.
- first owner/admin identity outside repo notes.
- any infrastructure change approval required by the operator team.

Track these approvals in `docs/hosted-internal-alpha-operator-decisions.md` using placeholders only. Do not deploy until every required decision is approved outside repo.

Owner/migration credentials must never remain in the long-running Coolify application environment. Keep /healthz as liveness only; production startup posture validation occurs before the server listens, while migration readiness remains an explicit operator command.

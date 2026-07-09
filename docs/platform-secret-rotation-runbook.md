# Platform Secret Rotation Runbook

Production readiness is not approved. This runbook is pre-VPS planning only. It does not create, request, store, rotate, print, or validate real secrets. Do not paste secret values into this repo, chat, tickets, PRs, logs, screenshots, or shell history.

Real values belong only in the approved hosting secret/env store or another approved secret manager after the shared Hostinger/Coolify foundation exists and deployment is separately approved.

## Env Names Only

Secret runtime names:

- `DATABASE_URL`
- `SESSION_SECRET`
- `CSRF_TOKEN_HASH_SECRET`
- `AUTH_STATE_HASH_SECRET`
- `APP_LAUNCH_TOKEN_HASH_SECRET`
- `AUTH_CLIENT_SECRET`

Private operational data names:

- `AUTH_ALLOWED_EMAILS`

One-off operator names that must not live on the long-running service:

- `DATABASE_MIGRATIONS_CONFIRM`
- `PLATFORM_SEED_CONFIRM`
- `PLATFORM_SEED_USER_EMAIL`
- `PLATFORM_SEED_MEMBERSHIP_ROLE`

Non-secret runtime names that still require reviewed values:

- `NODE_ENV`
- `PLATFORM_HTTP_HOST`
- `PLATFORM_HTTP_PORT`
- `PLATFORM_PUBLIC_BASE_URL`
- `PLATFORM_ALLOWED_ORIGINS`
- `PLATFORM_COOKIE_SECURE`
- `DATABASE_SSL_MODE`
- `PLATFORM_AUTH_PROVIDER_MODE`
- `AUTH_PROVIDER_KEY`
- `AUTH_ISSUER_URL`
- `AUTH_AUTHORIZATION_URL`
- `AUTH_TOKEN_URL`
- `AUTH_JWKS_URL`
- `AUTH_USERINFO_URL`
- `AUTH_CLIENT_ID`
- `AUTH_REDIRECT_URI`
- `AUTH_ALLOWED_DOMAINS`
- `PLATFORM_SQAG_LAUNCH_MODE`
- `PLATFORM_SQAG_APP_BASE_URL`

## Routine Rotation

Use this only after an operator approves the target environment, owner, and maintenance window.

1. Record the rotation scope by env name only.
2. Confirm the rotation owner, reviewer, and rollback approver outside the repo.
3. Generate replacement values outside the repo using an approved secret-generation process.
4. Store replacements only in the approved secret manager or hosting env store.
5. Review expected impact before restart:
   - `DATABASE_URL` can change database connectivity and must be paired with readiness checks.
   - `SESSION_SECRET` can invalidate or change session reference behavior depending on the active runtime boundary.
   - `CSRF_TOKEN_HASH_SECRET` can invalidate outstanding CSRF tokens.
   - `AUTH_STATE_HASH_SECRET` can invalidate outstanding auth state/nonce references.
   - `APP_LAUNCH_TOKEN_HASH_SECRET` can invalidate outstanding app launch tokens.
   - `AUTH_CLIENT_SECRET` can affect OIDC callback token exchange.
6. Restart or redeploy only in a separately approved hosted execution window.
7. Run env readiness and DB readiness checks from the reviewed environment, recording sanitized pass/fail categories only.
8. Run hosted login/logout, CSRF, admin, entitlement, and launch smoke only after hosted smoke is explicitly approved.
9. Remove old values from the active secret store after the rollback window closes.
10. Record sanitized completion evidence outside the repo or as a placeholder-only note.

## Emergency Revoke

Use this if a secret value, cookie, token, provider value, backup/export, log, screenshot, shell history entry, or private operator note may have exposed secret material.

1. Stop sharing the exposed material immediately. Do not paste it again for analysis.
2. Identify affected env names without recording values.
3. Decide whether to pause hosted traffic, disable the affected provider client, or keep the service in manual mode while rotation proceeds.
4. Rotate affected env names through the approved secret store.
5. Revoke active Platform sessions if browser session material or session secret material may be exposed.
6. Invalidate outstanding auth state, CSRF, and launch-token material by rotating the relevant hash secret names when affected.
7. Rotate provider or database credentials at the provider when those values may be affected.
8. Review logs for secret exposure using sanitized search notes only.
9. Record incident category, affected env names, owner, reviewer, and pass/fail remediation status without values.
10. Reopen access only after the incident owner and final approver accept the sanitized evidence.

## Evidence Rules

Allowed in repo notes:

- Env names.
- Owner role placeholders.
- Status categories.
- Sanitized pass/fail results.
- Route names.
- Evidence ids that do not reveal provider or storage paths.

Not allowed in repo notes:

- Secret values or partial secret values.
- Database connection strings.
- OAuth client secrets, auth codes, access tokens, refresh tokens, ID tokens, state, or nonce values.
- Cookies, CSRF tokens, app launch tokens, token hashes, or browser storage.
- Real staff emails, private allowlists, provider payloads, provider subjects, table data, backup exports, screenshots of provider consoles, private domains, private IPs, or internal file paths.

This runbook is not rotation evidence and does not approve hosted launch.

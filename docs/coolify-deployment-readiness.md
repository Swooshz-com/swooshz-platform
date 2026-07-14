# Coolify Deployment Readiness

Production readiness is not approved. This document is repo-side deployment readiness only. It does not deploy Swooshz Platform, create a VPS, configure Coolify, configure DNS/TLS, configure OAuth, run hosted smoke, or approve production launch.

The shared Hostinger/Coolify foundation is not created yet. That future VPS/Coolify foundation is shared across Swooshz Platform, Swooshz Quote Auto Generator, and SKR; it must not become Platform-only. Swooshz Quote Auto Generator remains a separate product app launched from Platform, not embedded in Platform. SKR remains a separate website/app. The SEO/GEO/Seozilla product direction is retired and must remain absent from customer-facing Platform surfaces.

## App Type And Build Strategy

- App type: Node.js TypeScript HTTP service.
- Runtime entrypoint: `npm run platform:start`.
- Build command: `npm run build`.
- CI validation command set: `npm ci`, `npm run typecheck`, `npm run build`, and `npm test`.
- Container build command: `docker build --pull --tag swooshz-platform:local .`.
- Container smoke command: `docker run --rm --env-file <local-placeholder-env-file> --publish 3000:3000 swooshz-platform:local`.
- Expected runtime port: `3000` inside the container unless `PLATFORM_HTTP_PORT` is set differently by the reviewed host.
- Healthcheck endpoint: `GET /healthz`.

The container image is a runtime artifact only. It must not run migrations, seed access, call OAuth providers, call Swooshz Quote Auto Generator, run hosted smoke, or store secrets in image layers.

## Container Runtime Shape

The Dockerfile uses a build stage and a minimal Node runtime stage:

- Installs dependencies with `npm ci`.
- Builds TypeScript with `npm run build`.
- Prunes dev dependencies before copying runtime dependencies.
- Runs as the non-root `node` user.
- Exposes container port `3000`.
- Starts with `npm run platform:start`.
- Defines a container healthcheck that calls local `GET /healthz`.

Runtime env is injected by the operator platform, not baked into the image. `.dockerignore` excludes `.git`, `node_modules`, local env files, logs, build caches, backups, exports, private screenshots, and Stitch/private visual assets.

## Required Env Names

Use names only in repo docs and PRs. Real values belong only in Coolify secrets/env storage or another approved secret manager.

Non-secret runtime names:

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

Secret runtime names:

- `DATABASE_URL`
- `SESSION_SECRET`
- `CSRF_TOKEN_HASH_SECRET`
- `AUTH_STATE_HASH_SECRET`
- `APP_LAUNCH_TOKEN_HASH_SECRET`
- `AUTH_CLIENT_SECRET`

Private operational data names:

- `AUTH_ALLOWED_EMAILS`

One-off operator names, not long-running service env:

- `DATABASE_MIGRATIONS_CONFIRM`
- `PLATFORM_SEED_CONFIRM`
- `PLATFORM_SEED_USER_EMAIL`
- `PLATFORM_SEED_WORKSPACE_SLUG`
- `PLATFORM_SEED_WORKSPACE_NAME`
- `PLATFORM_SEED_MEMBERSHIP_ROLE`

Do not commit, print, screenshot, or paste real values for these names into repo files, tickets, PRs, logs, or chat.

## OAuth Callback Placeholders

Use placeholders only:

- Platform base URL: `<hosted-platform-base-url>`.
- OIDC callback URI: `<hosted-oidc-redirect-uri>`.
- Swooshz Quote Auto Generator base URL: `<hosted-sqag-base-url>`.

The hosted OIDC callback must end with `/api/platform/auth/callback` and must not include query parameters or fragments. Real provider console values and client secrets stay outside the repo.

## Healthcheck And Readiness Expectations

Coolify healthcheck:

- Path: `/healthz`.
- Expected result: successful HTTP response with safe JSON.
- Limit: healthcheck proves only that the HTTP adapter is reachable.

Before hosted start, operators should run:

```powershell
npm run platform:readiness-check
```

That command is a dry-run env shape check. It does not connect to PostgreSQL, run migrations, start the server, call OAuth, call Swooshz Quote Auto Generator, or seed access.

When an operator intentionally validates the hosted database from a reviewed shell:

```powershell
npm run platform:db-readiness-check
```

That command uses `DATABASE_URL` and must print sanitized status only.

## Coolify App Shape

Recommended future Coolify app settings, after the shared foundation exists and deployment is explicitly approved:

- Source: reviewed branch, release tag, or image built from this repo.
- Build strategy: Dockerfile.
- Runtime command: image default command, equivalent to `npm run platform:start`.
- Exposed port: `3000`, or the reviewed `PLATFORM_HTTP_PORT` value.
- Healthcheck path: `/healthz`.
- Restart policy: explicit and reviewed by the operator.
- Secrets/env: injected through Coolify, not committed.
- Migrations: manual one-off only, never build/start/deploy/restart/healthcheck hooks.
- Seed/bootstrap: manual one-off only after real hosted auth creates the user.

Do not configure production deploy automation from GitHub Actions until a separate approval names the target environment and deployment operation.

## GitHub Actions Deployment Design Guidance

Current status: deployment workflow is disabled/planning-only. CI validates the repo and container build but does not push images, deploy to Coolify, mutate a VPS, configure DNS/TLS, or run hosted smoke.

Protected GitHub environment names to reserve for a future deployment design:

- `staging/internal-alpha`
- `production`

Future deployment rules:

- Production deploy requires manual approval through a protected GitHub environment.
- Production should not deploy blindly on every push.
- Staging/internal-alpha can be considered first, but only after the shared Hostinger/Coolify foundation exists.
- Secrets are referenced by name only and stored in GitHub Environments or Coolify, never in repo files.
- Prefer short-lived credentials or pull-from-Git in Coolify over long-lived deploy tokens when the operator platform supports it.
- Any deployment workflow must wait for CI repository guardrails, tests, build, and container build to pass.

Secret names for a future GitHub-to-host deployment design, if one is approved later:

- `COOLIFY_DEPLOY_WEBHOOK_URL`
- `COOLIFY_DEPLOY_TOKEN`

These names are placeholders only. They are not required by current CI and no values should be added until deployment is approved.

## Rollback Expectations

Application rollback:

- Redeploy the previous reviewed image or branch/release reference.
- Re-run `GET /healthz` after rollback.
- Run hosted auth/admin/Swooshz Quote Auto Generator launch smoke only after a reviewed hosted execution window exists.

Database rollback:

- Prefer fix-forward for reviewed additive migrations when practical.
- Restore only after backup owner, restore target, and restore approval are recorded outside the repo.
- Do not run ad hoc destructive SQL from this repo.

Swooshz Quote Auto Generator handoff rollback:

- Keep `PLATFORM_SQAG_LAUNCH_MODE=manual` until hosted handoff is approved.
- If a future handoff fails, return to manual mode without exposing raw launch tokens.

## Deployment Approval Model

Deployment remains blocked until:

- Shared Hostinger/Coolify foundation exists.
- DNS/TLS baseline is approved.
- Hosted OAuth/provider configuration is completed outside repo.
- Hosted env/secret categories are injected outside repo.
- Backup/restore owner and restore evidence exist.
- Logging/monitoring/incident owner and retention are approved.
- Hosted Platform and Swooshz Quote Auto Generator deployment evidence exists.
- Live Platform-to-Swooshz Quote Auto Generator smoke is approved and completed.
- Final go/no-go is recorded outside repo.

This document is not hosted evidence. It is not a production readiness claim.

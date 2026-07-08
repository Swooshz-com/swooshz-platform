# Current CI/CD Status

Production readiness is not approved. This status document records repo-side CI/CD and container readiness only. It does not deploy, configure DNS/TLS, configure OAuth, run hosted smoke, or approve production launch.

## Current Setup

- Setup branch: `codex/platform-ci-container-readiness`.
- Deployment status: disabled/planning-only.
- Default CI target: pull requests, pushes to `main`, and manual `workflow_dispatch`.
- Shared hosting status: future Hostinger/Coolify foundation is not created yet and must be shared across Platform, Swooshz Quote Auto Generator, and SKR.

## Workflow Files

- `.github/workflows/ci.yml`

## Checks That Run

Repository guardrail gate:

- Deterministic CI/container readiness test with `node --test tests/ci-container-readiness.test.mjs`.
- Checks workflow coverage, container documentation, placeholder-only deployment docs, and hosted-evidence boundaries.

Validation gate:

- `npm ci`
- `npm run typecheck`
- `npm run build`
- `npm test`

Container gate:

- `docker build --pull --tag swooshz-platform:ci .`
- The image is built but not pushed or deployed.

## Deployment

Deployment is disabled. No GitHub Actions workflow deploys to Coolify, Hostinger, a VPS, production, staging/internal-alpha, Swooshz Quote Auto Generator, SKR, or any external service.

Protected environment names reserved for future design:

- `staging/internal-alpha`
- `production`

Production deployment must require manual approval and must not run blindly on every push.

## Required Secrets By Name Only

Current CI requires no repository secrets.

Runtime secrets for a future hosted Platform deployment:

- `DATABASE_URL`
- `SESSION_SECRET`
- `CSRF_TOKEN_HASH_SECRET`
- `AUTH_STATE_HASH_SECRET`
- `APP_LAUNCH_TOKEN_HASH_SECRET`
- `AUTH_CLIENT_SECRET`

Potential future deployment secrets, only if deployment automation is separately approved:

- `COOLIFY_DEPLOY_WEBHOOK_URL`
- `COOLIFY_DEPLOY_TOKEN`

Do not paste secret values into chat, docs, PRs, logs, screenshots, or committed files.

## Manual Steps Still Required

- Create the shared Hostinger/Coolify foundation outside this repo.
- Approve DNS/TLS, firewall/server access, Coolify ownership, and log/backup posture outside this repo.
- Configure hosted OAuth/provider values outside this repo.
- Inject hosted env and secret values through Coolify or another approved secret manager.
- Run hosted smoke only after an approved hosted execution window.
- Configure GitHub protected environments only after deployment automation is explicitly approved.

## Safe Next Actions

- Review CI results on the pull request.
- Build the container locally with placeholder env only.
- Continue docs/tests for legal/compliance, monitoring, backup/restore, or incident planning.

## Must Not Do Yet

- Do not deploy.
- Do not configure DNS/TLS.
- Do not configure real OAuth values.
- Do not add secrets.
- Do not run hosted smoke.
- Do not implement frontend redesign.
- Do not integrate hosted Swooshz Quote Auto Generator launch.
- Do not integrate SEO/GEO/Seozilla.
- Do not claim production readiness.

## How To Rerun Or Debug

- In GitHub Actions, open the `CI` workflow and use `Run workflow` for manual reruns.
- For local validation, run `npm run typecheck`, `npm run build`, and `npm test`.
- For local container build validation, run `docker build --pull --tag swooshz-platform:local .`.
- For local container smoke, run `docker run --rm --env-file <local-placeholder-env-file> --publish 3000:3000 swooshz-platform:local`, then request `GET /healthz`.
- If repository guardrails fail, inspect only the failing assertion and file path. Do not print or copy secret values. Rotate any exposed real secret before continuing.

## Privacy-Safe Observability Baseline

Before deployment or background AI features are enabled, observability must stay metadata-only:

- Daily PASS/WARN/FAIL rollup for CI health, deployment readiness, dependency/security checks, failed jobs, pending approvals, and rollback readiness.
- Event allowlist for deployment attempts, health checks, smoke tests, rollback readiness, manual approvals, and alert decisions.
- WARN/FAIL criteria that require human review before production deploys, provider changes, notification tests, production mutations, or auto-remediation.
- No provider calls, notification tests, production mutations, or auto-remediation unless a future task explicitly approves the exact target operation.

If future AI features are added, record only a metadata AI attempt ledger with timestamp, module, request id, provider/model identifier, status, latency, retry count, safe token/byte counts, failure taxonomy, and output-shape diagnostics. Do not log raw prompts, uploads, model responses, customer content, secrets, auth headers, cookies, private connector data, payment data, or private files.

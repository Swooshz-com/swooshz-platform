# Hosted Internal Alpha Operator Briefing

This briefing helps a human operator decide whether Swooshz Platform should move toward a later hosted internal-alpha execution window. It is planning guidance only. It does not deploy, provision, expose, configure, restart, run migrations, connect to databases, call OIDC, call SQAG, seed access, add runtime features, or approve hosted execution.

Default posture: No-go until approved. Hosted execution remains blocked until the operator approvals, real infrastructure choices, real OIDC configuration, hosted SQAG handoff/session strategy, real secret storage/log/incident process, first owner/admin identity approval, and hosted smoke evidence are reviewed outside the repo.

## Purpose and non-goals

Purpose:

- Give the operator a concise decision pack before any hosted internal-alpha execution planning.
- Summarize the current local/internal UAT posture and the hosted no-go blockers.
- Compare hosted topology options at a planning level.
- Keep Platform/SQAG ownership, secret handling, migration, backup, restore, logging, incident, identity, and smoke evidence requirements visible in one place.

Non-goals:

- This briefing does not approve hosted deployment or production use.
- This briefing does not claim production readiness.
- This briefing does not add Docker, Caddy, Traefik, Nginx, Coolify, process manager, or deployment config.
- This briefing does not add password auth, 2FA, fake/demo auth, sample data, broad fallbacks, Google Stitch, UI polish, billing/credits implementation, or SQAG runtime changes.

## Current local/internal UAT readiness summary

The local/internal UAT platform-admin foundation is mostly implemented/documented for narrow reviewed internal use:

- Provider-backed generic OIDC login and Platform-owned server-side sessions are documented.
- `/app` and `/app/admin` use the approved compact production interface locally; hosted visual evidence and hosted smoke remain pending.
- Owner/admin flows can add existing provider-backed users by email after first sign-in, change roles, disable and reactivate non-owner memberships, enable/disable SQAG entitlement, and browse recent activity.
- App launch checks fail closed across session, user, workspace, membership, entitlement, role, and app availability conditions.
- The SQAG handoff path keeps the raw one-time launch token out of browser URLs and storage.
- Local UAT references should use `127.0.0.1` where a local address is needed.

This local posture supports reviewed internal UAT only. It is not a public launch and does not approve hosted execution.

## Hosted internal-alpha no-go blockers

Hosted internal alpha remains no-go until all of these are approved and evidenced outside the repo:

- Platform host/provider choice.
- SQAG host/provider choice.
- TLS/reverse proxy approach.
- Process manager or container approach.
- PostgreSQL provider, backup owner, restore owner, and restore-test process.
- Migration approver and rollback approver.
- OIDC provider/client owner and reviewed hosted callback value.
- Secret storage owner and rotation owner.
- Log retention/access owner and privacy review process.
- First owner/admin identity approval.
- Add-existing-user process owner.
- SQAG handoff mode and cross-host session/cookie strategy.
- Incident contact/escalation path.
- Final go/no-go approver.
- Hosted smoke evidence after reviewed infrastructure exists.

Passing `npm run platform:readiness-check` is only a dry-run env shape and safety check. It does not prove OIDC, database, SQAG, backups, rollback, logs, session cookies, cross-host handoff, or smoke behavior.

## Required operator approvals before execution

Before execution, the operator must collect approval evidence outside the repo for:

| Approval area | Required evidence | Repo impact |
| --- | --- | --- |
| Hosting and topology | Approved Platform and SQAG hosting targets plus operations owner. | Docs only; no hosted config in this PR. |
| TLS/proxy | Approved HTTPS termination, forwarded host/protocol handling, and allowed-origin plan. | Docs only; no proxy config. |
| Runtime supervision | Approved process manager or container operation approach. | Docs only; no supervisor config. |
| Database | Approved PostgreSQL provider, backup/restore owner, retention, and restore test. | Docs only; no DB connection or migration. |
| Migrations/rollback | Approved manual migration window, approver, rollback approver, and backup prerequisite. | Migrations remain explicit/manual only. |
| OIDC | Approved provider/client owner and hosted redirect value registration. | Docs only; no provider call. |
| Secrets | Approved storage, access review, and rotation owner. | No secrets committed. |
| Logs/incidents | Approved retention/access owner, redaction process, and escalation path. | No log backend config. |
| First owner/admin | Approved first identity outside source control after real provider sign-in. | No real identity values in repo. |
| SQAG handoff | Approved `manual` or `server_handoff` mode and cross-host session/cookie strategy. | Platform handoff placeholders only. |
| Final decision | Go/no-go approver signs off after smoke evidence. | Hosted execution stays blocked until approved. |

## Recommended hosted topology options

These options are planning guidance only. They compare operational tradeoffs without adding deployment files or scripts.

| Option | Fit | Operator decisions required | Risks to resolve before go |
| --- | --- | --- | --- |
| Single VPS/process manager reverse-proxy setup | Simple first hosted alpha when one operator owns the host and reverse proxy. | Host owner, process supervisor, TLS/proxy, firewall, log capture, backup access, rollback process. | Manual host drift, weaker separation between Platform/SQAG if placed together, process restart discipline, secret access controls. |
| Containerised VPS setup | Useful if the operator wants repeatable build artifacts and clearer process isolation on a single host. | Image build/release owner, container runtime owner, env injection, volume/log policy, migration window, rollback image. | Must not imply deployment approval; image/env secrets must stay outside repo; container networking and graceful stop need smoke evidence. |
| Managed app/database provider setup | Useful if the operator wants managed runtime, managed PostgreSQL, backups, and access controls. | App provider owner, managed database owner, secret manager owner, log retention owner, custom domain/TLS owner, rollback path. | Provider-specific limits, cross-host SQAG session/cookie behavior, backup restore access, and log redaction must be reviewed. |

Do not add Docker, Caddy, Traefik, Nginx, Coolify, process manager, or deployment config from this briefing. Pick an option only through operator approval outside the repo.

## SQAG handoff/session strategy options

Platform handles identity, workspace, membership, entitlement, and launch checks.

SQAG owns quote/session/profile/pricing/generated-artifact data.

SQAG owns quote generation, profiles, pricing references, quote sessions/history/dashboard, generated artifacts, and runtime/app data.

Options:

| Strategy | When to consider | Required proof before go |
| --- | --- | --- |
| `manual` first | Safest hosted planning default when cross-host SQAG handoff is not approved. | Platform access checks, SQAG entitlement behavior, and operator manual access path are documented and smoke-tested. |
| `server_handoff` later | Only after hosted SQAG base, cookie/session strategy, token privacy, and failure modes are approved. | Hosted SQAG handoff/session/cookie decision must be approved and smoke-tested before execution. Confirm no raw launch token appears in browser URL, storage, logs, or tickets. |

Do not move SQAG quote data into Platform. Do not propose Platform storage for SQAG quote/session/profile/pricing/generated-artifact data. Platform handoff placeholders may be documented, but SQAG app-data responsibilities stay outside this Platform repo.

## Secret/config handling requirements

- Store real env values, secrets, OAuth values, database connection values, hosted URLs, staff identities, provider material, cookies, and tokens outside the repo.
- Use placeholders only in repo docs and PRs.
- Run `npm run platform:readiness-check` only as a dry-run env-shape check before migration or startup.
- Treat allowlists, first owner/admin identity, log excerpts, screenshots, callback traces, provider diagnostics, and incident notes as private operational material.
- Stop and redact any workflow that prints or captures secret values, database connection values, OAuth values, browser session material, provider identity material, or SQAG private data.

## Migration/backup/restore decision requirements

- Migrations are explicit/manual only and must not run on app startup.
- A reviewed backup must exist before manual migration execution.
- Restore owner, restore test process, retention policy, and rollback approver must be decided outside the repo.
- If rollback needs database restore, the operator must decide whether to stop Platform traffic, restore from the approved backup, and rerun smoke checks before reopening access.
- No ad hoc destructive SQL or migration execution should be introduced by this briefing.

## Logging/privacy/incident handling requirements

- Logs should use safe categories and must not include secret values, database connection values, cookies, OAuth values, provider identity details, raw app launch tokens, or SQAG private data.
- Decide log retention, log access, redaction owner, incident contact, escalation path, and evidence storage outside the repo.
- Smoke evidence should record pass/fail status, timestamps, command names, and safe categories only.
- If private material appears in logs, screenshots, tickets, or shared notes, stop the hosted window and follow the operator incident path.

## First owner/admin identity approval requirements

- Approve the first owner/admin identity outside the repo before any hosted seed operation.
- The first owner/admin must sign in once through the real hosted OIDC provider so Platform has a provider-backed user.
- The seed path must not create fake users, provider identities, sessions, hidden fallback auth, or sample data.
- The owner/admin identity value must not be committed, rendered in docs, pasted into PRs, or logged in shared artifacts.
- Confirm owner/admin access to `/app/admin`, member/viewer denial, and safe audit/activity evidence during hosted smoke.

## Hosted smoke evidence requirements

Hosted smoke is required after reviewed infrastructure exists and before broader internal-alpha use. Evidence should cover:

- `npm run platform:readiness-check` passed without printing values.
- Manual migration approval and backup prerequisite were recorded outside repo.
- `GET /healthz` reached the hosted Platform process.
- Auth start/callback completed without logging callback query details or provider material.
- `/app` and `/app/admin` loaded for the approved owner/admin.
- Add-existing-user worked only after teammate first sign-in.
- Role change, membership disable/reactivation, SQAG entitlement enable/disable, and audit/activity checks passed.
- SQAG launch mode behaved as approved and did not expose raw launch tokens.
- Logout and missing/expired/disabled session checks failed closed.
- Member/viewer admin access was denied.

Smoke evidence does not create production readiness. It is one input to a hosted internal-alpha go/no-go decision.

## Final go/no-go decision template

Default decision: No-go until approved.

| Decision field | Operator entry |
| --- | --- |
| Decision | `<No-go until approved OR go for reviewed hosted internal-alpha execution window>` |
| Approver | `<go-no-go-approver-placeholder>` |
| Approval evidence location | `<outside-repo-evidence-location-placeholder>` |
| Hosted topology option | `<approved-topology-option-placeholder>` |
| SQAG handoff/session strategy | `<approved-sqag-strategy-placeholder>` |
| Secret/log/incident owners approved | `<yes-or-no-placeholder>` |
| Migration/backup/restore owners approved | `<yes-or-no-placeholder>` |
| First owner/admin identity approved | `<yes-or-no-placeholder>` |
| Hosted smoke evidence reviewed | `<yes-or-no-placeholder>` |
| Remaining blockers | `<blocker-summary-placeholder>` |

If any required approval or smoke evidence is missing, the final decision remains No-go until approved. This briefing does not approve hosted execution and does not claim production readiness.

# Hosted Internal Alpha Operator Decisions

This decision record defines the operator decisions required before any real hosted internal-alpha execution. It is documentation and approval tracking only. It does not deploy, provision, expose, configure, restart, run migrations, connect to databases, call OIDC, call KQAG, seed access, or approve hosted infrastructure.

Hosted deployment is not approved by this PR. Do not deploy until every required decision is approved outside repo.

Related docs:

- `docs/auth-session-security-contract.md`
- `docs/hosted-internal-alpha-runbook.md`
- `docs/internal-alpha-platform-contract.md`
- `docs/roadmap.md`

## Readiness Gate Alignment

PR #55 readiness check only validates env shape and dry-run safety. It does not approve actual deployment.

The readiness checker does not prove OIDC, database, KQAG, backups, rollback, logs, session cookies, or cross-host handoff work. Those require operator approval and smoke testing after reviewed hosted infrastructure exists.

Passing `npm run platform:readiness-check` means only that required hosted env categories and safe URL shapes are present in the current shell. It remains a preflight checklist, not a launch authorization.

The auth/session security contract documents implemented auth/session behavior, intentionally deferred controls, and the pre-alpha gap inventory. It does not add a session-management UI, approve hosted deployment, or replace operator approval and smoke testing.

## Required Decisions

- Platform host/provider choice: decide the reviewed Platform hosting target and who owns its operation outside this repo.
- KQAG host/provider choice: decide the reviewed KQAG hosting target outside this Platform PR.
- TLS/reverse proxy approach: decide how HTTPS termination, forwarded host/protocol handling, and allowed origin expectations are reviewed.
- Process manager/container approach: decide the approved runtime supervisor or container approach without adding deployment config in this PR.
- PostgreSQL provider and backup/restore owner: decide the database provider, backup cadence, restore owner, and restore test process.
- Migration approver and rollback approver: decide who approves manual migrations and who can approve rollback or fix-forward.
- OIDC provider/client owner: decide who owns provider registration, client settings, and hosted auth configuration outside this repo.
- Exact hosted redirect URI placeholder approval process: decide how `<hosted-oidc-redirect-uri>` becomes the reviewed hosted callback value outside repo notes.
- Secret storage owner and rotation owner: decide where secrets are stored, who can read them, and who rotates them.
- Log retention/access owner: decide who owns hosted logs, retention, access review, and redaction process.
- First owner/admin identity approval outside repo: decide the first internal owner/admin identity outside source control.
- Add-existing-user internal alpha process owner: decide who runs and reviews the add-existing-user process after teammates sign in once.
- KQAG handoff mode decision: `manual` first vs `server_handoff`: decide whether hosted alpha starts with manual handoff or reviewed server handoff.
- Cross-host KQAG session/cookie strategy decision before `server_handoff`: decide the hosted browser/session/cookie strategy before enabling cross-host handoff.
- Incident contact/escalation path: decide who receives hosted internal-alpha incidents and how escalation happens.
- Go/no-go approver: decide who can approve starting hosted internal-alpha execution after all required evidence is reviewed.

## Approval Checklist

Every row uses placeholders only. Fill actual owners, providers, domains, identities, secrets, and evidence outside the repo.

| Decision item | Required owner/approver placeholder | Evidence required | Repo impact | Status placeholder |
| --- | --- | --- | --- | --- |
| Platform host/provider choice | `<owner-or-approver-placeholder>` | `<approved-platform-hosting-target-evidence>` | Docs only; no deployment config in this PR. | `<status-placeholder>` |
| KQAG host/provider choice | `<owner-or-approver-placeholder>` | `<approved-kqag-hosting-target-evidence>` | Platform handoff placeholders only; no KQAG repo change. | `<status-placeholder>` |
| TLS/reverse proxy approach | `<owner-or-approver-placeholder>` | `<approved-tls-reverse-proxy-evidence>` | Hosted docs only; no proxy config. | `<status-placeholder>` |
| Process manager/container approach | `<owner-or-approver-placeholder>` | `<approved-process-manager-or-container-evidence>` | Hosted docs only; no runtime supervisor config. | `<status-placeholder>` |
| PostgreSQL provider and backup/restore owner | `<owner-or-approver-placeholder>` | `<approved-database-backup-restore-evidence>` | Hosted docs only; no DB connection or migration. | `<status-placeholder>` |
| Migration approver and rollback approver | `<owner-or-approver-placeholder>` | `<approved-migration-rollback-evidence>` | Migrations stay explicit/manual only. | `<status-placeholder>` |
| OIDC provider/client owner | `<owner-or-approver-placeholder>` | `<approved-oidc-client-evidence>` | Hosted docs only; no provider calls. | `<status-placeholder>` |
| Exact hosted redirect URI placeholder approval process | `<owner-or-approver-placeholder>` | `<approved-hosted-redirect-uri-process-evidence>` | Placeholder docs only; no real hosted URL. | `<status-placeholder>` |
| Secret storage owner and rotation owner | `<owner-or-approver-placeholder>` | `<approved-secret-storage-rotation-evidence>` | Hosted docs only; no secrets committed. | `<status-placeholder>` |
| Log retention/access owner | `<owner-or-approver-placeholder>` | `<approved-log-retention-access-evidence>` | Hosted docs only; no log backend config. | `<status-placeholder>` |
| First owner/admin identity approval outside repo | `<owner-or-approver-placeholder>` | `<approved-first-owner-admin-identity-evidence>` | Hosted docs only; no real identity values. | `<status-placeholder>` |
| Add-existing-user internal alpha process owner | `<owner-or-approver-placeholder>` | `<approved-add-existing-user-process-evidence>` | Existing Platform flow only; no invitation delivery. | `<status-placeholder>` |
| KQAG handoff mode decision: `manual` first vs `server_handoff` | `<owner-or-approver-placeholder>` | `<approved-kqag-handoff-mode-evidence>` | Hosted docs only; no KQAG call. | `<status-placeholder>` |
| Cross-host KQAG session/cookie strategy decision before `server_handoff` | `<owner-or-approver-placeholder>` | `<approved-cross-host-session-cookie-evidence>` | Hosted docs only; no session strategy code. | `<status-placeholder>` |
| Incident contact/escalation path | `<owner-or-approver-placeholder>` | `<approved-incident-escalation-evidence>` | Hosted docs only; no alerting config. | `<status-placeholder>` |
| Go/no-go approver | `<owner-or-approver-placeholder>` | `<approved-go-no-go-evidence>` | Hosted execution remains blocked until approved outside repo. | `<status-placeholder>` |

## Non-Approval Statement

This record is not approved by this PR. It documents what must be approved outside the repo before hosted execution. Do not deploy until every required decision is approved outside repo and the hosted smoke checklist has a reviewed execution window.

Approval evidence should stay outside this repo when it contains real providers, domains, identities, URLs, credentials, database details, OAuth values, cookies, tokens, provider identity material, log exports, or private operational details.

## Platform And KQAG Boundary

Platform does not own KQAG quote data.

KQAG deployment/runtime/data decisions remain outside this Platform PR except for Platform handoff placeholders. Platform may document the handoff mode decision and the placeholder for the KQAG hosted base, but it does not decide or implement KQAG runtime operations in this repo.

No KQAG app-data editing, KQAG profiles/pricing, quote history, generated artifacts, or quote sessions move into Platform.

Platform continues to own auth, users, sessions, workspaces, roles, memberships, app entitlements, app launch checks, and audit events.

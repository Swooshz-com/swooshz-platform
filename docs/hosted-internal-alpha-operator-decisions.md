# Hosted Internal Alpha Operator Decisions

This decision record defines the operator decisions required before any real hosted internal-alpha execution. It is documentation and approval tracking only. It does not deploy, provision, expose, configure, restart, run migrations, connect to databases, call OIDC, call SQAG, seed access, or approve hosted infrastructure.

Hosted deployment is not approved by this PR. Do not deploy until every required decision is approved outside repo.

Related docs:

- `docs/auth-session-security-contract.md`
- `docs/hosted-internal-alpha-operator-briefing.md`
- `docs/hosted-internal-alpha-runbook.md`
- `docs/internal-alpha-platform-contract.md`
- `docs/roadmap.md`

## Readiness Gate Alignment

PR #55 readiness check only validates env shape and dry-run safety. It does not approve actual deployment.

The dry-run readiness checker does not prove OIDC, database, SQAG, backups, rollback, logs, session cookies, or cross-host handoff work. The DB readiness checker can verify configured Postgres reachability plus required Platform schema/migration state, but it still does not approve hosted execution. Those require operator approval and smoke testing after reviewed hosted infrastructure exists.

Passing `npm run platform:readiness-check` means only that required hosted env categories and safe URL shapes are present in the current shell. It remains a preflight checklist, not a launch authorization.

The auth/session security contract documents implemented auth/session behavior, intentionally deferred controls, and the pre-alpha gap inventory. It does not add a session-management UI, approve hosted deployment, or replace operator approval and smoke testing.

## Required Decisions

- Platform host/provider choice: decide the reviewed Platform hosting target and who owns its operation outside this repo.
- SQAG host/provider choice: decide the reviewed SQAG hosting target outside this Platform PR.
- TLS/reverse proxy approach: decide how HTTPS termination, forwarded host/protocol handling, and allowed origin expectations are reviewed.
- Process manager/container approach: decide the approved runtime supervisor or container approach without adding deployment config in this PR.
- PostgreSQL provider and backup/restore owner: approve the recommended Neon target or a replacement provider, backup cadence, restore owner, and restore test process. Recommended non-secret target: project `swooshz-platform`, region `Singapore / aws-ap-southeast-1`, database `swooshz_platform`, role/user `platform_app`, pooled `DATABASE_URL` for runtime.
- Migration approver and rollback approver: decide who approves manual migrations and who can approve rollback or fix-forward.
- OIDC provider/client owner: decide who owns provider registration, client settings, and hosted auth configuration outside this repo.
- Exact hosted callback registration owner: decide who registers `https://swooshz.com/api/platform/auth/callback` with the OIDC provider outside the repo.
- Secret storage owner and rotation owner: decide where secrets are stored, who can read them, and who rotates them.
- Log retention/access owner: decide who owns hosted logs, retention, access review, and redaction process.
- First owner/admin identity approval outside repo: decide the first internal owner/admin identity outside source control.
- Add-existing-user internal alpha process owner: decide who runs and reviews the add-existing-user process after teammates sign in once.
- SQAG `server_handoff` smoke approval: decide who approves the implemented production handoff after hosted evidence passes.
- Host-only SQAG session/finalization evidence: decide who reviews the two host-only cookies, header-only finalization, and live-validation smoke evidence.
- Incident contact/escalation path: decide who receives hosted internal-alpha incidents and how escalation happens.
- Go/no-go approver: decide who can approve starting hosted internal-alpha execution after all required evidence is reviewed.

## Approval Checklist

Every private or operational row uses placeholders only. Fill actual owners, providers, identities, secrets, and evidence outside the repo; public origins use the canonical routing contract.

| Decision item | Required owner/approver placeholder | Evidence required | Repo impact | Status placeholder |
| --- | --- | --- | --- | --- |
| Platform host/provider choice | `<owner-or-approver-placeholder>` | `<approved-platform-hosting-target-evidence>` | Docs only; no deployment config in this PR. | `<status-placeholder>` |
| SQAG host/provider choice | `<owner-or-approver-placeholder>` | `<approved-sqag-hosting-target-evidence>` | Canonical `https://quote.swooshz.com` handoff contract only; no SQAG repo change. | `<status-placeholder>` |
| TLS/reverse proxy approach | `<owner-or-approver-placeholder>` | `<approved-tls-reverse-proxy-evidence>` | Hosted docs only; no proxy config. | `<status-placeholder>` |
| Process manager/container approach | `<owner-or-approver-placeholder>` | `<approved-process-manager-or-container-evidence>` | Hosted docs only; no runtime supervisor config. | `<status-placeholder>` |
| PostgreSQL provider and backup/restore owner | `<owner-or-approver-placeholder>` | `<approved-neon-target-backup-restore-evidence>` | Hosted docs and readiness checks only; no Neon creation, no secrets, no deployment. | `<status-placeholder>` |
| Migration approver and rollback approver | `<owner-or-approver-placeholder>` | `<approved-migration-rollback-evidence>` | Migrations stay explicit/manual only. | `<status-placeholder>` |
| OIDC provider/client owner | `<owner-or-approver-placeholder>` | `<approved-oidc-client-evidence>` | Hosted docs only; no provider calls. | `<status-placeholder>` |
| Exact hosted callback registration owner | `<owner-or-approver-placeholder>` | `<approved-hosted-redirect-uri-process-evidence>` | Register `https://swooshz.com/api/platform/auth/callback`; no provider action in this repo. | `<status-placeholder>` |
| Secret storage owner and rotation owner | `<owner-or-approver-placeholder>` | `<approved-secret-storage-rotation-evidence>` | Hosted docs only; no secrets committed. | `<status-placeholder>` |
| Log retention/access owner | `<owner-or-approver-placeholder>` | `<approved-log-retention-access-evidence>` | Hosted docs only; no log backend config. | `<status-placeholder>` |
| First owner/admin identity approval outside repo | `<owner-or-approver-placeholder>` | `<approved-first-owner-admin-identity-evidence>` | Hosted docs only; no real identity values. | `<status-placeholder>` |
| Add-existing-user internal alpha process owner | `<owner-or-approver-placeholder>` | `<approved-add-existing-user-process-evidence>` | Existing Platform flow only; no invitation delivery. | `<status-placeholder>` |
| SQAG `server_handoff` smoke approval | `<owner-or-approver-placeholder>` | `<approved-sqag-handoff-mode-evidence>` | Hosted evidence only; no SQAG call from this record. | `<status-placeholder>` |
| Host-only SQAG session/finalization evidence | `<owner-or-approver-placeholder>` | `<approved-cross-host-session-cookie-evidence>` | Review the implemented contract and hosted smoke; no live action from this record. | `<status-placeholder>` |
| Incident contact/escalation path | `<owner-or-approver-placeholder>` | `<approved-incident-escalation-evidence>` | Hosted docs only; no alerting config. | `<status-placeholder>` |
| Go/no-go approver | `<owner-or-approver-placeholder>` | `<approved-go-no-go-evidence>` | Hosted execution remains blocked until approved outside repo. | `<status-placeholder>` |

## Non-Approval Statement

This record is not approved by this PR. It documents what must be approved outside the repo before hosted execution. Do not deploy until every required decision is approved outside repo and the hosted smoke checklist has a reviewed execution window.

Approval evidence should stay outside this repo when it contains private provider configuration, identities, credentials, database details, OAuth values, cookies, tokens, provider identity material, log exports, or private operational details. Canonical public origins remain documented in the repo.

## Platform And SQAG Boundary

Platform does not own SQAG quote data.

SQAG deployment/runtime/data decisions remain outside this Platform PR except for the Platform handoff contract. Platform implements and documents its `server_handoff` boundary to the canonical SQAG origin, but it does not decide or implement SQAG runtime operations in this repo.

No SQAG app-data editing, SQAG profiles/pricing, quote history, generated artifacts, or quote sessions move into Platform.

Platform continues to own auth, users, sessions, workspaces, roles, memberships, app entitlements, app launch checks, and audit events.

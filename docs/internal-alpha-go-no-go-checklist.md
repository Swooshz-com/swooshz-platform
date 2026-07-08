# Internal Alpha Go/No-Go Checklist

This reviewer-facing checklist consolidates the internal-alpha platform contract, hosted runbook, operator decision record, dry-run readiness checker, internal smoke runbook, SQAG integration contract, roadmap, and auth/session security contract into one go/no-go review surface.

This document is docs/tests only. It does not deploy, configure hosted infrastructure, run migrations, connect to databases, start servers, call OIDC, call SQAG, seed access, add password auth or 2FA, add a session-management UI, add billing/credits, add Google Stitch, or approve hosted execution.

Related source docs:

- `docs/internal-alpha-platform-contract.md`
- `docs/hosted-internal-alpha-runbook.md`
- `docs/hosted-internal-alpha-operator-decisions.md`
- `docs/hosted-internal-alpha-operator-briefing.md`
- `docs/auth-session-security-contract.md`
- `docs/internal-platform-smoke-runbook.md`
- `docs/sqag-integration-contract.md`
- `docs/roadmap.md`

## Readiness Decision Summary

### Local/internal UAT readiness

The local/internal UAT platform-admin foundation is mostly implemented/documented for a narrow internal-alpha review: provider-backed login, server-side Platform sessions, `/app`, `/app/admin`, owner/admin workspace member administration, pending workspace approval onboarding, SQAG entitlement toggling, audit/activity browsing, fail-closed launch checks, explicit local smoke guidance, and a browser-safe SQAG handoff path are documented and covered by tests.

Go decision: Platform local/internal alpha can proceed only for reviewed local/internal UAT using approved existing services, placeholders in docs, and production-grade security expectations. This is not a public launch and does not claim production readiness.

### Hosted internal-alpha readiness

Hosted execution is still blocked until operator approvals, real infra choices, real OIDC config, hosted SQAG handoff/session strategy, and smoke execution. Passing `npm run platform:readiness-check` only confirms hosted env shape, HTTPS/origin/callback validation, SQAG handoff guardrails, value-safe output, and dry-run safety in the current shell.

Go decision: no-go for actual hosted execution until the hosted operator decision record is approved outside the repo, reviewed hosted infrastructure exists, real hosted values are configured outside source control, manual migrations are explicitly approved if needed, and the hosted smoke checklist passes.

Do not deploy until every required operator decision is approved outside repo and hosted smoke testing is complete. This checklist does not claim production readiness.

SQAG production readiness is separate from this Platform repository. Platform can prove its account, workspace, entitlement, audit, and launch-token boundary without claiming SQAG quote-workflow, runtime, hosted handoff, or production readiness.

## Product/admin surface

| Checklist item | Current status | Evidence/source doc or source file | Go/no-go decision | Notes |
| --- | --- | --- | --- | --- |
| Minimal `/app` shell for internal app access | Implemented | `README.md`; `docs/internal-alpha-platform-contract.md`; `src/http/platform-shell.ts`; `tests/platform-shell.test.mjs` | Go for local/internal UAT | Functional shell only; not a polished dashboard or marketing UI. |
| Minimal `/app/admin` owner/admin surface | Implemented | `docs/internal-alpha-platform-contract.md`; `src/http/platform-shell.ts`; `tests/platform-shell.test.mjs`; `tests/http-admin-routes.test.mjs` | Go for local/internal UAT | Supports current member, pending approval, entitlement, and activity workflows. |
| Google Stitch / UI polish | Deferred | `docs/internal-alpha-platform-contract.md`; `docs/roadmap.md` | No-go until separately approved | No Google Stitch or visual redesign is started by this checklist. |

## Auth/session security

| Checklist item | Current status | Evidence/source doc or source file | Go/no-go decision | Notes |
| --- | --- | --- | --- | --- |
| Generic OIDC login and provider-backed user requirement | Implemented | `docs/auth-session-security-contract.md`; `src/http/auth-handlers.ts`; `src/auth/callback-service.ts`; `tests/auth-http-handlers.test.mjs` | Go for reviewed provider-backed UAT | Real provider configuration remains outside repo notes. Pending approvals still require real OIDC sign-in before membership activation. |
| Server-side sessions, HttpOnly/SameSite cookies, and secure production cookie requirement | Implemented | `docs/auth-session-security-contract.md`; `src/http/session-cookie.ts`; `src/http/runtime-config.ts`; `tests/http-session-cookie.test.mjs` | Go for local/internal UAT; hosted go blocked on HTTPS config | Hosted production must use secure cookies over HTTPS. |
| CSRF/origin protections for browser-cookie mutations | Implemented | `docs/auth-session-security-contract.md`; `src/http/request-security.ts`; `src/http/route-contracts.ts`; `tests/http-request-security.test.mjs` | Go for current protected routes | Preserve fail-closed behavior for future browser-cookie mutations. |
| Password auth and 2FA | Deferred | `docs/auth-session-security-contract.md` | No-go for this PR | No password auth or 2FA is added. |
| Security/session management UI | Deferred | `docs/auth-session-security-contract.md`; `docs/internal-alpha-platform-contract.md` | No-go until future product/admin surface | Includes account security page and broader security management UI. |
| Revoke-other-sessions | Deferred | `docs/auth-session-security-contract.md`; `src/auth/session-revocation-service.ts` | No-go until future security surface | Current logout revokes the current session only. |
| Active-session viewer | Deferred | `docs/auth-session-security-contract.md`; `docs/internal-alpha-platform-contract.md` | No-go until future security surface | Workspace-wide active-session viewer remains future work. |
| Auth failure dashboard | Deferred | `docs/auth-session-security-contract.md`; `src/http/auth-handlers.ts` | No-go until future observability surface | Current diagnostics remain category-only. |
| Rate limiting/lockout | Deferred | `docs/auth-session-security-contract.md` | No-go until reviewed control exists | Do not overclaim throttling or lockout as implemented. |

## Workspace/team management

| Checklist item | Current status | Evidence/source doc or source file | Go/no-go decision | Notes |
| --- | --- | --- | --- | --- |
| Owner/admin workspace member listing | Implemented | `docs/internal-alpha-platform-contract.md`; `src/platform/workspace-admin-service.ts`; `tests/workspace-admin-service.test.mjs` | Go for local/internal UAT | Uses safe user and membership summaries. |
| Pending workspace approval onboarding | Implemented | `docs/hosted-internal-alpha-runbook.md`; `src/platform/workspace-admin-service.ts`; `tests/http-admin-routes.test.mjs`; `tests/auth-platform-identity-resolver.test.mjs` | Go for internal-alpha onboarding | Owner/admin can create a pending approval before sign-in; real OIDC sign-in activates the pending approval and creates membership through normal role and entitlement gates. Existing provider-backed users are still added immediately. No invitation delivery occurs. |
| Role change and membership disable/reactivation guardrails | Implemented | `docs/internal-alpha-platform-contract.md`; `src/platform/workspace-admin-service.ts`; `tests/workspace-admin-service.test.mjs` | Go for local/internal UAT | Last-owner, self-change, and owner-reactivation guardrails remain required. |
| Full invitation acceptance flow | Deferred | `docs/auth-session-security-contract.md`; `docs/internal-alpha-platform-contract.md` | No-go until separately approved | Email invitation delivery, links, tokens, and invitation acceptance are not added. |
| Disabled non-owner membership reactivation | Implemented | `docs/hosted-internal-alpha-runbook.md`; `docs/internal-alpha-platform-contract.md`; `tests/workspace-admin-service.test.mjs` | Go for local/internal UAT | Add-existing-user still does not reactivate memberships; owners/admins use the explicit reactivation action. |
| First-class `operator` role | Future | `docs/internal-alpha-platform-contract.md`; `docs/roadmap.md` | No-go until schema and policy PR | Quote operators remain mapped to `member` for internal alpha. |

## App entitlement/SQAG launch

| Checklist item | Current status | Evidence/source doc or source file | Go/no-go decision | Notes |
| --- | --- | --- | --- | --- |
| SQAG entitlement enable/disable for owner/admin | Implemented | `docs/internal-alpha-platform-contract.md`; `src/platform/workspace-admin-service.ts`; `tests/http-admin-routes.test.mjs` | Go for local/internal UAT | Platform manages entitlement state only. |
| SQAG launch access decision | Implemented | `docs/sqag-integration-contract.md`; `src/access/decide-app-access.ts`; `tests/account-domain.test.mjs`; `tests/platform-app-access-service.test.mjs` | Go for current roles | Owner/admin/member launch is allowed when workspace and entitlement are active; viewer remains denied. Future apps inherit the blocked viewer launch default until an explicit read-only product policy is approved. |
| Header-only one-time app launch token consume | Implemented | `docs/sqag-integration-contract.md`; `docs/auth-session-security-contract.md`; `src/platform/app-launch-token-consume-service.ts`; `tests/app-launch-token-consume-service.test.mjs` | Go for current contract | Consume is POST and token-consuming; it is not a read-only browser-session route. |
| Hosted SQAG handoff/session strategy | Blocked until operator approval | `docs/hosted-internal-alpha-operator-decisions.md`; `docs/hosted-internal-alpha-runbook.md` | No-go for hosted execution | Cross-host session/cookie strategy must be approved and smoke-tested outside this PR. |

## Audit/activity

| Checklist item | Current status | Evidence/source doc or source file | Go/no-go decision | Notes |
| --- | --- | --- | --- | --- |
| Privacy-minimized audit events for admin actions | Implemented | `docs/internal-alpha-platform-contract.md`; `src/platform/workspace-admin-service.ts`; `tests/workspace-admin-service.test.mjs`; `tests/auth-platform-identity-resolver.test.mjs` | Go for local/internal UAT | Covers membership add, membership approval create/revoke/accept, role change, membership disable, membership reactivation, and SQAG entitlement changes. |
| Owner/admin activity browsing | Implemented | `docs/internal-alpha-platform-contract.md`; `src/http/handlers.ts`; `tests/http-admin-routes.test.mjs` | Go for local/internal UAT | Recent activity browsing is minimal and read-only. |
| Audit export/filtering/retention | Deferred | `docs/internal-alpha-platform-contract.md`; `docs/roadmap.md` | No-go until future audit PR | Export, filtering, and retention workflow decisions remain future work. |

## Hosted readiness

| Checklist item | Current status | Evidence/source doc or source file | Go/no-go decision | Notes |
| --- | --- | --- | --- | --- |
| Hosted runbook and smoke checklist | Documented | `docs/hosted-internal-alpha-runbook.md` | Go as documentation only | Does not approve deployment by itself. |
| Dry-run readiness checker | Implemented | `scripts/platform-readiness-check.mjs`; `tests/platform-readiness-check.test.mjs`; `docs/hosted-internal-alpha-runbook.md` | Go as preflight validation only | Does not call OIDC, SQAG, databases, migrations, servers, or seed commands. |
| Hosted production/HTTPS/origin/callback guardrails | Implemented | `docs/hosted-internal-alpha-runbook.md`; `tests/platform-readiness-check.test.mjs` | Go as hosted env-shape validation | Real hosted values must remain outside repo and be reviewed by operators. |
| Actual hosted deployment execution | Blocked until operator approval | `docs/hosted-internal-alpha-operator-decisions.md`; `docs/hosted-internal-alpha-runbook.md` | No-go until approvals and smoke pass | No deployment/config/runtime code is added here. |

## Operator approvals

| Checklist item | Current status | Evidence/source doc or source file | Go/no-go decision | Notes |
| --- | --- | --- | --- | --- |
| Hosted operator decision record | Documented | `docs/hosted-internal-alpha-operator-decisions.md` | No-go until every required decision is approved outside repo | Includes host/provider, TLS/proxy, process/container, database, migration, OIDC, secret, log, identity, SQAG handoff, incident, and go/no-go approvals. |
| Hosted operator briefing | Documented | `docs/hosted-internal-alpha-operator-briefing.md` | No-go until approvals and smoke pass | Concise operator-facing decision pack; planning guidance only, not hosted approval. |
| Real infra choices | Blocked until operator approval | `docs/hosted-internal-alpha-operator-decisions.md` | No-go for hosted execution | Host, process manager/container, database, backup/restore, TLS, logs, and incident path remain outside repo. |
| Real OIDC config | Blocked until operator approval | `docs/hosted-internal-alpha-runbook.md`; `docs/hosted-internal-alpha-operator-decisions.md` | No-go for hosted execution | Provider client values and redirect registration remain outside source control. |
| Production observability/alerts | Future | `docs/hosted-internal-alpha-runbook.md`; `docs/auth-session-security-contract.md` | No-go until approved operations surface | Request ids, alert thresholds, retention, and dashboards remain future work. |

## Platform/SQAG boundary

| Checklist item | Current status | Evidence/source doc or source file | Go/no-go decision | Notes |
| --- | --- | --- | --- | --- |
| Platform ownership boundary | Documented | `README.md`; `docs/internal-alpha-platform-contract.md`; `docs/sqag-integration-contract.md` | Go for current platform scope | Platform owns auth, users, sessions, workspaces, roles, memberships, app entitlements, app launch checks, and audit events. |
| SQAG ownership boundary | Documented | `docs/sqag-integration-contract.md`; `docs/auth-session-security-contract.md` | Go only if boundary remains intact | Platform does not own SQAG quote data. |
| SQAG app-data movement into Platform | Deferred | `docs/sqag-integration-contract.md`; `docs/internal-alpha-platform-contract.md` | No-go | SQAG owns quote generation, profiles, pricing references, quote sessions, generated artifacts, and quote dashboard/history. No SQAG app-data editing, SQAG profiles/pricing, quote history, generated artifacts, or quote sessions move into Platform. |

## Privacy/logging/secrets

| Checklist item | Current status | Evidence/source doc or source file | Go/no-go decision | Notes |
| --- | --- | --- | --- | --- |
| Placeholder-only hosted docs | Documented | `docs/hosted-internal-alpha-runbook.md`; `docs/hosted-internal-alpha-operator-decisions.md`; this checklist | Go for docs review | Real hosted values, identities, domains, URLs, credentials, and private operational evidence stay outside repo. |
| Secret/value-safe readiness output | Implemented | `scripts/platform-readiness-check.mjs`; `tests/platform-readiness-check.test.mjs` | Go for dry-run validation | Output is limited to env names, categories, and safe failure reasons. |
| Privacy-safe logs and screenshots guidance | Documented | `docs/hosted-internal-alpha-runbook.md`; `docs/internal-platform-smoke-runbook.md` | Go for runbook review | Do not paste real private values, auth material, DB material, browser session material, provider identity material, or SQAG private data into repo notes. |

## Known deferred items

| Checklist item | Current status | Evidence/source doc or source file | Go/no-go decision | Notes |
| --- | --- | --- | --- | --- |
| Full invitation acceptance flow | Deferred | `docs/auth-session-security-contract.md`; `docs/internal-alpha-platform-contract.md` | No-go until separate PR | Pending workspace approval onboarding is implemented; email invitation delivery, links, tokens, and invitation acceptance remain separate future scope. |
| Audit export/filtering/retention | Deferred | `docs/internal-alpha-platform-contract.md`; `docs/roadmap.md` | No-go until separate audit PR | Current activity browsing is minimal. |
| Security/session management UI | Deferred | `docs/auth-session-security-contract.md`; `docs/internal-alpha-platform-contract.md` | No-go until future product/admin surface | Includes account security and session review surfaces. |
| Revoke-other-sessions | Deferred | `docs/auth-session-security-contract.md` | No-go until future security PR | Current logout revokes only the current session. |
| Active-session viewer | Deferred | `docs/auth-session-security-contract.md` | No-go until future security PR | Workspace-wide and account-level session viewers remain future work. |
| Auth failure dashboard | Deferred | `docs/auth-session-security-contract.md` | No-go until future observability PR | Current auth diagnostics are category-only. |
| Rate limiting/lockout | Deferred | `docs/auth-session-security-contract.md` | No-go until reviewed control exists | Manual/operator incident process covers narrow alpha until approved controls exist. |
| First-class `operator` role | Future | `docs/internal-alpha-platform-contract.md`; `docs/roadmap.md` | No-go until schema and access policy PR | `member` remains the internal-alpha quote-operator mapping. |
| Google Stitch / UI polish | Future | `docs/internal-alpha-platform-contract.md`; `docs/roadmap.md` | No-go until approved IA and visual work | No visual redesign is started here. |
| Billing/credits | Future | `README.md`; `docs/roadmap.md`; `docs/sqag-integration-contract.md` | No-go until Phase 6 approval | No billing or credits are added. |
| Production observability/alerts | Future | `docs/hosted-internal-alpha-runbook.md`; `docs/auth-session-security-contract.md` | No-go until operations approval | Logs, retention, alerts, and dashboards need separate owner approval. |
| Actual hosted deployment execution | Blocked until operator approval | `docs/hosted-internal-alpha-operator-decisions.md`; `docs/hosted-internal-alpha-runbook.md` | No-go until approvals and smoke pass | This checklist documents the gate only. |

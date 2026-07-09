# Swooshz Platform Production Readiness Roadmap

Production readiness is not yet approved.

Goal: prod-ready, not just MVP. This roadmap is a living launch checklist for Swooshz Platform. Codex must update it gate-by-gate as PRs merge, blockers change, or operator evidence is reviewed.

This checklist covers Platform readiness only. Platform owns auth, provider identities, sessions, workspaces, roles/memberships, app registry, entitlements, launch checks/tokens, audit/activity events, hosted runbooks/operator decisions, and future billing/credits when approved. Platform must not own product workflow/runtime data. Swooshz Quote Auto Generator and SKR hosted readiness stay separate unless a future task explicitly scopes them.

Non-goals for this roadmap update:

- No deployment.
- No DNS configuration.
- No real OAuth values.
- No secrets or private values.
- No request for the user to paste secrets.
- No SEO/GEO/Seozilla integration.
- No hosted Swooshz Quote Auto Generator launch integration.
- No local/demo/fallback business-state behavior.
- No product workflow/runtime data in Platform.
- No production-readiness approval claim.

## Current Status Summary

| Status | Count / notes |
| --- | --- |
| Done | Gate 0 foundation items with merged-code, merged-doc, and local-test evidence are checked below. |
| In progress | Hosted readiness documentation, env checks, DB readiness tooling, repo-side CI/container readiness, admin/member flows, audit/activity, and launch-token contracts exist, but hosted smoke evidence is not recorded. |
| Frontend visual freeze candidate | A 34-screen Stitch visual/layout freeze candidate exists and is recorded in `docs/frontend-stitch-visual-freeze-parity-plan.md`; scoped public, portal, workspace-admin, access-information, and resources slices are locally implemented after PRs #86-#90, but full frontend launch clearance, production copy, consolidated screenshot parity, and hosted visual evidence remain unchecked. |
| Blocked until VPS/shared hosting foundation | Gate 1 and Platform hosted deployment execution are blocked until the shared Hostinger/Coolify foundation exists. That foundation is shared across Platform, SQAG, and SKR; it must not become Platform-only. |
| Blocked until SQAG/SKR hosting readiness | Shared VPS purchase/use is intentionally waiting for SQAG and SKR to reach hosting readiness; Platform must not assume the VPS already exists. |
| Can be worked before VPS | Security hardening review, backup/restore procedure detail, monitoring/incident decisions, legal/compliance drafts, session-management planning, rate-limit review, and roadmap updates can continue without live hosting. Pre-VPS planning templates now exist, but they are not hosted evidence or production approval. |

## Next Recommended Pre-VPS Work

- Use `docs/platform-pre-vps-security-hardening.md` to review security hardening items that do not need live hosting: CSRF smoke plan, rate limiting posture, session expiry/rotation posture, security headers, dependency/security audit cadence, and secret rotation plan. Keep hosted evidence unchecked until the hosted environment exists and smoke is separately approved.
- Use `docs/platform-final-go-no-go-checklist.md` to track legal/compliance and launch governance placeholders: privacy policy, terms, data retention policy, account/member removal policy, vendor/subprocessor notes, and final go/no-go owner. Do not treat the checklist template as launch approval.
- Use `docs/platform-backup-restore-evidence-template.md` for future operator-owned restore evidence. It records sanitized fields only and is not backup/restore evidence until a real approved restore test produces reviewed evidence.
- Use `docs/platform-secret-rotation-runbook.md` for secret rotation planning with env names only. Do not add or request real secret values.
- Keep the frontend design readiness gate in `docs/frontend-design-readiness.md`, the Stitch parity plan in `docs/frontend-stitch-visual-freeze-parity-plan.md`, and the current audit in `docs/frontend-readiness-audit.md` aligned before any further public website, Blog/resources, portal, customer admin, or internal admin/content admin implementation. Do not tick frontend work complete without implemented UI, canonical copy corrections, deterministic tests, screenshot parity evidence, and later hosted evidence after deployment is separately approved.
- Review repo-side CI/container readiness in `docs/ci-cd/CURRENT_CICD_STATUS.md` and `docs/coolify-deployment-readiness.md`; keep it separate from hosted deployment evidence.
- Keep SQAG/SKR hosting-readiness work separate from Platform. Do not purchase or configure the shared VPS from this Platform roadmap alone.
- Update this roadmap immediately after any relevant merged PR or blocker, using the rules below.

## Checklist Update Rules For Codex

- Codex must update this roadmap after every relevant merged PR or blocker.
- Codex must not tick a checkbox without evidence.
- Codex must add the PR number/commit or sanitized operator evidence next to completed items.
- Codex must leave blocked items unchecked and add the next action.
- Codex must not claim production readiness until every launch-critical gate is complete and final go/no-go is recorded.
- Codex must not paste or request secrets.
- Codex must treat local success as useful local evidence only; local success is not hosted evidence.
- Codex must treat docs-only readiness as planning evidence only; docs-only readiness is not deployed evidence.
- Codex must not treat the Stitch visual freeze candidate as frontend implementation or hosted visual evidence.
- Codex must distinguish Platform, SQAG, and SKR responsibilities.
- Codex must not use screenshots, logs, PRs, or docs to store real domains, private staff identities, OAuth values, cookies, tokens, database URLs, provider console values, backup exports, table data, or product runtime data.

## Frontend Visual Freeze And Implementation Gate

Gate status: partially implemented locally, not hosted-verified. The 34-screen Stitch visual freeze candidate exists and is approved as visual/layout reference only. Raw Stitch copy is not production copy, and canonical copy override rules must be applied before screenshot parity is judged. PRs #86-#90 implemented the currently scoped public, portal, workspace-admin, access-information, and resources slices locally, but this does not approve hosted visual evidence, production copy, or final frontend launch clearance.

Hosted OAuth/provider configuration remains unchecked, and the existing hosted Platform deployment, hosted Swooshz Quote Auto Generator deployment, live Platform-to-Swooshz Quote Auto Generator smoke, monitoring/logging/alerting, backup/restore, and final go/no-go gates remain unchecked.

- [ ] Frontend implementation complete.
  Blocker: Scoped slices are locally implemented, but production copy, full consolidated parity review, hosted evidence, access-status nuance, and future internal admin/content admin decisions remain incomplete or out of scope.
  Next action: Treat `docs/frontend-readiness-audit.md` as the current local frontend audit. Do not add new Platform frontend features unless a clear copy, accessibility, or safety blocker is found; otherwise return to SQAG/SKR hosting readiness and shared-hosting prerequisites.
  Evidence required: Implemented routes/components, deterministic tests, screenshot parity review against all approved scopes, production copy approval, hosted visual review after deployment is separately approved, and confirmation that canonical copy overrides were applied.
- [ ] Hosted visual evidence complete.
  Blocker: No reviewed hosted Platform deployment exists.
  Next action: After hosted deployment is separately approved and completed, capture sanitized hosted visual evidence for implemented public and portal surfaces.
  Evidence required: Sanitized hosted screenshots or visual smoke notes with no private paths, private identities, secrets, cookies, tokens, provider values, table exports, or product runtime data.
- [ ] Production copy approved.
  Blocker: Raw Stitch copy is not production copy.
  Next action: Review public site, Blog/resources, access, member, entitlement, audit, and product-copy strings against `docs/frontend-stitch-visual-freeze-parity-plan.md`.
  Evidence required: Approved copy review showing Swooshz Quote Auto Generator naming, SEO/GEO/Seozilla pending status, safe entitlement wording, role vocabulary, safe audit events, and draft Blog/resources boundaries.

## Gate 0: Current Foundation Already Completed

Gate status: completed only for the specific items below. This gate does not approve hosted deployment or final launch.

- [x] DB-backed users/workspaces/memberships.
  Evidence: Drizzle schema and repositories cover `users`, `provider_identities`, `workspaces`, `memberships`, `sessions`, `app_entitlements`, `audit_events`, and related tables in `src/db/schema.ts` and `src/db/repositories.ts`; covered by `tests/db-schema.test.mjs`, `tests/db-repositories.test.mjs`, and default `npm test` scope on `main`.
- [x] Pending workspace member approval.
  Evidence: PR #70 `b8a148f` ("Add pending workspace approval onboarding"); implemented in `src/platform/workspace-admin-service.ts` and `src/auth/platform-identity-resolver.ts`; covered by `tests/workspace-admin-service.test.mjs`, `tests/auth-platform-identity-resolver.test.mjs`, and `tests/http-admin-routes.test.mjs`.
- [x] Removed-member denial.
  Evidence: PR #71 `dc99f05` and PR #72 `38f973d`; removed or disabled memberships fail closed through app-access decisions in `src/access/decide-app-access.ts`, `src/platform/protected-app-access-service.ts`, and launch-token services; covered by `tests/account-domain.test.mjs`, `tests/app-launch-intent-service.test.mjs`, `tests/app-launch-token-consume-service.test.mjs`, and `tests/workspace-admin-service.test.mjs`.
- [x] Session revocation on removal.
  Evidence: PR #73 `6a142fe` ("Revoke removed member sessions"); `removeWorkspaceMembership` revokes active sessions in `src/platform/workspace-admin-service.ts`; covered by `tests/workspace-admin-service.test.mjs` and documented in `docs/auth-session-security-contract.md`.
- [x] Neon readiness checks.
  Evidence: PR #75 `15d2686` and PR #76 `7477b37`; `npm run platform:db-readiness-check` checks sanitized DB config, reachability, required tables, and Drizzle migration state through `scripts/platform-db-readiness-check.mjs` and `src/db/readiness.ts`; covered by `tests/platform-db-readiness-check.test.mjs`.
- [x] Neon migrated and readiness `ready`.
  Evidence: PR #77 `60cd5e2`; sanitized operator evidence in `docs/hosted-internal-alpha-runbook.md` records pre-migration DB readiness `schema_not_ready`, guarded manual migration through `npm run db:migrate`, and post-migration DB readiness `ready`. No secret values are recorded.
- [x] Hostinger/Coolify deployment readiness docs.
  Evidence: PR #78 `5662901` ("Add Hostinger Coolify deployment readiness"); `docs/hosted-internal-alpha-runbook.md` documents future Hostinger/Coolify app shape, build command `npm run build`, start command `npm run platform:start`, health check `/healthz`, env/secret categories, and no migration/seed hooks.
- [x] Production fail-closed hosted URL validation.
  Evidence: hosted readiness docs and `scripts/platform-readiness-check.mjs` require production mode, HTTPS browser/provider-facing URLs, origin-only allowed origins, callback path shape, valid Postgres-shaped `DATABASE_URL`, secure cookies, and safe output; covered by `tests/platform-readiness-check.test.mjs` and `tests/hosted-internal-alpha-runbook.test.mjs`.
- [x] Repo-side CI and container readiness.
  Evidence: this readiness PR adds `.github/workflows/ci.yml` gates for deterministic repository guardrails, dependency install, `npm run typecheck`, `npm run build`, `npm test`, and Docker image build without push/deploy; adds `Dockerfile`, `.dockerignore`, `docs/ci-cd/CURRENT_CICD_STATUS.md`, and `docs/coolify-deployment-readiness.md`; covered by `tests/ci-container-readiness.test.mjs`.

## Gate 1: Hostinger/Coolify Shared Hosting Foundation Gate

Gate status: blocked. This Hostinger/Coolify shared hosting foundation gate is shared across Platform, SQAG, and SKR. It is not Platform-only, and Platform must not assume the VPS exists yet.

- [ ] Hostinger VPS created.
  Blocker: User is waiting for SQAG and SKR hosting readiness before purchasing the shared VPS.
  Next action: Revisit only after SQAG/SKR hosting readiness is separately recorded and the user approves the shared VPS purchase/setup window.
  Evidence required: Sanitized operator evidence that the shared VPS exists, with owner and purpose recorded outside repo secrets.
- [ ] Coolify installed/reachable.
  Blocker: No shared VPS exists yet.
  Next action: After VPS creation, record Coolify owner, access policy, and reachability without exposing admin URLs, credentials, or screenshots.
  Evidence required: Sanitized operator evidence that Coolify is reachable by approved operators.
- [ ] DNS/TLS baseline ready.
  Blocker: No hosted domains/TLS decisions are approved for the shared foundation.
  Next action: Decide shared DNS/TLS owner and per-app hostname strategy outside repo.
  Evidence required: Sanitized TLS/DNS baseline note with no provider console values or secrets.
- [ ] GitHub connection ready.
  Blocker: Coolify is not installed/reachable.
  Next action: Connect the shared foundation to GitHub only after operator approval.
  Evidence required: Sanitized note that the correct repo access is configured, with no tokens or private screenshots.
- [ ] Firewall/server access policy decided.
  Blocker: Shared VPS security posture is not decided.
  Next action: Decide operator access, open ports, admin interface exposure, and emergency access.
  Evidence required: Sanitized firewall/server access decision record.
- [ ] Logs/restart/backup posture decided.
  Blocker: Shared foundation owner and process model are not yet approved.
  Next action: Decide log retention, restart policy, backup owner, restore owner, and evidence storage for shared apps.
  Evidence required: Sanitized shared-host operations decision record.

## Gate 2: Platform Hosted Deployment Gate

Gate status: blocked until Gate 1 exists and Platform hosted values are injected outside source control. This hosted deployment gate cannot be completed with docs-only evidence.

- [ ] Coolify Platform app created.
  Blocker: Shared Coolify foundation does not exist.
  Next action: Create the Platform app only in a reviewed hosted execution window.
  Evidence required: Sanitized operator evidence that the Platform app exists in Coolify, without admin URLs or secrets.
- [ ] Build command `npm run build`.
  Blocker: Not configured in hosted Coolify yet.
  Next action: Configure only after Coolify app creation.
  Evidence required: Hosted build configuration evidence plus build log summary with no secret values.
- [ ] Start command `npm run platform:start`.
  Blocker: Not configured in hosted Coolify yet.
  Next action: Configure only after hosted env and secrets are ready.
  Evidence required: Hosted start configuration evidence plus safe startup log summary.
- [ ] Health check `/healthz`.
  Blocker: No hosted Platform service exists.
  Next action: Add health check after service creation.
  Evidence required: Hosted `/healthz` smoke result and status/timestamp.
- [ ] Secret/env injection.
  Blocker: Secret storage owner and hosted env values are not approved.
  Next action: Configure real values outside the repo in the hosting secret/env store.
  Evidence required: Sanitized env category checklist showing required names present, not values.
- [ ] Hosted env readiness check.
  Blocker: Hosted env does not exist.
  Next action: Run `npm run platform:readiness-check` in the hosted env shape.
  Evidence required: Sanitized command result with pass/fail categories only.
- [ ] Hosted DB readiness check returns `ready`.
  Blocker: Hosted app env is not configured against the migrated Neon target.
  Next action: Run `npm run platform:db-readiness-check` from a reviewed hosted/operator shell.
  Evidence required: Sanitized `ready` result with timestamp, no connection values.
- [ ] No migrations/seeding in build/start/deploy/restart/health checks.
  Blocker: Hosted process configuration does not exist yet.
  Next action: Review Coolify hooks, commands, jobs, and health checks before start.
  Evidence required: Sanitized process configuration review confirming no `npm run db:migrate` or `npm run platform:seed-internal-access` in normal lifecycle hooks.

## Gate 3: Hosted OAuth/Auth/Member Smoke Gate

Gate status: blocked until hosted deployment exists and real OAuth/provider configuration is completed outside the repo. This hosted OAuth/auth/member smoke gate must use hosted evidence, not local UAT.

- [ ] Hosted Google OAuth client/redirect configured outside repo.
  Blocker: Hosted Platform URL and provider client are not approved/configured.
  Next action: Configure provider console outside repo after hosted base URL is finalized.
  Evidence required: Sanitized operator note that redirect ends with `/api/platform/auth/callback`, without client secret, auth codes, query strings, or screenshots.
- [ ] Login/logout smoke.
  Blocker: Hosted OAuth and app service do not exist.
  Next action: Run hosted login/logout only after provider setup.
  Evidence required: Sanitized smoke result with route names, status categories, and timestamp.
- [ ] First owner/admin bootstrap.
  Blocker: Hosted owner/admin identity is not approved outside repo and hosted login has not occurred.
  Next action: Approve first owner/admin identity outside repo, complete real OIDC login, then run the seed only as a reviewed one-off.
  Evidence required: Sanitized owner/admin bootstrap result; no real email or seed env values.
- [ ] Pending member activation.
  Blocker: Hosted owner/admin and teammate smoke users are not approved.
  Next action: Create pending approval from `/app/admin`, complete real OIDC sign-in for the matching user, and verify activation.
  Evidence required: Sanitized audit/activity event types and pass/fail result.
- [ ] Remove/disable member denial.
  Blocker: Hosted member smoke users are not configured.
  Next action: Disable/remove a non-owner member in hosted smoke workspace and confirm app/admin/launch denial.
  Evidence required: Sanitized hosted smoke result and relevant audit event types.
- [ ] Removed member cannot regain access through Google sign-in.
  Blocker: Hosted provider smoke has not run.
  Next action: Attempt sign-in after removal and confirm no active workspace membership or matching pending approval allows a new session.
  Evidence required: Sanitized denial category and timestamp; no provider payload or private identity values.
- [ ] Audit/activity actor/target smoke.
  Blocker: Hosted admin mutations have not run.
  Next action: Confirm `/app/admin` Activity shows actor/target/event/timestamp with privacy-minimized metadata only.
  Evidence required: Sanitized event-type list and pass/fail status; no raw table data.

## Gate 4: Backup/Restore Gate And Migration Operations

Gate status: mostly blocked until shared hosting operations are decided. Some procedure detail can be worked before VPS.

- [x] Backup/restore evidence template drafted.
  Evidence: `docs/platform-backup-restore-evidence-template.md` records sanitized evidence fields and explicitly states that the template is not evidence until a real approved restore test occurs; covered by `tests/platform-pre-vps-security-hardening.test.mjs`.
- [ ] Backup owner.
  Blocker: Shared foundation operations owner is not decided.
  Next action: Name the backup owner outside repo planning notes.
  Evidence required: Sanitized owner/approver record.
- [ ] Restore target.
  Blocker: Restore environment/target is not decided.
  Next action: Choose a restore target separate from production runtime.
  Evidence required: Sanitized restore target decision with no connection details.
- [ ] Restore test evidence.
  Blocker: No restore target or hosted execution window exists.
  Next action: Run a restore test only after provider and target are approved.
  Evidence required: Sanitized restore test result with timestamp and pass/fail status; no backup export.
- [ ] Migration approval procedure.
  Blocker: Migration approver is documented as required but not approved for production launch.
  Next action: Convert hosted runbook procedure into an operator approval template.
  Evidence required: Approved migration approver and guarded command evidence using `DATABASE_MIGRATIONS_CONFIRM=apply-reviewed-migrations`.
- [ ] Rollback/fix-forward decision.
  Blocker: Rollback approver and restore owner are not approved.
  Next action: Decide when to restore vs fix forward for reviewed additive migrations.
  Evidence required: Sanitized rollback/fix-forward decision record.
- [ ] No automatic app-start migrations.
  Blocker: Hosted process configuration does not exist yet.
  Next action: Re-review after Coolify app/hook configuration.
  Evidence required: Process configuration evidence showing migrations are absent from build/start/deploy/restart/health hooks.

## Gate 5: Logging/Monitoring/Incident Gate

Gate status: blocked until shared hosting and Platform hosted process exist. Logging/monitoring/incident gate planning can continue before VPS.

- [x] Monitoring/logging/incident planning placeholders drafted.
  Evidence: `docs/platform-pre-vps-security-hardening.md` and `docs/platform-final-go-no-go-checklist.md` list required owner, retention, alert destination, and incident placeholders while preserving that real monitoring/logging/alerting evidence remains pending; covered by `tests/platform-pre-vps-security-hardening.test.mjs`.
- [ ] Coolify log retention.
  Blocker: Coolify foundation does not exist.
  Next action: Decide retention duration, access owner, and redaction process.
  Evidence required: Sanitized log retention/access decision.
- [ ] Secret-safe log review.
  Blocker: Hosted app logs do not exist.
  Next action: Review startup, auth, admin, launch, and error logs after hosted smoke.
  Evidence required: Sanitized log review result confirming no secrets, cookies, OAuth material, database values, or product runtime data.
- [ ] Uptime monitoring.
  Blocker: Hosted endpoint does not exist.
  Next action: Configure monitor after `/healthz` is hosted.
  Evidence required: Monitor target status, owner, and alert policy without secret URLs.
- [ ] Error monitoring or equivalent.
  Blocker: Error-monitoring owner/tool is not decided.
  Next action: Choose error monitoring, log-based alerting, or an equivalent manual process for early launch.
  Evidence required: Sanitized decision record and smoke evidence.
- [ ] Incident owner.
  Blocker: Incident contact/escalation path is not approved.
  Next action: Name owner and escalation route outside repo.
  Evidence required: Sanitized incident owner record.
- [ ] Incident checklist.
  Blocker: Incident process is not drafted for Platform/SQAG/SKR shared hosting.
  Next action: Draft a checklist that separates Platform account/access incidents from product runtime incidents.
  Evidence required: Approved incident checklist with no private data.
- [ ] Alert destination.
  Blocker: Alert destination is not approved.
  Next action: Decide where alerts go and who can view them.
  Evidence required: Sanitized alert destination record.

## Gate 6: Security Hardening Gate

Gate status: partially implemented locally, not hosted-verified. Security hardening gate completion requires hosted evidence where browser/runtime behavior depends on hosted deployment.

- [x] Pre-VPS security hardening plan documented.
  Evidence: `docs/platform-pre-vps-security-hardening.md` records CSRF smoke expectations, origin/referer expectations, session/cookie posture, security-header posture, rate limiting posture, dependency/security audit cadence planning, incident placeholders, legal/compliance placeholders, and final go/no-go ownership boundaries; covered by `tests/platform-pre-vps-security-hardening.test.mjs`.
- [x] Secret rotation runbook drafted with env names only.
  Evidence: `docs/platform-secret-rotation-runbook.md` documents routine rotation and emergency revoke planning using env names only and no values; covered by `tests/platform-pre-vps-security-hardening.test.mjs`.
- [x] Dependency/security audit cadence planning documented.
  Evidence: `docs/platform-pre-vps-security-hardening.md` proposes review timing and command candidates while keeping first audit result pending; covered by `tests/platform-pre-vps-security-hardening.test.mjs`.
- [ ] HTTPS-only hosted config.
  Blocker: Hosted Platform URL/TLS does not exist.
  Next action: Run hosted readiness and hosted smoke after TLS is configured.
  Evidence required: Sanitized readiness result showing HTTPS public/provider-facing URLs.
- [ ] Secure cookies.
  Blocker: Hosted browser smoke has not run.
  Next action: Confirm production env uses secure cookies and smoke login/logout works over HTTPS.
  Evidence required: Hosted smoke result and safe cookie-policy confirmation, without cookie values.
- [ ] Explicit allowed origins.
  Blocker: Hosted origin is not approved.
  Next action: Configure only exact Platform origin(s), no wildcards and no path/query/fragment.
  Evidence required: Sanitized env readiness category pass.
- [ ] CSRF smoke.
  Blocker: Hosted browser session does not exist.
  Next action: Smoke a state-changing admin action with valid CSRF and a failure case with missing/invalid CSRF.
  Evidence required: Sanitized pass/fail result with route names only.
- [ ] Rate limiting review.
  Blocker: Current docs identify rate limiting/lockout as deferred.
  Next action: Decide whether hosting-layer rate limiting is required before launch or explicitly risk-accepted for narrow internal alpha.
  Evidence required: Reviewed control evidence or documented risk acceptance.
- [ ] Security headers review.
  Blocker: Hosted response posture is not reviewed.
  Next action: Review headers for HTML and JSON routes after hosting.
  Evidence required: Sanitized header review result.
- [ ] Session expiry/rotation review.
  Blocker: Session-management UI and broader session controls are deferred.
  Next action: Review current session duration, expiry behavior, rotation needs, and revoke-other-sessions plan.
  Evidence required: Documented decision and tests or smoke evidence.
- [ ] Dependency/security audit cadence.
  Blocker: Cadence is not decided.
  Next action: Choose local/CI audit command and review cadence.
  Evidence required: Recorded command, cadence, and first result.
- [ ] Secret rotation plan.
  Blocker: Secret storage/rotation owner is not approved.
  Next action: Define rotation owner, schedule, and emergency process outside repo.
  Evidence required: Sanitized rotation plan.
- [ ] Exposed ports/firewall review.
  Blocker: Shared VPS/firewall configuration does not exist.
  Next action: Review exposed ports after Hostinger/Coolify foundation exists.
  Evidence required: Sanitized firewall/port review.

## Gate 7: Swooshz Quote Auto Generator Launch Handoff Gate

Gate status: blocked until Swooshz Quote Auto Generator and SKR readiness and hosted Swooshz Quote Auto Generator decisions are separately scoped. This Swooshz Quote Auto Generator launch handoff gate must not turn Platform into product runtime storage.

- [ ] SQAG is a separate app, not the same app as Platform.
  Blocker: SQAG hosted architecture evidence is outside this repo and not yet recorded.
  Next action: Keep SQAG app hosting/readiness in its own repo/workstream unless explicitly scoped.
  Evidence required: SQAG readiness evidence from its own workstream.
- [ ] SQAG hosting readiness must be completed separately.
  Blocker: User is waiting for SQAG/SKR hosting readiness before shared VPS purchase.
  Next action: Track SQAG/SKR readiness outside this Platform roadmap and reference only sanitized status here later.
  Evidence required: Sanitized SQAG/SKR hosting-readiness completion note.
- [ ] Cross-host session/cookie strategy reviewed.
  Blocker: Hosted Platform and hosted Swooshz Quote Auto Generator hosts are not approved.
  Next action: Review cross-host cookie/session strategy before enabling server handoff.
  Evidence required: Approved strategy and hosted smoke result with no cookie values.
- [ ] Platform entitlement and launch-token flow smoke tested.
  Blocker: Hosted Platform and product app endpoint are not available.
  Next action: Smoke Platform launch-token issue/consume/open flow only after hosted handoff is approved.
  Evidence required: Sanitized hosted smoke result proving no raw token in URL, storage, logs, screenshots, or docs.
- [ ] Product workflow/runtime data remains outside Platform.
  Blocker: Hosted product integration is not scoped.
  Next action: During any integration PR, review that Platform stores only account/access/launch state and product app stores workflow/runtime data.
  Evidence required: Code review or test evidence from the relevant integration PR.
- [ ] Swooshz Quote Auto Generator stays manual mode until reviewed.
  Blocker: Cross-host handoff/session strategy is not approved.
  Next action: Keep hosted product launch mode manual until the handoff is reviewed and smoke-tested.
  Evidence required: Sanitized hosted env/config review showing manual mode or approved handoff mode.

## Gate 8: Legal/Compliance And Launch Governance Gate

Gate status: planning placeholders drafted; approvals not started. This legal/compliance gate and final go/no-go process can begin before VPS, but launch approval requires signed-off evidence.

- [x] Legal/compliance and final go/no-go placeholders drafted.
  Evidence: `docs/platform-pre-vps-security-hardening.md` lists legal/compliance placeholder categories, and `docs/platform-final-go-no-go-checklist.md` records owner placeholders and unchecked final gates; covered by `tests/platform-pre-vps-security-hardening.test.mjs`.
- [ ] Privacy policy.
  Blocker: Public/internal policy text is not drafted or approved.
  Next action: Draft policy reflecting Platform-owned account/access data and product-owned runtime data.
  Evidence required: Approved privacy policy link or document.
- [ ] Terms.
  Blocker: Terms are not drafted or approved.
  Next action: Draft internal-alpha terms or usage rules.
  Evidence required: Approved terms link or document.
- [ ] Data retention policy.
  Blocker: Retention rules for sessions, audit/activity, backups, logs, and product data are not approved.
  Next action: Draft retention policy separating Platform and product data responsibilities.
  Evidence required: Approved retention policy.
- [ ] Account/member removal policy.
  Blocker: Operational policy for member removal, disabled memberships, sessions, and provider identities is not approved.
  Next action: Draft policy using current fail-closed implementation as the technical baseline.
  Evidence required: Approved removal policy and smoke/test evidence.
- [ ] Vendor/subprocessor notes if needed.
  Blocker: Hosted provider stack is not finalized.
  Next action: List hosting, database, OAuth, monitoring, and product-app vendors after choices are approved.
  Evidence required: Approved vendor/subprocessor notes.
- [ ] Final internal go/no-go owner.
  Blocker: Owner is documented as required but not approved.
  Next action: Name the final launch approver outside repo.
  Evidence required: Sanitized final go/no-go owner record.
- [ ] Final launch checklist completed.
  Blocker: Gates 1-8 are not complete, and `docs/platform-final-go-no-go-checklist.md` is only an unchecked template.
  Next action: Complete the final checklist only after all launch-critical evidence is available.
  Evidence required: Completed gate checklist, hosted smoke evidence, security review evidence, legal/compliance approval, and final go/no-go decision.

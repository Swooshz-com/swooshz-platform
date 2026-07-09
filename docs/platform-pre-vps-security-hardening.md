# Platform Pre-VPS Security Hardening Plan

Production readiness is not approved. This document records pre-VPS Swooshz Platform hardening and launch-governance planning only. It does not deploy, configure DNS/TLS, configure OAuth, add secrets, run hosted smoke, or approve production launch.

The shared Hostinger/Coolify foundation does not exist yet. That future foundation remains shared across Swooshz Platform, Swooshz Quote Auto Generator, and SKR. Platform must not treat the shared VPS as Platform-only, and Platform must not own Swooshz Quote Auto Generator product workflow/runtime data.

Related source docs:

- `docs/auth-session-security-contract.md`
- `docs/hosted-internal-alpha-runbook.md`
- `docs/hosted-internal-alpha-operator-decisions.md`
- `docs/coolify-deployment-readiness.md`
- `docs/production-readiness-roadmap.md`
- `docs/platform-secret-rotation-runbook.md`
- `docs/platform-backup-restore-evidence-template.md`
- `docs/platform-final-go-no-go-checklist.md`

## Current Evidence Boundary

Local repository tests and docs already cover route contracts, production env-shape validation, session cookie helpers, origin/CSRF helpers, admin route CSRF wiring, session expiry/revocation behavior, no-store HTML responses, and value-safe readiness output.

That local evidence is not hosted evidence. Hosted deployment, hosted OAuth/provider setup, hosted security header review, hosted CSRF smoke, hosted session/cookie smoke, hosted backup/restore execution, hosted monitoring/log review, and final go/no-go remain pending.

## CSRF Smoke Plan

Current implementation posture:

- State-changing browser-cookie routes use `origin_referer_and_csrf_token` through `src/http/route-contracts.ts` and `src/http/request-security.ts`.
- Admin member, pending approval, role, membership status, entitlement, and logout mutations require an allowed Origin or Referer plus an `x-csrf-token` header before mutation.
- Read-only browser-session routes remain no-store and do not require CSRF.
- The app launch consume route is CSRF-exempt because it uses a header-only one-time launch token and does not use the browser session cookie.

Pre-launch hosted smoke expectations after deployment is separately approved:

| Smoke item | Expected result | Evidence to record |
| --- | --- | --- |
| Valid admin mutation with fresh CSRF token and allowed Origin | Allowed only when session, membership, role, and route checks pass | Route name, status category, and audit event type only |
| Missing CSRF token on the same mutation | Denied before service mutation | Route name and denial category only |
| Invalid CSRF token on the same mutation | Denied before service mutation | Route name and denial category only |
| Missing Origin and Referer on browser-cookie mutation | Denied before service mutation | Route name and denial category only |
| Unapproved Origin on browser-cookie mutation | Denied before service mutation | Route name and denial category only |
| Logout with valid CSRF token and allowed Origin | Current Platform session revoked and browser session cookie cleared | Route name and pass/fail only |

Do not record raw CSRF tokens, cookies, session ids, auth codes, provider payloads, private identities, request headers, table rows, or screenshots containing browser storage.

## Origin And Referer Expectations

Hosted `PLATFORM_ALLOWED_ORIGINS` must contain exact Platform origins only. Wildcards, path-shaped values, query strings, and fragments are not acceptable launch configuration.

For hosted smoke:

- Prefer the `Origin` header when browsers send it.
- Accept `Referer` only as a fallback origin source for browser behavior that omits `Origin`.
- Compare origins only, not path/query/fragment material.
- Treat missing, malformed, or unapproved origin material as a deny result.
- Keep real hosted domains and provider console values outside the repo.

## Session And Cookie Posture

Current implementation posture:

- Browser cookies carry only the Platform session reference.
- Session cookies are `HttpOnly` and `SameSite=Lax` by default.
- Production runtime requires secure browser cookies through production config.
- The default generic OIDC session duration in `scripts/platform-start.mjs` is one hour.
- Session context, admin authorization, app access, and launch checks reject missing, expired, revoked, inactive-user, and missing-user sessions.
- Workspace member removal revokes active Platform sessions for the removed user.
- Logout is POST-only, CSRF/origin protected in the Node adapter, revokes the current Platform session when present, and clears the browser session cookie.

Deferred or launch-decision items:

- Revoke-other-sessions is not a general user-facing or admin-facing workflow yet.
- Workspace-wide active-session viewing is not implemented.
- Device, geolocation, and enriched session metadata are not implemented.
- Cross-host Swooshz Quote Auto Generator session/cookie behavior must be reviewed before `server_handoff` is enabled for hosted use.

Hosted smoke must confirm secure cookie policy over HTTPS without storing cookie values in repo notes.

## Security Header Posture

Current implementation posture:

- Public, portal, admin, auth error, and implemented shell HTML routes return no-store headers through the Node adapter.
- Auth callback failures use safe HTML and category-only diagnostic headers.
- `/healthz` returns safe JSON and is not proof of auth, database, cookie, CSRF, or launch correctness.

Launch requirement:

- Review hosted response headers after the reverse proxy and app are configured.
- Decide and record the owner for header policy covering HSTS, CSP, frame embedding, MIME sniffing, referrer policy, and permissions policy.
- Do not claim hosted security-header completion from local docs or local adapter tests.

No runtime header behavior is changed by this plan.

## Rate Limiting Posture

Current implementation posture:

- Application-level rate limiting and lockout remain deferred, as documented in `docs/auth-session-security-contract.md`.
- No naive in-memory production rate limiter is considered complete for hosted production.

Launch requirement:

- Decide whether hosted internal alpha uses hosting-layer/proxy controls, app-level persistent controls, a reviewed provider-side control, or an explicit short-term risk acceptance.
- At minimum, review auth start/callback, session CSRF issue, logout, admin mutations, launch issue/open, and launch consume routes.
- Evidence must identify the chosen control category, owner, reviewed routes, and pass/fail or accepted-risk result without exposing private domains, IPs, request headers, provider data, or raw logs.

## Dependency And Security Audit Cadence

Planning cadence before hosted launch:

- Run dependency/security review before the shared Hostinger/Coolify foundation execution window.
- Run dependency/security review again before final go/no-go.
- During an active launch window, repeat at least monthly or whenever dependency, Docker base image, auth, session, database, or HTTP adapter code changes.

Suggested local command candidates:

- `npm audit --omit=dev` for dependency advisory review when network access is allowed by the operator.
- `npm run typecheck`, `npm run build`, and `npm test` for deterministic local repo validation.
- `docker build --pull --tag swooshz-platform:local .` when runtime image changes or an operator explicitly wants container freshness evidence.

This document does not record a first audit result. First-result evidence remains pending.

## Secret Rotation And Emergency Revoke

Use `docs/platform-secret-rotation-runbook.md` for routine rotation and emergency revoke planning. The runbook records env names only and no secret values.

Rotation launch requirements:

- Approve a secret storage owner and rotation owner outside the repo.
- Store real values only in the approved secret manager or hosting env store.
- Use emergency rotation when a value, cookie, token, OAuth material, or backup/export containing secret material may have been exposed.
- Treat real staff allowlists as private operational data even when they are not credentials.

## Backup And Restore Evidence

Use `docs/platform-backup-restore-evidence-template.md` for sanitized restore evidence. The template is not evidence until an operator completes it outside the repo or records a sanitized copy after an approved restore test.

Required evidence before launch:

- Backup owner.
- Restore owner and approver.
- Restore target category separated from production runtime.
- Backup artifact reference that is opaque and non-secret.
- Restore test result with pass/fail status.
- Decision on restore versus fix-forward.

Do not commit backup exports, database URLs, table dumps, provider console screenshots, private staff data, product runtime data, or exact internal storage paths.

## Monitoring, Logging, And Incident Placeholders

Pre-VPS decisions still needed:

- Log retention and access owner.
- Secret-safe log review owner.
- Uptime monitoring owner and alert destination.
- Error monitoring, log-based alerting, or manual equivalent.
- Incident owner and escalation path.
- Separation between Platform account/access incidents and Swooshz Quote Auto Generator product runtime incidents.

Planning docs are not monitoring evidence. Do not mark monitoring/logging/alerting complete until the chosen hosted process exists and sanitized evidence is reviewed.

## Legal And Compliance Placeholders

Launch governance still needs approved placeholders and owners for:

- Privacy policy.
- Terms or internal-alpha usage rules.
- Data retention policy for sessions, audit/activity, backups, logs, and product data boundaries.
- Account/member removal policy.
- Vendor/subprocessor notes after hosted provider choices are approved.
- Final launch approver.

These are not legal approvals. They are placeholder categories for future reviewed documents and owner decisions.

## Final Go/No-Go Ownership

Use `docs/platform-final-go-no-go-checklist.md` for the final checklist. It must remain unchecked until every launch-critical gate has hosted or operator evidence, legal/compliance decisions are approved, and the final approver records a go/no-go decision outside this repo.

Recommended next move:

- If SQAG and SKR are both hosting-ready, proceed to shared Hostinger/Coolify foundation planning.
- Otherwise continue only non-hosted Platform governance work or return to the app that still blocks shared hosting.

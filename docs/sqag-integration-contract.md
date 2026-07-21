# SQAG Integration Contract

SQAG is the first app integration target for Swooshz Platform. This contract defines the platform-owned launch boundary now that SQAG can consume platform launch context server-side. The current platform code implements the launch-token issue and consume endpoints plus a narrow browser-safe SQAG handoff route. SQAG quote workflow storage and app behavior remain owned by the SQAG repository.

SQAG-side PR #122 and Platform PR #79 established the historical `appKey=sqag` baseline. They are not evidence of compatibility with the later cross-origin finalization and live-access-validation protocol. Before enabling `server_handoff`, operators must record and jointly review the exact Platform and SQAG revisions that implement this contract. Live Platform-to-SQAG smoke remains pending until an operator deliberately runs the hosted/live smoke; the local synthetic readiness check does not claim production readiness.

## Boundary Summary

SQAG remains the quote-generation workflow app. It owns:

- Booth/render image intake.
- Quote-company profile import and selection.
- Pricing-reference import, review, save, edit, list, selection, and export.
- Quote basis review.
- Pricing review.
- `quotation.xlsx` generation.
- Optional PDF viewing/export behavior when locally supported.
- Quote workflow runtime/session behavior until the platform adapter phase.

Swooshz Platform owns:

- Login and sessions.
- Users.
- Workspaces/accounts.
- Workspace memberships and roles.
- Invitations.
- App whitelist and app entitlements.
- App access decisions.
- Short-lived app launch token issue and consume.
- Platform audit events.
- Billing and credits later, if approved.
- Shared platform shell and SQAG browser launch handoff.

SQAG must not grow:

- Email/password login.
- Public signup.
- Users table.
- Workspace or account membership model.
- Team/company membership model.
- Billing, credits, Stripe, or ecommerce.
- Customer portal.
- Platform app registry or whitelist.
- Shared platform navigation shell.

## Current Platform Launch Handoff Contract

The platform-side handoff contract is now explicit:

1. Browser user signs in to Swooshz Platform through OIDC.
2. Swooshz Platform owns the browser session, platform user, workspace membership, membership role, app entitlement, and app access decision.
3. The direct browser launch-token route `POST /api/platform/apps/launch?workspaceId=<platform-workspace-id>&appKey=sqag` is disabled for raw-token delivery and must not mint or return a raw token to the browser.
4. The browser-safe SQAG handoff route is `POST /api/platform/apps/launch/open?workspaceId=<platform-workspace-id>&appKey=sqag`.
5. The browser-safe handoff route requires an active browser session cookie plus Origin/Referer and CSRF validation.
6. In browser-safe handoff mode, Platform creates the launch intent internally, stores only a versioned hash of the launch token plus lifecycle metadata, and sends the raw launch token only in the server-side `x-app-launch-token` header to SQAG. The same request includes exactly one `x-sqag-service-authorization` header so SQAG can authenticate Platform before it inspects or consumes the launch token. SQAG consumes it, registers only a hash of a distinct one-time finalization handle, and returns that handle to Platform only through `X-SQAG-Finalization-Handle`.
7. Platform returns the finalization handle to its browser shell only through `X-SQAG-Finalization-Handle`. The shell posts it once, with credentials, to the exact SQAG finalization origin. SQAG sets its host-only session cookie from `quote.swooshz.com`; Platform never relays SQAG `Set-Cookie` and never sets `Domain=.swooshz.com`.
8. The browser-safe handoff response must not include the raw launch token, token hash, provider tokens, provider claims, auth code, state, nonce, database URL, or platform session secret.
9. The raw launch token must not be placed in browser response bodies, URL query parameters, browser storage, cookies, logs, docs, screenshots, committed files, or app telemetry.
10. SQAG must send any raw launch token only in the `x-app-launch-token` header to `POST /api/platform/apps/launch/consume?appKey=sqag`.
11. The consume route requires no browser cookie and no CSRF token because the raw launch token is the credential.
12. Platform hashes the submitted token before lookup, rejects missing, invalid, expired, consumed, revoked, and app-mismatched tokens safely, re-checks app access, consumes the token once, and returns only safe user/workspace/app context plus a dedicated validation-grant identifier.
13. The consume response may establish the bounded SQAG session binding, but it is not continuing authorization. SQAG must validate the bound Platform grant on every authenticated API request and fail closed on revocation, expiry, access change, malformed response, timeout, or Platform unavailability.

The old pre-namespace app key is not whitelisted, is not an alias, and must not be accepted by launch/open or consume flows.

Disabled direct launch-token response shape:

```json
{
  "outcome": "error",
  "message": "Direct launch token responses are disabled. Use the server-side launch handoff."
}
```

Safe browser launch request shape:

```http
POST /api/platform/apps/launch/open?workspaceId=<platform-workspace-id>&appKey=sqag HTTP/1.1
Host: <platform-host>
Cookie: <platform-browser-session-cookie>
X-CSRF-Token: <platform-csrf-token>
Origin: <platform-origin>
```

Safe browser launch server-side SQAG consume request shape:

```http
POST <sqag-local-base-url>/api/platform/launch HTTP/1.1
X-App-Launch-Token: <one-time-raw-launch-token>
X-SQAG-Service-Authorization: <shared-platform-sqag-service-secret>
```

The same shared service-secret value must be entered separately and securely as
`PLATFORM_SQAG_SERVICE_SECRET` in Platform and `SQAG_PLATFORM_SERVICE_SECRET`
in SQAG. SQAG independently verifies the credential before consuming the
one-time launch token. The value must never appear in repositories, logs,
screenshots, reports, or chat.

Safe browser launch response shape:

```json
{
  "outcome": "launch_opened",
  "appKey": "sqag",
  "workspaceId": "<platform-workspace-id>",
  "launchUrl": "https://quote.swooshz.com/",
  "finalizationUrl": "https://quote.swooshz.com/api/auth/platform/finalize"
}
```

The same response carries the raw one-time finalization handle only in `X-SQAG-Finalization-Handle`.

The browser-safe launch response does not include the raw launch token. The raw token is not placed in URL query parameters, fragments, browser storage, cookies, logs, docs, screenshots, committed files, or app telemetry.

Safe consume request shape for the implemented SQAG adapter:

```http
POST /api/platform/apps/launch/consume?appKey=sqag HTTP/1.1
Host: <platform-host>
X-App-Launch-Token: <one-time-raw-launch-token>
```

Safe consume success response shape:

```json
{
  "outcome": "consumed",
  "user": {
    "userId": "<platform-user-id>",
    "email": "<platform-user-email-placeholder>",
    "displayName": "<display-name-placeholder>",
    "status": "active"
  },
  "workspace": {
    "workspaceId": "<platform-workspace-id>",
    "workspaceSlug": "<platform-workspace-slug>",
    "workspaceName": "<platform-workspace-name>"
  },
  "app": {
    "appKey": "sqag",
    "appName": "SQAG"
  },
  "membershipRole": "owner",
  "launchTokenExpiresAt": "<iso-expiry>",
  "validationGrantId": "<non-secret-grant-id>"
}
```

SQAG must not receive:

- Auth provider access tokens.
- Auth provider refresh tokens.
- ID tokens.
- Raw auth provider claims.
- Raw provider responses.
- OIDC authorization codes.
- Raw OIDC state or nonce.
- Platform session secrets or session cookie values.
- CSRF secrets or CSRF token hashes.
- App launch token hashes.
- Database URLs.
- Billing provider secrets.
- Other workspace memberships.
- Private SQAG runtime data outside the scoped adapter flow.

SQAG should use the safe consume context to scope runtime/session/history data once that integration exists.

## Runtime And History Direction

Today, SQAG can use local/runtime storage for internal UAT. The next SQAG adapter phase should move SQAG runtime and session history behind the platform consume context without making SQAG the owner of accounts.

The implemented hosted browser-safe direction is:

1. Platform authenticates the user.
2. Platform selects the workspace.
3. Platform authorizes SQAG launch.
4. Platform issues a one-time launch token.
5. Platform posts the token server-to-server to SQAG as `x-app-launch-token`.
6. SQAG consumes that token through the platform header-only consume endpoint.
7. SQAG receives scoped workspace identity.
8. SQAG stores or resolves quote workflow state under that workspace context.

This does not mean SQAG becomes the owner of accounts. It means SQAG uses the platform account context to partition quote workflow data.

## No Customer Portal Yet

The integration target is internal platform access for Swooshz/Koncept users. It is not a public customer portal. Customer-facing login, customer quote approval, public signup, and external customer collaboration are out of scope until separately approved.

## No Public SaaS Launch Yet

The platform contract prepares account and app-access architecture. It does not approve public SaaS launch, production hosting, VPS/Coolify deployment, DNS, TLS, firewall work, public billing, or public signup.

## No Billing/Credits Inside SQAG

Billing and credits belong to Swooshz Platform if they are approved later. SQAG may eventually receive a platform decision such as `app_launch_allowed`, but it must not implement:

- Credit ledgers.
- Stripe customers.
- Subscription state.
- Pricing plans.
- Payment collection.
- Usage billing.

## Phases

### Phase 1: Internal Platform Account Contract Only

Define accounts, workspaces, memberships, roles, invitations, sessions, audit events, app records, and app entitlement contract.

No frontend, auth provider, database migration, billing, deployment, or SQAG code changes.

### Phase 2: Platform Login/Workspace/App Access Backend

Scaffold and harden the platform backend for:

- Users.
- Workspaces.
- Memberships.
- Sessions.
- Invitations.
- Apps.
- App entitlements.
- Access decision service.
- Audit events.
- OIDC-backed login.
- Session context.
- CSRF-protected browser launch intent.
- Header-only app launch token consume.

Auth provider selection may happen here or in a dedicated preceding decision record.

### Phase 3: Platform-Side Launch Handoff Contract

Finalize the platform-side handoff contract around the launch-token issue, consume, and browser-safe open endpoints.

No provider SDKs, fake login, billing, deployment, or migration automation.

### Phase 4: SQAG Platform Adapter (Implemented Contract)

Implement and harden the SQAG-side adapter in the SQAG repository. The adapter consumes the platform launch token through the header-only consume endpoint and remains scoped to quote workflow runtime/session behavior.

SQAG changes should stay adapter-scoped and quote-workflow-specific.

## Local UAT Configuration

Browser-safe SQAG launch is disabled by default. To enable the reviewed hosted handoff, use injected values such as:

```text
PLATFORM_SQAG_LAUNCH_MODE=server_handoff
PLATFORM_SQAG_APP_BASE_URL=<sqag-local-base-url>
```

The platform start CLI validates the configured SQAG base URL before listening and does not call SQAG during startup. The launch contract uses separate HTTPS origins (`https://swooshz.com` and `https://quote.swooshz.com`) and host-only cookies. SQAG registers a short-lived SHA-256 handle hash against the non-secret validation grant through service-authenticated internal endpoints. Finalization is atomic and one-time; every later validation re-evaluates the live Platform session, user, workspace, membership role, app, and entitlement without a positive cache. The response field is `finalizationUrl`.

Before any operator-hosted smoke, run the DB-free synthetic preflight:

```powershell
npm run platform:sqag-smoke-readiness
```

That command exercises the existing deterministic launch/open, consume,
seed/bootstrap, contract-doc, and app-key migration tests. It uses no real
OAuth provider, hosted database, hosted SQAG instance, Coolify, Hostinger, or
secret values. Passing it only confirms local synthetic readiness; live
Platform-to-SQAG smoke remains pending until an operator-approved hosted/live
run succeeds.

### Phase 5: Platform Frontend Shell

Build the minimal platform UI only after backend account and app-access contracts are stable. It may include login, workspace switcher, app launcher, and internal admin views.

### Phase 6: Billing/Credits If Approved Later

Add billing and credit concepts only after the account/app entitlement model is working. Billing should influence entitlement decisions without changing the core membership model.

## Open Decisions For Later

- SQAG runtime storage location once platform-scoped.
- Billing provider and credit model.
- Platform shell frontend stack.
- SQAG-side adapter implementation details that do not change the platform launch-token contract.

# App Access Contract

This document defines how Swooshz Platform decides whether a workspace and user can access an app. It separates app whitelist, entitlement, role permission, and billing status so future apps can be added without reshaping the account model.

## Terms

### App Whitelist

The app whitelist is the set of app records that the platform knows about and is willing to expose in the platform environment.

Example:

- `sqag`: SQAG quote generator.

The whitelist answers: "Can this app exist in this platform environment?"

It does not answer:

- Whether a workspace has access.
- Whether a user has permission.
- Whether billing is paid.

### Workspace Entitlement

An entitlement grants a workspace access to a whitelisted app.

It answers: "Has this workspace been granted this app?"

It does not answer:

- Whether a specific user is allowed to launch it.
- Whether the app is currently healthy.
- Whether the user has an active session.

### Role Permission

Role permission decides what an active workspace member can do.

It answers: "Can this user's role launch or administer this app?"

Default launch permission is intentionally least-privilege:

- `owner`: can launch and manage app access.
- `admin`: can launch and manage app access unless ownership-only.
- `member`: can launch enabled apps.
- `viewer`: can see read-only workspace/app visibility in Platform only. It cannot administer the workspace and cannot launch operational products unless a future app-specific read-only launch contract is deliberately designed and tested.

SQAG initially has no read-only mode, so `viewer` app launch is blocked. Future apps inherit the same blocked viewer launch default until an explicit per-product read-only use case exists.

## Role And Product Access Matrix

| Role | Platform workspace visibility | `/app/admin` and admin APIs | Product launch default | SQAG launch today |
| --- | --- | --- | --- | --- |
| `owner` | Yes, for active memberships. | Yes, including workspace control except owner-transfer flows that remain guarded/deferred. | Allowed when session, user, workspace, app status, and entitlement all allow. | Allowed when SQAG is `available` or `private_preview` and entitlement is `enabled` or `trial`. |
| `admin` | Yes, for active memberships. | Yes, except ownership-only operations. | Allowed when session, user, workspace, app status, and entitlement all allow. | Allowed when SQAG is `available` or `private_preview` and entitlement is `enabled` or `trial`. |
| `member` | Yes, for active memberships. | No. | Allowed when session, user, workspace, app status, and entitlement all allow. | Allowed when SQAG is `available` or `private_preview` and entitlement is `enabled` or `trial`. |
| `viewer` | Yes, for active memberships. | No. | Blocked unless a future app-specific read-only launch policy is designed, implemented, and tested. | Blocked because SQAG has no read-only launch mode. |

Only `available` and `private_preview` app statuses are launchable. Unknown, inactive, unavailable, private-disabled, and globally disabled app states fail closed as `app_not_available`. Only `enabled` and `trial` entitlement statuses are launchable; missing, `disabled`, and `suspended` entitlements fail closed as `app_not_enabled_for_workspace`.

### Billing Status

Billing status is reserved. It will eventually answer: "Is this workspace in a commercial state that allows this app?"

Billing status must not be used as the source of truth for users, memberships, roles, or the app whitelist.

## Initial Allowed App

The initial allowed app is:

- App key: `sqag`
- Name: `SQAG`
- Purpose: quote-generation workflow app.
- Integration status: future platform adapter.
- Initial app status: `private_preview`.

SQAG remains a separate repository and separate app:

- `Swooshz-com/koncept-quote-auto-generator`

## Workspace App Access Flow

To enable an app for a workspace:

1. Confirm the app exists in the platform app whitelist.
2. Confirm the workspace exists and is active.
3. Create or update the workspace entitlement for the app.
4. Record an audit event for the entitlement change.
5. Later: optionally bind billing/plan metadata without changing membership.

To disable an app for a workspace:

1. Set entitlement status to `disabled` or `suspended`.
2. Record the actor and reason where available.
3. Record an audit event.
4. Reject new launch attempts.
5. Do not delete app-owned data unless a separate retention workflow exists.

## Internal Seed Preparation

The platform may prepare internal SQAG access before a frontend or SQAG launch adapter exists. The internal seed contract is limited to platform-owned records:

- Active workspace.
- App registry entry with key `sqag`.
- Workspace app entitlement.
- Active owner/admin/member membership for an authenticated platform user, or a pending first-owner approval for a reviewed email on a fresh hosted DB.

The seed must be explicit and idempotent. It may reuse matching records and must fail safely on conflicts. It must not create fake login state, create app launch tokens, call SQAG, write SQAG storage, run migrations, call provider networks, or grant viewer launch access for `sqag`.

Membership can be granted to an existing active user by user id or normalized email lookup. First-owner bootstrap mode may create a pending owner approval only when the reviewed workspace has no memberships; real OIDC sign-in for the matching email creates/links the provider-backed user and activates membership transactionally. Creating a user together with a provider identity directly in the seed remains forbidden. This avoids partial identity state such as an active email-only user without the intended provider identity. Email-only user precreation for future provider linking is forbidden.

The internal seed CLI, `npm run platform:seed-internal-access`, requires `PLATFORM_SEED_CONFIRM=seed-reviewed-internal-access`, `PLATFORM_SEED_USER_EMAIL`, `PLATFORM_SEED_WORKSPACE_SLUG`, and `PLATFORM_SEED_WORKSPACE_NAME`, validates those before connecting to the database, and refuses unsafe drift. With `PLATFORM_SEED_BOOTSTRAP_MODE=first-owner-pending-approval`, it creates or reuses reviewed platform-owned workspace, app registry, entitlement, and pending owner approval records for the first real OIDC sign-in. Without that mode, it grants app access only to a platform user who has already logged in through real OIDC and therefore already has a provider identity. It does not create users, provider identities, sessions, app launch tokens, fake login state, SQAG storage, default production workspace data, private SQAG profile/pricing data, migrations, provider network calls, or deployment changes.

## Current Session Context

`GET /api/platform/session/context` is a read-only platform endpoint for a future platform shell or dashboard. It uses the browser session cookie to return safe active-session status, platform user summary, active workspace memberships, and per-workspace app access summaries derived from the same entitlement and role rules as app launch decisions.

The session context response is informational. It does not launch apps, mint app launch tokens, persist workspace selection, accept invitations, create memberships, grant entitlements, call SQAG, or expose provider tokens, raw claims, session secrets, CSRF material, database details, quote data, pricing files, or private app payloads.

## App Launch Intent Endpoint

`POST /api/platform/apps/launch?workspaceId=...&appKey=...` is disabled for direct browser raw-token delivery. It is a state-changing browser-cookie route, so it still requires Origin/Referer validation and a CSRF token before returning the safe disabled response.

The endpoint does not create a launch token and does not expose raw token material in browser response bodies. Browser launch should use the SQAG browser launch open endpoint below, which creates and forwards the token server-side.

The database stores only a versioned HMAC token hash plus session, user, workspace, app, expiry, consumed, and revoked metadata for launch tokens created by the server-side handoff path. Raw launch tokens must not be put in browser response bodies, URLs, browser storage, cookies, logs, screenshots, docs, or telemetry.

## SQAG Browser Launch Open Endpoint

`POST /api/platform/apps/launch/open?workspaceId=...&appKey=sqag` is the implemented browser-safe hosted handoff for SQAG. It requires the active apex Platform browser session, Origin/Referer validation, and CSRF, then re-checks protected SQAG access before the server-to-server launch.

When explicitly configured with `PLATFORM_SQAG_LAUNCH_MODE=server_handoff`, `PLATFORM_SQAG_APP_BASE_URL=<sqag-https-origin>`, and the shared service secret, Platform forwards the raw one-time launch token to SQAG server-to-server as `x-app-launch-token`. SQAG returns a one-time finalization handle only in `X-SQAG-Finalization-Handle`; Platform relays that header, never SQAG cookies, and returns same-origin SQAG finalize and launch URLs.

The hosted contract deliberately requires separate HTTPS origins. The browser posts the ephemeral handle in the same header to the exact SQAG finalize origin with credentials enabled, then navigates to the clean launch URL. The handle is never put in a URL, body, DOM, cookie, or browser storage.

The endpoint is restricted to `appKey=sqag`. It does not create SQAG users, SQAG auth, SQAG storage, billing, public signup, invitations, member management, deployment automation, DNS/TLS, object storage, or a general-purpose proxy.

## App Launch Token Consume Endpoint

`POST /api/platform/apps/launch/consume?appKey=...` validates and consumes a platform-issued app launch token for a future app backend. It does not require a platform browser session cookie and does not require CSRF because the raw launch token is the credential.

The raw launch token is accepted only in the `x-app-launch-token` header, not in the query string. The platform hashes the raw token before lookup and never returns the raw token or token hash. Unknown, expired, consumed, revoked, and app-mismatched tokens fail safely without returning launch context.

Before returning context, the platform reloads the launch token's session, user, workspace, app, membership, and entitlement context and re-checks app access using the same protected app access rules as the launch intent endpoint. Denied access, including SQAG viewer access while no read-only SQAG mode exists, does not consume the token when possible.

Successful validation marks the unconsumed active token consumed and returns only safe user, workspace, app, membership role, and launch-token expiry context for app integration. It does not create app sessions, write SQAG storage, add billing, or run migrations.

## App Launch Flow

The platform app launch flow is:

1. User logs into the platform.
2. User selects an active workspace.
3. Platform verifies active membership in that workspace.
4. Platform verifies the app exists and is available.
5. Platform verifies workspace entitlement for the app.
6. Platform verifies the user's role can launch the app.
7. Later: platform verifies billing or credit status.
8. Platform launches SQAG through the server-side handoff and two-stage, header-only finalization when explicitly configured.
9. App receives or resolves platform identity/workspace context through that boundary.

No app should infer workspace access from a display name, email domain, or local app setting.

The service-level entitlement mutation contract is generic by `appKey` so future products can use the same Platform entitlement model. The current browser/admin HTTP route and UI control remain deliberately SQAG-scoped until another app has an approved product contract and route surface.

## Platform-To-App Boundary

The Platform-owned mechanism combines a short-lived app launch token with a distinct non-secret validation grant. SQAG registers only a short-lived handle hash; a header-only consume route single-uses the raw finalization handle; every later service-authenticated validation re-evaluates the live Platform session, user, workspace, membership role, app status, and entitlement with no positive cache.

Any future app integration mechanism must preserve this contract:

- The platform is the authority for user, workspace, membership, role, and app entitlement.
- The app is the authority for app workflow state.
- The app receives a platform-issued context that includes at least:
  - `user_id`
  - `workspace_id`
  - `membership_role`
  - `app_key`
  - `launch_context_id` or equivalent request id
- The app must not receive billing secrets, provider tokens, raw auth claims, or unrelated workspace memberships.

Possible future integration mechanisms:

- Signed short-lived launch token.
- Backend-to-backend session exchange.
- Shared internal auth gateway.

The current launch-token mechanism does not move app-owned runtime data into Platform.

## Access Decision Matrix

| Condition | Result |
| --- | --- |
| No valid user session | `not_authenticated` |
| No workspace selected | `workspace_not_selected` |
| User lacks active workspace membership | `membership_required` |
| Workspace is archived or suspended | `workspace_not_active` |
| App is not in whitelist | `app_not_available` |
| App is disabled globally | `app_not_available` |
| Workspace lacks app entitlement | `app_not_enabled_for_workspace` |
| Entitlement is suspended | `app_not_enabled_for_workspace` |
| Role cannot launch app | `role_not_permitted` |
| Future billing blocks app | `billing_blocked` |
| All checks pass | `allowed` |

## Adding Future Apps

Future apps should require:

1. New app record.
2. App-specific integration contract.
3. Workspace entitlement records.
4. Role-permission mapping if different from default launch permission.

Future apps should not require:

- New user model.
- New workspace model.
- New membership model.
- New billing fields on users or memberships.
- App-specific account tables inside the app repo.

## Non-Goals

- No polished product launcher or dashboard redesign in this contract.
- No fake login, hidden fallback auth, password auth, or 2FA in this contract.
- No hosted deployment execution or hosted approval from this contract.
- No billing or credits implementation in this contract.
- No SQAG code changes or SQAG-owned runtime data movement in this contract.

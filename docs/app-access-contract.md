# App Access Contract

This document defines how Swooshz Platform decides whether a workspace and user can access an app. It separates app whitelist, entitlement, role permission, and billing status so future apps can be added without reshaping the account model.

## Terms

### App Whitelist

The app whitelist is the set of app records that the platform knows about and is willing to expose in the platform environment.

Example:

- `kqag`: KQAG / SAQG quote generator.

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

Initial launch permission can be simple:

- `owner`: can launch and manage app access.
- `admin`: can launch and manage app access unless ownership-only.
- `member`: can launch enabled apps.
- `viewer`: can launch read-only app views only when the app supports them.

KQAG initially has no read-only mode, so `viewer` app launch may be blocked until a later app adapter defines what viewer means.

### Billing Status

Billing status is reserved. It will eventually answer: "Is this workspace in a commercial state that allows this app?"

Billing status must not be used as the source of truth for users, memberships, roles, or the app whitelist.

## Initial Allowed App

The initial allowed app is:

- App key: `kqag`
- Name: `KQAG / SAQG`
- Purpose: quote-generation workflow app.
- Integration status: future platform adapter.
- Initial app status: `private_preview`.

KQAG remains a separate repository and separate app:

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

The platform may prepare internal KQAG/SAQG access before a frontend or KQAG launch adapter exists. The internal seed contract is limited to platform-owned records:

- Active workspace.
- App registry entry with key `kqag`.
- Workspace app entitlement.
- Active owner/admin/member membership for an authenticated platform user.

The seed must be explicit and idempotent. It may reuse matching records and must fail safely on conflicts. It must not create fake login state, create app launch tokens, call KQAG, write KQAG storage, run migrations, call provider networks, or grant viewer launch access for `kqag`.

Membership can be granted to an existing active user by user id or normalized email lookup. Creating a new user together with a provider identity is deferred until an explicit transactional identity seed boundary exists. This avoids partial identity state such as an active email-only user without the intended provider identity. Email-only user precreation for future provider linking is forbidden.

## Current Session Context

`GET /api/platform/session/context` is a read-only platform endpoint for a future platform shell or dashboard. It uses the browser session cookie to return safe active-session status, platform user summary, active workspace memberships, and per-workspace app access summaries derived from the same entitlement and role rules as app launch decisions.

The session context response is informational. It does not launch apps, mint app launch tokens, persist workspace selection, accept invitations, create memberships, grant entitlements, call KQAG, or expose provider tokens, raw claims, session secrets, CSRF material, database details, quote data, pricing files, or private app payloads.

## App Launch Intent Endpoint

`POST /api/platform/apps/launch?workspaceId=...&appKey=...` creates a platform launch intent for an active browser session. It is a state-changing browser-cookie route, so it requires Origin/Referer validation and a CSRF token before the handler can create a launch token.

The endpoint re-checks the same protected app access rules used by session app-access decisions. Missing, revoked, or expired platform sessions are unauthenticated. Denied app access, including KQAG viewer access while no read-only KQAG mode exists, does not create a token.

Allowed access creates one short-lived launch token record. The database stores only a versioned HMAC token hash plus session, user, workspace, app, expiry, consumed, and revoked metadata. The raw launch token/reference is returned only once in the immediate no-store response with the app key, workspace id, optional app launch URL, and expiry. Token consumption/validation, redirects, KQAG launch/storage integration, frontend UI, fake login, billing, deployment, and migration execution are out of scope until separately approved.

## App Launch Flow

The platform app launch flow is:

1. User logs into the platform.
2. User selects an active workspace.
3. Platform verifies active membership in that workspace.
4. Platform verifies the app exists and is available.
5. Platform verifies workspace entitlement for the app.
6. Platform verifies the user's role can launch the app.
7. Later: platform verifies billing or credit status.
8. Platform launches the app through a defined integration boundary.
9. App receives or resolves platform identity/workspace context through that boundary.

No app should infer workspace access from a display name, email domain, or local app setting.

## Platform-To-App Boundary

The exact technical mechanism is deferred, but it must preserve this contract:

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

No mechanism is selected in this PR.

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

- No frontend app launcher in this PR.
- No real auth provider integration in this PR.
- No database migrations in this PR.
- No billing or credits implementation in this PR.
- No KQAG code changes in this PR.

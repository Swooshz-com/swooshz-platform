# KQAG Integration Contract

KQAG/SAQG is the first app integration target for Swooshz Platform. This contract defines the platform-owned boundary for the later KQAG adapter PR. The current platform code already implements the launch-token issue and consume endpoints; KQAG integration code remains out of scope for this PR.

## Boundary Summary

KQAG remains the quote-generation workflow app. It owns:

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
- Shared platform shell later.

KQAG must not grow:

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
3. A browser launch intent calls `POST /api/platform/apps/launch?workspaceId=<platform-workspace-id>&appKey=kqag`.
4. The launch intent route requires an active browser session cookie plus Origin/Referer and CSRF validation.
5. Platform re-checks app access before minting a launch token.
6. Platform stores only a versioned hash of the launch token plus lifecycle metadata.
7. The raw launch token is returned once only in the immediate no-store response.
8. The raw launch token must not be placed in URL query parameters, browser storage, logs, docs, screenshots, committed files, or app telemetry.
9. The future KQAG adapter must send the raw launch token only in the `x-app-launch-token` header to `POST /api/platform/apps/launch/consume?appKey=kqag`.
10. The consume route requires no browser cookie and no CSRF token because the raw launch token is the credential.
11. Platform hashes the submitted token before lookup, rejects missing, invalid, expired, consumed, revoked, and app-mismatched tokens safely, re-checks app access, consumes the token once, and returns only safe user/workspace/app context.
12. The consume response is the only platform-owned context KQAG should use to create its own adapter-side runtime/session boundary.

Safe launch intent response shape:

```json
{
  "outcome": "launch_intent_created",
  "appKey": "kqag",
  "workspaceId": "<platform-workspace-id>",
  "launchUrl": "<optional-kqag-launch-url-or-null>",
  "launchToken": "<one-time-raw-launch-token-returned-once>",
  "launchTokenExpiresAt": "<iso-expiry>"
}
```

Safe consume request shape for the future KQAG adapter:

```http
POST /api/platform/apps/launch/consume?appKey=kqag HTTP/1.1
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
    "appKey": "kqag",
    "appName": "KQAG / SAQG"
  },
  "membershipRole": "owner",
  "launchTokenExpiresAt": "<iso-expiry>"
}
```

KQAG must not receive:

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
- Private KQAG runtime data outside the scoped adapter flow.

KQAG should use the safe consume context to scope runtime/session/history data once that integration exists.

## Runtime And History Direction

Today, KQAG can use local/runtime storage for internal UAT. The next KQAG adapter phase should move KQAG runtime and session history behind the platform consume context without making KQAG the owner of accounts.

The future direction is:

1. Platform authenticates the user.
2. Platform selects the workspace.
3. Platform authorizes KQAG launch.
4. Platform issues a one-time launch token.
5. KQAG adapter consumes that token through the platform header-only consume endpoint.
6. KQAG receives scoped workspace identity.
7. KQAG stores or resolves quote workflow state under that workspace context.

This does not mean KQAG becomes the owner of accounts. It means KQAG uses the platform account context to partition quote workflow data.

## No Customer Portal Yet

The integration target is internal platform access for Swooshz/Koncept users. It is not a public customer portal. Customer-facing login, customer quote approval, public signup, and external customer collaboration are out of scope until separately approved.

## No Public SaaS Launch Yet

The platform contract prepares account and app-access architecture. It does not approve public SaaS launch, production hosting, VPS/Coolify deployment, DNS, TLS, firewall work, public billing, or public signup.

## No Billing/Credits Inside KQAG

Billing and credits belong to Swooshz Platform if they are approved later. KQAG may eventually receive a platform decision such as `app_launch_allowed`, but it must not implement:

- Credit ledgers.
- Stripe customers.
- Subscription state.
- Pricing plans.
- Payment collection.
- Usage billing.

## Phases

### Phase 1: Internal Platform Account Contract Only

Define accounts, workspaces, memberships, roles, invitations, sessions, audit events, app records, and app entitlement contract.

No frontend, auth provider, database migration, billing, deployment, or KQAG code changes.

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

Current phase. Finalize the platform-side handoff contract around the already-implemented launch-token issue and consume endpoints before changing KQAG.

No KQAG code changes, app redirect integration, provider SDKs, fake login, billing, deployment, or migration automation.

### Phase 4: KQAG Platform Adapter

Implement the KQAG-side adapter in the KQAG repository after this platform contract is merged. The adapter should consume the platform launch token through the header-only consume endpoint and remain scoped to quote workflow runtime/session behavior.

KQAG changes should stay adapter-scoped and quote-workflow-specific.

### Phase 5: Platform Frontend Shell

Build the minimal platform UI only after backend account and app-access contracts are stable. It may include login, workspace switcher, app launcher, and internal admin views.

### Phase 6: Billing/Credits If Approved Later

Add billing and credit concepts only after the account/app entitlement model is working. Billing should influence entitlement decisions without changing the core membership model.

## Open Decisions For Later

- KQAG runtime storage location once platform-scoped.
- Billing provider and credit model.
- Platform shell frontend stack.
- KQAG-side adapter implementation details that do not change the platform launch-token contract.

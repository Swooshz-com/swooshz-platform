# ADR 0002: Auth And Session Strategy

## Status

Accepted.

## Context

Swooshz Platform now has a documented account, workspace, app-access, and SQAG boundary plus an executable TypeScript domain core. The next platform step needs an auth/session strategy before login routes, provider callbacks, persistence, or frontend work begin.

The platform should avoid choosing an auth vendor before the provider requirements, current pricing, operational tradeoffs, and persistence boundary are reviewed. A premature provider choice would risk coupling account, membership, workspace selection, and app launch behavior to vendor-specific concepts.

## Core Decision

Swooshz Platform owns users, workspace memberships, workspace selection, platform sessions, app entitlements, audit events, and app launch decisions.

An auth provider, when selected later, proves user identity only. The provider must not become the source of truth for Swooshz workspace membership, roles, app entitlements, billing, or SQAG access.

After provider authentication succeeds, the platform should create and own its own platform session. Browser-facing session representation should use secure, HttpOnly, SameSite cookies when implementation begins.

No auth provider is selected in this ADR. Clerk, Auth0, Supabase Auth, custom OIDC, or another provider may be evaluated in a later provider-selection PR using current pricing, features, operational constraints, and security requirements at that time.

## Session Ownership

Platform sessions should include:

- A stable platform user id.
- A created timestamp.
- An expiry timestamp.
- A revocation marker when revoked.
- Privacy-minimized metadata only when needed for audit or abuse controls.

Expired or revoked sessions cannot launch apps. A valid session alone is not enough for app access: launch decisions must still check selected workspace, active membership, active workspace, app availability, workspace entitlement, role permission, and later billing or credit gates if approved.

Session implementation should emit audit events for sign-in, sign-out, session revocation, invitation acceptance, membership changes, and entitlement changes once those operations exist.

Session errors must be privacy-safe. Public or unauthenticated responses must not reveal whether a private email address belongs to an existing user, whether an invitation exists for that email, or which entitlement condition failed internally.

## Provider Boundary

The future provider adapter should translate provider authentication into a platform-owned identity resolution step. The adapter may verify provider assertions, resolve a provider subject, and hand platform code only the normalized identity facts needed to create or find a platform user.

The platform must not expose raw provider access tokens, refresh tokens, authorization codes, session secrets, raw provider claims, or provider error details to apps.

Provider identifiers should be stored separately from business profile fields. Provider access tokens or refresh tokens should not be stored unless a later ADR explicitly approves encrypted token storage, retention rules, rotation expectations, and operational access controls.

## User Identity Boundary

Platform users remain Swooshz-owned account records. Normalized email is used for sign-in matching and invitations, but email domain or display name must not grant app access.

Provider subject identifiers can help link a provider identity to a platform user, but they must not replace platform user ids in memberships, app entitlements, audit events, or SQAG launch context.

Disabled users cannot start new sessions or launch apps even if the provider says the identity is valid.

## Workspace Selection

Workspace selection is a platform concern. The platform session may remember the selected workspace when implemented, but every app launch must re-check that the user still has active membership in that workspace.

The selected workspace must be active. Suspended or archived workspaces cannot launch apps. Session state must not be treated as authorization without membership and entitlement checks.

## Invitation Acceptance Direction

Invitations should target normalized email addresses. Invitation tokens must be stored hashed if token storage is implemented.

Accepting an invitation should create or activate exactly one membership for the target workspace and role. Revoked or expired invitations must not be accepted.

Invitation acceptance may require provider authentication first or may bridge into provider authentication, depending on the future provider decision. Public self-serve signup remains out of scope unless explicitly approved later.

## App Launch Identity Context

Apps should receive platform-issued launch context, not raw provider auth. The context mechanism is deferred, but it may later be a signed short-lived launch token, backend-to-backend exchange, or internal auth gateway.

The launch context should include only the minimum app boundary data:

- `platform_user_id`.
- `platform_workspace_id`.
- `membership_role`.
- `app_key`.
- `launch_context_id` or request id.
- Expiry or freshness information if signed context is used.

Apps must not receive billing secrets, provider tokens, raw provider claims, unrelated workspace memberships, or platform session secrets.

## SQAG Integration Implications

SQAG remains a quote-workflow app and must not own Swooshz users, workspaces, memberships, app entitlements, billing, credits, or platform sessions.

When the SQAG adapter is implemented, SQAG should accept platform-scoped identity and workspace context from Swooshz Platform. SQAG must not receive auth provider tokens or raw provider claims. Viewer behavior remains blocked until a future SQAG adapter defines read-only behavior.

## Privacy And Security Rules

- Do not commit secrets, provider tokens, populated `.env` files, private customer files, bank data, payment details, or provider responses.
- Do not leak provider error payloads to public callers or apps.
- Store provider identifiers separately from business profile fields.
- Do not store provider access tokens or refresh tokens unless a later ADR approves encrypted token storage.
- Store invitation tokens hashed if invitation token storage is implemented.
- Use privacy-minimized audit metadata.
- Use platform-issued launch context for apps.
- Treat app payloads as app-owned private data.

## Deferred Decisions

- Auth provider selection.
- Session persistence technology and schema.
- Cookie names, lifetimes, rotation behavior, and CSRF strategy.
- MFA requirements and provider-specific assurance levels.
- Invitation acceptance UX and provider handoff.
- Launch-token or backend exchange mechanism for apps.
- SQAG adapter protocol details.
- Database and migration format.
- Billing or credit gates if approved later.

## Explicit Non-Goals

- No Next.js, Vite, React, frontend shell, or UI.
- No email/password login implementation.
- No public signup.
- No OAuth/OIDC provider calls.
- No Clerk, Auth0, Supabase Auth, custom OIDC, or other provider integration.
- No database migrations.
- No Supabase setup.
- No Stripe, billing, or credits implementation.
- No customer portal.
- No deployment, VPS, Coolify, DNS, TLS, or firewall work.
- No secrets.
- No SQAG repository changes.

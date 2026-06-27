# ADR 0006: Auth Provider Selection

## Status

Accepted.

## Context

Swooshz Platform now has account/app-access contracts, a pure account/app-access domain core, provider-agnostic auth/session strategy, persistence and migration ADRs, Drizzle/Postgres schema, repository/service ports, Drizzle repository adapters, a database connection and migration workflow ADR, and a lazy `pg`/Drizzle database client boundary.

The repository still has no auth provider, no login/callback/logout routes, no auth SDK, no frontend, and no KQAG adapter. The next auth step should decide the provider strategy before any implementation couples platform sessions, users, provider identities, invitations, workspace memberships, or app access to a vendor-specific model.

ADR 0002 already established that the auth provider proves identity only. The platform owns users, provider identities, platform sessions, workspace selection, memberships, invitations, app access decisions, app entitlements, and audit events.

## Decision

Use a provider-agnostic OIDC adapter boundary for the first authentication implementation phase.

The first implementation should support a generic OIDC provider contract with:

- Authorization URL.
- Token URL.
- JWKS and/or userinfo/claims validation strategy.
- Client id from environment.
- Client secret from environment.
- Redirect/callback URI from environment.
- Provider key from environment.
- Platform-owned session creation after provider identity is verified.

Do not hard-couple the platform account model to Clerk, Auth0, Supabase Auth, or another provider SDK in the first implementation. A specific managed provider may still be used behind the generic OIDC contract if it fits the environment and security needs, but platform user, workspace, membership, invitation, session, app entitlement, and app access logic must remain provider-owned only at the identity-proof boundary.

Do not select Supabase Auth in this ADR. Supabase remains only a possible managed Postgres provider from the database ADRs, not an auth decision.

Do not build email/password or magic-link auth owned by Swooshz Platform now.

## Provider Role

The auth provider proves identity only.

After callback verification, Swooshz Platform owns:

- Platform user lookup or creation policy.
- Provider identity linking.
- Platform session creation, expiry, and revocation.
- Workspace selection.
- Membership and role checks.
- Invitation acceptance.
- App access decisions.
- Audit events.

The platform must not expose provider tokens, raw claims, raw OIDC responses, auth codes, access tokens, refresh tokens, ID tokens, or provider error payloads to KQAG or future apps.

KQAG should later receive only platform-scoped identity, workspace, membership role, app key, and launch context data through a future KQAG adapter. KQAG must not receive raw provider auth material.

## Session Model

Browser-facing platform sessions should use secure HttpOnly SameSite cookies when implemented.

Session records are stored in the platform database and remain platform-owned. Session expiry and revocation are enforced by platform session records and access decisions, not by provider session state alone.

Raw provider access tokens, refresh tokens, ID tokens, auth codes, raw claims, and raw OIDC responses must not be stored unless a later ADR explicitly approves a narrow encrypted-token storage use case with retention, rotation, access-control, and audit rules.

Raw auth codes and raw provider responses must never be logged or exposed. Authentication errors shown to users or callers should be generic and privacy-safe.

## Identity Mapping

Provider identities should map to platform users by:

- Provider key.
- Provider subject.

Provider subject is the durable external identity key. Email may be stored for display, notification, invitation matching, or allowlist checks only after normalization and provider verification. Email alone must not be the primary immutable identity key.

Provider identity records remain separate from:

- User profile fields.
- Workspace membership.
- Business profile data.
- App entitlements.
- Audit event actor ids.

Platform user ids remain the ids used by memberships, sessions, audit events, entitlements, app launch context, and KQAG launch context.

## Invitation And Allowlist Posture

For internal UAT, access should be gated by invitation and/or approved email or domain allowlist.

Public signup remains deferred. Workspace creation remains controlled or admin-created unless a later ADR or implementation plan explicitly approves a self-serve workspace creation flow.

Membership role assignment remains platform-owned. Provider identity, email domain, display name, or successful authentication alone must not grant workspace membership or app access.

Invitation matching should use normalized email only after provider verification confirms the email. Accepting an invitation should create or activate exactly one membership for the target workspace and role.

## Future Environment Variables

Future auth implementation may use:

- `AUTH_PROVIDER_KEY`.
- `AUTH_ISSUER_URL`.
- `AUTH_AUTHORIZATION_URL`.
- `AUTH_TOKEN_URL`.
- `AUTH_USERINFO_URL`.
- `AUTH_JWKS_URL`.
- `AUTH_CLIENT_ID`.
- `AUTH_CLIENT_SECRET`.
- `AUTH_REDIRECT_URI`.
- `AUTH_ALLOWED_EMAILS`.
- `AUTH_ALLOWED_DOMAINS`.
- `SESSION_SECRET`.

This ADR does not add populated `.env` files, real URLs, real domains, client ids, client secrets, session secrets, provider tokens, or auth codes.

Environment examples, if added later, must use synthetic placeholders only.

## Security And Privacy Rules

Never commit, print, or log:

- Provider tokens.
- Auth codes.
- Client secrets.
- Access tokens.
- Refresh tokens.
- ID tokens.
- Raw provider claims.
- Raw OIDC/provider responses.
- Provider error payloads.
- Session secrets.
- Populated `.env` values.

Never expose access tokens, refresh tokens, ID tokens, raw claims, or provider responses to apps.

Authentication errors should be generic and privacy-safe. Backend logs may include privacy-minimized metadata such as error code, provider key, request id, timestamp, route name, and high-level failure category. Logs must not include secrets, raw provider payloads, raw profile JSON, auth headers, cookies, or private customer/app data.

## Options Considered

### Provider-Agnostic OIDC Adapter Boundary

Pros:

- Preserves the ADR 0002 boundary that provider auth proves identity only.
- Avoids hard-coupling platform accounts, memberships, sessions, and app access to a vendor SDK.
- Can work with many managed providers that support OIDC.
- Keeps Supabase Auth separate from the managed Postgres provider decision.
- Lets tests focus on adapter contracts and platform-owned session behavior.

Cons:

- Requires more initial adapter design than a provider SDK quickstart.
- Some provider-specific features may need explicit adapter extension later.
- The team must implement careful callback and token validation flows.

Conclusion: selected first.

### Clerk

Pros:

- Strong managed auth product with polished user management and frontend-friendly flows.
- Can speed up UI login and account experiences.
- Supports modern identity features that may be useful later.

Cons:

- Risks pulling platform account, organization, session, and membership concepts toward Clerk-specific models too early.
- Would require evaluating current pricing, data model fit, and operational constraints.
- Not necessary before the platform has a provider-agnostic backend callback boundary.

Conclusion: not selected now; may be evaluated later as an OIDC-compatible provider or explicit vendor decision.

### Auth0

Pros:

- Mature OIDC/OAuth provider with broad enterprise patterns.
- Strong fit for a generic OIDC adapter contract.
- Useful if future customer or enterprise requirements demand it.

Cons:

- Vendor-specific SDK and tenant configuration could leak into platform logic if selected too early.
- Pricing and operational setup should be evaluated when implementation is ready.

Conclusion: not selected as a hard dependency now; remains compatible with the selected OIDC adapter direction.

### Supabase Auth

Pros:

- Convenient if Supabase is later selected as a managed Postgres provider.
- Integrated developer experience for projects already using Supabase.

Cons:

- Selecting Supabase Auth would blur the database provider decision with the auth provider decision.
- ADR 0004 explicitly did not select Supabase Auth.
- Platform account and app-access boundaries should not depend on Supabase Auth-specific session or user models.

Conclusion: not selected. Supabase may remain a possible managed Postgres provider only.

### Custom OIDC / Generic External OIDC Provider

Pros:

- Aligns with the selected provider-agnostic adapter boundary.
- Keeps platform-owned sessions, users, provider identities, and app access independent from a specific vendor.
- Supports future provider substitution if needed.

Cons:

- Requires careful security implementation.
- Requires more explicit testing of token validation, callback handling, state/nonce behavior, and error privacy.

Conclusion: selected as the implementation strategy, with the provider-specific runtime kept behind an adapter.

### Email/Password Auth Owned By Swooshz Platform

Pros:

- Full control of credential storage and login flow.
- No external auth provider dependency.

Cons:

- Requires password storage, reset flows, abuse controls, MFA strategy, email deliverability, and a larger security surface.
- Contradicts the current desire to let a provider prove identity while the platform owns sessions and app access.

Conclusion: not selected.

### Magic-Link Or Email OTP Owned By Swooshz Platform

Pros:

- Avoids password storage.
- Can work well for lightweight internal access.

Cons:

- Requires email delivery, token issuance, replay protection, rate limiting, abuse controls, and session hardening.
- Still makes Swooshz Platform the auth provider rather than only the account/session owner.

Conclusion: not selected.

### Temporary Internal Allowlist/Test-Only Auth

Pros:

- Fast for prototypes.
- Useful for local test fixtures or isolated developer-only demos.

Cons:

- Easy to accidentally promote into real auth.
- Does not prove identity through a real provider.
- Can weaken security expectations before real login exists.

Conclusion: not selected as an auth strategy. Internal UAT should use invitation and/or allowlist gates after provider identity is verified, not bypass authentication.

## Future Implementation Sequence

Recommended next auth implementation sequence:

1. Add auth config/env parser and callback contract tests, DB-free where practical.
2. Add an auth provider adapter interface for OIDC authorization, token exchange, JWKS/userinfo/claims verification, and normalized identity output.
3. Add callback service logic that verifies provider identity through the adapter and resolves provider key plus provider subject.
4. Create or link platform user/provider identity records through repositories.
5. Create platform session records with expiry, revocation support, and privacy-minimized metadata.
6. Add logout/session revocation.
7. Add a minimal protected app-access or launch-decision endpoint.
8. Add frontend/login shell only after backend auth, session, and app-access boundaries are stable.

KQAG adapter work should wait until platform auth/session/app-access endpoints can provide platform-scoped launch context without exposing provider auth material.

## Consequences

Positive consequences:

- Preserves platform ownership of account, session, workspace, membership, invitation, audit, and app access state.
- Avoids premature vendor lock-in.
- Keeps Supabase Auth separate from managed Postgres considerations.
- Gives implementation work a clear adapter contract and privacy boundary.
- Supports internal UAT through invitation and allowlist posture without public signup.

Tradeoffs:

- The first implementation must build more adapter and callback tests than a vendor quickstart.
- Provider-specific capabilities such as hosted user profile management or organizations are deferred.
- Auth provider runtime configuration and exact provider selection remain implementation details behind the OIDC boundary.

## Deferred Decisions

- Exact OIDC provider used for internal UAT.
- Whether Clerk, Auth0, another managed provider, or a generic OIDC tenant is used behind the adapter.
- Cookie name, cookie max age, rotation behavior, and CSRF details.
- State and nonce storage implementation.
- MFA assurance requirements.
- Invitation acceptance UX.
- Admin-created workspace flow.
- Public signup, if ever approved.
- KQAG launch-token or backend exchange protocol.

## Explicit Non-Goals

- No login implementation.
- No callback implementation.
- No logout implementation.
- No auth provider SDK.
- No OIDC network calls.
- No token exchange code.
- No session cookie issuance.
- No backend API routes.
- No HTTP server.
- No frontend shell.
- No Next.js, Vite, React, or UI.
- No public signup.
- No email/password auth.
- No magic-link auth.
- No Clerk SDK.
- No Auth0 SDK.
- No Supabase Auth.
- No real auth URLs.
- No real auth secrets.
- No populated `.env`.
- No provider tokens.
- No raw provider claims.
- No billing, credits, Stripe, or customer portal.
- No KQAG adapter.
- No KQAG repository changes.
- No quote exports, pricing files, embedded logos, bank details, customer/company private data, or private app payloads.

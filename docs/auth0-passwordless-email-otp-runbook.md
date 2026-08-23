# Auth0 Passwordless Email OTP Runbook

This runbook records the accepted production human-authentication boundary for Swooshz Platform. It is repository documentation only: it does not configure a tenant, create a connection, send email, call a live provider, or approve hosted execution.

This implementation adds no fake login, platform-owned email/password auth, active multi-provider runtime, provider SDKs, deployment, database provisioning, or migration automation. External provider, hosting, database, and email setup remain outside this repository change.

## Accepted authentication boundary

Auth0 Universal Login with passwordless email OTP owns human authentication. Swooshz Platform remains a standards-compliant generic OIDC authorization-code client. The platform does not add an Auth0 SDK, platform-owned passwords, OTP generation, or platform-owned OTP email delivery.

The authorization request uses the fixed provider parameter `connection=email`. This is a code-level contract, not a mutable repository configuration selector. No second auth-method or connection selector is supported.

Authentication proves provider identity only. Swooshz Platform remains the sole authority for pending approval, active workspace membership, role, app entitlement, Platform session, and app-launch authority. Successful provider authentication alone grants none of those privileges.

## Synthetic environment mapping

The following values are intercepted-test placeholders. The `.invalid` authority is intentionally non-routable and must not be replaced in repository documentation with a real tenant hostname or credential.

```text
PLATFORM_AUTH_PROVIDER_MODE=generic_oidc
AUTH_PROVIDER_KEY=auth0
AUTH_ISSUER_URL=https://auth0.example.invalid/
AUTH_AUTHORIZATION_URL=https://auth0.example.invalid/authorize
AUTH_TOKEN_URL=https://auth0.example.invalid/oauth/token
AUTH_USERINFO_URL=https://auth0.example.invalid/userinfo
AUTH_JWKS_URL=https://auth0.example.invalid/.well-known/jwks.json
OIDC_CLIENT_ID=<oidc-client-id-placeholder>
OIDC_CLIENT_SECRET=<oidc-client-secret-placeholder>
AUTH_REDIRECT_URI=https://swooshz.com/api/platform/auth/callback
SESSION_SECRET=<session-secret-placeholder>
AUTH_STATE_HASH_SECRET=<auth-state-hash-secret-placeholder>
CSRF_TOKEN_HASH_SECRET=<csrf-token-hash-secret-placeholder>
APP_LAUNCH_TOKEN_HASH_SECRET=<app-launch-token-hash-secret-placeholder>
```

Use the canonical generic runtime names above. Retired client credential aliases and email/domain environment variables are unsupported. Email is a verified, mutable attribute used for the transactional pending-approval match; it is never the permanent identity key. Stable external identity is the approved provider authority plus provider subject (`sub`).

## Security and authorization checks

The generic OIDC path must continue to validate the exact configured issuer, audience and authorized party, RS256 signatures, algorithm, `exp`/`nbf`/`iat`, nonce, required subject, verified email, and exact-sub userinfo responses. State remains hashed, expiring, browser-bound, and one-time. Session cookies, CSRF, Origin/Referer checks, and no-store responses remain enabled.

An authenticated but unapproved identity receives no Platform session or application access except the existing transactional pending-approval acceptance. That acceptance creates only the persisted records authorized by the existing contract; it does not create an arbitrary workspace, role, entitlement, or app authority. A matching email with a different subject or provider authority cannot merge or hijack an existing identity.

App-launch tokens remain short-lived, hashed, one-time, header-only, and revalidated by Platform before the separate-origin handoff. Do not log secrets, tokens, provider claims, or private identity data.

## Synthetic validation sequence

Repository tests use intercepted provider fixtures only. They must prove the fixed `connection=email` selector and the accepted Auth0-shaped `.invalid` issuer while covering wrong issuer, audience, signature, algorithm, nonce, time claims, missing subject, unverified email, mismatched userinfo subject, retired aliases, unsupported allowlist variables, browser binding, one-time state, secure cookies, CSRF/Origin/Referer checks, and app-launch revalidation. Synthetic evidence must never be described as live Auth0 validation.

## Operator smoke outline

After separate controller approval and external provider configuration, an operator may verify that Universal Login completes the passwordless email OTP flow, the callback returns to the exact hosted redirect URI, and the platform applies the existing approval and membership rules. This repository runbook does not authorize those external actions. The first-admin/pending-approval path must be prepared through the existing Platform contract before a reviewed email sign-in.

Verify that `/app` exposes only the active workspace membership and entitled app, and that app launch uses the separate-origin, header-only token handoff. Do not infer Platform authorization from a successful Universal Login screen.

## Troubleshooting

- Authorization errors: confirm the generic OIDC URLs, exact callback shape, and fixed email connection parameter in the reviewed configuration. Do not add a repository-side provider selector.
- Issuer, audience, algorithm, signature, nonce, or time-claim failures: stop and correct the reviewed provider metadata or synthetic fixture; do not weaken verification.
- Unverified email or mismatched userinfo subject: stop; the callback must fail closed.
- Approval-required denial: use the existing Platform admin approval flow. Do not restore email/domain allowlists or create a workspace during authentication.
- No application access after sign-in: check persisted active membership, role, and app entitlement through the existing Platform operator process.

Never paste live tenant values, client secrets, tokens, provider claims, private URLs, or customer email addresses into this document, tests, logs, or visible output.

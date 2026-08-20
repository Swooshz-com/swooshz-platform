# External Auth Provider Selection

This note records the near-term provider posture for internal Swooshz Platform UAT. It is operational guidance for configuring one external identity provider behind the existing generic OIDC runtime. It does not add runtime behavior.

## Platform Identity Model

The external auth provider proves identity. Swooshz Platform owns users, provider identity links, platform sessions, workspaces, memberships, roles, invitations, app access decisions, app entitlements, and app launch tokens.

Provider claims are inputs to the platform identity boundary. They are not the workspace model, not app authorization, and not the SQAG access model. Apps should receive only platform-scoped context through approved platform contracts.

A valid provider identity is not Platform authorization. Without a matching pending workspace-membership approval or active workspace membership, the identity receives a safe approval-required denial. Pending onboarding matches verified normalized email transactionally; membership does not infer role or create app entitlement, and product access continues to require the existing entitlement checks. Auth0 passwordless email sign-in is not public signup, and email/domain environment variables do not admit users.

## Current Runtime Choice

The current runtime supports one active generic OIDC provider through environment configuration:

- `PLATFORM_AUTH_PROVIDER_MODE=generic_oidc`
- `AUTH_PROVIDER_KEY=auth0` for the accepted production authority
- provider endpoint env such as issuer, authorization, token, JWKS, and userinfo URLs
- canonical OIDC client env: `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, and `AUTH_REDIRECT_URI`

Do not implement true active multi-provider login in this phase. Do not build platform-owned email/password auth in this phase. Do not add fake login.

For internal SQAG UAT, Auth0 Universal Login with passwordless email OTP is the accepted smoke target because it exercises the existing generic OIDC login, callback, Platform session, internal access seed, and browser shell flow without adding an Auth0 SDK. The authorization request uses the fixed `connection=email` parameter.

WorkOS/AuthKit is a strong future B2B/hosted-auth candidate, especially for organization-oriented SaaS scenarios. It should be provider-fit checked before any runtime wiring is added.

## Switching Providers Later

Switching providers later is possible because provider identities are separate from platform users. It must still be deliberate because provider subject ids differ across providers. Email alone must not be treated as the immutable external identity key, even when an email address matches.

A future provider migration should define controlled identity linking rules, operator review steps, rollback posture, and audit records before changing the active provider for real users.

## Future Multi-Provider Support

Future active multi-provider login should be a separate architecture PR. That PR should cover:

- provider selection at login start;
- callback disambiguation;
- provider-specific state handling;
- controlled account-linking rules;
- duplicate email and verified-email semantics;
- migration from existing provider subject ids;
- operational logging that remains privacy-safe;
- tests for provider confusion and unsafe account linking.

Until then, keep one active OIDC provider configured by env and run the existing smoke flow against that provider.

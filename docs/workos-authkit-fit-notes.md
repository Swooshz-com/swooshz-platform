# WorkOS/AuthKit Fit Notes

WorkOS/AuthKit is a potential future hosted-auth provider candidate for Swooshz Platform. It may be stronger than plain Google OAuth for B2B, organization, and customer-facing SaaS needs.

Do not wire WorkOS runtime integration in this PR. Do not implement active multi-provider login in this PR. Keep the current operational smoke target on one active generic OIDC provider until a separate provider-fit decision is reviewed.

## Fit Check Before Runtime Wiring

A future provider-fit PR should verify:

- OIDC/OAuth endpoints;
- issuer URL;
- authorization URL;
- token URL;
- JWKS URL;
- userinfo or claims shape;
- provider subject stability;
- verified email semantics;
- MFA policy support;
- organization and team model interaction with the Swooshz-owned workspace model;
- redirect and callback constraints;
- local and internal smoke steps;
- pricing and plan assumptions at decision time.

Use placeholders only while evaluating fit. Do not include real account ids, tenant ids, API keys, domains, client secrets, staff emails, provider subjects, callback payloads, provider claims, provider responses, or production URLs in repo docs or tests.

## Platform Boundary

Even if WorkOS later owns login, Swooshz Platform should still own users, sessions, workspaces, memberships, roles, app access, app entitlements, invitations, and app launch tokens.

The WorkOS organization or team model may be useful context, but it must not silently replace the platform workspace and membership model. Any mapping must be explicit, tested, and reversible.

## Migration Notes

Future migration from Google to WorkOS requires deliberate provider-identity linking or migration because provider subject ids differ. A matching email address is not enough to prove the same external identity.

A future migration PR should define operator review, account-linking rules, duplicate handling, audit events, rollback posture, and privacy-safe troubleshooting before changing real users to a new provider.

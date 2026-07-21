# Google OIDC Setup Runbook

This runbook configures Google as the first practical external OIDC provider for internal Swooshz Platform UAT. Google proves identity through OIDC. Swooshz Platform still owns users, sessions, workspaces, memberships, roles, app access, app entitlements, invitations, and app launch tokens.

Google does not own workspace roles or SQAG access. We are not building our own email/password or 2FA system in this phase, and we are not adding fake login.

## Google OAuth App Setup

Use placeholders only in shared docs, tickets, and PRs. Do not paste real client secrets, auth codes, provider tokens, provider responses, provider claims, staff emails, private domains, or database URLs.

1. Create or select a Google Cloud project.
2. Configure the OAuth consent screen.
3. Use External audience if personal Google accounts or Gmail accounts need to log in.
4. Use Internal audience only if testing is limited to Google Workspace organization accounts.
5. Create OAuth client credentials for a web application.
6. Add this authorized redirect URI:

```text
<platform-base-url>/api/platform/auth/callback
```

7. Request only these scopes:

```text
openid
email
profile
```

## Platform Env Mapping

Set the generic OIDC runtime mode and Google endpoint mapping with placeholders for provider credentials and platform URL:

```text
PLATFORM_AUTH_PROVIDER_MODE=generic_oidc
AUTH_PROVIDER_KEY=google
AUTH_ISSUER_URL=https://accounts.google.com
AUTH_AUTHORIZATION_URL=https://accounts.google.com/o/oauth2/v2/auth
AUTH_TOKEN_URL=https://oauth2.googleapis.com/token
AUTH_JWKS_URL=https://www.googleapis.com/oauth2/v3/certs
AUTH_USERINFO_URL=https://openidconnect.googleapis.com/v1/userinfo
AUTH_CLIENT_ID=<google-oauth-client-id>
AUTH_CLIENT_SECRET=<google-oauth-client-secret>
AUTH_REDIRECT_URI=https://swooshz.com/api/platform/auth/callback
AUTH_ALLOWED_EMAILS=<comma-separated-allowlisted-emails>
AUTH_ALLOWED_DOMAINS=<comma-separated-allowed-domains>
```

The existing required platform env remains necessary:

```text
DATABASE_URL=<database-url-from-existing-service>
DATABASE_SSL_MODE=<ssl-mode-if-needed>
PLATFORM_HTTP_HOST=<host-to-bind>
PLATFORM_HTTP_PORT=<port-to-bind>
PLATFORM_PUBLIC_BASE_URL=<platform-base-url>
PLATFORM_ALLOWED_ORIGINS=<comma-separated-platform-origins>
PLATFORM_COOKIE_SECURE=<true-or-false-for-this-environment>
SESSION_SECRET=<strong-random-placeholder>
CSRF_TOKEN_HASH_SECRET=<strong-random-placeholder>
APP_LAUNCH_TOKEN_HASH_SECRET=<strong-random-placeholder>
AUTH_STATE_HASH_SECRET=<strong-random-placeholder>
```

## Security Notes

Personal Google accounts can be invited or allowed by exact email. With personal Gmail, Swooshz cannot enforce the user's Google 2FA policy. With Google Workspace, administrators can enforce 2-Step Verification in Workspace admin settings outside this repo.

For internal UAT, exact `AUTH_ALLOWED_EMAILS` is preferred over open domain allow. `AUTH_ALLOWED_EMAILS` is only a provider-entry filter; it does not create Platform users, workspaces, memberships, or first-owner access. Do not use broad domain allow unless intentionally approved. Keep `AUTH_ALLOWED_DOMAINS` unset unless the UAT risk and user population have been reviewed.

Do not commit `.env` files or real provider secrets. Do not log provider tokens, ID tokens, auth codes, raw OIDC state, raw OIDC nonce, provider claims, raw provider responses, callback URLs containing secrets, or user profile JSON.

## Smoke Sequence With Google

Use this runbook together with `docs/internal-platform-smoke-runbook.md`.

1. Apply reviewed migrations explicitly with the existing guarded migration flow.
2. Start the server with `npm run platform:start`.
3. Visit `/`.
4. Click sign in.
5. For a fresh DB, run `npm run platform:seed-internal-access` with `PLATFORM_SEED_BOOTSTRAP_MODE=first-owner-pending-approval` for the reviewed first-owner email before login.
6. Complete Google login with that reviewed email.
7. Confirm the callback redirects to `/app` and activates the pending first-owner approval.
8. Refresh `/app`.
9. Confirm workspace access, app access, and launch intent behavior.

## Troubleshooting

- `redirect_uri_mismatch`: confirm the Google OAuth client authorized redirect URI exactly matches `https://swooshz.com/api/platform/auth/callback` and `AUTH_REDIRECT_URI`. Never register `www.swooshz.com` as a callback.
- Google consent screen not configured or not published for external users: finish the consent screen setup or keep testing within the configured audience.
- Test user not added while the app is in testing mode: add the placeholder tester account in Google Cloud before retrying.
- Invalid client id or secret: replace the local env values from the Google OAuth client without pasting the values into docs or logs.
- Missing `openid email profile` scope: update the auth request scope configuration to include the required OIDC scopes.
- Callback state or nonce failure: restart login from `/`, check `AUTH_STATE_HASH_SECRET`, and confirm callback requests return to the same platform origin and database-backed auth state store.
- Email not allowed by `AUTH_ALLOWED_EMAILS`: add the exact reviewed email to the local allowlist and restart login.
- User logs in before being allowlisted: allowlist the exact email, restart login, and avoid using broad domain allow as a shortcut.
- Seed says user not found: either use first-owner pending approval mode before first login, or complete Google login first when seeding an existing provider-backed user.
- Seed says missing provider identity: inspect the auth callback path; existing-user seeding requires an already-authenticated user with a provider identity.
- `/app` has a session but no workspace or app access: run the internal access seed for the exact logged-in email, then refresh `/app`.

## Out Of Scope

This runbook does not add platform-owned email/password auth, fake login, active multi-provider runtime behavior, provider SDKs, deployment, database provisioning, migration automation, SQAG integration, app redirect integration into SQAG, billing, or Stripe.

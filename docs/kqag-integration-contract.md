# KQAG Integration Contract

KQAG/SAQG is the first app integration target for Swooshz Platform. This contract defines the boundary before any integration code exists.

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

## Future Identity Context

In a future adapter phase, KQAG should accept a platform-issued identity and workspace context instead of owning account identity.

Minimum context:

- `platform_user_id`.
- `platform_workspace_id`.
- `membership_role`.
- `app_key`: `kqag`.
- `launch_context_id` or request id.
- Expiry or freshness claim if a signed launch token is used.

KQAG should use this context to scope runtime/session/history data once that integration exists.

KQAG should not receive:

- Raw auth provider claims.
- OIDC authorization codes.
- Access tokens.
- Refresh tokens.
- Platform session secrets.
- Billing provider secrets.
- Other workspace memberships.

## Runtime And History Direction

Today, KQAG can use local/runtime storage for internal UAT. Later, KQAG runtime and session history can move behind platform-owned workspace identity.

The future direction is:

1. Platform authenticates the user.
2. Platform selects the workspace.
3. Platform authorizes KQAG launch.
4. KQAG receives scoped workspace identity.
5. KQAG stores or resolves quote workflow state under that workspace context.

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

Current phase. Define accounts, workspaces, memberships, roles, invitations, sessions, audit events, app records, and app entitlement contract.

No frontend, auth provider, database migration, billing, deployment, or KQAG code changes.

### Phase 2: Platform Login/Workspace/App Access Backend

Scaffold the platform backend for:

- Users.
- Workspaces.
- Memberships.
- Sessions.
- Invitations.
- Apps.
- App entitlements.
- Access decision service.
- Audit events.

Auth provider selection may happen here or in a dedicated preceding decision record.

### Phase 3: KQAG Platform Adapter

Define and implement the integration boundary between Swooshz Platform and KQAG. This may include signed launch context, backend session exchange, or another approved mechanism.

KQAG changes should stay adapter-scoped and quote-workflow-specific.

### Phase 4: Platform Frontend Shell

Build the minimal platform UI only after backend account and app-access contracts are stable. It may include login, workspace switcher, app launcher, and internal admin views.

### Phase 5: Billing/Credits If Approved Later

Add billing and credit concepts only after the account/app entitlement model is working. Billing should influence entitlement decisions without changing the core membership model.

## Open Decisions For Later

- Auth provider and session storage.
- Database technology and migration format.
- Launch-token or backend exchange mechanism.
- KQAG runtime storage location once platform-scoped.
- Billing provider and credit model.
- Platform shell frontend stack.

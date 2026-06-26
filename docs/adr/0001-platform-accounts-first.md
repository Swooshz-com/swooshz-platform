# ADR 0001: Platform Accounts First

## Status

Accepted.

## Context

Swooshz needs a platform that can own accounts, workspaces, app access, and eventually billing or credits across apps. KQAG/SAQG already exists as a quote-workflow-specific app and should remain focused on quoting.

Without a clear account and app-access contract, the project is likely to fall into repeated frontend rewrites: login screens, dashboards, app shells, and workspace selectors can be designed many ways if the underlying product scope is unclear.

## Decision

Define accounts, workspaces, memberships, roles, invitations, sessions, audit events, apps, and app entitlements before implementing frontend UI.

The first platform PRs should establish backend-ready contracts and architecture boundaries. Frontend shell work waits until the account and app-access model is stable enough to support it.

## Consequences

Positive:

- Backend scaffolding can proceed from a clear model.
- KQAG remains quote-workflow-specific.
- Future apps can be added through app records and entitlements instead of new account concepts.
- Billing/credits have a reserved location without contaminating users or memberships.
- Frontend work can be smaller and less likely to churn.

Tradeoffs:

- There is no visible platform UI from this PR.
- Some implementation decisions remain deferred, including auth provider, database, and launch-token mechanism.
- Product stakeholders must review contract docs before expecting UI delivery.

## Explicit Non-Goals

- No Next.js, Vite, React, or frontend shell.
- No UI design.
- No email/password login.
- No public signup.
- No real auth provider integration.
- No database migrations.
- No Supabase setup.
- No Stripe, billing, or credits implementation.
- No customer portal.
- No deployment, VPS, Coolify, DNS, TLS, or firewall work.
- No secrets.
- No KQAG repo changes.

## Follow-Up Decisions

- Auth provider selection.
- Database and migration strategy.
- Session storage and revocation strategy.
- App launch integration mechanism.
- KQAG adapter contract details.
- Billing/credits architecture if approved.

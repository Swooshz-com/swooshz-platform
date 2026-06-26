# Swooshz Platform

Swooshz Platform is the future shared platform layer for Swooshz apps. It will own account identity, workspace membership, app access, app whitelisting, and eventually billing or credits when those are explicitly approved.

The current priority is not a frontend shell. The current priority is to define the account, workspace, and app-access contract clearly enough that backend scaffolding can start without reopening basic product boundaries.

## What This Platform Owns

- Users and sessions.
- Workspaces/accounts representing the organization or operating unit that uses Swooshz apps.
- Workspace memberships and roles.
- Invitations into a workspace.
- Audit events for account, access, and security-relevant actions.
- App registry records for Swooshz apps.
- App entitlements and app access decisions per workspace.
- Later billing, credits, subscriptions, or usage ledgers if approved in a future phase.
- Later shared platform shell and cross-app navigation after the backend contract is stable.

## What This Platform Does Not Own

- App-specific workflow logic.
- Quote generation, pricing reference import, quotation layout, or quote export logic.
- KQAG/SAQG runtime behavior until a platform adapter phase is explicitly started.
- Customer portal behavior.
- Public SaaS launch behavior.
- Deployment, VPS, Coolify, DNS, TLS, or firewall setup in this initial contract PR.
- Billing or credits implementation in this initial contract PR.

## Current Priority

Phase 0 is contract and architecture only:

1. Define the account domain.
2. Define workspace app access.
3. Define the KQAG integration boundary.
4. Record the decision to build accounts/workspaces/app access before UI.

No Next.js, Vite, React, frontend shell, database migration, real auth provider, public signup, deployment, Supabase setup, Stripe setup, or secrets are part of this phase.

## First App Integration Target

KQAG/SAQG is the first app integration target. It remains a separate app in `Swooshz-com/koncept-quote-auto-generator` and stays quote-workflow-specific.

The platform will eventually provide KQAG with platform-issued identity and workspace context. KQAG should not grow its own accounts, users, billing, workspace membership, app registry, customer portal, or platform shell.

## Contract Docs

- `docs/accounts-contract.md`
- `docs/app-access-contract.md`
- `docs/kqag-integration-contract.md`
- `docs/adr/0001-platform-accounts-first.md`
- `docs/roadmap.md`

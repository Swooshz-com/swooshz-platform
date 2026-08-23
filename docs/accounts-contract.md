# Accounts Contract

This document defines the platform account domain before implementation. The goal is to make the next backend scaffold PR mechanical: create the models, validation, and service boundaries described here without re-deciding what an account means.

## Scope

The platform owns users, workspaces, memberships, roles, invitations, sessions, audit events, app records, and app entitlements. Billing and credits are reserved concepts only in this phase.

SQAG and other apps own their app-specific workflow state. They must not create separate user, workspace, billing, or entitlement concepts.

## Core Entities

### User

A user is a human identity that can sign in to the platform and hold membership in one or more workspaces.

MVP fields:

- `id`: stable platform user id.
- `email`: normalized email address used for sign-in and invitations.
- `display_name`: user-visible name.
- `status`: `active`, `invited`, `disabled`.
- `created_at`: timestamp.
- `updated_at`: timestamp.
- `last_login_at`: nullable timestamp.

Deferred fields:

- `avatar_url`.
- `preferred_locale`.
- `timezone`.
- `mfa_status`.
- `external_identity_subject`.
- `deleted_at` or retention/anonymization markers.

Invariants:

- Email is unique among non-deleted users after normalization.
- A disabled user cannot start new sessions.
- A user alone does not grant app access; access is decided through workspace membership plus app entitlement.
- Internal access seeding must not create email-only users for future provider linking. A user should receive seeded app access only after real auth has created the platform user and provider identity records.

### Workspace / Account

A workspace, also called an account in business-facing copy, is the owning container for organization-level access to apps.

MVP fields:

- `id`: stable workspace id.
- `slug`: unique URL-safe workspace key.
- `display_name`: workspace name.
- `status`: `active`, `suspended`, `archived`.
- `created_at`: timestamp.
- `updated_at`: timestamp.

Deferred fields:

- `legal_name`.
- `billing_email`.
- `tax_id`.
- `country`.
- `address`.
- `data_region`.
- `branding_settings`.
- `retention_policy`.

Invariants:

- Every app access decision is scoped to a workspace.
- Archived workspaces cannot launch apps.
- Workspace display name is not proof of legal ownership or billing status.

### Membership

A membership connects a user to a workspace with a role.

MVP fields:

- `id`: stable membership id.
- `workspace_id`: workspace id.
- `user_id`: user id.
- `role`: role key.
- `status`: `active`, `disabled`.
- `created_at`: timestamp.
- `updated_at`: timestamp.

Deferred fields:

- `created_by_user_id`.
- `disabled_by_user_id`.
- `disabled_reason`.
- `last_workspace_access_at`.
- Per-app role overrides.

Invariants:

- A user can have at most one active membership per workspace.
- A user cannot access workspace apps without an active membership.
- Disabling membership removes workspace access even if the user remains active.

### Role

A role defines workspace-level permissions. Roles are platform concepts; app permissions can map to them but must not redefine account membership.

MVP roles:

- `admin`: full workspace administration, including membership and app access management.
- `operator`: normal internal application use where entitlement allows it; no workspace administration.
- `viewer`: read-only Platform workspace visibility; no operational app launch by default.


MVP fields if stored:

- `key`: role key.
- `label`: user-visible label.
- `description`: short description.
- `permissions`: platform permission keys.

Deferred fields:

- Custom roles.
- Per-app permission grants.
- Permission groups.
- Role templates.

Invariants:

- Every active workspace with memberships must retain at least one active `admin`. Zero-member state is valid only for the defined first-admin bootstrap case.
- Role grants are necessary but not sufficient for app launch; workspace app entitlement must also allow the app. Current stored role values are exactly `admin`, `operator`, and `viewer`.
- Billing state must not silently grant platform admin permissions.

### Current Role Migration

The current role vocabulary is exactly `admin`, `operator`, and `viewer`.

The atomic migration in `drizzle/migrations/0010_admin_operator_viewer_role_collapse.sql` maps current stored values as follows:

- `owner` -> `admin`.
- `admin` -> `admin`.
- `member` -> `operator`.
- `viewer` -> `viewer`.

The mapping applies to membership, pending workspace membership approval, and invitation role columns. Historical audit JSON is factual evidence and is not rewritten; old `owner` and `member` values shown there are historical, not selectable current roles. Quiesce old writers, apply the migration, verify the post-migration admin invariant, then start or serve the new application contract. Mixed application versions across this migration are unsupported.
### Invitation

An invitation allows a new or existing user to join a workspace.

MVP fields:

- `id`: stable invitation id.
- `workspace_id`: target workspace id.
- `email`: normalized invited email.
- `role`: role to grant on acceptance.
- `status`: `pending`, `accepted`, `expired`, `revoked`.
- `invited_by_user_id`: inviting user id.
- `created_at`: timestamp.
- `expires_at`: timestamp.
- `accepted_at`: nullable timestamp.

Deferred fields:

- `message`.
- `resent_at`.
- `accepted_by_user_id`.
- Domain policy checks.
- Invite link delivery provider metadata.

Invariants:

- Accepting an invitation creates or activates exactly one membership.
- Revoked or expired invitations cannot be accepted.
- Invitation tokens must be stored hashed if token storage is implemented.

### Session

A session represents a signed-in browser or API client context for a user.

MVP fields:

- `id`: stable session id.
- `user_id`: user id.
- `created_at`: timestamp.
- `expires_at`: timestamp.
- `last_seen_at`: timestamp.
- `revoked_at`: nullable timestamp.

Deferred fields:

- `auth_provider`.
- `auth_provider_session_id`.
- `ip_hash`.
- `user_agent_hash`.
- `mfa_verified_at`.
- Device label.

Invariants:

- Session storage must not contain raw provider tokens unless a later auth design explicitly approves encrypted token storage.
- Revoked or expired sessions cannot launch apps.
- Session data must not be used as workspace authorization without checking active membership and entitlement.

### Audit Event

An audit event records security, account, membership, and app access changes.

MVP fields:

- `id`: stable event id.
- `workspace_id`: nullable workspace id.
- `actor_user_id`: nullable user id.
- `event_type`: stable event key.
- `target_type`: affected entity type.
- `target_id`: affected entity id.
- `created_at`: timestamp.
- `metadata`: privacy-minimized JSON object.

Deferred fields:

- `request_id`.
- `ip_hash`.
- `user_agent_hash`.
- Export status.
- Retention class.

Invariants:

- Audit metadata must not store secrets, raw auth headers, provider tokens, invitation tokens, payment details, bank details, quote exports, or private app payloads.
- Account and app-access changes should emit audit events.
- Audit events should be append-only from the application perspective.

### App

An app is a platform-known product surface that can be enabled for workspaces.

MVP fields:

- `id`: stable app id, for example `sqag`.
- `key`: stable slug, for example `sqag`.
- `name`: user-visible app name.
- `status`: `available`, `private_preview`, `disabled`.
- `launch_url`: nullable future app launch URL.
- `created_at`: timestamp.
- `updated_at`: timestamp.

Deferred fields:

- `icon_url`.
- `description`.
- `category`.
- `integration_mode`.
- `required_scopes`.
- `healthcheck_url`.
- `support_url`.

Invariants:

- App records describe launchable apps; they do not grant access by themselves.
- Future apps must be addable without changing the user, workspace, or membership model.
- Disabling an app prevents new launches even if a workspace has entitlement.

### App Entitlement / App Access

An app entitlement grants a workspace access to an app. App access is the runtime decision that combines entitlement, user membership, role permission, app status, and later billing status.

MVP fields:

- `id`: stable entitlement id.
- `workspace_id`: workspace id.
- `app_id`: app id.
- `status`: `enabled`, `disabled`, `trial`, `suspended`.
- `granted_by_user_id`: nullable user id.
- `created_at`: timestamp.
- `updated_at`: timestamp.

Deferred fields:

- `starts_at`.
- `ends_at`.
- `plan_key`.
- `seat_limit`.
- `usage_limit`.
- `billing_subscription_id`.
- `credit_pool_id`.
- `reason`.

Invariants:

- A workspace can have at most one active entitlement record per app.
- Entitlement does not replace membership or role checks.
- Suspended entitlement blocks app launch even for `admin`, `operator`, or `viewer` memberships.
- Billing/credits can later influence entitlement status but must not be mixed into the membership model.

## Internal Access Seed Contract

Internal workspace/app-access seed code is a platform-only backend contract. It may prepare:

- An active internal workspace by stable slug.
- The `sqag` app registry record.
- An enabled or trial workspace entitlement for that app.
- An active membership grant for an `admin`, `operator`, or `viewer`.

The seed contract must be idempotent. Existing matching workspace, app, entitlement, membership, or user records may be reused. Existing conflicting records must fail with privacy-safe stable errors instead of being overwritten silently.

Identity-linking safety is required:

- A membership may be granted to an existing user by user id or normalized email lookup only if that user already exists and is active.
- Creating a new user together with a provider identity is deferred until an explicit transactional identity seed boundary exists.
- Provider-identity user creation must fail before any platform writes in this PR so it cannot leave behind a partial active user or identity record.
- The seed must never create an email-only user intended for future provider linking. The auth resolver intentionally rejects linking a new provider identity to an existing email-only user to avoid account takeover, and seed code must preserve that behaviour.
- Membership grants may be seeded for `admin`, `operator`, or `viewer`; a valid `viewer` membership remains denied SQAG launch by the current app-access decision.

This contract does not add a fake-login shortcut, hardcoded production account, provider SDK, provider network call, migration execution path, frontend, SQAG adapter, app launch token, billing, deployment script, or live seed command.

### Billing / Credits Reserved Concepts

Billing and credits are reserved for later phases. They are named now to avoid polluting the account model later, but they are not implemented in this PR.

Reserved concepts:

- `billing_customer`.
- `subscription`.
- `invoice`.
- `credit_pool`.
- `credit_transaction`.
- `usage_event`.

MVP fields:

- None in this phase.

Deferred fields:

- All payment provider ids.
- Subscription plan ids.
- Credit balances.
- Usage metering.
- Invoice and tax fields.

Invariants:

- Do not put Stripe or payment provider ids on `User`, `Workspace`, `Membership`, or `App`.
- Billing state may affect entitlement status later.
- Credits must never live inside SQAG.

## Access Decision Contract

For an app launch request, the platform must check:

1. User session is valid.
2. User has active membership in selected workspace.
3. Workspace is active.
4. App exists and is available.
5. Workspace has enabled entitlement for the app.
6. User role permits app launch.
7. Later: billing or credit status does not block the app.

Return values should be generic and privacy-safe:

- `allowed`.
- `not_authenticated`.
- `workspace_not_selected`.
- `membership_required`.
- `app_not_available`.
- `app_not_enabled_for_workspace`.
- `role_not_permitted`.
- `billing_blocked` once billing exists.

## Privacy And Security Rules

- Never commit secrets, populated `.env` files, private customer files, bank data, payment details, real auth tokens, or provider responses.
- Store authentication provider identifiers separately from business-facing profile fields.
- Do not expose whether a private email belongs to an existing user in public responses.
- Normalize emails consistently before uniqueness, invitation, and membership checks.
- Use privacy-minimized audit metadata.
- Treat app payloads as app-owned private data; the platform should store only the account/access metadata it needs.
- Platform errors must not leak raw provider messages, tokens, invitation secrets, or entitlement internals.

## Example Initial Workspace

This is a contract example, not seed data and not a migration.

Workspace:

- `id`: `workspace_koncept_images`
- `slug`: `koncept-images`
- `display_name`: `Koncept Images Pte Ltd`
- `status`: `active`

User:

- `id`: `user_admin_example`
- `email`: `admin@example.com`
- `display_name`: `Platform Admin`
- `status`: `active`

Membership:

- `workspace_id`: `workspace_koncept_images`
- `user_id`: `user_admin_example`
- `role`: `admin`
- `status`: `active`

App:

- `id`: `app_sqag`
- `key`: `sqag`
- `name`: `SQAG`
- `status`: `private_preview`

App entitlement:

- `workspace_id`: `workspace_koncept_images`
- `app_id`: `app_sqag`
- `status`: `enabled`

Expected launch decision for `user_admin_example` in `workspace_koncept_images` launching `app_sqag`: `allowed`.

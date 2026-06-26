# Accounts Contract

This document defines the platform account domain before implementation. The goal is to make the next backend scaffold PR mechanical: create the models, validation, and service boundaries described here without re-deciding what an account means.

## Scope

The platform owns users, workspaces, memberships, roles, invitations, sessions, audit events, app records, and app entitlements. Billing and credits are reserved concepts only in this phase.

KQAG/SAQG and other apps own their app-specific workflow state. They must not create separate user, workspace, billing, or entitlement concepts.

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

- `owner`: full workspace administration, including membership and app access management.
- `admin`: workspace administration except destructive ownership transfer.
- `member`: normal app usage where entitlement allows it.
- `viewer`: read-only app usage where supported.

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

- Every active workspace should have at least one active `owner`.
- Role grants are necessary but not sufficient for app launch; workspace app entitlement must also allow the app.
- Billing state must not silently grant platform admin permissions.

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

- `id`: stable app id, for example `kqag`.
- `key`: stable slug, for example `kqag`.
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
- Suspended entitlement blocks app launch even for owners.
- Billing/credits can later influence entitlement status but must not be mixed into the membership model.

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
- Credits must never live inside KQAG/SAQG.

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

- `id`: `user_owner_example`
- `email`: `owner@example.com`
- `display_name`: `Platform Owner`
- `status`: `active`

Membership:

- `workspace_id`: `workspace_koncept_images`
- `user_id`: `user_owner_example`
- `role`: `owner`
- `status`: `active`

App:

- `id`: `app_kqag`
- `key`: `kqag`
- `name`: `KQAG / SAQG`
- `status`: `private_preview`

App entitlement:

- `workspace_id`: `workspace_koncept_images`
- `app_id`: `app_kqag`
- `status`: `enabled`

Expected launch decision for `user_owner_example` in `workspace_koncept_images` launching `app_kqag`: `allowed`.

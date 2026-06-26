import assert from "node:assert/strict";
import test from "node:test";

import {
  AccessDecisionResult,
  decideAppAccess,
  normalizeEmail,
  normalizeWorkspaceSlug,
} from "../dist/index.js";

const now = "2026-06-26T00:00:00.000Z";

function baseFixture(overrides = {}) {
  const workspace = {
    id: "workspace_koncept_images",
    slug: "koncept-images-pte-ltd",
    displayName: "Koncept Images Pte Ltd",
    status: "active",
    createdAt: now,
    updatedAt: now,
    ...overrides.workspace,
  };

  const app = {
    id: "app_kqag",
    key: "kqag",
    name: "KQAG / SAQG",
    status: "private_preview",
    launchUrl: null,
    createdAt: now,
    updatedAt: now,
    ...overrides.app,
  };

  const entitlement = {
    id: "entitlement_koncept_kqag",
    workspaceId: workspace.id,
    appId: app.id,
    status: "enabled",
    grantedByUserId: "user_owner_example",
    createdAt: now,
    updatedAt: now,
    ...overrides.entitlement,
  };

  const usersByRole = Object.fromEntries(
    ["owner", "admin", "member", "viewer"].map((role) => [
      role,
      {
        id: `user_${role}_example`,
        email: `${role}@example.com`,
        displayName: `${role[0].toUpperCase()}${role.slice(1)} Example`,
        status: "active",
        createdAt: now,
        updatedAt: now,
        lastLoginAt: now,
      },
    ]),
  );

  const memberships = Object.entries(usersByRole).map(([role, user]) => ({
    id: `membership_${role}_example`,
    workspaceId: workspace.id,
    userId: user.id,
    role,
    status: "active",
    createdAt: now,
    updatedAt: now,
  }));

  const role = overrides.role ?? "owner";
  const user = { ...usersByRole[role], ...overrides.user };
  const session = {
    id: `session_${role}_example`,
    userId: user.id,
    createdAt: now,
    expiresAt: "2026-06-27T00:00:00.000Z",
    lastSeenAt: now,
    revokedAt: null,
    ...overrides.session,
  };

  return {
    appKey: "kqag",
    session:
      overrides.session === undefined
        ? session
        : overrides.session === null
          ? null
          : { ...session, ...overrides.session },
    user,
    selectedWorkspaceId:
      overrides.selectedWorkspaceId === undefined ? workspace.id : overrides.selectedWorkspaceId,
    workspaces: [workspace],
    memberships: overrides.memberships ?? memberships,
    apps: overrides.apps ?? [app],
    entitlements: overrides.entitlements ?? [entitlement],
    billingGate: overrides.billingGate,
    now: overrides.now ?? now,
  };
}

function resultFor(overrides = {}) {
  return decideAppAccess(baseFixture(overrides));
}

// Synthetic fixtures only. These values are not production seed data.
test("normalizes email addresses deterministically", () => {
  assert.equal(normalizeEmail("  Owner@Example.COM  "), "owner@example.com");
  assert.equal(normalizeEmail("ADMIN+KQAG@EXAMPLE.com"), "admin+kqag@example.com");
});

test("normalizes workspace slugs to URL-safe lowercase values", () => {
  assert.equal(normalizeWorkspaceSlug("Koncept Images Pte Ltd"), "koncept-images-pte-ltd");
  assert.equal(normalizeWorkspaceSlug("  Swooshz / KQAG Preview!  "), "swooshz-kqag-preview");
});

test("allows KQAG for owner role", () => {
  assert.equal(resultFor({ role: "owner" }).result, AccessDecisionResult.Allowed);
});

test("allows KQAG for admin role", () => {
  assert.equal(resultFor({ role: "admin" }).result, AccessDecisionResult.Allowed);
});

test("allows KQAG for member role", () => {
  assert.equal(resultFor({ role: "member" }).result, AccessDecisionResult.Allowed);
});

test("blocks KQAG for viewer role until a viewer adapter exists", () => {
  assert.equal(resultFor({ role: "viewer" }).result, AccessDecisionResult.RoleNotPermitted);
});

test("returns not_authenticated when no session exists", () => {
  assert.equal(resultFor({ session: null }).result, AccessDecisionResult.NotAuthenticated);
});

test("returns not_authenticated when session is expired", () => {
  assert.equal(
    resultFor({ session: { expiresAt: "2026-06-25T23:59:59.000Z" } }).result,
    AccessDecisionResult.NotAuthenticated,
  );
});

test("returns not_authenticated when session is revoked", () => {
  assert.equal(
    resultFor({ session: { revokedAt: "2026-06-26T00:00:00.000Z" } }).result,
    AccessDecisionResult.NotAuthenticated,
  );
});

test("returns not_authenticated when session user does not match the user", () => {
  assert.equal(
    resultFor({ session: { userId: "user_other_example" } }).result,
    AccessDecisionResult.NotAuthenticated,
  );
});

test("allows normal access when session is valid and unexpired", () => {
  assert.equal(
    resultFor({ session: { expiresAt: "2026-06-27T00:00:00.000Z" } }).result,
    AccessDecisionResult.Allowed,
  );
});

test("returns workspace_not_selected when no workspace is selected", () => {
  assert.equal(resultFor({ selectedWorkspaceId: null }).result, AccessDecisionResult.WorkspaceNotSelected);
});

test("returns user_not_active for disabled users", () => {
  assert.equal(resultFor({ user: { status: "disabled" } }).result, AccessDecisionResult.UserNotActive);
});

test("returns membership_required when membership is missing", () => {
  assert.equal(resultFor({ memberships: [] }).result, AccessDecisionResult.MembershipRequired);
});

test("returns membership_required when membership is disabled", () => {
  const fixture = baseFixture();
  const memberships = fixture.memberships.map((membership) =>
    membership.userId === fixture.user.id ? { ...membership, status: "disabled" } : membership,
  );

  assert.equal(resultFor({ memberships }).result, AccessDecisionResult.MembershipRequired);
});

test("returns workspace_not_active when workspace is suspended", () => {
  assert.equal(resultFor({ workspace: { status: "suspended" } }).result, AccessDecisionResult.WorkspaceNotActive);
});

test("returns workspace_not_active when workspace is archived", () => {
  assert.equal(resultFor({ workspace: { status: "archived" } }).result, AccessDecisionResult.WorkspaceNotActive);
});

test("returns app_not_available when app is globally disabled", () => {
  assert.equal(resultFor({ app: { status: "disabled" } }).result, AccessDecisionResult.AppNotAvailable);
});

test("returns app_not_available when app is missing from the whitelist", () => {
  assert.equal(resultFor({ apps: [] }).result, AccessDecisionResult.AppNotAvailable);
});

test("returns app_not_enabled_for_workspace when entitlement is missing", () => {
  assert.equal(resultFor({ entitlements: [] }).result, AccessDecisionResult.AppNotEnabledForWorkspace);
});

test("returns app_not_enabled_for_workspace when entitlement is suspended", () => {
  assert.equal(
    resultFor({ entitlement: { status: "suspended" } }).result,
    AccessDecisionResult.AppNotEnabledForWorkspace,
  );
});

test("returns billing_blocked only when the future billing gate explicitly blocks", () => {
  assert.equal(resultFor({ billingGate: { blocked: false } }).result, AccessDecisionResult.Allowed);
  assert.equal(resultFor({ billingGate: { blocked: true } }).result, AccessDecisionResult.BillingBlocked);
  assert.equal(
    resultFor({ app: { status: "disabled" }, billingGate: { blocked: true } }).result,
    AccessDecisionResult.AppNotAvailable,
  );
});

test("does not leak private fixture details in access decision messages", () => {
  const decision = resultFor({ role: "viewer" });

  assert.doesNotMatch(decision.message, /example\.com/i);
  assert.doesNotMatch(decision.message, /Koncept/i);
  assert.doesNotMatch(decision.message, /workspace_koncept_images/i);
  assert.doesNotMatch(decision.message, /user_viewer_example/i);
});

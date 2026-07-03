import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  AccessDecisionResult,
  decidePlatformAppAccess,
} from "../dist/index.js";
import { createInMemoryPlatformRepositories } from "./helpers/in-memory-platform-repositories.mjs";

const now = "2026-06-26T00:00:00.000Z";

function platformFixture(overrides = {}) {
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

  const memberships = Object.entries(usersByRole).map(([membershipRole, membershipUser]) => ({
    id: `membership_${membershipRole}_example`,
    workspaceId: workspace.id,
    userId: membershipUser.id,
    role: membershipRole,
    status: "active",
    createdAt: now,
    updatedAt: now,
  }));

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

  const repositories = createInMemoryPlatformRepositories({
    users: overrides.users ?? [user],
    sessions:
      overrides.sessions ??
      (overrides.session === null ? [] : [{ ...session, ...overrides.session }]),
    workspaces: overrides.workspaces ?? [workspace],
    memberships: overrides.memberships ?? memberships,
    apps: overrides.apps ?? [app],
    appEntitlements: overrides.appEntitlements ?? [entitlement],
  });

  return {
    repositories,
    input: {
      sessionId: overrides.sessionId === undefined ? session.id : overrides.sessionId,
      selectedWorkspaceId:
        overrides.selectedWorkspaceId === undefined
          ? workspace.id
          : overrides.selectedWorkspaceId,
      appKey: overrides.appKey ?? "kqag",
      billingGate: overrides.billingGate,
      now: overrides.now ?? now,
    },
  };
}

async function decisionFor(overrides = {}) {
  const fixture = platformFixture(overrides);
  return decidePlatformAppAccess(fixture.repositories, fixture.input);
}

// Synthetic fixtures only. These values are not production seed data.
test("allows KQAG for owner, admin, and member through repository-loaded records", async () => {
  for (const role of ["owner", "admin", "member"]) {
    const decision = await decisionFor({ role });

    assert.equal(decision.result, AccessDecisionResult.Allowed);
  }
});

test("blocks KQAG for viewer through the service layer", async () => {
  const decision = await decisionFor({ role: "viewer" });

  assert.equal(decision.result, AccessDecisionResult.RoleNotPermitted);
});

test("blocks viewer launch for future apps unless a read-only policy exists", async () => {
  const futureApp = {
    id: "app_ops_console",
    key: "ops_console",
    name: "Ops Console",
    status: "available",
    launchUrl: null,
    createdAt: now,
    updatedAt: now,
  };
  const futureEntitlement = {
    id: "entitlement_ops_console",
    workspaceId: "workspace_koncept_images",
    appId: futureApp.id,
    status: "enabled",
    grantedByUserId: "user_owner_example",
    createdAt: now,
    updatedAt: now,
  };

  for (const role of ["owner", "admin", "member"]) {
    const decision = await decisionFor({
      role,
      appKey: futureApp.key,
      apps: [futureApp],
      appEntitlements: [futureEntitlement],
    });

    assert.equal(decision.result, AccessDecisionResult.Allowed);
  }

  const viewerDecision = await decisionFor({
    role: "viewer",
    appKey: futureApp.key,
    apps: [futureApp],
    appEntitlements: [futureEntitlement],
  });

  assert.equal(viewerDecision.result, AccessDecisionResult.RoleNotPermitted);
});

test("blocks missing session", async () => {
  const decision = await decisionFor({ sessionId: "session_missing_example" });

  assert.equal(decision.result, AccessDecisionResult.NotAuthenticated);
});

test("blocks expired session using deterministic now", async () => {
  const decision = await decisionFor({
    session: { expiresAt: "2026-06-25T23:59:59.000Z" },
  });

  assert.equal(decision.result, AccessDecisionResult.NotAuthenticated);
});

test("blocks revoked session", async () => {
  const decision = await decisionFor({
    session: { revokedAt: "2026-06-26T00:00:00.000Z" },
  });

  assert.equal(decision.result, AccessDecisionResult.NotAuthenticated);
});

test("blocks disabled user", async () => {
  const decision = await decisionFor({ user: { status: "disabled" } });

  assert.equal(decision.result, AccessDecisionResult.UserNotActive);
});

test("blocks missing and disabled membership", async () => {
  const missingDecision = await decisionFor({ memberships: [] });
  assert.equal(missingDecision.result, AccessDecisionResult.MembershipRequired);

  const disabledFixture = platformFixture();
  const disabledMemberships = (await disabledFixture.repositories.memberships.listForUser(
    "user_owner_example",
  )).map((membership) => ({ ...membership, status: "disabled" }));

  const disabledDecision = await decisionFor({ memberships: disabledMemberships });
  assert.equal(disabledDecision.result, AccessDecisionResult.MembershipRequired);
});

test("blocks inactive workspace states", async () => {
  for (const status of ["suspended", "archived"]) {
    const decision = await decisionFor({ workspace: { status } });

    assert.equal(decision.result, AccessDecisionResult.WorkspaceNotActive);
  }
});

test("blocks missing and disabled app", async () => {
  const missingDecision = await decisionFor({ apps: [] });
  assert.equal(missingDecision.result, AccessDecisionResult.AppNotAvailable);

  const disabledDecision = await decisionFor({ app: { status: "disabled" } });
  assert.equal(disabledDecision.result, AccessDecisionResult.AppNotAvailable);
});

test("blocks missing disabled and suspended entitlement", async () => {
  const missingDecision = await decisionFor({ appEntitlements: [] });
  assert.equal(missingDecision.result, AccessDecisionResult.AppNotEnabledForWorkspace);

  const disabledDecision = await decisionFor({ entitlement: { status: "disabled" } });
  assert.equal(
    disabledDecision.result,
    AccessDecisionResult.AppNotEnabledForWorkspace,
  );

  const suspendedDecision = await decisionFor({ entitlement: { status: "suspended" } });
  assert.equal(
    suspendedDecision.result,
    AccessDecisionResult.AppNotEnabledForWorkspace,
  );
});

test("returns privacy-safe static messages", async () => {
  const decisions = await Promise.all([
    decisionFor({ role: "viewer" }),
    decisionFor({ sessionId: "session_missing_example" }),
    decisionFor({ user: { status: "disabled" } }),
    decisionFor({ appEntitlements: [] }),
  ]);

  for (const decision of decisions) {
    assert.doesNotMatch(decision.message, /example\.com/i);
    assert.doesNotMatch(decision.message, /Koncept/i);
    assert.doesNotMatch(decision.message, /workspace_koncept_images/i);
    assert.doesNotMatch(decision.message, /user_(owner|admin|member|viewer)_example/i);
    assert.doesNotMatch(decision.message, /session_/i);
  }
});

test("platform service and repository ports do not import database implementation details", async () => {
  const platformFiles = [
    "src/platform/repositories.ts",
    "src/platform/app-access-service.ts",
  ];

  for (const filePath of platformFiles) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /drizzle-orm/);
    assert.doesNotMatch(contents, /src\/db|\.{1,2}\/db|\.{1,2}\/\.{1,2}\/db/);
    assert.doesNotMatch(contents, /schema\.js|schema\.ts/);
    assert.doesNotMatch(contents, /\bsql\b/i);
    assert.doesNotMatch(contents, /migrations?/i);
  }
});

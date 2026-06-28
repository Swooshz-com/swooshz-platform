import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  AccessDecisionResult,
  getPlatformSessionContext,
  PlatformSessionContextServiceError,
} from "../dist/index.js";

const now = "2026-06-27T00:00:00.000Z";
const earlier = "2026-06-26T23:00:00.000Z";
const future = "2026-06-27T01:00:00.000Z";
const past = "2026-06-26T22:00:00.000Z";
const privateStorageError =
  "database exploded raw-session-token provider-token postgresql://private-host select *";

test("missing revoked and expired sessions return unauthenticated safely", async () => {
  for (const overrides of [
    { sessions: [] },
    { session: { revokedAt: earlier } },
    { session: { expiresAt: past } },
  ]) {
    const { repositories, calls } = sessionContextFixture(overrides);
    const result = await getPlatformSessionContext(repositories, {
      sessionId: "session_owner_example",
      now,
    });

    assert.equal(result.outcome, "unauthenticated");
    assert.equal(calls.usersFindById, 0);
    assert.equal(calls.membershipsListForUser, 0);
    assert.equal(calls.sessionsCreate, 0);
    assert.equal(calls.membershipsCreate, 0);
  }
});

test("active session returns safe user workspace and app context", async () => {
  const { repositories, calls } = sessionContextFixture();

  const result = await getPlatformSessionContext(repositories, {
    sessionId: "session_owner_example",
    now,
    selectedWorkspaceId: "workspace_koncept_images",
  });

  assert.equal(result.outcome, "authenticated");
  assert.deepEqual(result.session, {
    status: "active",
    expiresAt: future,
  });
  assert.deepEqual(result.user, {
    userId: "user_owner_example",
    email: "owner@example.com",
    displayName: "Owner Example",
    status: "active",
  });
  assert.equal(result.selectedWorkspaceId, "workspace_koncept_images");
  assert.deepEqual(
    result.workspaces.map((workspace) => ({
      workspaceId: workspace.workspaceId,
      membershipRole: workspace.membershipRole,
      membershipStatus: workspace.membershipStatus,
      appResults: workspace.apps.map((app) => app.access.result),
    })),
    [
      {
        workspaceId: "workspace_koncept_images",
        membershipRole: "owner",
        membershipStatus: "active",
        appResults: [AccessDecisionResult.Allowed],
      },
      {
        workspaceId: "workspace_viewer_team",
        membershipRole: "viewer",
        membershipStatus: "active",
        appResults: [AccessDecisionResult.RoleNotPermitted],
      },
    ],
  );
  assert.equal(calls.sessionsCreate, 0);
  assert.equal(calls.usersCreate, 0);
  assert.equal(calls.membershipsCreate, 0);
  assert.equal(calls.appEntitlementsCreate, 0);
  assertResponseIsPrivacySafe(result);
});

test("inactive or missing user returns safe unauthenticated result", async () => {
  const inactive = sessionContextFixture({ user: { status: "disabled" } });
  const missing = sessionContextFixture({ users: [] });

  assert.deepEqual(
    await getPlatformSessionContext(inactive.repositories, {
      sessionId: "session_owner_example",
      now,
    }),
    {
      outcome: "unauthenticated",
      reason: "user_not_active",
    },
  );
  assert.deepEqual(
    await getPlatformSessionContext(missing.repositories, {
      sessionId: "session_owner_example",
      now,
    }),
    {
      outcome: "unauthenticated",
      reason: "missing_user",
    },
  );
});

test("session context includes only active memberships with active workspaces", async () => {
  const { repositories } = sessionContextFixture({
    disabledMembership: { status: "disabled" },
    archivedWorkspace: { status: "archived" },
  });

  const result = await getPlatformSessionContext(repositories, {
    sessionId: "session_owner_example",
    now,
  });

  assert.equal(result.outcome, "authenticated");
  assert.deepEqual(
    result.workspaces.map((workspace) => workspace.workspaceId),
    ["workspace_koncept_images", "workspace_viewer_team"],
  );
});

test("repository failure becomes privacy-safe session context service error", async () => {
  const { repositories } = sessionContextFixture({ failMembershipList: true });

  await assert.rejects(
    () => getPlatformSessionContext(repositories, {
      sessionId: "session_owner_example",
      now,
    }),
    assertPrivacySafeSessionContextError("context_lookup_failed"),
  );
});

test("session context service module stays platform-only and framework-free", async () => {
  const contents = await readFile("src/platform/session-context-service.ts", "utf8");

  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?|kqag)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono|node:http)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:clerk|auth0|supabase|stripe)/i);
});

function sessionContextFixture(overrides = {}) {
  const calls = {
    sessionsFindById: 0,
    sessionsCreate: 0,
    usersFindById: 0,
    usersCreate: 0,
    membershipsListForUser: 0,
    membershipsCreate: 0,
    workspacesFindById: 0,
    appsListAll: 0,
    appEntitlementsListForWorkspace: 0,
    appEntitlementsCreate: 0,
  };
  const user = {
    id: "user_owner_example",
    email: "owner@example.com",
    displayName: "Owner Example",
    status: "active",
    createdAt: now,
    updatedAt: now,
    lastLoginAt: now,
    ...overrides.user,
  };
  const session = {
    id: "session_owner_example",
    userId: user.id,
    createdAt: earlier,
    expiresAt: future,
    lastSeenAt: earlier,
    revokedAt: null,
    ...overrides.session,
  };
  const workspace = {
    id: "workspace_koncept_images",
    slug: "koncept-images",
    displayName: "Koncept Images",
    status: "active",
    createdAt: now,
    updatedAt: now,
  };
  const viewerWorkspace = {
    id: "workspace_viewer_team",
    slug: "viewer-team",
    displayName: "Viewer Team",
    status: "active",
    createdAt: now,
    updatedAt: now,
  };
  const archivedWorkspace = {
    id: "workspace_archived",
    slug: "archived-team",
    displayName: "Archived Team",
    status: "active",
    createdAt: now,
    updatedAt: now,
    ...overrides.archivedWorkspace,
  };
  const app = {
    id: "app_kqag",
    key: "kqag",
    name: "KQAG / SAQG",
    status: "private_preview",
    launchUrl: null,
    createdAt: now,
    updatedAt: now,
  };
  const membership = {
    id: "membership_owner_example",
    workspaceId: workspace.id,
    userId: user.id,
    role: "owner",
    status: "active",
    createdAt: now,
    updatedAt: now,
  };
  const viewerMembership = {
    id: "membership_viewer_example",
    workspaceId: viewerWorkspace.id,
    userId: user.id,
    role: "viewer",
    status: "active",
    createdAt: now,
    updatedAt: now,
  };
  const disabledMembership = {
    id: "membership_disabled_example",
    workspaceId: archivedWorkspace.id,
    userId: user.id,
    role: "member",
    status: "disabled",
    createdAt: now,
    updatedAt: now,
    ...overrides.disabledMembership,
  };
  const entitlement = {
    id: "entitlement_kqag_owner",
    workspaceId: workspace.id,
    appId: app.id,
    status: "enabled",
    grantedByUserId: user.id,
    createdAt: now,
    updatedAt: now,
  };
  const viewerEntitlement = {
    ...entitlement,
    id: "entitlement_kqag_viewer",
    workspaceId: viewerWorkspace.id,
  };
  const records = {
    users: overrides.users ?? [user],
    sessions: overrides.sessions ?? [session],
    workspaces: [workspace, viewerWorkspace, archivedWorkspace],
    memberships: [membership, viewerMembership, disabledMembership],
    apps: [app],
    appEntitlements: [entitlement, viewerEntitlement],
  };
  const repositories = {
    sessions: {
      async findById(id) {
        calls.sessionsFindById += 1;
        return records.sessions.find((candidate) => candidate.id === id) ?? null;
      },
      async create(value) {
        calls.sessionsCreate += 1;
        records.sessions.push(value);
        return value;
      },
      async revoke() {
        throw new Error(privateStorageError);
      },
    },
    users: {
      async findById(id) {
        calls.usersFindById += 1;
        return records.users.find((candidate) => candidate.id === id) ?? null;
      },
      async findByNormalizedEmail() {
        throw new Error(privateStorageError);
      },
      async create(value) {
        calls.usersCreate += 1;
        records.users.push(value);
        return value;
      },
    },
    memberships: {
      async listForUser(userId) {
        calls.membershipsListForUser += 1;
        if (overrides.failMembershipList) {
          throw new Error(privateStorageError);
        }
        return records.memberships.filter((candidate) => candidate.userId === userId);
      },
      async findForUserInWorkspace() {
        throw new Error(privateStorageError);
      },
      async create(value) {
        calls.membershipsCreate += 1;
        records.memberships.push(value);
        return value;
      },
    },
    workspaces: {
      async findById(id) {
        calls.workspacesFindById += 1;
        return records.workspaces.find((candidate) => candidate.id === id) ?? null;
      },
      async findBySlug() {
        throw new Error(privateStorageError);
      },
      async create(value) {
        records.workspaces.push(value);
        return value;
      },
    },
    apps: {
      async listAll() {
        calls.appsListAll += 1;
        return records.apps;
      },
      async findByKey() {
        throw new Error(privateStorageError);
      },
      async findById() {
        throw new Error(privateStorageError);
      },
      async create(value) {
        records.apps.push(value);
        return value;
      },
    },
    appEntitlements: {
      async listForWorkspace(workspaceId) {
        calls.appEntitlementsListForWorkspace += 1;
        return records.appEntitlements.filter(
          (candidate) => candidate.workspaceId === workspaceId,
        );
      },
      async findForWorkspaceApp() {
        throw new Error(privateStorageError);
      },
      async create(value) {
        calls.appEntitlementsCreate += 1;
        records.appEntitlements.push(value);
        return value;
      },
    },
  };

  return { repositories, calls, records };
}

function assertPrivacySafeSessionContextError(expectedCode) {
  return (error) => {
    assert.equal(error instanceof PlatformSessionContextServiceError, true);
    assert.equal(error.code, expectedCode);
    assert.equal(error.publicMessage, "Session context could not be loaded.");
    assertResponseIsPrivacySafe(error);
    return true;
  };
}

function assertResponseIsPrivacySafe(value) {
  const serialized = JSON.stringify(value) + String(value?.message ?? "");

  assert.doesNotMatch(serialized, /raw-session-token|provider-token|auth-code/i);
  assert.doesNotMatch(serialized, /raw-state|raw-nonce|state_hash|nonce_hash/i);
  assert.doesNotMatch(serialized, /csrf|client-secret|session-secret/i);
  assert.doesNotMatch(serialized, /postgresql:\/\/private-host|database exploded|select \*/i);
}

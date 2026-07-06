import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  AccessDecisionResult,
  ProtectedAppAccessServiceError,
  decideProtectedAppAccess,
} from "../dist/index.js";
import { createInMemoryPlatformRepositories } from "./helpers/in-memory-platform-repositories.mjs";

const now = "2026-06-27T00:00:00.000Z";
const earlier = "2026-06-26T23:00:00.000Z";
const future = "2026-06-27T01:00:00.000Z";
const past = "2026-06-26T22:00:00.000Z";
const privateStorageError =
  "database exploded session_active postgresql://private-host raw-session-token SQL select *";

test("missing session denies safely before app-access repositories are read", async () => {
  const { repositories, input, calls } = protectedFixture({
    sessions: [],
  });

  const result = await decideProtectedAppAccess(repositories, input);

  assert.deepEqual(result, {
    outcome: "denied",
    reason: "missing_session",
  });
  assert.equal(calls.usersFindById, 0);
  assert.equal(calls.membershipsFindForUserInWorkspace, 0);
  assert.equal(calls.appsFindByKey, 0);
});

test("revoked session denies safely before app-access repositories are read", async () => {
  const { repositories, input, calls } = protectedFixture({
    session: { revokedAt: earlier },
  });

  const result = await decideProtectedAppAccess(repositories, input);

  assert.deepEqual(result, {
    outcome: "denied",
    reason: "revoked_session",
  });
  assert.equal(calls.usersFindById, 0);
  assert.equal(calls.membershipsFindForUserInWorkspace, 0);
  assert.equal(calls.appsFindByKey, 0);
});

test("expired session denies safely using deterministic now", async () => {
  const { repositories, input, calls } = protectedFixture({
    session: { expiresAt: past },
  });

  const result = await decideProtectedAppAccess(repositories, input);

  assert.deepEqual(result, {
    outcome: "denied",
    reason: "expired_session",
  });
  assert.equal(calls.usersFindById, 0);
  assert.equal(calls.membershipsFindForUserInWorkspace, 0);
  assert.equal(calls.appsFindByKey, 0);
});

test("active unexpired owner session delegates and allows KQAG access", async () => {
  const { repositories, input, calls } = protectedFixture({ role: "owner" });

  const result = await decideProtectedAppAccess(repositories, input);

  assert.equal(result.outcome, "allowed");
  assert.equal(result.sessionId, "session_owner_example");
  assert.equal(result.userId, "user_owner_example");
  assert.equal(result.workspaceId, "workspace_koncept_images");
  assert.equal(result.appKey, "kqag");
  assert.deepEqual(result.decision, {
    result: AccessDecisionResult.Allowed,
    allowed: true,
    message: "Access allowed.",
  });
  assert.equal(calls.sessionsFindById, 2);
  assert.equal(calls.usersFindById, 1);
  assert.equal(calls.membershipsFindForUserInWorkspace, 1);
  assert.equal(calls.appsFindByKey, 1);
});

test("active unexpired viewer session delegates and denies through domain app-access logic", async () => {
  const { repositories, input } = protectedFixture({ role: "viewer" });

  const result = await decideProtectedAppAccess(repositories, input);

  assert.equal(result.outcome, "denied");
  assert.equal(result.reason, "app_access_denied");
  assert.deepEqual(result.decision, {
    result: AccessDecisionResult.RoleNotPermitted,
    allowed: false,
    message: "The current role cannot launch this app.",
  });
});

test("active unexpired disabled user denial is delegated to app-access service", async () => {
  const { repositories, input } = protectedFixture({
    user: { status: "disabled" },
  });

  const result = await decideProtectedAppAccess(repositories, input);

  assert.equal(result.outcome, "denied");
  assert.equal(result.reason, "app_access_denied");
  assert.equal(result.decision.result, AccessDecisionResult.UserNotActive);
});

test("removed user with another workspace keeps access only to the remaining workspace", async () => {
  const otherWorkspace = {
    id: "workspace_other_example",
    slug: "other-team",
    displayName: "Other Team",
    status: "active",
    createdAt: now,
    updatedAt: now,
  };
  const { repositories, input } = protectedFixture({
    role: "member",
    workspaces: [
      {
        id: "workspace_koncept_images",
        slug: "koncept-images-pte-ltd",
        displayName: "Koncept Images Pte Ltd",
        status: "active",
        createdAt: now,
        updatedAt: now,
      },
      otherWorkspace,
    ],
    memberships: [
      {
        id: "membership_member_other_example",
        workspaceId: otherWorkspace.id,
        userId: "user_member_example",
        role: "member",
        status: "active",
        createdAt: now,
        updatedAt: now,
      },
    ],
    appEntitlements: [
      {
        id: "entitlement_koncept_kqag",
        workspaceId: "workspace_koncept_images",
        appId: "app_kqag",
        status: "enabled",
        grantedByUserId: "user_owner_example",
        createdAt: now,
        updatedAt: now,
      },
      {
        id: "entitlement_other_kqag",
        workspaceId: otherWorkspace.id,
        appId: "app_kqag",
        status: "enabled",
        grantedByUserId: "user_owner_example",
        createdAt: now,
        updatedAt: now,
      },
    ],
  });

  const removedWorkspaceResult = await decideProtectedAppAccess(repositories, input);
  const otherWorkspaceResult = await decideProtectedAppAccess(repositories, {
    ...input,
    selectedWorkspaceId: otherWorkspace.id,
  });

  assert.equal(removedWorkspaceResult.outcome, "denied");
  assert.equal(removedWorkspaceResult.reason, "app_access_denied");
  assert.equal(removedWorkspaceResult.decision.result, AccessDecisionResult.MembershipRequired);
  assert.equal(otherWorkspaceResult.outcome, "allowed");
  assert.equal(otherWorkspaceResult.workspaceId, otherWorkspace.id);
});

test("billing gate denial is delegated without creating launch tokens or grants", async () => {
  const { repositories, input, records, calls } = protectedFixture({
    billingGate: { blocked: true },
  });

  const result = await decideProtectedAppAccess(repositories, input);

  assert.equal(result.outcome, "denied");
  assert.equal(result.reason, "app_access_denied");
  assert.equal(result.decision.result, AccessDecisionResult.BillingBlocked);
  assert.equal(calls.sessionsCreate, 0);
  assert.equal(calls.usersCreate, 0);
  assert.equal(calls.providerIdentitiesCreate, 0);
  assert.equal(calls.auditEventsAppend, 0);
  assert.deepEqual(records.memberships.map((membership) => membership.id), [
    "membership_owner_example",
    "membership_admin_example",
    "membership_member_example",
    "membership_viewer_example",
  ]);
  assert.deepEqual(records.appEntitlements.map((entitlement) => entitlement.id), [
    "entitlement_koncept_kqag",
  ]);
});

test("session lookup repository failure becomes privacy-safe service error", async () => {
  const { repositories, input } = protectedFixture({
    failSessionFind: true,
  });

  await assert.rejects(
    () => decideProtectedAppAccess(repositories, input),
    assertPrivacySafeProtectedAccessError("session_lookup_failed"),
  );
});

test("app-access repository failure becomes privacy-safe service error", async () => {
  const { repositories, input } = protectedFixture({
    failUserFind: true,
  });

  await assert.rejects(
    () => decideProtectedAppAccess(repositories, input),
    assertPrivacySafeProtectedAccessError("app_access_decision_failed"),
  );
});

test("protected app-access results do not expose tokens secrets provider material or storage details", async () => {
  const { repositories, input } = protectedFixture();

  const result = await decideProtectedAppAccess(repositories, input);
  const serialized = JSON.stringify(result);

  assert.doesNotMatch(serialized, /cookie|raw-session-token|session-secret/i);
  assert.doesNotMatch(serialized, /provider-token|auth-code|raw-claim/i);
  assert.doesNotMatch(serialized, /postgresql:\/\/private-host|database exploded|select \*/i);
});

test("protected app-access service module does not import DB, HTTP, frontend, KQAG, provider SDK, or migrations", async () => {
  const contents = await readFile("src/platform/protected-app-access-service.ts", "utf8");

  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?|kqag)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono|node:http)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:clerk|auth0|supabase)/i);
  assert.doesNotMatch(contents, /src\/db|\.{1,2}\/db|\.{1,2}\/\.{1,2}\/db/i);
});

test("pure domain modules do not import protected app-access or auth modules", async () => {
  const pureDomainFiles = [
    "src/accounts/types.ts",
    "src/accounts/normalization.ts",
    "src/apps/types.ts",
    "src/access/decide-app-access.ts",
  ];

  for (const filePath of pureDomainFiles) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /src\/auth|\.{1,2}\/auth|\.{1,2}\/\.{1,2}\/auth/);
    assert.doesNotMatch(
      contents,
      /protected-app-access|src\/platform|\.{1,2}\/platform|\.{1,2}\/\.{1,2}\/platform/,
    );
  }
});

function protectedFixture(overrides = {}) {
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
    createdAt: earlier,
    expiresAt: future,
    lastSeenAt: earlier,
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

  const records = {
    users: overrides.users ?? [user],
    providerIdentities: [],
    sessions: overrides.sessions ?? [session],
    workspaces: overrides.workspaces ?? [workspace],
    memberships: overrides.memberships ?? memberships,
    apps: overrides.apps ?? [app],
    appEntitlements: overrides.appEntitlements ?? [entitlement],
    auditEvents: [],
  };
  const repositories = createInMemoryPlatformRepositories(records);
  const calls = instrumentRepositories(repositories, overrides);

  return {
    records,
    calls,
    repositories,
    input: {
      sessionId: overrides.sessionId ?? session.id,
      selectedWorkspaceId: overrides.selectedWorkspaceId ?? workspace.id,
      appKey: overrides.appKey ?? "kqag",
      billingGate: overrides.billingGate,
      now: overrides.now ?? now,
    },
  };
}

function instrumentRepositories(repositories, options) {
  const calls = {
    usersFindById: 0,
    usersCreate: 0,
    providerIdentitiesCreate: 0,
    sessionsFindById: 0,
    sessionsCreate: 0,
    membershipsFindForUserInWorkspace: 0,
    appsFindByKey: 0,
    auditEventsAppend: 0,
  };

  const originalSessionFindById = repositories.sessions.findById.bind(repositories.sessions);
  repositories.sessions.findById = async (id) => {
    calls.sessionsFindById += 1;
    if (options.failSessionFind) {
      throw new Error(privateStorageError);
    }

    return originalSessionFindById(id);
  };

  const originalUserFindById = repositories.users.findById.bind(repositories.users);
  repositories.users.findById = async (id) => {
    calls.usersFindById += 1;
    if (options.failUserFind) {
      throw new Error(privateStorageError);
    }

    return originalUserFindById(id);
  };

  const originalUserCreate = repositories.users.create.bind(repositories.users);
  repositories.users.create = async (user) => {
    calls.usersCreate += 1;
    return originalUserCreate(user);
  };

  const originalProviderIdentityCreate =
    repositories.providerIdentities.create.bind(repositories.providerIdentities);
  repositories.providerIdentities.create = async (identity) => {
    calls.providerIdentitiesCreate += 1;
    return originalProviderIdentityCreate(identity);
  };

  const originalSessionCreate = repositories.sessions.create.bind(repositories.sessions);
  repositories.sessions.create = async (session) => {
    calls.sessionsCreate += 1;
    return originalSessionCreate(session);
  };

  const originalMembershipFind =
    repositories.memberships.findForUserInWorkspace.bind(repositories.memberships);
  repositories.memberships.findForUserInWorkspace = async (userId, workspaceId) => {
    calls.membershipsFindForUserInWorkspace += 1;
    return originalMembershipFind(userId, workspaceId);
  };

  const originalAppFindByKey = repositories.apps.findByKey.bind(repositories.apps);
  repositories.apps.findByKey = async (key) => {
    calls.appsFindByKey += 1;
    return originalAppFindByKey(key);
  };

  const originalAuditAppend = repositories.auditEvents.append.bind(repositories.auditEvents);
  repositories.auditEvents.append = async (event) => {
    calls.auditEventsAppend += 1;
    return originalAuditAppend(event);
  };

  return calls;
}

function assertPrivacySafeProtectedAccessError(expectedCode) {
  return (error) => {
    assert.equal(error instanceof ProtectedAppAccessServiceError, true);
    assert.equal(error.code, expectedCode);
    assert.equal(error.publicMessage, "App access decision could not be completed.");
    assert.doesNotMatch(error.message, /database exploded/);
    assert.doesNotMatch(error.message, /session_active/);
    assert.doesNotMatch(error.message, /postgresql:\/\/private-host/);
    assert.doesNotMatch(error.message, /raw-session-token/);
    assert.doesNotMatch(error.message, /select \*/i);
    assert.doesNotMatch(error.message, /storage|sql|database|db url/i);
    return true;
  };
}

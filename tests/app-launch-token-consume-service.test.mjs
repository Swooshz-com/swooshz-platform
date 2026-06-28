import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  AppLaunchTokenConsumeServiceError,
  consumeAppLaunchToken,
} from "../dist/index.js";
import { createInMemoryPlatformRepositories } from "./helpers/in-memory-platform-repositories.mjs";

const now = "2026-06-27T00:00:00.000Z";
const earlier = "2026-06-26T23:00:00.000Z";
const future = "2026-06-27T00:05:00.000Z";
const past = "2026-06-26T23:55:00.000Z";
const rawLaunchToken = "synthetic-raw-launch-token-reference";
const launchTokenHash = "app-launch:v1:hmac-sha256:synthetic_hash_reference";
const privateStorageError =
  "storage exploded synthetic-raw-launch-token-reference app-launch:v1:hmac-sha256:synthetic_hash_reference postgresql://private-host";

test("missing or blank raw launch tokens fail safely without lookup", async () => {
  for (const token of ["", "   "]) {
    const { dependencies, calls } = consumeFixture();

    const result = await consumeAppLaunchToken(dependencies, {
      rawLaunchToken: token,
      appKey: "kqag",
      now,
    });

    assert.deepEqual(result, {
      outcome: "invalid",
      reason: "missing_launch_token",
    });
    assert.equal(calls.hashToken, 0);
    assert.equal(calls.findByTokenHash, 0);
    assertResponseIsPrivacySafe(result);
  }
});

test("unknown expired consumed revoked and app mismatch tokens fail safely without context", async () => {
  for (const [overrides, expectedReason] of [
    [{ appLaunchTokens: [] }, "invalid_launch_token"],
    [{ launchToken: { expiresAt: past } }, "expired_launch_token"],
    [{ launchToken: { consumedAt: earlier } }, "consumed_launch_token"],
    [{ launchToken: { revokedAt: earlier } }, "revoked_launch_token"],
    [{ inputAppKey: "other-app" }, "app_mismatch"],
  ]) {
    const { dependencies, input, records } = consumeFixture(overrides);

    const result = await consumeAppLaunchToken(dependencies, input);

    assert.equal(result.outcome, "invalid");
    assert.equal(result.reason, expectedReason);
    assert.equal(records.appLaunchTokens[0]?.consumedAt ?? null, overrides.launchToken?.consumedAt ?? null);
    assertResponseIsPrivacySafe(result);
  }
});

test("missing platform context and denied re-checks fail safely without consuming", async () => {
  for (const [overrides, expected] of [
    [{ sessions: [] }, { outcome: "invalid", reason: "missing_session" }],
    [{ users: [] }, { outcome: "invalid", reason: "missing_user" }],
    [{ workspaces: [] }, { outcome: "invalid", reason: "missing_workspace" }],
    [{ apps: [] }, { outcome: "invalid", reason: "missing_app" }],
    [{ memberships: [] }, { outcome: "denied", reason: "app_access_denied" }],
    [{ appEntitlements: [] }, { outcome: "denied", reason: "app_access_denied" }],
    [{ role: "viewer" }, { outcome: "denied", reason: "app_access_denied" }],
  ]) {
    const { dependencies, input, records } = consumeFixture(overrides);

    const result = await consumeAppLaunchToken(dependencies, input);

    assert.equal(result.outcome, expected.outcome);
    assert.equal(result.reason, expected.reason);
    assert.equal(records.appLaunchTokens[0].consumedAt, null);
    assertResponseIsPrivacySafe(result);
  }
});

test("successful consume returns safe context and marks launch token consumed exactly once", async () => {
  const { dependencies, input, records, calls } = consumeFixture();

  const result = await consumeAppLaunchToken(dependencies, input);

  assert.deepEqual(result, {
    outcome: "consumed",
    user: {
      userId: "user_owner_example",
      email: "owner@example.com",
      displayName: "Owner Example",
      status: "active",
    },
    workspace: {
      workspaceId: "workspace_koncept_images",
      workspaceSlug: "koncept-images-pte-ltd",
      workspaceName: "Koncept Images Pte Ltd",
    },
    app: {
      appKey: "kqag",
      appName: "KQAG / SAQG",
    },
    membershipRole: "owner",
    launchTokenExpiresAt: future,
  });
  assert.equal(records.appLaunchTokens[0].consumedAt, now);
  assert.equal(calls.consumeUnconsumed, 1);
  assert.equal(calls.sessionsFindById > 0, true);
  assert.equal(calls.membershipsFindForUserInWorkspace > 0, true);
  assertResponseIsPrivacySafe(result);

  const replay = await consumeAppLaunchToken(dependencies, input);

  assert.deepEqual(replay, {
    outcome: "invalid",
    reason: "consumed_launch_token",
  });
  assert.equal(calls.consumeUnconsumed, 1);
});

test("consume race returns consumed failure without returning context", async () => {
  const { dependencies, input } = consumeFixture({ consumeReturnsNull: true });

  const result = await consumeAppLaunchToken(dependencies, input);

  assert.deepEqual(result, {
    outcome: "invalid",
    reason: "consumed_launch_token",
  });
  assertResponseIsPrivacySafe(result);
});

test("repository and hash failures become privacy-safe consume service errors", async () => {
  for (const overrides of [
    { failHash: true },
    { failFindByTokenHash: true },
    { failSessionFind: true },
    { failConsume: true },
  ]) {
    const { dependencies, input } = consumeFixture(overrides);

    await assert.rejects(
      () => consumeAppLaunchToken(dependencies, input),
      assertPrivacySafeServiceError,
    );
  }
});

test("consume service module does not import DB HTTP frontend KQAG provider SDK or migrations", async () => {
  const contents = await readFile("src/platform/app-launch-token-consume-service.ts", "utf8");

  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?|kqag)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono|node:http)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:clerk|auth0|supabase)/i);
  assert.doesNotMatch(contents, /src\/db|\.{1,2}\/db|\.{1,2}\/\.{1,2}\/db/i);
});

function consumeFixture(overrides = {}) {
  const workspace = {
    id: "workspace_koncept_images",
    slug: "koncept-images-pte-ltd",
    displayName: "Koncept Images Pte Ltd",
    status: "active",
    createdAt: now,
    updatedAt: now,
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
  const role = overrides.role ?? "owner";
  const user = {
    id: `user_${role}_example`,
    email: `${role}@example.com`,
    displayName: `${role[0].toUpperCase()}${role.slice(1)} Example`,
    status: "active",
    createdAt: now,
    updatedAt: now,
    lastLoginAt: now,
  };
  const session = {
    id: `session_${role}_example`,
    userId: user.id,
    createdAt: earlier,
    expiresAt: "2026-06-27T01:00:00.000Z",
    lastSeenAt: earlier,
    revokedAt: null,
  };
  const membership = {
    id: `membership_${role}_example`,
    workspaceId: workspace.id,
    userId: user.id,
    role,
    status: "active",
    createdAt: now,
    updatedAt: now,
  };
  const entitlement = {
    id: "entitlement_koncept_kqag",
    workspaceId: workspace.id,
    appId: app.id,
    status: "enabled",
    grantedByUserId: "user_owner_example",
    createdAt: now,
    updatedAt: now,
  };
  const launchToken = {
    id: "app_launch_token_1",
    sessionId: session.id,
    userId: user.id,
    workspaceId: workspace.id,
    appId: app.id,
    tokenHash: launchTokenHash,
    createdAt: now,
    expiresAt: future,
    consumedAt: null,
    revokedAt: null,
    ...overrides.launchToken,
  };
  const records = {
    users: overrides.users ?? [user],
    providerIdentities: [],
    sessions: overrides.sessions ?? [session],
    workspaces: overrides.workspaces ?? [workspace],
    memberships: overrides.memberships ?? [membership],
    apps: overrides.apps ?? [app],
    appEntitlements: overrides.appEntitlements ?? [entitlement],
    auditEvents: [],
    appLaunchTokens: overrides.appLaunchTokens ?? [launchToken],
  };
  const repositories = createInMemoryPlatformRepositories(records);
  const calls = instrumentRepositories(repositories, overrides);
  repositories.appLaunchTokens = {
    async create(record) {
      records.appLaunchTokens.push(record);
      return record;
    },
    async findByTokenHash(tokenHash) {
      calls.findByTokenHash += 1;
      if (overrides.failFindByTokenHash) {
        throw new Error(privateStorageError);
      }

      return records.appLaunchTokens.find((record) => record.tokenHash === tokenHash) ?? null;
    },
    async consumeUnconsumed(id, consumedAt) {
      calls.consumeUnconsumed += 1;
      if (overrides.failConsume) {
        throw new Error(privateStorageError);
      }

      const record = records.appLaunchTokens.find((candidate) => candidate.id === id);
      if (!record || record.consumedAt || record.revokedAt || overrides.consumeReturnsNull) {
        return null;
      }

      record.consumedAt = consumedAt;
      return record;
    },
  };

  return {
    records,
    calls,
    input: {
      rawLaunchToken,
      appKey: overrides.inputAppKey ?? "kqag",
      now,
    },
    dependencies: {
      repositories,
      launchTokenHasher: {
        async hashToken(token) {
          calls.hashToken += 1;
          if (overrides.failHash) {
            throw new Error(privateStorageError);
          }

          assert.equal(token, rawLaunchToken);
          return launchTokenHash;
        },
      },
    },
  };
}

function instrumentRepositories(repositories, options) {
  const calls = {
    hashToken: 0,
    findByTokenHash: 0,
    consumeUnconsumed: 0,
    sessionsFindById: 0,
    usersFindById: 0,
    workspacesFindById: 0,
    membershipsFindForUserInWorkspace: 0,
    appsFindByKey: 0,
    appsFindById: 0,
    appEntitlementsFindForWorkspaceApp: 0,
  };

  const sessionFind = repositories.sessions.findById.bind(repositories.sessions);
  repositories.sessions.findById = async (id) => {
    calls.sessionsFindById += 1;
    if (options.failSessionFind) {
      throw new Error(privateStorageError);
    }

    return sessionFind(id);
  };
  const userFind = repositories.users.findById.bind(repositories.users);
  repositories.users.findById = async (id) => {
    calls.usersFindById += 1;
    return userFind(id);
  };
  const workspaceFind = repositories.workspaces.findById.bind(repositories.workspaces);
  repositories.workspaces.findById = async (id) => {
    calls.workspacesFindById += 1;
    return workspaceFind(id);
  };
  const membershipFind =
    repositories.memberships.findForUserInWorkspace.bind(repositories.memberships);
  repositories.memberships.findForUserInWorkspace = async (userId, workspaceId) => {
    calls.membershipsFindForUserInWorkspace += 1;
    return membershipFind(userId, workspaceId);
  };
  const appFindByKey = repositories.apps.findByKey.bind(repositories.apps);
  repositories.apps.findByKey = async (key) => {
    calls.appsFindByKey += 1;
    return appFindByKey(key);
  };
  const appFindById = repositories.apps.findById.bind(repositories.apps);
  repositories.apps.findById = async (id) => {
    calls.appsFindById += 1;
    return appFindById(id);
  };
  const entitlementFind =
    repositories.appEntitlements.findForWorkspaceApp.bind(repositories.appEntitlements);
  repositories.appEntitlements.findForWorkspaceApp = async (workspaceId, appId) => {
    calls.appEntitlementsFindForWorkspaceApp += 1;
    return entitlementFind(workspaceId, appId);
  };

  return calls;
}

function assertPrivacySafeServiceError(error) {
  assert.equal(error instanceof AppLaunchTokenConsumeServiceError, true);
  assert.equal(error.publicMessage, "App launch token could not be consumed.");
  const serialized = JSON.stringify(error) + String(error.message ?? "");
  assert.doesNotMatch(serialized, new RegExp(rawLaunchToken));
  assert.doesNotMatch(serialized, new RegExp(launchTokenHash));
  assert.doesNotMatch(serialized, /postgresql:\/\/private-host|storage exploded/i);
  return true;
}

function assertResponseIsPrivacySafe(value) {
  const serialized = JSON.stringify(value);

  assert.doesNotMatch(serialized, new RegExp(rawLaunchToken));
  assert.doesNotMatch(serialized, new RegExp(launchTokenHash));
  assert.doesNotMatch(serialized, /raw-session-token|session-secret|provider-token/i);
  assert.doesNotMatch(serialized, /auth-code|raw-claim|client-secret|csrf-secret/i);
  assert.doesNotMatch(serialized, /postgresql:\/\/private-host|select \*|storage exploded/i);
}

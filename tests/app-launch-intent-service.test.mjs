import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  AppLaunchIntentServiceError,
  createAppLaunchIntent,
} from "../dist/index.js";
import { createInMemoryPlatformRepositories } from "./helpers/in-memory-platform-repositories.mjs";

const now = "2026-06-27T00:00:00.000Z";
const earlier = "2026-06-26T23:00:00.000Z";
const future = "2026-06-27T01:00:00.000Z";
const past = "2026-06-26T22:00:00.000Z";
const rawLaunchToken = "synthetic-raw-launch-token-reference";
const launchTokenHash = "app-launch:v1:hmac-sha256:synthetic_hash_reference";
const privateStorageError =
  "storage exploded synthetic-raw-launch-token-reference app-launch:v1:hmac-sha256:synthetic_hash_reference postgresql://private-host";

test("missing revoked and expired sessions are unauthenticated and create no launch token", async () => {
  for (const overrides of [
    { sessions: [] },
    { session: { revokedAt: earlier } },
    { session: { expiresAt: past } },
  ]) {
    const { dependencies, input, records } = launchFixture(overrides);

    const result = await createAppLaunchIntent(dependencies, input);

    assert.equal(result.outcome, "unauthenticated");
    assert.equal(records.appLaunchTokens.length, 0);
  }
});

test("viewer SQAG access is denied without creating a launch token", async () => {
  const { dependencies, input, records } = launchFixture({ role: "viewer" });

  const result = await createAppLaunchIntent(dependencies, input);

  assert.equal(result.outcome, "denied");
  assert.equal(result.reason, "app_access_denied");
  assert.equal(result.decision.result, "role_not_permitted");
  assert.equal(records.appLaunchTokens.length, 0);
  assertResponseIsPrivacySafe(result);
});

test("removed member existing session cannot create a launch token for that workspace", async () => {
  const { dependencies, input, records } = launchFixture({
    role: "member",
    memberships: [],
  });

  const result = await createAppLaunchIntent(dependencies, input);

  assert.equal(result.outcome, "denied");
  assert.equal(result.reason, "app_access_denied");
  assert.equal(result.decision.result, "membership_required");
  assert.equal(records.appLaunchTokens.length, 0);
  assertResponseIsPrivacySafe(result);
});

test("future app launch uses the same least-privilege role policy", async () => {
  const futureApp = {
    id: "app_ops_console",
    key: "ops_console",
    name: "Ops Console",
    status: "available",
    launchUrl: "https://apps.example.invalid/ops-console",
  };

  for (const role of ["owner", "admin", "member"]) {
    const { dependencies, input, records } = launchFixture({
      role,
      app: futureApp,
      entitlement: { id: "entitlement_ops_console", appId: futureApp.id },
    });

    const result = await createAppLaunchIntent(dependencies, {
      ...input,
      appKey: futureApp.key,
    });

    assert.equal(result.outcome, "created");
    assert.equal(result.appKey, futureApp.key);
    assert.equal(records.appLaunchTokens.length, 1);
    assert.equal(records.appLaunchTokens[0].appId, futureApp.id);
    assert.equal("launchToken" in records.appLaunchTokens[0], false);
  }

  const viewer = launchFixture({
    role: "viewer",
    app: futureApp,
    entitlement: { id: "entitlement_ops_console", appId: futureApp.id },
  });

  const viewerResult = await createAppLaunchIntent(viewer.dependencies, {
    ...viewer.input,
    appKey: futureApp.key,
  });

  assert.equal(viewerResult.outcome, "denied");
  assert.equal(viewerResult.reason, "app_access_denied");
  assert.equal(viewerResult.decision.result, "role_not_permitted");
  assert.equal(viewer.records.appLaunchTokens.length, 0);
  assertResponseIsPrivacySafe(viewerResult);
});

test("allowed owner admin and member SQAG access creates one hash-only launch token record", async () => {
  for (const role of ["owner", "admin", "member"]) {
    const { dependencies, input, records } = launchFixture({
      role,
      app: { launchUrl: "https://apps.example.invalid/sqag" },
    });

    const result = await createAppLaunchIntent(dependencies, input);

    assert.deepEqual(result, {
      outcome: "created",
      appKey: "sqag",
      workspaceId: "workspace_koncept_images",
      appLaunchUrl: "https://apps.example.invalid/sqag",
      launchToken: rawLaunchToken,
      launchTokenExpiresAt: "2026-06-27T00:05:00.000Z",
    });
    assert.equal(records.appLaunchTokens.length, 1);
    assert.deepEqual(records.appLaunchTokens[0], {
      id: "app_launch_token_1",
      sessionId: `session_${role}_example`,
      userId: `user_${role}_example`,
      workspaceId: "workspace_koncept_images",
      appId: "app_sqag",
      tokenHash: launchTokenHash,
      createdAt: now,
      expiresAt: "2026-06-27T00:05:00.000Z",
      consumedAt: null,
      revokedAt: null,
    });
    assert.equal("launchToken" in records.appLaunchTokens[0], false);
    assert.equal("rawToken" in records.appLaunchTokens[0], false);
    assert.doesNotMatch(JSON.stringify(records.appLaunchTokens), new RegExp(rawLaunchToken));
    assertResponseIsPrivacySafe(result);
  }
});

test("repository token store failure becomes privacy-safe service error", async () => {
  const { dependencies, input } = launchFixture({ failLaunchTokenCreate: true });

  await assert.rejects(
    () => createAppLaunchIntent(dependencies, input),
    assertPrivacySafeServiceError("launch_token_store_failed"),
  );
});

test("launch intent service does not create users sessions memberships entitlements or audit records", async () => {
  const { dependencies, input, calls } = launchFixture();

  await createAppLaunchIntent(dependencies, input);

  assert.equal(calls.usersCreate, 0);
  assert.equal(calls.sessionsCreate, 0);
  assert.equal(calls.membershipsCreate, 0);
  assert.equal(calls.appEntitlementsCreate, 0);
  assert.equal(calls.auditEventsAppend, 0);
});

test("launch intent service module does not import DB HTTP frontend SQAG provider SDK or migrations", async () => {
  const contents = await readFile("src/platform/app-launch-intent-service.ts", "utf8");

  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?|sqag)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono|node:http)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:clerk|auth0|supabase)/i);
  assert.doesNotMatch(contents, /src\/db|\.{1,2}\/db|\.{1,2}\/\.{1,2}\/db/i);
});

function launchFixture(overrides = {}) {
  const workspace = {
    id: "workspace_koncept_images",
    slug: "koncept-images-pte-ltd",
    displayName: "Koncept Images Pte Ltd",
    status: "active",
    createdAt: now,
    updatedAt: now,
  };
  const app = {
    id: "app_sqag",
    key: "sqag",
    name: "SQAG",
    status: "private_preview",
    launchUrl: null,
    ...overrides.app,
    createdAt: now,
    updatedAt: now,
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
  const user = usersByRole[role];
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
    id: "entitlement_koncept_sqag",
    workspaceId: workspace.id,
    appId: app.id,
    status: "enabled",
    grantedByUserId: "user_owner_example",
    createdAt: now,
    updatedAt: now,
    ...overrides.entitlement,
  };
  const records = {
    users: [user],
    providerIdentities: [],
    sessions: overrides.sessions ?? [session],
    workspaces: [workspace],
    memberships: overrides.memberships ?? memberships,
    apps: [app],
    appEntitlements: [entitlement],
    auditEvents: [],
    appLaunchTokens: [],
  };
  const repositories = createInMemoryPlatformRepositories(records);
  repositories.appLaunchTokens = {
    async create(record) {
      if (overrides.failLaunchTokenCreate) {
        throw new Error(privateStorageError);
      }

      records.appLaunchTokens.push(record);
      return record;
    },
  };
  const calls = instrumentWrites(repositories);

  return {
    records,
    calls,
    input: {
      sessionId: overrides.sessionId ?? session.id,
      selectedWorkspaceId: workspace.id,
      appKey: "sqag",
      now,
    },
    dependencies: {
      repositories,
      launchTokenFactory: {
        async createToken() {
          return rawLaunchToken;
        },
      },
      launchTokenHasher: {
        async hashToken(token) {
          assert.equal(token, rawLaunchToken);
          return launchTokenHash;
        },
      },
      launchTokenIdFactory: {
        createId() {
          return `app_launch_token_${records.appLaunchTokens.length + 1}`;
        },
      },
      ttlSeconds: 300,
    },
  };
}

function instrumentWrites(repositories) {
  const calls = {
    usersCreate: 0,
    sessionsCreate: 0,
    membershipsCreate: 0,
    appEntitlementsCreate: 0,
    auditEventsAppend: 0,
  };

  const userCreate = repositories.users.create.bind(repositories.users);
  repositories.users.create = async (record) => {
    calls.usersCreate += 1;
    return userCreate(record);
  };
  const sessionCreate = repositories.sessions.create.bind(repositories.sessions);
  repositories.sessions.create = async (record) => {
    calls.sessionsCreate += 1;
    return sessionCreate(record);
  };
  const membershipCreate = repositories.memberships.create.bind(repositories.memberships);
  repositories.memberships.create = async (record) => {
    calls.membershipsCreate += 1;
    return membershipCreate(record);
  };
  const entitlementCreate = repositories.appEntitlements.create.bind(repositories.appEntitlements);
  repositories.appEntitlements.create = async (record) => {
    calls.appEntitlementsCreate += 1;
    return entitlementCreate(record);
  };
  const auditAppend = repositories.auditEvents.append.bind(repositories.auditEvents);
  repositories.auditEvents.append = async (record) => {
    calls.auditEventsAppend += 1;
    return auditAppend(record);
  };

  return calls;
}

function assertPrivacySafeServiceError(expectedCode) {
  return (error) => {
    assert.equal(error instanceof AppLaunchIntentServiceError, true);
    assert.equal(error.code, expectedCode);
    assert.equal(error.publicMessage, "App launch intent could not be created.");
    const serialized = JSON.stringify(error) + String(error.message ?? "");
    assert.doesNotMatch(serialized, new RegExp(rawLaunchToken));
    assert.doesNotMatch(serialized, new RegExp(launchTokenHash));
    assert.doesNotMatch(serialized, /postgresql:\/\/private-host|storage exploded/i);
    return true;
  };
}

function assertResponseIsPrivacySafe(value) {
  const serialized = JSON.stringify(value);

  assert.doesNotMatch(serialized, /session-secret|raw-session-token|provider-token/i);
  assert.doesNotMatch(serialized, /auth-code|raw-claim|client-secret|csrf-secret/i);
  assert.doesNotMatch(serialized, /postgresql:\/\/private-host|select \*|storage exploded/i);
  assert.doesNotMatch(serialized, new RegExp(launchTokenHash));
}

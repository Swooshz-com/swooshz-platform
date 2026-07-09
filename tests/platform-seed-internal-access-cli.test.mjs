import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  PlatformSeedInternalAccessError,
  executePlatformSeedInternalAccess,
  readPlatformSeedInternalAccessConfig,
  seedInternalAccessForExistingUser,
} from "../scripts/platform-seed-internal-access.mjs";
import { createInMemoryPlatformRepositories } from "./helpers/in-memory-platform-repositories.mjs";

const now = "2026-06-28T00:00:00.000Z";
const later = "2026-06-29T00:00:00.000Z";
const privateDatabasePlaceholder = "synthetic-private-database-placeholder";

test("seed CLI validation refuses missing confirmation before DB connection", async () => {
  let connected = false;

  await assert.rejects(
    () => executePlatformSeedInternalAccess({
      env: {
        DATABASE_URL: privateDatabasePlaceholder,
        PLATFORM_SEED_USER_EMAIL: "owner@example.test",
      },
      now: () => now,
      createDatabaseRepositories() {
        connected = true;
        throw new Error("should not connect");
      },
      writeLine() {},
    }),
    assertSeedCliError("missing_confirm"),
  );

  assert.equal(connected, false);
});

test("seed CLI validation refuses missing user email before DB connection", async () => {
  let connected = false;

  await assert.rejects(
    () => executePlatformSeedInternalAccess({
      env: {
        DATABASE_URL: privateDatabasePlaceholder,
        PLATFORM_SEED_CONFIRM: "seed-reviewed-internal-access",
        PLATFORM_SEED_WORKSPACE_SLUG: "internal-workspace",
        PLATFORM_SEED_WORKSPACE_NAME: "Internal Workspace",
      },
      now: () => now,
      createDatabaseRepositories() {
        connected = true;
        throw new Error("should not connect");
      },
      writeLine() {},
    }),
    assertSeedCliError("missing_user_email"),
  );

  assert.equal(connected, false);
});

test("seed CLI validation refuses missing workspace identity before DB connection", async () => {
  let connected = false;

  await assert.rejects(
    () => executePlatformSeedInternalAccess({
      env: {
        DATABASE_URL: privateDatabasePlaceholder,
        PLATFORM_SEED_CONFIRM: "seed-reviewed-internal-access",
        PLATFORM_SEED_USER_EMAIL: "owner@example.test",
      },
      now: () => now,
      createDatabaseRepositories() {
        connected = true;
        throw new Error("should not connect");
      },
      writeLine() {},
    }),
    assertSeedCliError("missing_workspace_identity"),
  );

  assert.equal(connected, false);
});

test("seed CLI config requires explicit workspace identity without exposing private values", () => {
  const config = readPlatformSeedInternalAccessConfig({
    PLATFORM_SEED_CONFIRM: "seed-reviewed-internal-access",
    PLATFORM_SEED_USER_EMAIL: " Owner@Example.TEST ",
    PLATFORM_SEED_WORKSPACE_SLUG: " internal-workspace ",
    PLATFORM_SEED_WORKSPACE_NAME: " Internal Workspace ",
  });

  assert.deepEqual(config, {
    normalizedUserEmail: "owner@example.test",
    workspaceSlug: "internal-workspace",
    workspaceName: "Internal Workspace",
    appKey: "sqag",
    appName: "SQAG",
    membershipRole: "owner",
    appLaunchUrl: null,
  });
});

test("seed CLI rejects app identity overrides before DB connection", async () => {
  for (const override of [
    { PLATFORM_SEED_APP_KEY: "kqag" },
    { PLATFORM_SEED_APP_KEY: "sqag" },
    { PLATFORM_SEED_APP_NAME: "SQAG" },
  ]) {
    let connected = false;

    await assert.rejects(
      () => executePlatformSeedInternalAccess({
        env: {
          DATABASE_URL: privateDatabasePlaceholder,
          ...validEnv(),
          ...override,
        },
        now: () => now,
        createDatabaseRepositories() {
          connected = true;
          throw new Error("should not connect");
        },
        writeLine() {},
      }),
      assertSeedCliError("unsupported_app_identity_override"),
    );

    assert.equal(connected, false);
  }
});

test("existing user with provider identity gets idempotent workspace app entitlement and membership", async () => {
  const fixture = createSeedFixture({
    users: [existingUser()],
    providerIdentities: [providerIdentity()],
  });
  const config = readPlatformSeedInternalAccessConfig(validEnv());

  const first = await seedInternalAccessForExistingUser(fixture.repositories, config, now);
  const second = await seedInternalAccessForExistingUser(fixture.repositories, config, now);

  assert.equal(first.outcome, "seeded");
  assert.equal(first.user.email, "owner@example.test");
  assert.equal(first.providerIdentity.id, "provider_identity_owner");
  assert.equal(first.workspace.slug, "internal-workspace");
  assert.equal(first.app.key, "sqag");
  assert.equal(first.app.name, "SQAG");
  assert.equal(first.membership.role, "owner");
  assert.deepEqual(first.created, {
    workspace: true,
    app: true,
    entitlement: true,
    membership: true,
    user: false,
    providerIdentity: false,
  });
  assert.deepEqual(second.created, {
    workspace: false,
    app: false,
    entitlement: false,
    membership: false,
    user: false,
    providerIdentity: false,
  });
  assert.equal(fixture.records.workspaces.length, 1);
  assert.equal(fixture.records.apps.length, 1);
  assert.equal(fixture.records.appEntitlements.length, 1);
  assert.equal(fixture.records.memberships.length, 1);
  assert.equal(fixture.writeCounts.users, 0);
  assert.equal(fixture.writeCounts.providerIdentities, 0);
  assert.equal(fixture.writeCounts.sessions, 0);
  assert.equal(fixture.writeCounts.appLaunchTokens, 0);
});

test("seed rejects missing user and user without provider identity safely", async () => {
  const config = readPlatformSeedInternalAccessConfig(validEnv());
  const missingUser = createSeedFixture();
  const emailOnlyUser = createSeedFixture({
    users: [existingUser()],
  });

  await assert.rejects(
    () => seedInternalAccessForExistingUser(missingUser.repositories, config, now),
    assertSeedCliError("user_not_found"),
  );
  await assert.rejects(
    () => seedInternalAccessForExistingUser(emailOnlyUser.repositories, config, now),
    assertSeedCliError("missing_provider_identity"),
  );

  assert.equal(missingUser.records.workspaces.length, 0);
  assert.equal(emailOnlyUser.records.workspaces.length, 0);
  assert.equal(emailOnlyUser.writeCounts.users, 0);
  assert.equal(emailOnlyUser.writeCounts.providerIdentities, 0);
});

test("seed rejects unavailable provider identity repository safely", async () => {
  const fixture = createSeedFixture({
    users: [existingUser()],
  });
  const config = readPlatformSeedInternalAccessConfig(validEnv());
  delete fixture.repositories.providerIdentities;

  await assert.rejects(
    () => seedInternalAccessForExistingUser(fixture.repositories, config, now),
    assertSeedCliError("provider_identity_repository_unavailable"),
  );
  assert.equal(fixture.records.workspaces.length, 0);
});

test("seed rejects viewer role for SQAG and permits owner admin member roles", async () => {
  await assert.rejects(
    async () => {
      const config = readPlatformSeedInternalAccessConfig({
        ...validEnv(),
        PLATFORM_SEED_MEMBERSHIP_ROLE: "viewer",
      });
      return seedInternalAccessForExistingUser(
        createSeedFixture({
          users: [existingUser()],
          providerIdentities: [providerIdentity()],
        }).repositories,
        config,
        now,
      );
    },
    assertSeedCliError("unsupported_role"),
  );

  for (const role of ["owner", "admin", "member"]) {
    const fixture = createSeedFixture({
      users: [existingUser({ id: `user_${role}`, email: `${role}@example.test` })],
      providerIdentities: [providerIdentity({ userId: `user_${role}` })],
    });
    const result = await seedInternalAccessForExistingUser(
      fixture.repositories,
      readPlatformSeedInternalAccessConfig({
        ...validEnv(`${role}@example.test`),
        PLATFORM_SEED_MEMBERSHIP_ROLE: role,
      }),
      now,
    );

    assert.equal(result.membership.role, role);
  }
});

test("seed supports optional app launch URL without printing it in summary output", async () => {
  const fixture = createSeedFixture({
    users: [existingUser()],
    providerIdentities: [providerIdentity()],
  });
  const lines = [];
  const client = {
    repositories: fixture.repositories,
    pool: {
      async end() {
        fixture.closed = true;
      },
    },
  };

  const result = await executePlatformSeedInternalAccess({
    env: {
      ...validEnv(),
      PLATFORM_SEED_APP_LAUNCH_URL: "https://apps.example.test/sqag",
    },
    now: () => now,
    createDatabaseRepositories() {
      return client;
    },
    writeLine(line) {
      lines.push(line);
    },
  });

  assert.equal(result.app.launchUrl, "https://apps.example.test/sqag");
  assert.equal(fixture.closed, true);
  assert.match(lines.join("\n"), /workspace=configured/);
  assert.doesNotMatch(lines.join("\n"), /internal-workspace|Internal Workspace/);
  assert.match(lines.join("\n"), /app=sqag/);
  assert.match(lines.join("\n"), /user=existing_provider_backed_user/);
  assert.match(lines.join("\n"), /role=owner/);
  assert.doesNotMatch(lines.join("\n"), /apps\.example\.test/);
  assert.doesNotMatch(lines.join("\n"), /owner@example\.test/);
  assertOutputPrivacySafe(lines.join("\n"));
});

test("seed CLI import and module boundaries are side-effect safe", async () => {
  const script = await readFile("scripts/platform-seed-internal-access.mjs", "utf8");
  const packageJson = JSON.parse(await readFile("package.json", "utf8"));

  assert.equal(
    packageJson.scripts["platform:seed-internal-access"],
    "node scripts/platform-seed-internal-access.mjs",
  );
  assert.doesNotMatch(script, /drizzle-orm\/node-postgres\/migrator|db-migrate|migrate\(/);
  assert.doesNotMatch(script, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono)/i);
  assert.doesNotMatch(script, /from\s+["'][^"']*(?:sqag|clerk|auth0|supabase|stripe)/i);
  assert.doesNotMatch(script, /userinfo|jwks|token_endpoint|authorization_endpoint/i);
});

function validEnv(email = "owner@example.test") {
  return {
    PLATFORM_SEED_CONFIRM: "seed-reviewed-internal-access",
    PLATFORM_SEED_USER_EMAIL: email,
    PLATFORM_SEED_WORKSPACE_SLUG: "internal-workspace",
    PLATFORM_SEED_WORKSPACE_NAME: "Internal Workspace",
  };
}

function createSeedFixture(initial = {}) {
  const records = {
    users: initial.users ?? [],
    providerIdentities: initial.providerIdentities ?? [],
    sessions: [],
    workspaces: [],
    memberships: [],
    apps: [],
    appEntitlements: [],
    appLaunchTokens: [],
  };
  const repositories = createInMemoryPlatformRepositories(records);
  const writeCounts = {
    users: 0,
    providerIdentities: 0,
    sessions: 0,
    appLaunchTokens: 0,
  };

  const originalUserCreate = repositories.users.create;
  repositories.users.create = async (user) => {
    writeCounts.users += 1;
    return originalUserCreate(user);
  };
  const originalProviderIdentityCreate = repositories.providerIdentities.create;
  repositories.providerIdentities.create = async (identity) => {
    writeCounts.providerIdentities += 1;
    return originalProviderIdentityCreate(identity);
  };
  const originalSessionCreate = repositories.sessions.create;
  repositories.sessions.create = async (session) => {
    writeCounts.sessions += 1;
    return originalSessionCreate(session);
  };
  const originalAppLaunchTokenCreate = repositories.appLaunchTokens.create;
  repositories.appLaunchTokens.create = async (record) => {
    writeCounts.appLaunchTokens += 1;
    return originalAppLaunchTokenCreate(record);
  };

  return {
    records,
    repositories,
    writeCounts,
    closed: false,
  };
}

function existingUser(overrides = {}) {
  return {
    id: "user_owner",
    email: "owner@example.test",
    displayName: "Owner Example",
    status: "active",
    createdAt: now,
    updatedAt: now,
    lastLoginAt: now,
    ...overrides,
  };
}

function providerIdentity(overrides = {}) {
  return {
    id: "provider_identity_owner",
    userId: "user_owner",
    providerKey: "example-oidc",
    providerSubject: "synthetic-provider-reference",
    createdAt: now,
    updatedAt: later,
    ...overrides,
  };
}

function assertSeedCliError(expectedCode) {
  return (error) => {
    assert.equal(error instanceof PlatformSeedInternalAccessError, true);
    assert.equal(error.code, expectedCode);
    assertOutputPrivacySafe(String(error.message) + JSON.stringify(error));
    return true;
  };
}

function assertOutputPrivacySafe(serialized) {
  assert.doesNotMatch(serialized, /private-user|private-password|private-host|DATABASE_URL/i);
  assert.doesNotMatch(serialized, /synthetic-provider-reference|providerSubject/i);
  assert.doesNotMatch(serialized, /session_|csrf|auth-code|launch-token|token_hash/i);
  assert.doesNotMatch(serialized, /raw-state|raw-nonce|access_token|refresh_token|id_token/i);
}

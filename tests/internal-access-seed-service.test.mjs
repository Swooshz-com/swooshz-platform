import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  AccessDecisionResult,
  InternalAccessSeedError,
  decidePlatformAppAccess,
  ensureInternalWorkspaceAppAccess,
} from "../dist/index.js";

const now = "2026-06-28T00:00:00.000Z";
const future = "2026-06-29T00:00:00.000Z";

test("internal access seed creates and reuses workspace app entitlement and membership for existing user", async () => {
  const fixture = createSeedFixture({
    users: [existingUser()],
  });

  const first = await ensureInternalWorkspaceAppAccess(fixture.repositories, existingUserSeed());
  const second = await ensureInternalWorkspaceAppAccess(fixture.repositories, existingUserSeed());

  assert.equal(first.outcome, "seeded");
  assert.equal(second.outcome, "seeded");
  assert.equal(first.workspace.id, "workspace_koncept_images_seed");
  assert.equal(first.app.key, "kqag");
  assert.equal(first.app.name, "SAQG / KQAG");
  assert.equal(first.entitlement.status, "enabled");
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
});

test("internal access seed can grant membership to an existing user found by normalized email", async () => {
  const fixture = createSeedFixture({
    users: [existingUser({ email: "internal.member@example.test" })],
  });

  const result = await ensureInternalWorkspaceAppAccess(
    fixture.repositories,
    existingEmailSeed("internal.member@example.test"),
  );

  assert.equal(result.user.id, "user_internal_existing");
  assert.equal(result.membership.userId, "user_internal_existing");
  assert.equal(fixture.records.providerIdentities.length, 0);
});

test("internal access seed creates user and provider identity together only with explicit provider identity", async () => {
  const fixture = createSeedFixture();

  const result = await ensureInternalWorkspaceAppAccess(
    fixture.repositories,
    providerIdentitySeed(),
  );

  assert.equal(result.created.user, true);
  assert.equal(result.created.providerIdentity, true);
  assert.equal(result.user.email, "provider.user@example.test");
  assert.equal(result.providerIdentity.providerKey, "example-oidc");
  assert.equal(result.providerIdentity.providerSubject, "provider-subject-internal");
  assert.equal(fixture.records.users.length, 1);
  assert.equal(fixture.records.providerIdentities.length, 1);
});

test("internal access seed refuses email-only user creation and provider linking to existing email-only users", async () => {
  const emptyFixture = createSeedFixture();

  await assert.rejects(
    () => ensureInternalWorkspaceAppAccess(emptyFixture.repositories, emailOnlyCreateSeed()),
    assertSeedError("email_only_user_creation_forbidden"),
  );

  const existingEmailFixture = createSeedFixture({
    users: [existingUser({ email: "provider.user@example.test" })],
  });

  await assert.rejects(
    () => ensureInternalWorkspaceAppAccess(
      existingEmailFixture.repositories,
      providerIdentitySeed(),
    ),
    assertSeedError("existing_email_without_provider_identity"),
  );
});

test("internal access seed refuses conflicting existing platform state safely", async () => {
  await assert.rejects(
    () => ensureInternalWorkspaceAppAccess(
      createSeedFixture({
        workspaces: [{
          ...workspaceRecord(),
          status: "suspended",
        }],
        users: [existingUser()],
      }).repositories,
      existingUserSeed(),
    ),
    assertSeedError("workspace_conflict"),
  );

  await assert.rejects(
    () => ensureInternalWorkspaceAppAccess(
      createSeedFixture({
        apps: [{
          ...appRecord(),
          status: "disabled",
        }],
        users: [existingUser()],
      }).repositories,
      existingUserSeed(),
    ),
    assertSeedError("app_conflict"),
  );

  await assert.rejects(
    () => ensureInternalWorkspaceAppAccess(
      createSeedFixture({
        users: [existingUser()],
        workspaces: [workspaceRecord()],
        apps: [appRecord()],
        appEntitlements: [{
          ...entitlementRecord(),
          status: "disabled",
        }],
      }).repositories,
      existingUserSeed(),
    ),
    assertSeedError("entitlement_conflict"),
  );

  await assert.rejects(
    () => ensureInternalWorkspaceAppAccess(
      createSeedFixture({
        users: [existingUser()],
        workspaces: [workspaceRecord()],
        apps: [appRecord()],
        appEntitlements: [entitlementRecord()],
        memberships: [{
          ...membershipRecord(),
          role: "viewer",
        }],
      }).repositories,
      existingUserSeed(),
    ),
    assertSeedError("membership_conflict"),
  );
});

test("internal access seed refuses conflicting provider identity state safely", async () => {
  const fixture = createSeedFixture({
    users: [existingUser({ id: "user_other_existing", email: "other@example.test" })],
    providerIdentities: [{
      id: "provider_identity_other",
      userId: "user_other_existing",
      providerKey: "example-oidc",
      providerSubject: "provider-subject-internal",
      createdAt: now,
      updatedAt: now,
    }],
  });

  await assert.rejects(
    () => ensureInternalWorkspaceAppAccess(fixture.repositories, providerIdentitySeed()),
    assertSeedError("provider_identity_conflict"),
  );
});

test("seeded KQAG access is allowed for owner admin member and viewer remains blocked", async () => {
  for (const role of ["owner", "admin", "member"]) {
    const fixture = createSeedFixture({
      users: [existingUser({ id: `user_${role}_existing`, email: `${role}@example.test` })],
    });

    const seed = existingUserSeed({
      userId: `user_${role}_existing`,
      role,
      membershipId: `membership_${role}_seed`,
    });
    const result = await ensureInternalWorkspaceAppAccess(fixture.repositories, seed);
    const session = {
      id: `session_${role}_seed`,
      userId: result.user.id,
      createdAt: now,
      expiresAt: future,
      lastSeenAt: now,
      revokedAt: null,
    };
    fixture.records.sessions.push(session);

    const decision = await decidePlatformAppAccess(fixture.repositories, {
      sessionId: session.id,
      selectedWorkspaceId: result.workspace.id,
      appKey: "kqag",
      now,
    });

    assert.equal(
      decision.result,
      AccessDecisionResult.Allowed,
    );
  }

  const viewerFixture = createSeedFixture({
    users: [existingUser({ id: "user_viewer_existing", email: "viewer@example.test" })],
    workspaces: [workspaceRecord()],
    apps: [appRecord()],
    appEntitlements: [entitlementRecord()],
    memberships: [{
      ...membershipRecord(),
      id: "membership_viewer_existing",
      userId: "user_viewer_existing",
      role: "viewer",
    }],
    sessions: [{
      id: "session_viewer_seed",
      userId: "user_viewer_existing",
      createdAt: now,
      expiresAt: future,
      lastSeenAt: now,
      revokedAt: null,
    }],
  });
  const viewerDecision = await decidePlatformAppAccess(viewerFixture.repositories, {
    sessionId: "session_viewer_seed",
    selectedWorkspaceId: "workspace_koncept_images_seed",
    appKey: "kqag",
    now,
  });

  assert.equal(viewerDecision.result, AccessDecisionResult.RoleNotPermitted);
  await assert.rejects(
    () => ensureInternalWorkspaceAppAccess(
      createSeedFixture({
        users: [existingUser({ id: "user_viewer_existing", email: "viewer@example.test" })],
      }).repositories,
      existingUserSeed({
        userId: "user_viewer_existing",
        role: "viewer",
        membershipId: "membership_viewer_seed",
      }),
    ),
    assertSeedError("role_not_seedable"),
  );
});

test("internal access seed modules do not import DB frontend KQAG provider SDK framework billing or migrations", async () => {
  const platformFiles = [
    "src/platform/internal-access-seed-service.ts",
    "src/platform/repositories.ts",
  ];

  for (const filePath of platformFiles) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?|kqag)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono|node:http)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:clerk|auth0|supabase|stripe)/i);
    assert.doesNotMatch(contents, /DATABASE_URL|AUTH_CLIENT_SECRET|SESSION_SECRET/);
  }
});

function existingUserSeed(overrides = {}) {
  return baseSeed({
    user: {
      mode: "existing",
      userId: overrides.userId ?? "user_internal_existing",
      normalizedEmail: overrides.normalizedEmail,
    },
    role: overrides.role ?? "owner",
    membershipId: overrides.membershipId ?? "membership_internal_seed",
  });
}

function existingEmailSeed(email) {
  return baseSeed({
    user: {
      mode: "existing",
      normalizedEmail: email,
    },
  });
}

function providerIdentitySeed() {
  return baseSeed({
    user: {
      mode: "create_with_provider_identity",
      userId: "user_provider_seed",
      providerIdentityId: "provider_identity_seed",
      providerKey: "example-oidc",
      providerSubject: "provider-subject-internal",
      verifiedEmail: "provider.user@example.test",
      displayName: "Provider User",
    },
  });
}

function emailOnlyCreateSeed() {
  return baseSeed({
    user: {
      mode: "create_with_provider_identity",
      userId: "user_email_only_seed",
      verifiedEmail: "email.only@example.test",
      displayName: "Email Only",
    },
  });
}

function baseSeed(overrides = {}) {
  return {
    now,
    workspace: {
      id: "workspace_koncept_images_seed",
      slug: "koncept-images-pte-ltd",
      displayName: "Koncept Images Pte Ltd",
    },
    app: {
      id: "app_kqag",
      key: "kqag",
      name: "SAQG / KQAG",
      status: "private_preview",
    },
    entitlement: {
      id: "entitlement_koncept_kqag_seed",
      status: "enabled",
      grantedByUserId: null,
    },
    membership: {
      id: overrides.membershipId ?? "membership_internal_seed",
      role: overrides.role ?? "owner",
    },
    ...overrides,
  };
}

function createSeedFixture(initial = {}) {
  const records = {
    users: initial.users ?? [],
    providerIdentities: initial.providerIdentities ?? [],
    sessions: initial.sessions ?? [],
    workspaces: initial.workspaces ?? [],
    memberships: initial.memberships ?? [],
    apps: initial.apps ?? [],
    appEntitlements: initial.appEntitlements ?? [],
  };

  return {
    records,
    repositories: {
      users: {
        async findById(id) {
          return records.users.find((user) => user.id === id) ?? null;
        },
        async findByNormalizedEmail(email) {
          return records.users.find((user) => user.email === email) ?? null;
        },
        async create(user) {
          records.users.push(user);
          return user;
        },
      },
      providerIdentities: {
        async findByProviderSubject(providerKey, providerSubject) {
          return records.providerIdentities.find(
            (identity) =>
              identity.providerKey === providerKey &&
              identity.providerSubject === providerSubject,
          ) ?? null;
        },
        async listForUser(userId) {
          return records.providerIdentities.filter((identity) => identity.userId === userId);
        },
        async create(identity) {
          records.providerIdentities.push(identity);
          return identity;
        },
      },
      sessions: {
        async findById(id) {
          return records.sessions.find((session) => session.id === id) ?? null;
        },
        async create(session) {
          records.sessions.push(session);
          return session;
        },
        async revoke() {
          return null;
        },
      },
      workspaces: {
        async findById(id) {
          return records.workspaces.find((workspace) => workspace.id === id) ?? null;
        },
        async findBySlug(slug) {
          return records.workspaces.find((workspace) => workspace.slug === slug) ?? null;
        },
        async create(workspace) {
          records.workspaces.push(workspace);
          return workspace;
        },
      },
      memberships: {
        async findForUserInWorkspace(userId, workspaceId) {
          return records.memberships.find(
            (membership) =>
              membership.userId === userId &&
              membership.workspaceId === workspaceId,
          ) ?? null;
        },
        async listForUser(userId) {
          return records.memberships.filter((membership) => membership.userId === userId);
        },
        async create(membership) {
          records.memberships.push(membership);
          return membership;
        },
      },
      invitations: {
        async findById() {
          return null;
        },
        async create(invitation) {
          return invitation;
        },
        async updateStatus() {
          return null;
        },
      },
      apps: {
        async findByKey(key) {
          return records.apps.find((app) => app.key === key) ?? null;
        },
        async findById(id) {
          return records.apps.find((app) => app.id === id) ?? null;
        },
        async create(app) {
          records.apps.push(app);
          return app;
        },
      },
      appEntitlements: {
        async findForWorkspaceApp(workspaceId, appId) {
          return records.appEntitlements.find(
            (entitlement) =>
              entitlement.workspaceId === workspaceId &&
              entitlement.appId === appId,
          ) ?? null;
        },
        async create(entitlement) {
          records.appEntitlements.push(entitlement);
          return entitlement;
        },
      },
    },
  };
}

function existingUser(overrides = {}) {
  return {
    id: "user_internal_existing",
    email: "internal.owner@example.test",
    displayName: "Internal Owner",
    status: "active",
    createdAt: now,
    updatedAt: now,
    lastLoginAt: now,
    ...overrides,
  };
}

function workspaceRecord() {
  return {
    id: "workspace_koncept_images_seed",
    slug: "koncept-images-pte-ltd",
    displayName: "Koncept Images Pte Ltd",
    status: "active",
    createdAt: now,
    updatedAt: now,
  };
}

function appRecord() {
  return {
    id: "app_kqag",
    key: "kqag",
    name: "SAQG / KQAG",
    status: "private_preview",
    launchUrl: null,
    createdAt: now,
    updatedAt: now,
  };
}

function entitlementRecord() {
  return {
    id: "entitlement_koncept_kqag_seed",
    workspaceId: "workspace_koncept_images_seed",
    appId: "app_kqag",
    status: "enabled",
    grantedByUserId: null,
    createdAt: now,
    updatedAt: now,
  };
}

function membershipRecord() {
  return {
    id: "membership_internal_seed",
    workspaceId: "workspace_koncept_images_seed",
    userId: "user_internal_existing",
    role: "owner",
    status: "active",
    createdAt: now,
    updatedAt: now,
  };
}

function assertSeedError(expectedCode) {
  return (error) => {
    assert.equal(error instanceof InternalAccessSeedError, true);
    assert.equal(error.code, expectedCode);
    assert.equal(error.publicMessage, "Internal access seed could not be completed.");
    const serialized = JSON.stringify(error) + String(error.message ?? "");
    assert.doesNotMatch(serialized, /provider-subject-internal|provider\.user@example/i);
    assert.doesNotMatch(serialized, /internal\.owner@example|raw-session-token/i);
    assert.doesNotMatch(serialized, /postgresql:\/\/private-host|DATABASE_URL/i);
    return true;
  };
}

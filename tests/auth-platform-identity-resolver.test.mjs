import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  AuthCallbackError,
  createPlatformIdentitySessionResolver,
} from "../dist/auth/index.js";
import { AccessDecisionResult, decidePlatformAppAccess } from "../dist/index.js";

const now = "2026-06-27T00:00:00.000Z";
const expiresAt = "2026-06-27T01:00:00.000Z";
const sessionDurationMs = 60 * 60 * 1000;

const activeUser = {
  id: "user_owner",
  email: "owner@example.com",
  displayName: "Synthetic Owner",
  status: "active",
  createdAt: "2026-06-26T00:00:00.000Z",
  updatedAt: "2026-06-26T00:00:00.000Z",
  lastLoginAt: null,
};

const disabledUser = {
  ...activeUser,
  id: "user_disabled",
  email: "disabled@example.com",
  status: "disabled",
};

const existingProviderIdentity = {
  id: "provider_identity_owner",
  userId: activeUser.id,
  providerKey: "example-oidc",
  providerSubject: "provider-subject-123",
  createdAt: "2026-06-26T00:00:00.000Z",
  updatedAt: "2026-06-26T00:00:00.000Z",
};

const verifiedIdentity = {
  providerKey: "example-oidc",
  providerSubject: "provider-subject-123",
  verifiedEmail: "owner@example.com",
  displayName: "Synthetic Owner",
  metadata: { emailVerified: true },
};
const privateStorageError =
  "database exploded owner@example.com provider-subject-123 postgresql://private-host";

test("existing provider identity resolves existing active user and creates session", async () => {
  const deps = createResolverDependencies({
    users: [activeUser],
    providerIdentities: [existingProviderIdentity],
  });
  const resolver = createPlatformIdentitySessionResolver(deps);

  const result = await resolver.resolveAuthenticatedIdentity({
    identity: verifiedIdentity,
    stateReference: createStateReference(),
    now,
  });

  assert.equal(result.platformUserId, activeUser.id);
  assert.equal(result.providerIdentityId, existingProviderIdentity.id);
  assert.deepEqual(result.session, {
    id: "session_auth_callback_1",
    userId: activeUser.id,
    createdAt: now,
    expiresAt,
    lastSeenAt: now,
    revokedAt: null,
  });
  assert.deepEqual(deps.records.sessions, [result.session]);
  assert.equal(Object.hasOwn(result, "workspaceId"), false);
  assert.equal(Object.hasOwn(result, "appKey"), false);
});

test("new provider identity creates user, links provider identity, and creates session", async () => {
  const deps = createResolverDependencies();
  const resolver = createPlatformIdentitySessionResolver(deps);

  const result = await resolver.resolveAuthenticatedIdentity({
    identity: {
      ...verifiedIdentity,
      providerSubject: "new-provider-subject",
      verifiedEmail: "new-owner@example.com",
      displayName: " New Owner ",
    },
    stateReference: createStateReference(),
    now,
  });

  assert.equal(result.platformUserId, "user_auth_callback_1");
  assert.equal(result.providerIdentityId, "provider_identity_auth_callback_1");
  assert.deepEqual(deps.records.users, [
    {
      id: "user_auth_callback_1",
      email: "new-owner@example.com",
      displayName: "New Owner",
      status: "active",
      createdAt: now,
      updatedAt: now,
      lastLoginAt: now,
    },
  ]);
  assert.deepEqual(deps.records.providerIdentities, [
    {
      id: "provider_identity_auth_callback_1",
      userId: "user_auth_callback_1",
      providerKey: "example-oidc",
      providerSubject: "new-provider-subject",
      createdAt: now,
      updatedAt: now,
    },
  ]);
  assert.equal(deps.records.sessions[0].id, "session_auth_callback_1");
});

test("pending approval activates only after real provider-backed sign-in with matching email", async () => {
  const deps = createResolverDependencies({
    membershipApprovals: [pendingApproval()],
    membershipIdFactory: () => "membership_from_pending_approval",
    auditEventIdFactory: () => "audit_membership_approval_accepted",
  });
  const resolver = createPlatformIdentitySessionResolver(deps);

  const result = await resolver.resolveAuthenticatedIdentity({
    identity: {
      ...verifiedIdentity,
      providerSubject: "pending-provider-subject",
      verifiedEmail: "pending.user@example.test",
      displayName: "Pending User",
    },
    stateReference: createStateReference(),
    now,
    authPolicy: {
      providerEmailAllowed: false,
    },
  });

  assert.equal(result.platformUserId, "user_auth_callback_1");
  assert.equal(result.providerIdentityId, "provider_identity_auth_callback_1");
  assert.equal(result.workspaceMembershipGranted, true);
  assert.deepEqual(deps.records.memberships, [
    {
      id: "membership_from_pending_approval",
      workspaceId: "workspace_koncept_images",
      userId: "user_auth_callback_1",
      role: "member",
      status: "active",
      createdAt: now,
      updatedAt: now,
    },
  ]);
  assert.deepEqual(deps.records.membershipApprovals, [
    {
      ...pendingApproval(),
      status: "accepted",
      updatedAt: now,
      acceptedAt: now,
      acceptedUserId: "user_auth_callback_1",
    },
  ]);
  assert.deepEqual(deps.records.auditEvents, [
    {
      id: "audit_membership_approval_accepted",
      workspaceId: "workspace_koncept_images",
      actorUserId: "user_auth_callback_1",
      eventType: "workspace.membership_approval.accepted",
      targetType: "membership_approval",
      targetId: "approval_pending_example",
      createdAt: now,
      metadata: {
        newRole: "member",
        newStatus: "active",
        targetUserId: "user_auth_callback_1",
        source: "provider_backed_sign_in",
      },
    },
  ]);

  const accessDecision = await decidePlatformAppAccess(deps.repositories, {
    sessionId: "session_auth_callback_1",
    selectedWorkspaceId: "workspace_koncept_images",
    appKey: "kqag",
    now,
  });
  assert.equal(accessDecision.result, AccessDecisionResult.Allowed);
});

test("pending approval activates even when provider email passes auth policy", async () => {
  const deps = createResolverDependencies({
    membershipApprovals: [pendingApproval()],
    membershipIdFactory: () => "membership_from_pending_approval",
    auditEventIdFactory: () => "audit_membership_approval_accepted",
  });
  const resolver = createPlatformIdentitySessionResolver(deps);

  const result = await resolver.resolveAuthenticatedIdentity({
    identity: {
      ...verifiedIdentity,
      providerSubject: "pending-provider-subject",
      verifiedEmail: "pending.user@example.test",
      displayName: "Pending User",
    },
    stateReference: createStateReference(),
    now,
    authPolicy: {
      providerEmailAllowed: true,
    },
  });

  assert.equal(result.workspaceMembershipGranted, true);
  assert.deepEqual(deps.records.memberships, [
    {
      id: "membership_from_pending_approval",
      workspaceId: "workspace_koncept_images",
      userId: "user_auth_callback_1",
      role: "member",
      status: "active",
      createdAt: now,
      updatedAt: now,
    },
  ]);
  assert.deepEqual(deps.records.membershipApprovals, [
    {
      ...pendingApproval(),
      status: "accepted",
      updatedAt: now,
      acceptedAt: now,
      acceptedUserId: "user_auth_callback_1",
    },
  ]);
});

test("revoked or missing pending approval does not authorize non-allowlisted sign-in", async () => {
  for (const [name, membershipApprovals] of [
    ["missing approval", []],
    ["revoked approval", [pendingApproval({ status: "revoked", revokedAt: now })]],
  ]) {
    const deps = createResolverDependencies({ membershipApprovals });
    const resolver = createPlatformIdentitySessionResolver(deps);

    await assert.rejects(
      () =>
        resolver.resolveAuthenticatedIdentity({
          identity: {
            ...verifiedIdentity,
            providerSubject: `pending-provider-subject-${name}`,
            verifiedEmail: "pending.user@example.test",
          },
          stateReference: createStateReference(),
          now,
          authPolicy: {
            providerEmailAllowed: false,
          },
        }),
      (error) => {
        assert.equal(error instanceof AuthCallbackError, true);
        assert.equal(error.code, "onboarding_approval_required");
        return true;
      },
      name,
    );
    assert.deepEqual(deps.records.users, []);
    assert.deepEqual(deps.records.providerIdentities, []);
    assert.deepEqual(deps.records.memberships, []);
    assert.deepEqual(deps.records.sessions, []);
    assert.deepEqual(deps.records.auditEvents, []);
  }
});

test("pending approval activation rolls back identity and membership state when audit fails", async () => {
  const deps = createResolverDependencies({
    membershipApprovals: [pendingApproval()],
    failAuditAppend: true,
  });
  const resolver = createPlatformIdentitySessionResolver(deps);

  await assert.rejects(
    () =>
      resolver.resolveAuthenticatedIdentity({
        identity: {
          ...verifiedIdentity,
          providerSubject: "pending-provider-subject",
          verifiedEmail: "pending.user@example.test",
        },
        stateReference: createStateReference(),
        now,
        authPolicy: {
          providerEmailAllowed: false,
        },
      }),
    (error) => {
      assert.equal(error instanceof AuthCallbackError, true);
      assert.equal(error.code, "membership_approval_acceptance_failed");
      return true;
    },
  );
  assert.deepEqual(deps.records.users, []);
  assert.deepEqual(deps.records.providerIdentities, []);
  assert.deepEqual(deps.records.memberships, []);
  assert.deepEqual(deps.records.sessions, []);
  assert.deepEqual(deps.records.membershipApprovals, [pendingApproval()]);
  assert.deepEqual(deps.records.auditEvents, []);
});

test("session creation uses deterministic id and expiry inputs", async () => {
  const deps = createResolverDependencies({
    users: [activeUser],
    providerIdentities: [existingProviderIdentity],
    sessionIdFactory: () => "session_deterministic",
  });
  const resolver = createPlatformIdentitySessionResolver(deps);

  const result = await resolver.resolveAuthenticatedIdentity({
    identity: verifiedIdentity,
    stateReference: createStateReference(),
    now,
  });

  assert.equal(result.session.id, "session_deterministic");
  assert.equal(result.session.createdAt, now);
  assert.equal(result.session.lastSeenAt, now);
  assert.equal(result.session.expiresAt, expiresAt);
  assert.equal(result.session.revokedAt, null);
});

test("result includes safe session id and expiry but no raw token or secret material", async () => {
  const deps = createResolverDependencies({
    users: [activeUser],
    providerIdentities: [existingProviderIdentity],
  });
  const resolver = createPlatformIdentitySessionResolver(deps);

  const result = await resolver.resolveAuthenticatedIdentity({
    identity: verifiedIdentity,
    stateReference: createStateReference(),
    now,
  });
  const serialized = JSON.stringify(result);

  assert.equal(result.session.id, "session_auth_callback_1");
  assert.equal(result.session.expiresAt, expiresAt);
  assert.doesNotMatch(serialized, /session-secret|client-secret|raw-session|auth-code/i);
});

test("provider identity is matched by provider key and subject, not email alone", async () => {
  const deps = createResolverDependencies({
    users: [activeUser],
    providerIdentities: [
      {
        ...existingProviderIdentity,
        providerKey: "other-oidc",
      },
    ],
  });
  const resolver = createPlatformIdentitySessionResolver(deps);

  await assert.rejects(
    () =>
      resolver.resolveAuthenticatedIdentity({
        identity: verifiedIdentity,
        stateReference: createStateReference(),
        now,
      }),
    (error) => {
      assert.equal(error instanceof AuthCallbackError, true);
      assert.equal(error.code, "provider_identity_link_failed");
      assert.doesNotMatch(error.message, /owner@example.com|provider-subject-123/);
      return true;
    },
  );
  assert.deepEqual(deps.records.sessions, []);
});

test("verified email alone cannot hijack a different provider subject", async () => {
  const deps = createResolverDependencies({
    users: [activeUser],
    providerIdentities: [
      {
        ...existingProviderIdentity,
        providerSubject: "different-provider-subject",
      },
    ],
  });
  const resolver = createPlatformIdentitySessionResolver(deps);

  await assert.rejects(
    () =>
      resolver.resolveAuthenticatedIdentity({
        identity: verifiedIdentity,
        stateReference: createStateReference(),
        now,
      }),
    (error) => {
      assert.equal(error instanceof AuthCallbackError, true);
      assert.equal(error.code, "provider_identity_link_failed");
      assert.doesNotMatch(error.message, /owner@example.com|different-provider-subject/);
      return true;
    },
  );
});

test("login session creation does not grant workspace membership or app access", async () => {
  const deps = createResolverDependencies({
    users: [activeUser],
    providerIdentities: [existingProviderIdentity],
  });
  const resolver = createPlatformIdentitySessionResolver(deps);

  const result = await resolver.resolveAuthenticatedIdentity({
    identity: verifiedIdentity,
    stateReference: createStateReference(),
    now,
  });

  assert.equal(Object.hasOwn(result, "workspaceId"), false);
  assert.equal(Object.hasOwn(result, "workspaceMembershipGranted"), false);
  assert.equal(Object.hasOwn(result, "appAccessGranted"), false);
});

test("disabled user mapped from provider identity is rejected", async () => {
  const deps = createResolverDependencies({
    users: [disabledUser],
    providerIdentities: [
      {
        ...existingProviderIdentity,
        userId: disabledUser.id,
      },
    ],
  });
  const resolver = createPlatformIdentitySessionResolver(deps);

  await assert.rejects(
    () =>
      resolver.resolveAuthenticatedIdentity({
        identity: verifiedIdentity,
        stateReference: createStateReference(),
        now,
      }),
    (error) => {
      assert.equal(error instanceof AuthCallbackError, true);
      assert.equal(error.code, "user_not_active");
      return true;
    },
  );
});

test("provider identity lookup errors become privacy-safe auth errors", async () => {
  const deps = createResolverDependencies({
    failProviderIdentityLookup: true,
  });
  const resolver = createPlatformIdentitySessionResolver(deps);

  await assert.rejects(
    () =>
      resolver.resolveAuthenticatedIdentity({
        identity: verifiedIdentity,
        stateReference: createStateReference(),
        now,
      }),
    assertPrivacySafeLookupError("provider_identity_link_failed"),
  );
});

test("user lookup by id errors become privacy-safe auth errors", async () => {
  const deps = createResolverDependencies({
    users: [activeUser],
    providerIdentities: [existingProviderIdentity],
    failUserFindById: true,
  });
  const resolver = createPlatformIdentitySessionResolver(deps);

  await assert.rejects(
    () =>
      resolver.resolveAuthenticatedIdentity({
        identity: verifiedIdentity,
        stateReference: createStateReference(),
        now,
      }),
    assertPrivacySafeLookupError("provider_identity_link_failed"),
  );
});

test("user lookup by normalized email errors become privacy-safe auth errors", async () => {
  const deps = createResolverDependencies({
    failUserFindByNormalizedEmail: true,
  });
  const resolver = createPlatformIdentitySessionResolver(deps);

  await assert.rejects(
    () =>
      resolver.resolveAuthenticatedIdentity({
        identity: {
          ...verifiedIdentity,
          providerSubject: "new-provider-subject",
        },
        stateReference: createStateReference(),
        now,
      }),
    assertPrivacySafeLookupError("provider_identity_link_failed"),
  );
});

test("session repository errors become privacy-safe auth errors", async () => {
  const deps = createResolverDependencies({
    users: [activeUser],
    providerIdentities: [existingProviderIdentity],
    failSessionCreate: true,
  });
  const resolver = createPlatformIdentitySessionResolver(deps);

  await assert.rejects(
    () =>
      resolver.resolveAuthenticatedIdentity({
        identity: verifiedIdentity,
        stateReference: createStateReference(),
        now,
      }),
    (error) => {
      assert.equal(error instanceof AuthCallbackError, true);
      assert.equal(error.code, "session_creation_failed");
      assert.doesNotMatch(error.message, /database exploded|owner@example.com|provider-subject/);
      return true;
    },
  );
});

test("auth platform identity resolver does not import DB client or HTTP framework details", async () => {
  const contents = await readFile("src/auth/platform-identity-resolver.ts", "utf8");

  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?|kqag)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono|node:http)/i);
  assert.doesNotMatch(contents, /src\/db|\.{1,2}\/db|\.{1,2}\/\.{1,2}\/db/i);
});

function createResolverDependencies(options = {}) {
  const records = {
    users: [...(options.users ?? [])],
    providerIdentities: [...(options.providerIdentities ?? [])],
    sessions: [],
    workspaces: [
      {
        id: "workspace_koncept_images",
        slug: "koncept-images",
        displayName: "Koncept Images",
        status: "active",
        createdAt: now,
        updatedAt: now,
      },
      ...(options.workspaces ?? []),
    ],
    memberships: [...(options.memberships ?? [])],
    membershipApprovals: [...(options.membershipApprovals ?? [])],
    apps: [
      {
        id: "app_kqag",
        key: "kqag",
        name: "KQAG / SAQG",
        status: "private_preview",
        launchUrl: null,
        createdAt: now,
        updatedAt: now,
      },
    ],
    appEntitlements: [
      {
        id: "entitlement_kqag",
        workspaceId: "workspace_koncept_images",
        appId: "app_kqag",
        status: "enabled",
        grantedByUserId: "user_owner",
        createdAt: now,
        updatedAt: now,
      },
    ],
    auditEvents: [],
  };
  const repositories = {
    users: {
      async findById(id) {
        if (options.failUserFindById) {
          throw new Error(privateStorageError);
        }

        return records.users.find((user) => user.id === id) ?? null;
      },
      async findByNormalizedEmail(email) {
        if (options.failUserFindByNormalizedEmail) {
          throw new Error(privateStorageError);
        }

        return records.users.find((user) => user.email === email) ?? null;
      },
      async create(user) {
        records.users.push(user);
        return user;
      },
    },
    providerIdentities: {
      async findByProviderSubject(providerKey, providerSubject) {
        if (options.failProviderIdentityLookup) {
          throw new Error(privateStorageError);
        }

        return (
          records.providerIdentities.find(
            (identity) =>
              identity.providerKey === providerKey &&
              identity.providerSubject === providerSubject,
          ) ?? null
        );
      },
      async listForUser(userId) {
        return records.providerIdentities.filter((identity) => identity.userId === userId);
      },
      async create(identity) {
        records.providerIdentities.push(identity);
        return identity;
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
        return (
          records.memberships.find(
            (membership) =>
              membership.userId === userId && membership.workspaceId === workspaceId,
          ) ?? null
        );
      },
      async listForUser(userId) {
        return records.memberships.filter((membership) => membership.userId === userId);
      },
      async listForWorkspace(workspaceId) {
        return records.memberships.filter(
          (membership) => membership.workspaceId === workspaceId,
        );
      },
      async create(membership) {
        records.memberships.push(membership);
        return membership;
      },
      async updateRole() {
        throw new Error(privateStorageError);
      },
      async updateStatus() {
        throw new Error(privateStorageError);
      },
    },
    membershipApprovals: {
      async findById(id) {
        return records.membershipApprovals.find((approval) => approval.id === id) ?? null;
      },
      async findPendingForWorkspaceEmail(workspaceId, email) {
        return (
          records.membershipApprovals.find(
            (approval) =>
              approval.workspaceId === workspaceId &&
              approval.email === email &&
              approval.status === "pending",
          ) ?? null
        );
      },
      async listPendingForWorkspace(workspaceId) {
        return records.membershipApprovals.filter(
          (approval) =>
            approval.workspaceId === workspaceId && approval.status === "pending",
        );
      },
      async listPendingForEmail(email) {
        return records.membershipApprovals.filter(
          (approval) => approval.email === email && approval.status === "pending",
        );
      },
      async create(approval) {
        records.membershipApprovals.push(approval);
        return approval;
      },
      async updateStatus(id, status, timestamps = {}) {
        const approval = records.membershipApprovals.find(
          (candidate) => candidate.id === id,
        );
        if (!approval) {
          return null;
        }

        Object.assign(approval, { status }, timestamps);
        return approval;
      },
    },
    sessions: {
      async findById(id) {
        return records.sessions.find((session) => session.id === id) ?? null;
      },
      async create(session) {
        if (options.failSessionCreate) {
          throw new Error("database exploded with private implementation detail");
        }

        records.sessions.push(session);
        return session;
      },
    },
    apps: {
      async findByKey(key) {
        return records.apps.find((app) => app.key === key) ?? null;
      },
      async findById(id) {
        return records.apps.find((app) => app.id === id) ?? null;
      },
      async listAll() {
        return records.apps;
      },
      async create(app) {
        records.apps.push(app);
        return app;
      },
    },
    appEntitlements: {
      async findForWorkspaceApp(workspaceId, appId) {
        return (
          records.appEntitlements.find(
            (entitlement) =>
              entitlement.workspaceId === workspaceId && entitlement.appId === appId,
          ) ?? null
        );
      },
      async listForWorkspace(workspaceId) {
        return records.appEntitlements.filter(
          (entitlement) => entitlement.workspaceId === workspaceId,
        );
      },
      async create(entitlement) {
        records.appEntitlements.push(entitlement);
        return entitlement;
      },
      async updateStatus() {
        throw new Error(privateStorageError);
      },
    },
    auditEvents: {
      async append(event) {
        if (options.failAuditAppend) {
          throw new Error(privateStorageError);
        }

        records.auditEvents.push(event);
        return event;
      },
      async listForWorkspace(workspaceId) {
        return records.auditEvents.filter((event) => event.workspaceId === workspaceId);
      },
    },
  };
  repositories.workspaceAdminTransactions = {
    async run(operation) {
      const snapshots = [
        records.users,
        records.providerIdentities,
        records.sessions,
        records.workspaces,
        records.memberships,
        records.membershipApprovals,
        records.apps,
        records.appEntitlements,
        records.auditEvents,
      ].map(snapshotRecords);

      try {
        return await operation(repositories);
      } catch (error) {
        restoreRecords(records.users, snapshots[0]);
        restoreRecords(records.providerIdentities, snapshots[1]);
        restoreRecords(records.sessions, snapshots[2]);
        restoreRecords(records.workspaces, snapshots[3]);
        restoreRecords(records.memberships, snapshots[4]);
        restoreRecords(records.membershipApprovals, snapshots[5]);
        restoreRecords(records.apps, snapshots[6]);
        restoreRecords(records.appEntitlements, snapshots[7]);
        restoreRecords(records.auditEvents, snapshots[8]);
        throw error;
      }
    },
  };

  return {
    records,
    repositories,
    sessionDurationMs,
    sessionIdFactory: options.sessionIdFactory ?? (() => "session_auth_callback_1"),
    userIdFactory: () => "user_auth_callback_1",
    providerIdentityIdFactory: () => "provider_identity_auth_callback_1",
    membershipIdFactory:
      options.membershipIdFactory ?? (() => "membership_auth_callback_1"),
    auditEventIdFactory:
      options.auditEventIdFactory ?? (() => "audit_auth_callback_1"),
  };
}

function assertPrivacySafeLookupError(expectedCode) {
  return (error) => {
    assert.equal(error instanceof AuthCallbackError, true);
    assert.equal(error.code, expectedCode);
    assert.doesNotMatch(error.message, /database exploded/);
    assert.doesNotMatch(error.message, /owner@example.com/);
    assert.doesNotMatch(error.message, /provider-subject-123/);
    assert.doesNotMatch(error.message, /postgresql:\/\/private-host/);
    assert.doesNotMatch(error.message, /storage|sql|database|db url/i);
    return true;
  };
}

function createStateReference() {
  return {
    providerKey: "example-oidc",
    stateHash: "hash:synthetic-state",
    nonceHash: "hash:synthetic-nonce",
  };
}

function pendingApproval(overrides = {}) {
  return {
    id: "approval_pending_example",
    workspaceId: "workspace_koncept_images",
    email: "pending.user@example.test",
    role: "member",
    status: "pending",
    requestedByUserId: "user_owner",
    createdAt: "2026-06-26T00:00:00.000Z",
    updatedAt: "2026-06-26T00:00:00.000Z",
    acceptedAt: null,
    revokedAt: null,
    acceptedUserId: null,
    revokedByUserId: null,
    ...overrides,
  };
}

function snapshotRecords(records) {
  return records.map((record) => ({ ...record }));
}

function restoreRecords(records, snapshot) {
  records.splice(0, records.length, ...snapshot.map((record) => ({ ...record })));
}

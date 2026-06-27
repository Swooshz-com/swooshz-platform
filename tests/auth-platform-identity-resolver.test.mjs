import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  AuthCallbackError,
  createPlatformIdentitySessionResolver,
} from "../dist/auth/index.js";

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
  };

  return {
    records,
    repositories,
    sessionDurationMs,
    sessionIdFactory: options.sessionIdFactory ?? (() => "session_auth_callback_1"),
    userIdFactory: () => "user_auth_callback_1",
    providerIdentityIdFactory: () => "provider_identity_auth_callback_1",
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

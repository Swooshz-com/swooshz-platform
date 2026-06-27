import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  AuthSessionError,
  revokePlatformSession,
} from "../dist/auth/index.js";

const now = "2026-06-27T00:00:00.000Z";
const earlier = "2026-06-26T23:00:00.000Z";
const future = "2026-06-27T01:00:00.000Z";
const past = "2026-06-26T22:00:00.000Z";
const privateStorageError =
  "database exploded session_active postgresql://private-host raw-session-token";

test("revokes active session without touching unrelated platform state", async () => {
  const deps = createSessionRevocationDependencies();

  const result = await revokePlatformSession(deps, {
    sessionId: "session_active",
    now,
  });

  assert.deepEqual(result, {
    outcome: "revoked",
    sessionId: "session_active",
    revokedAt: now,
  });
  assert.equal(deps.records.sessions[0].revokedAt, now);
  assert.equal(deps.records.sessions[0].userId, "user_owner");
  assert.equal(deps.records.sessions[0].createdAt, earlier);
  assert.equal(deps.records.sessions[0].expiresAt, future);
  assert.equal(deps.records.sessions[0].lastSeenAt, earlier);
  assert.deepEqual(deps.records.providerIdentities, [{ id: "provider_identity_owner" }]);
  assert.deepEqual(deps.records.memberships, [{ id: "membership_owner" }]);
  assert.deepEqual(deps.records.appEntitlements, [{ id: "entitlement_kqag" }]);
});

test("already revoked session is idempotent and does not overwrite revokedAt", async () => {
  const deps = createSessionRevocationDependencies({
    sessions: [
      createSession({
        id: "session_revoked",
        revokedAt: earlier,
      }),
    ],
  });

  const result = await revokePlatformSession(deps, {
    sessionId: "session_revoked",
    now,
  });

  assert.deepEqual(result, {
    outcome: "already_revoked",
    sessionId: "session_revoked",
    revokedAt: earlier,
  });
  assert.equal(deps.revokeCalls.length, 0);
  assert.equal(deps.records.sessions[0].revokedAt, earlier);
});

test("missing session returns privacy-safe not_found result", async () => {
  const deps = createSessionRevocationDependencies();

  const result = await revokePlatformSession(deps, {
    sessionId: "missing_session",
    now,
  });

  assert.deepEqual(result, { outcome: "not_found" });
  assert.equal(deps.revokeCalls.length, 0);
});

test("expired but unrevoked session is still revoked", async () => {
  const deps = createSessionRevocationDependencies({
    sessions: [
      createSession({
        id: "session_expired",
        expiresAt: past,
      }),
    ],
  });

  const result = await revokePlatformSession(deps, {
    sessionId: "session_expired",
    now,
  });

  assert.deepEqual(result, {
    outcome: "revoked",
    sessionId: "session_expired",
    revokedAt: now,
  });
});

test("repository find failure becomes privacy-safe auth session error", async () => {
  const deps = createSessionRevocationDependencies({
    failFind: true,
  });

  await assert.rejects(
    () => revokePlatformSession(deps, { sessionId: "session_active", now }),
    assertPrivacySafeSessionError("session_lookup_failed"),
  );
});

test("repository revoke failure becomes privacy-safe auth session error", async () => {
  const deps = createSessionRevocationDependencies({
    failRevoke: true,
  });

  await assert.rejects(
    () => revokePlatformSession(deps, { sessionId: "session_active", now }),
    assertPrivacySafeSessionError("session_revocation_failed"),
  );
});

test("revocation result does not expose tokens secrets provider material or storage details", async () => {
  const deps = createSessionRevocationDependencies();

  const result = await revokePlatformSession(deps, {
    sessionId: "session_active",
    now,
  });
  const serialized = JSON.stringify(result);

  assert.doesNotMatch(serialized, /cookie|raw-session-token|session-secret/i);
  assert.doesNotMatch(serialized, /provider-token|auth-code|raw-claim/i);
  assert.doesNotMatch(serialized, /postgresql:\/\/private-host|database exploded/i);
});

test("auth session modules do not import DB, HTTP, frontend, KQAG, provider SDK, or migrations", async () => {
  const authFiles = await listFiles("src/auth");

  for (const filePath of authFiles) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?|kqag)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono|node:http)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:clerk|auth0|supabase)/i);
    assert.doesNotMatch(contents, /src\/db|\.{1,2}\/db|\.{1,2}\/\.{1,2}\/db/i);
  }
});

test("pure domain modules do not import auth modules", async () => {
  const pureDomainFiles = [
    "src/accounts/types.ts",
    "src/accounts/normalization.ts",
    "src/apps/types.ts",
    "src/access/decide-app-access.ts",
  ];

  for (const filePath of pureDomainFiles) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /src\/auth|\.{1,2}\/auth|\.{1,2}\/\.{1,2}\/auth/);
  }
});

function createSessionRevocationDependencies(options = {}) {
  const records = {
    sessions: [...(options.sessions ?? [createSession()])],
    providerIdentities: [{ id: "provider_identity_owner" }],
    memberships: [{ id: "membership_owner" }],
    appEntitlements: [{ id: "entitlement_kqag" }],
  };
  const revokeCalls = [];

  return {
    records,
    revokeCalls,
    sessions: {
      async findById(id) {
        if (options.failFind) {
          throw new Error(privateStorageError);
        }

        return records.sessions.find((session) => session.id === id) ?? null;
      },
      async create(session) {
        records.sessions.push(session);
        return session;
      },
      async revoke(id, revokedAt) {
        if (options.failRevoke) {
          throw new Error(privateStorageError);
        }

        revokeCalls.push({ id, revokedAt });
        const session = records.sessions.find((candidate) => candidate.id === id);

        if (!session) {
          return null;
        }

        session.revokedAt = revokedAt;
        return session;
      },
    },
  };
}

function createSession(overrides = {}) {
  return {
    id: "session_active",
    userId: "user_owner",
    createdAt: earlier,
    expiresAt: future,
    lastSeenAt: earlier,
    revokedAt: null,
    ...overrides,
  };
}

function assertPrivacySafeSessionError(expectedCode) {
  return (error) => {
    assert.equal(error instanceof AuthSessionError, true);
    assert.equal(error.code, expectedCode);
    assert.equal(error.publicMessage, "Session operation could not be completed.");
    assert.doesNotMatch(error.message, /database exploded/);
    assert.doesNotMatch(error.message, /session_active/);
    assert.doesNotMatch(error.message, /postgresql:\/\/private-host/);
    assert.doesNotMatch(error.message, /raw-session-token/);
    assert.doesNotMatch(error.message, /storage|sql|database|db url/i);
    return true;
  };
}

async function listFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const path = join(directory, entry.name);

    if (entry.isDirectory()) {
      files.push(...(await listFiles(path)));
    } else if (entry.isFile() && path.endsWith(".ts")) {
      files.push(path);
    }
  }

  return files;
}

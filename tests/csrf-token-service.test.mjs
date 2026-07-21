import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  CsrfTokenServiceError,
  createRepositoryBackedCsrfTokenValidator,
  issueCsrfTokenForSession,
} from "../dist/index.js";
import { maxActiveCsrfTokensPerSessionPurpose } from "../dist/db/csrf-token-repository.js";

const now = "2026-06-27T00:00:00.000Z";
const later = "2026-06-27T00:15:00.000Z";
const past = "2026-06-26T23:55:00.000Z";
const sessionId = "session_owner_example";
const otherSessionId = "session_other_example";
const rawToken = "synthetic-csrf-token-reference";
const tokenHash = "hash_synthetic_csrf_token_reference";
const privateFailure =
  "storage exploded synthetic-csrf-token-reference hash_synthetic_csrf_token_reference postgresql://private-host";

test("issue service requires sessionId", async () => {
  const fixture = csrfFixture();

  await assert.rejects(
    () => issueCsrfTokenForSession(fixture.dependencies, {
      sessionId: "",
      now,
      ttlSeconds: 900,
      purpose: "browser_session",
    }),
    assertPrivacySafeError("invalid_session"),
  );
  assert.equal(fixture.calls.tokenFactory, 0);
  assert.equal(fixture.records.length, 0);
});

test("issue service calls injected secure token factory", async () => {
  const fixture = csrfFixture();

  const result = await issueCsrfTokenForSession(fixture.dependencies, issueInput());

  assert.equal(fixture.calls.tokenFactory, 1);
  assert.deepEqual(result, {
    csrfToken: rawToken,
    expiresAt: later,
  });
});

test("issue service stores only token hash and metadata, not raw token", async () => {
  const fixture = csrfFixture();

  const result = await issueCsrfTokenForSession(fixture.dependencies, issueInput());
  const stored = fixture.records[0];

  assert.equal(stored.id, "csrf_record_1");
  assert.equal(stored.sessionId, sessionId);
  assert.equal(stored.tokenHash, tokenHash);
  assert.equal(stored.purpose, "browser_session");
  assert.equal(stored.createdAt, now);
  assert.equal(stored.expiresAt, later);
  assert.equal(stored.consumedAt, null);
  assert.equal(stored.revokedAt, null);
  assert.equal(stored.csrfToken, undefined);
  assert.doesNotMatch(JSON.stringify(fixture.records), new RegExp(rawToken));
  assert.equal(result.csrfToken, rawToken);
  assert.equal("tokenHash" in result, false);
});

test("issue service handles token factory failure safely", async () => {
  const fixture = csrfFixture({ failTokenFactory: true });

  await assert.rejects(
    () => issueCsrfTokenForSession(fixture.dependencies, issueInput()),
    assertPrivacySafeError("token_factory_failed"),
  );
});

test("issue service handles hash failure safely", async () => {
  const fixture = csrfFixture({ failHash: true });

  await assert.rejects(
    () => issueCsrfTokenForSession(fixture.dependencies, issueInput()),
    assertPrivacySafeError("token_hash_failed"),
  );
});

test("issue service handles repository create failure safely", async () => {
  const fixture = csrfFixture({ failCreate: true });

  await assert.rejects(
    () => issueCsrfTokenForSession(fixture.dependencies, issueInput()),
    assertPrivacySafeError("token_store_failed"),
  );
});

test("issue service rejects invalid now and ttlSeconds safely", async () => {
  const invalidInputs = [
    { now: "not-a-date synthetic-csrf-token-reference", ttlSeconds: 900 },
    { now, ttlSeconds: 0 },
    { now, ttlSeconds: -1 },
    { now, ttlSeconds: Number.POSITIVE_INFINITY },
    { now, ttlSeconds: Number.NaN },
  ];

  for (const invalidInput of invalidInputs) {
    const fixture = csrfFixture();

    await assert.rejects(
      () => issueCsrfTokenForSession(fixture.dependencies, issueInput(invalidInput)),
      assertPrivacySafeError("invalid_expiry"),
    );
    assert.equal(fixture.records.length, 0);
  }
});

test("issue service handles id factory failure safely", async () => {
  const fixture = csrfFixture({ failId: true });

  await assert.rejects(
    () => issueCsrfTokenForSession(fixture.dependencies, issueInput()),
    assertPrivacySafeError("token_store_failed"),
  );
});

test("issue service rejects blank token and blank hash safely", async () => {
  const blankToken = csrfFixture({ blankToken: true });
  const blankHash = csrfFixture({ blankHash: true });

  await assert.rejects(
    () => issueCsrfTokenForSession(blankToken.dependencies, issueInput()),
    assertPrivacySafeError("token_factory_failed"),
  );
  await assert.rejects(
    () => issueCsrfTokenForSession(blankHash.dependencies, issueInput()),
    assertPrivacySafeError("token_hash_failed"),
  );
});

test("issuing token B preserves token A for the same session and purpose", async () => {
  const tokenB = "synthetic-csrf-token-reference-b";
  const records = [tokenRecord()];
  const fixture = csrfFixture({ records, issuedTokens: [tokenB] });
  const validator = createRepositoryBackedCsrfTokenValidator(fixture.dependencies);

  await issueCsrfTokenForSession(fixture.dependencies, issueInput());

  assert.equal(records.length, 2);
  assert.deepEqual(await validator.validate({ csrfToken: rawToken, sessionId, now }), { valid: true });
  assert.deepEqual(await validator.validate({ csrfToken: tokenB, sessionId, now }), { valid: true });
  assert.equal(fixture.calls.createBoundedForSession, 1);
});

test("bounded issuance evicts only the oldest token and keeps the newest tokens valid", async () => {
  const issuedTokens = Array.from({ length: maxActiveCsrfTokensPerSessionPurpose + 1 }, (_, index) =>
    "synthetic-csrf-token-" + (index + 1),
  );
  const fixture = csrfFixture({ issuedTokens });
  const validator = createRepositoryBackedCsrfTokenValidator(fixture.dependencies);

  for (let index = 0; index < issuedTokens.length; index += 1) {
    await issueCsrfTokenForSession(fixture.dependencies, issueInput({
      now: new Date(Date.parse(now) + index * 1000).toISOString(),
      ttlSeconds: 3600,
    }));
  }

  assert.equal(fixture.records.length, maxActiveCsrfTokensPerSessionPurpose);
  assert.deepEqual(
    await validator.validate({ csrfToken: issuedTokens[0], sessionId, now }),
    { valid: false, reason: "unknown_token" },
  );
  for (const newest of issuedTokens.slice(1)) {
    assert.deepEqual(await validator.validate({ csrfToken: newest, sessionId, now }), { valid: true });
  }
});

test("bounded issuance isolates sessions and future token purposes", async () => {
  const otherSessionRecords = Array.from({ length: maxActiveCsrfTokensPerSessionPurpose }, (_, index) =>
    tokenRecord({ id: "other-session-" + index, sessionId: otherSessionId, tokenHash: "other-" + index }),
  );
  const futurePurposeRecords = Array.from({ length: maxActiveCsrfTokensPerSessionPurpose }, (_, index) =>
    tokenRecord({ id: "future-purpose-" + index, purpose: "future_purpose", tokenHash: "future-" + index }),
  );
  const records = [...otherSessionRecords, ...futurePurposeRecords];
  const fixture = csrfFixture({ records, issuedTokens: ["synthetic-current-pair-token"] });

  await issueCsrfTokenForSession(fixture.dependencies, issueInput());

  assert.equal(records.filter((record) => record.sessionId === otherSessionId).length, maxActiveCsrfTokensPerSessionPurpose);
  assert.equal(records.filter((record) => record.purpose === "future_purpose").length, maxActiveCsrfTokensPerSessionPurpose);
  assert.equal(records.filter((record) => record.sessionId === sessionId && record.purpose === "browser_session").length, 1);
});

test("bounded issuance removes expired consumed and revoked rows for its pair", async () => {
  const records = [
    tokenRecord({ id: "expired", expiresAt: now }),
    tokenRecord({ id: "consumed", consumedAt: past }),
    tokenRecord({ id: "revoked", revokedAt: past }),
    tokenRecord({ id: "active", tokenHash: "active_hash" }),
  ];
  const fixture = csrfFixture({ records, issuedTokens: ["synthetic-cleanup-token"] });

  await issueCsrfTokenForSession(fixture.dependencies, issueInput());

  assert.deepEqual(records.map((record) => record.id).sort(), ["active", "csrf_record_5"]);
});

test("concurrent issuance remains bounded", async () => {
  const issuanceCount = maxActiveCsrfTokensPerSessionPurpose * 3;
  const issuedTokens = Array.from({ length: issuanceCount }, (_, index) => "synthetic-concurrent-" + index);
  const fixture = csrfFixture({ issuedTokens });

  await Promise.all(issuedTokens.map((_, index) => issueCsrfTokenForSession(
    fixture.dependencies,
    issueInput({ now: new Date(Date.parse(now) + index).toISOString(), ttlSeconds: 3600 }),
  )));

  assert.equal(fixture.records.length, maxActiveCsrfTokensPerSessionPurpose);
  assert.equal(new Set(fixture.records.map((record) => record.id)).size, maxActiveCsrfTokensPerSessionPurpose);
});

test("repository-backed validator accepts valid token for same session", async () => {
  const fixture = csrfFixture({
    records: [tokenRecord()],
  });
  const validator = createRepositoryBackedCsrfTokenValidator(fixture.dependencies);

  const result = await validator.validate({
    csrfToken: rawToken,
    sessionId,
    now,
  });

  assert.deepEqual(result, { valid: true });
  assert.deepEqual(fixture.calls.findActiveBySessionAndTokenHash, [
    { sessionId, tokenHash, purpose: "browser_session" },
  ]);
});

test("validator denies missing sessionId", async () => {
  const fixture = csrfFixture({
    records: [tokenRecord()],
  });
  const validator = createRepositoryBackedCsrfTokenValidator(fixture.dependencies);

  const result = await validator.validate({
    csrfToken: rawToken,
    sessionId: null,
    now,
  });

  assert.deepEqual(result, {
    valid: false,
    reason: "missing_session",
  });
  assert.equal(fixture.calls.hash, 0);
});

test("validator denies unknown token", async () => {
  const fixture = csrfFixture();
  const validator = createRepositoryBackedCsrfTokenValidator(fixture.dependencies);

  const result = await validator.validate({
    csrfToken: rawToken,
    sessionId,
    now,
  });

  assert.deepEqual(result, {
    valid: false,
    reason: "unknown_token",
  });
});

test("validator denies wrong session", async () => {
  const fixture = csrfFixture({
    records: [tokenRecord({ sessionId: otherSessionId })],
  });
  const validator = createRepositoryBackedCsrfTokenValidator(fixture.dependencies);

  const result = await validator.validate({
    csrfToken: rawToken,
    sessionId,
    now,
  });

  assert.deepEqual(result, {
    valid: false,
    reason: "unknown_token",
  });
});

test("validator denies expired token", async () => {
  const fixture = csrfFixture({
    records: [tokenRecord({ expiresAt: past })],
  });
  const validator = createRepositoryBackedCsrfTokenValidator(fixture.dependencies);

  const result = await validator.validate({
    csrfToken: rawToken,
    sessionId,
    now,
  });

  assert.deepEqual(result, {
    valid: false,
    reason: "expired_token",
  });
});

test("validator denies consumed token", async () => {
  const fixture = csrfFixture({
    records: [tokenRecord({ consumedAt: now })],
  });
  const validator = createRepositoryBackedCsrfTokenValidator(fixture.dependencies);

  const result = await validator.validate({
    csrfToken: rawToken,
    sessionId,
    now,
  });

  assert.deepEqual(result, {
    valid: false,
    reason: "inactive_token",
  });
});

test("validator denies revoked token", async () => {
  const fixture = csrfFixture({
    records: [tokenRecord({ revokedAt: now })],
  });
  const validator = createRepositoryBackedCsrfTokenValidator(fixture.dependencies);

  const result = await validator.validate({
    csrfToken: rawToken,
    sessionId,
    now,
  });

  assert.deepEqual(result, {
    valid: false,
    reason: "inactive_token",
  });
});

test("validator handles hash failure safely", async () => {
  const fixture = csrfFixture({ failHash: true });
  const validator = createRepositoryBackedCsrfTokenValidator(fixture.dependencies);

  const result = await validator.validate({
    csrfToken: rawToken,
    sessionId,
    now,
  });

  assert.deepEqual(result, {
    valid: false,
    reason: "validation_failed",
  });
  assertPrivacySafeSerialized(result);
});

test("validator handles repository failure safely", async () => {
  const fixture = csrfFixture({ failLookup: true });
  const validator = createRepositoryBackedCsrfTokenValidator(fixture.dependencies);

  const result = await validator.validate({
    csrfToken: rawToken,
    sessionId,
    now,
  });

  assert.deepEqual(result, {
    valid: false,
    reason: "validation_failed",
  });
  assertPrivacySafeSerialized(result);
});

test("validator never returns raw token hash or storage errors", async () => {
  const fixture = csrfFixture({ failLookup: true });
  const validator = createRepositoryBackedCsrfTokenValidator(fixture.dependencies);

  const result = await validator.validate({
    csrfToken: rawToken,
    sessionId,
    now,
  });

  assertPrivacySafeSerialized(result);
});

test("CSRF lifecycle modules do not import frontend SQAG provider SDK framework live DB or migrations", async () => {
  const files = [
    "src/http/csrf-token-repositories.ts",
    "src/http/csrf-token-service.ts",
  ];

  for (const filePath of files) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:sqag|clerk|auth0|supabase)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?)/i);
    assert.doesNotMatch(contents, /src\/db|\.{1,2}\/db|\.{1,2}\/\.{1,2}\/db/i);
  }
});

test("CSRF lifecycle modules do not use Math.random or weak token generation", async () => {
  const files = [
    "src/http/csrf-token-repositories.ts",
    "src/http/csrf-token-service.ts",
    "src/http/handlers.ts",
    "src/http/node-adapter.ts",
    "src/http/route-contracts.ts",
  ];

  for (const filePath of files) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /Math\.random|randomUUID|createHash|createHmac|from\s+["'](?:node:)?crypto["']/i);
  }
});

function issueInput(overrides = {}) {
  return {
    sessionId,
    now,
    ttlSeconds: 900,
    purpose: "browser_session",
    ...overrides,
  };
}

function tokenRecord(overrides = {}) {
  return {
    id: "csrf_record_existing",
    sessionId,
    tokenHash,
    purpose: "browser_session",
    createdAt: past,
    expiresAt: later,
    consumedAt: null,
    revokedAt: null,
    replacedByTokenId: null,
    ...overrides,
  };
}

function csrfFixture(options = {}) {
  const records = options.records ?? [];
  let nextId = records.length;
  const calls = {
    tokenFactory: 0,
    hash: 0,
    createBoundedForSession: 0,
    findActiveBySessionAndTokenHash: [],
  };
  const dependencies = {
    tokenFactory: {
      async createToken() {
        calls.tokenFactory += 1;
        if (options.failTokenFactory) {
          throw new Error(privateFailure);
        }

        if (options.blankToken) {
          return "   ";
        }

        return options.issuedTokens?.[calls.tokenFactory - 1] ?? rawToken;
      },
    },
    tokenHasher: {
      async hashToken(token) {
        calls.hash += 1;
        if (options.failHash) {
          throw new Error(privateFailure);
        }

        if (options.blankHash) {
          return "   ";
        }

        return token === rawToken ? tokenHash : `hash_${token}`;
      },
    },
    idFactory: {
      createId() {
        if (options.failId) {
          throw new Error(privateFailure);
        }

        nextId += 1;
        return `csrf_record_${nextId}`;
      },
    },
    tokens: {
      async createBoundedForSession(record) {
        calls.createBoundedForSession += 1;
        if (options.failCreate) {
          throw new Error(privateFailure);
        }

        const nowMs = Date.parse(record.createdAt);
        for (let index = records.length - 1; index >= 0; index -= 1) {
          const candidate = records[index];
          if (
            candidate.sessionId === record.sessionId &&
            candidate.purpose === record.purpose &&
            (Date.parse(candidate.expiresAt) <= nowMs || candidate.consumedAt || candidate.revokedAt)
          ) {
            records.splice(index, 1);
          }
        }

        const activeForPair = records
          .filter((candidate) => candidate.sessionId === record.sessionId && candidate.purpose === record.purpose)
          .sort((left, right) => Date.parse(right.createdAt) - Date.parse(left.createdAt) || right.id.localeCompare(left.id));
        for (const evicted of activeForPair.slice(maxActiveCsrfTokensPerSessionPurpose - 1)) {
          records.splice(records.indexOf(evicted), 1);
        }

        records.push(record);
        return record;
      },
      async findBySessionAndTokenHash(sessionIdInput, tokenHashInput, purpose) {
        calls.findActiveBySessionAndTokenHash.push({
          sessionId: sessionIdInput,
          tokenHash: tokenHashInput,
          purpose,
        });
        if (options.failLookup) {
          throw new Error(privateFailure);
        }

        return records.find(
          (record) =>
            record.sessionId === sessionIdInput &&
            record.tokenHash === tokenHashInput &&
            record.purpose === purpose,
        ) ?? null;
      },
    },
  };

  return {
    calls,
    records,
    dependencies,
  };
}

function assertPrivacySafeError(expectedCode) {
  return (error) => {
    assert.equal(error instanceof CsrfTokenServiceError, true);
    assert.equal(error.code, expectedCode);
    assert.equal(error.publicMessage, "CSRF token operation could not be completed.");
    assertPrivacySafeSerialized(error);
    return true;
  };
}

function assertPrivacySafeSerialized(value) {
  const serialized = JSON.stringify(value) + String(value.message ?? "");

  assert.doesNotMatch(serialized, new RegExp(rawToken));
  assert.doesNotMatch(serialized, new RegExp(tokenHash));
  assert.doesNotMatch(serialized, /postgresql:\/\/private-host|storage exploded/i);
  assert.doesNotMatch(serialized, /session-secret|csrf-secret|provider-token|auth-code/i);
}

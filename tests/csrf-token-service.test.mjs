import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  CsrfTokenServiceError,
  createRepositoryBackedCsrfTokenValidator,
  issueCsrfTokenForSession,
} from "../dist/index.js";

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

test("CSRF lifecycle modules do not import frontend KQAG provider SDK framework live DB or migrations", async () => {
  const files = [
    "src/http/csrf-token-repositories.ts",
    "src/http/csrf-token-service.ts",
  ];

  for (const filePath of files) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:kqag|clerk|auth0|supabase)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?)/i);
    assert.doesNotMatch(contents, /src\/db|\.{1,2}\/db|\.{1,2}\/\.{1,2}\/db/i);
  }
});

test("CSRF lifecycle modules do not use Math.random or weak token generation", async () => {
  const files = [
    "src/http/csrf-token-repositories.ts",
    "src/http/csrf-token-service.ts",
  ];

  for (const filePath of files) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /Math\.random|randomUUID|createHash|createHmac|crypto/i);
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
  const calls = {
    tokenFactory: 0,
    hash: 0,
    create: 0,
    findActiveBySessionAndTokenHash: [],
  };
  const dependencies = {
    tokenFactory: {
      async createToken() {
        calls.tokenFactory += 1;
        if (options.failTokenFactory) {
          throw new Error(privateFailure);
        }

        return rawToken;
      },
    },
    tokenHasher: {
      async hashToken(token) {
        calls.hash += 1;
        if (options.failHash) {
          throw new Error(privateFailure);
        }

        assert.equal(token, rawToken);
        return tokenHash;
      },
    },
    idFactory: {
      createId() {
        return `csrf_record_${records.length + 1}`;
      },
    },
    tokens: {
      async create(record) {
        calls.create += 1;
        if (options.failCreate) {
          throw new Error(privateFailure);
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

import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  formatAuthCallbackFailureDiagnostic,
  handleAuthCallbackRequest,
  handleAuthStartRequest,
} from "../dist/index.js";
import { AuthProviderError, readAuthConfig } from "../dist/auth/index.js";

const now = "2026-06-27T00:00:00.000Z";
const future = "2026-06-27T00:10:00.000Z";
const rawState = "synthetic-browser-state-reference";
const rawNonce = "synthetic-browser-nonce-reference";
const stateHash = "hash_synthetic_browser_state_reference";
const nonceHash = "hash_synthetic_browser_nonce_reference";
const providerAuthorizationUrl =
  "https://auth.example.invalid/oauth2/authorize?request=synthetic-authorization";
const sessionId = "session_auth_callback_1";
const privateFailure =
  "database exploded synthetic-auth-code synthetic-browser-state-reference synthetic-client-secret-value postgresql://private-host";

const authConfig = readAuthConfig({
  AUTH_PROVIDER_KEY: "Example-OIDC",
  AUTH_AUTHORIZATION_URL: "https://auth.example.invalid/oauth2/authorize",
  AUTH_TOKEN_URL: "https://auth.example.invalid/oauth2/token",
  AUTH_CLIENT_ID: "synthetic-client-id",
  AUTH_CLIENT_SECRET: "synthetic-client-secret-value",
  AUTH_REDIRECT_URI: "https://platform.example.invalid/api/platform/auth/callback",
  SESSION_SECRET: "synthetic-session-secret-value-32",
});

test("auth start returns provider redirect and stores only hashed state and nonce", async () => {
  const fixture = createAuthStartFixture();

  const response = await handleAuthStartRequest(fixture.dependencies, { now });

  assert.equal(response.status, 302);
  assert.equal(response.headers.location, providerAuthorizationUrl);
  assert.deepEqual(response.body, { outcome: "redirecting" });
  assert.equal(fixture.records.states.length, 1);
  assert.deepEqual(fixture.records.states[0], {
    providerKey: "example-oidc",
    stateHash,
    nonceHash,
    redirectUri: "https://platform.example.invalid/api/platform/auth/callback",
    createdAt: now,
    expiresAt: future,
  });
  assert.equal(fixture.oidcAuthorizationInputs[0].state, rawState);
  assert.equal(fixture.oidcAuthorizationInputs[0].nonce, rawNonce);
  assert.doesNotMatch(JSON.stringify(fixture.records.states), /synthetic-browser-state-reference/);
  assert.doesNotMatch(JSON.stringify(fixture.records.states), /synthetic-browser-nonce-reference/);
  assertHttpAuthResponseIsSafe(response);
});

test("auth start errors are privacy-safe", async () => {
  for (const failure of ["stateFactory", "nonceFactory", "stateStore", "oidcAdapter"]) {
    const fixture = createAuthStartFixture({ fail: failure });

    const response = await handleAuthStartRequest(fixture.dependencies, { now });

    assert.equal(response.status, 500);
    assert.deepEqual(response.body, {
      outcome: "error",
      message: "Authentication start could not be completed.",
    });
    assertHttpAuthResponseIsSafe(response);
  }
});

test("auth callback missing code or state is privacy-safe", async () => {
  const diagnostics = [];
  const missingCode = await handleAuthCallbackRequest(
    createAuthCallbackFixture({
      callbackFailureReporter(diagnostic) {
        diagnostics.push(diagnostic);
      },
    }).dependencies,
    {
      query: { state: "synthetic-browser-state-reference" },
      now,
      cookie: { secure: true },
    },
  );
  const missingState = await handleAuthCallbackRequest(
    createAuthCallbackFixture({
      callbackFailureReporter(diagnostic) {
        diagnostics.push(diagnostic);
      },
    }).dependencies,
    {
      query: { code: "synthetic-auth-code" },
      now,
      cookie: { secure: true },
    },
  );

  assert.equal(missingCode.status, 400);
  assert.equal(missingState.status, 400);
  assert.deepEqual(missingCode.body, {
    outcome: "error",
    message: "Authentication callback could not be completed.",
  });
  assert.deepEqual(missingState.body, missingCode.body);
  assert.deepEqual(diagnostics, [
    { category: "missing_code" },
    { category: "missing_state" },
  ]);
  assertHttpAuthResponseIsSafe(missingCode);
  assertHttpAuthResponseIsSafe(missingState);
});

test("auth callback success sets browser session cookie without exposing session id in body", async () => {
  const fixture = createAuthCallbackFixture();

  const response = await handleAuthCallbackRequest(fixture.dependencies, {
    query: { code: "synthetic-auth-code", state: rawState },
    now,
    cookie: { secure: true },
  });

  assert.equal(response.status, 302);
  assert.equal(response.headers.location, "/app");
  assert.match(response.headers["set-cookie"], /^swooshz_session=session_auth_callback_1;/);
  assert.match(response.headers["set-cookie"], /HttpOnly/);
  assert.match(response.headers["set-cookie"], /SameSite=Lax/);
  assert.match(response.headers["set-cookie"], /Secure/);
  assert.deepEqual(response.body, { outcome: "authenticated" });
  assert.equal(fixture.stateStore.consumedInputs[0].stateHash, stateHash);
  assert.equal(fixture.oidcAdapter.exchangedInputs[0].code, "synthetic-auth-code");
  assert.doesNotMatch(JSON.stringify(response.body), new RegExp(sessionId));
  assertHttpAuthResponseIsSafe(response);
});

test("auth callback failure does not expose provider or callback details", async () => {
  const diagnostics = [];
  const fixture = createAuthCallbackFixture({
    providerFails: true,
    callbackFailureReporter(diagnostic) {
      diagnostics.push(diagnostic);
    },
  });

  const response = await handleAuthCallbackRequest(fixture.dependencies, {
    query: {
      error: "access_denied",
      error_description: privateFailure,
      code: "synthetic-auth-code",
      state: rawState,
    },
    now,
    cookie: { secure: true },
  });

  assert.equal(response.status, 400);
  assert.deepEqual(response.body, {
    outcome: "error",
    message: "Authentication callback could not be completed.",
  });
  assert.equal(response.headers?.["set-cookie"], undefined);
  assert.deepEqual(diagnostics, [{ category: "provider_error" }]);
  assertHttpAuthResponseIsSafe(response);
  assertHttpAuthDiagnosticIsSafe(diagnostics);
});

test("auth callback provider diagnostics report only a stable safe category", async () => {
  const diagnostics = [];
  const fixture = createAuthCallbackFixture({
    exchangeError: new AuthProviderError(
      "provider_verification_failed",
      "OIDC token exchange failed.",
    ),
    callbackFailureReporter(diagnostic) {
      diagnostics.push(diagnostic);
    },
  });

  const response = await handleAuthCallbackRequest(fixture.dependencies, {
    query: {
      code: "synthetic-auth-code",
      state: rawState,
    },
    now,
    cookie: { secure: true },
  });

  assert.equal(response.status, 400);
  assert.deepEqual(response.body, {
    outcome: "error",
    message: "Authentication callback could not be completed.",
  });
  assert.deepEqual(diagnostics, [{ category: "token_exchange_failed" }]);
  assert.equal(
    formatAuthCallbackFailureDiagnostic(diagnostics[0]),
    "auth_callback_failure category=token_exchange_failed",
  );
  assertHttpAuthResponseIsSafe(response);
  assertHttpAuthDiagnosticIsSafe(diagnostics);
});

test("auth HTTP handler modules do not import DB frontend KQAG provider SDK or HTTP frameworks", async () => {
  const httpFiles = ["src/http/auth-handlers.ts"];

  for (const filePath of httpFiles) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?|kqag)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono|node:http)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:clerk|auth0|supabase)/i);
    assert.doesNotMatch(contents, /fetch\(|XMLHttpRequest|https?:\/\//i);
  }
});

test("pure domain modules do not import auth HTTP handlers", async () => {
  const pureDomainFiles = [
    "src/accounts/types.ts",
    "src/accounts/normalization.ts",
    "src/apps/types.ts",
    "src/access/decide-app-access.ts",
  ];

  for (const filePath of pureDomainFiles) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /auth-handlers|src\/http|\.{1,2}\/http/);
  }
});

function createAuthStartFixture(options = {}) {
  const records = { states: [] };
  const oidcAuthorizationInputs = [];
  const dependencies = {
    authConfig,
    oidcAdapter: {
      async buildAuthorizationUrl(input) {
        if (options.fail === "oidcAdapter") {
          throw new Error(privateFailure);
        }

        oidcAuthorizationInputs.push(input);
        return { url: providerAuthorizationUrl };
      },
    },
    stateStore: {
      async storeState(record) {
        if (options.fail === "stateStore") {
          throw new Error(privateFailure);
        }

        records.states.push(record);
        return record;
      },
    },
    stateFactory: {
      createState() {
        if (options.fail === "stateFactory") {
          throw new Error(privateFailure);
        }

        return rawState;
      },
    },
    nonceFactory: {
      createNonce() {
        if (options.fail === "nonceFactory") {
          throw new Error(privateFailure);
        }

        return rawNonce;
      },
    },
    stateReferenceFactory(value) {
      if (value === rawState) {
        return stateHash;
      }

      if (value === rawNonce) {
        return nonceHash;
      }

      throw new Error(privateFailure);
    },
    ttlSeconds: 600,
  };

  return { dependencies, records, oidcAuthorizationInputs };
}

function createAuthCallbackFixture(options = {}) {
  const stateStore = {
    consumedInputs: [],
    async consumeState(input) {
      this.consumedInputs.push(input);
      return {
        providerKey: "example-oidc",
        stateHash,
        nonceHash,
        redirectUri: "https://platform.example.invalid/api/platform/auth/callback",
        createdAt: now,
        expiresAt: future,
      };
    },
  };
  const oidcAdapter = {
    exchangedInputs: [],
    async buildAuthorizationUrl() {
      throw new Error("Not used by callback handler tests.");
    },
    async exchangeCodeForTokens(input) {
      if (options.exchangeError) {
        throw options.exchangeError;
      }

      if (options.providerFails) {
        throw new Error(privateFailure);
      }

      this.exchangedInputs.push(input);
      return {
        providerKey: input.providerKey,
        receivedAt: input.now,
        tokenSetRef: "adapter_internal",
      };
    },
    async verifyTokens() {
      return {
        providerKey: "example-oidc",
        providerSubject: "provider-subject-123",
        verifiedEmail: "owner@example.com",
        displayName: "Synthetic Owner",
        metadata: { emailVerified: true },
      };
    },
  };
  const platformIdentityResolver = {
    async resolveAuthenticatedIdentity(input) {
      return {
        platformUserId: "user_owner",
        providerIdentityId: "provider_identity_1",
        session: {
          id: sessionId,
          userId: "user_owner",
          createdAt: input.now,
          expiresAt: future,
          lastSeenAt: input.now,
          revokedAt: null,
        },
      };
    },
  };

  return {
    stateStore,
    oidcAdapter,
    dependencies: {
      authConfig,
      oidcAdapter,
      platformIdentityResolver,
      callbackFailureReporter: options.callbackFailureReporter,
      stateReferenceFactory(value) {
        assert.equal(value, rawState);
        return stateHash;
      },
      stateStore,
    },
  };
}

function assertHttpAuthResponseIsSafe(response) {
  const body = JSON.stringify(response.body ?? {});
  const headersWithoutLocation = { ...(response.headers ?? {}) };
  delete headersWithoutLocation.location;
  const serialized = `${body} ${JSON.stringify(headersWithoutLocation)}`;

  assert.doesNotMatch(serialized, /synthetic-auth-code/);
  assert.doesNotMatch(serialized, /synthetic-browser-state-reference/);
  assert.doesNotMatch(serialized, /synthetic-browser-nonce-reference/);
  assert.doesNotMatch(serialized, /hash_synthetic_browser_state_reference/);
  assert.doesNotMatch(serialized, /hash_synthetic_browser_nonce_reference/);
  assert.doesNotMatch(serialized, /synthetic-client-secret|synthetic-session-secret/i);
  assert.doesNotMatch(serialized, /access-token|refresh-token|id-token|provider-token/i);
  assert.doesNotMatch(serialized, /raw-claim|rawProviderResponse|claims/i);
  assert.doesNotMatch(serialized, /postgresql:\/\/private-host|database exploded|select \*/i);
}

function assertHttpAuthDiagnosticIsSafe(diagnostics) {
  const serialized = JSON.stringify(diagnostics);

  assert.doesNotMatch(serialized, /synthetic-auth-code/);
  assert.doesNotMatch(serialized, /synthetic-browser-state-reference/);
  assert.doesNotMatch(serialized, /synthetic-browser-nonce-reference/);
  assert.doesNotMatch(serialized, /hash_synthetic_browser_state_reference/);
  assert.doesNotMatch(serialized, /hash_synthetic_browser_nonce_reference/);
  assert.doesNotMatch(serialized, /synthetic-client-secret|synthetic-session-secret/i);
  assert.doesNotMatch(serialized, /access-token|refresh-token|id-token|provider-token/i);
  assert.doesNotMatch(serialized, /raw-claim|rawProviderResponse|claims/i);
  assert.doesNotMatch(serialized, /postgresql:\/\/private-host|database exploded|select \*/i);
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

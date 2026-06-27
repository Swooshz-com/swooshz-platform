import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  AuthCallbackError,
  handleAuthCallback,
  readAuthConfig,
} from "../dist/auth/index.js";
import { decideAppAccess } from "../dist/index.js";

const now = "2026-06-27T00:00:00.000Z";
const future = "2026-06-27T00:10:00.000Z";
const past = "2026-06-26T23:59:00.000Z";

const baseEnv = {
  AUTH_PROVIDER_KEY: "Example-OIDC",
  AUTH_AUTHORIZATION_URL: "https://auth.example.invalid/oauth2/authorize",
  AUTH_TOKEN_URL: "https://auth.example.invalid/oauth2/token",
  AUTH_CLIENT_ID: "synthetic-client-id",
  AUTH_CLIENT_SECRET: "synthetic-client-secret-value",
  AUTH_REDIRECT_URI: "https://platform.example.invalid/auth/callback",
  SESSION_SECRET: "synthetic-session-secret-value-32",
};

test("successful callback returns safe platform auth result", async () => {
  const deps = createServiceDependencies();

  const result = await handleAuthCallback(deps, {
    params: { code: "synthetic-auth-code", state: "synthetic-state" },
    now,
  });

  assert.equal(result.outcome, "authenticated");
  assert.equal(result.platformUserId, "user_owner");
  assert.deepEqual(result.providerIdentity, {
    id: "provider_identity_1",
    providerKey: "example-oidc",
    providerSubject: "provider-subject-123",
  });
  assert.deepEqual(result.session, {
    id: "session_auth_callback_1",
    userId: "user_owner",
    createdAt: now,
    expiresAt: future,
    lastSeenAt: now,
    revokedAt: null,
  });
  assert.equal(result.verifiedEmail, "owner@example.com");
  assert.equal(result.displayName, "Synthetic Owner");
  assert.equal(result.workspaceMembershipGranted, false);
  assert.equal(result.appAccessGranted, false);

  assert.equal(deps.oidcAdapter.exchangedInputs[0].code, "synthetic-auth-code");
  assertServiceResultIsSafe(result);
});

test("missing code is rejected privacy-safely", async () => {
  const deps = createServiceDependencies();

  await assert.rejects(
    () =>
      handleAuthCallback(deps, {
        params: { state: "do-not-leak-state" },
        now,
      }),
    (error) => {
      assert.equal(error instanceof AuthCallbackError, true);
      assert.equal(error.code, "missing_code");
      assert.doesNotMatch(error.message, /do-not-leak/);
      return true;
    },
  );
});

test("missing state is rejected privacy-safely", async () => {
  const deps = createServiceDependencies();

  await assert.rejects(
    () =>
      handleAuthCallback(deps, {
        params: { code: "do-not-leak-code" },
        now,
      }),
    (error) => {
      assert.equal(error instanceof AuthCallbackError, true);
      assert.equal(error.code, "missing_state");
      assert.doesNotMatch(error.message, /do-not-leak/);
      return true;
    },
  );
});

test("provider error callback is rejected without leaking provider description", async () => {
  const deps = createServiceDependencies();

  await assert.rejects(
    () =>
      handleAuthCallback(deps, {
        params: {
          error: "access_denied",
          error_description: "do-not-leak-provider-description",
          code: "do-not-leak-code",
          state: "do-not-leak-state",
        },
        now,
      }),
    (error) => {
      assert.equal(error instanceof AuthCallbackError, true);
      assert.equal(error.code, "provider_error");
      assert.doesNotMatch(error.message, /do-not-leak/);
      return true;
    },
  );
});

test("missing stored state is rejected privacy-safely", async () => {
  const deps = createServiceDependencies({ storedState: null });

  await assert.rejects(
    () =>
      handleAuthCallback(deps, {
        params: { code: "do-not-leak-code", state: "do-not-leak-state" },
        now,
      }),
    (error) => {
      assert.equal(error instanceof AuthCallbackError, true);
      assert.equal(error.code, "missing_stored_state");
      assert.doesNotMatch(error.message, /do-not-leak/);
      return true;
    },
  );
});

test("expired stored state is rejected", async () => {
  const deps = createServiceDependencies({
    storedState: createStoredState({ expiresAt: past }),
  });

  await assert.rejects(
    () =>
      handleAuthCallback(deps, {
        params: { code: "synthetic-auth-code", state: "synthetic-state" },
        now,
      }),
    (error) => {
      assert.equal(error instanceof AuthCallbackError, true);
      assert.equal(error.code, "expired_state");
      return true;
    },
  );
});

test("state lookup uses only hash reference, not raw state", async () => {
  const deps = createServiceDependencies();

  await handleAuthCallback(deps, {
    params: { code: "synthetic-auth-code", state: "synthetic-state" },
    now,
  });

  assert.deepEqual(deps.stateReferences, ["synthetic-state"]);
  assert.deepEqual(deps.stateStore.consumedInputs, [
    {
      providerKey: "example-oidc",
      stateHash: "hash:synthetic-state",
      now,
    },
  ]);
  assert.equal(Object.hasOwn(deps.stateStore.consumedInputs[0], "state"), false);
});

test("fake adapter receives auth code internally but service result does not include it", async () => {
  const deps = createServiceDependencies();

  const result = await handleAuthCallback(deps, {
    params: { code: "synthetic-auth-code", state: "synthetic-state" },
    now,
  });

  assert.equal(deps.oidcAdapter.exchangedInputs[0].code, "synthetic-auth-code");
  assert.doesNotMatch(JSON.stringify(result), /synthetic-auth-code/);
});

test("fake adapter verified identity normalizes provider key and email", async () => {
  const deps = createServiceDependencies({
    verifiedIdentity: {
      providerKey: "Example-OIDC",
      providerSubject: "provider-subject-123",
      verifiedEmail: "OWNER@Example.COM",
      displayName: " Synthetic Owner ",
      metadata: { emailVerified: true },
    },
  });

  const result = await handleAuthCallback(deps, {
    params: { code: "synthetic-auth-code", state: "synthetic-state" },
    now,
  });

  assert.equal(result.providerIdentity.providerKey, "example-oidc");
  assert.equal(result.verifiedEmail, "owner@example.com");
  assert.equal(result.displayName, "Synthetic Owner");
});

test("raw tokens claims and provider responses are never present in service result", async () => {
  const deps = createServiceDependencies({
    includeUnsafeAdapterFields: true,
  });

  const result = await handleAuthCallback(deps, {
    params: { code: "synthetic-auth-code", state: "synthetic-state" },
    now,
  });

  assertServiceResultIsSafe(result);
});

test("allowlisted email passes", async () => {
  const deps = createServiceDependencies({
    authConfig: readAuthConfig({
      ...baseEnv,
      AUTH_ALLOWED_EMAILS: "owner@example.com",
    }),
  });

  const result = await handleAuthCallback(deps, {
    params: { code: "synthetic-auth-code", state: "synthetic-state" },
    now,
  });

  assert.equal(result.outcome, "authenticated");
  assert.equal(result.verifiedEmail, "owner@example.com");
});

test("non-allowlisted email fails", async () => {
  const deps = createServiceDependencies({
    authConfig: readAuthConfig({
      ...baseEnv,
      AUTH_ALLOWED_EMAILS: "other@example.com",
    }),
  });

  await assert.rejects(
    () =>
      handleAuthCallback(deps, {
        params: { code: "synthetic-auth-code", state: "synthetic-state" },
        now,
      }),
    (error) => {
      assert.equal(error instanceof AuthCallbackError, true);
      assert.equal(error.code, "email_not_allowed");
      assert.doesNotMatch(error.message, /owner@example.com|other@example.com/);
      return true;
    },
  );
});

test("allowlisted domain passes", async () => {
  const deps = createServiceDependencies({
    authConfig: readAuthConfig({
      ...baseEnv,
      AUTH_ALLOWED_DOMAINS: "example.com",
    }),
  });

  const result = await handleAuthCallback(deps, {
    params: { code: "synthetic-auth-code", state: "synthetic-state" },
    now,
  });

  assert.equal(result.outcome, "authenticated");
});

test("non-allowlisted domain fails", async () => {
  const deps = createServiceDependencies({
    authConfig: readAuthConfig({
      ...baseEnv,
      AUTH_ALLOWED_DOMAINS: "team.example.com",
    }),
  });

  await assert.rejects(
    () =>
      handleAuthCallback(deps, {
        params: { code: "synthetic-auth-code", state: "synthetic-state" },
        now,
      }),
    (error) => {
      assert.equal(error instanceof AuthCallbackError, true);
      assert.equal(error.code, "domain_not_allowed");
      assert.doesNotMatch(error.message, /owner@example.com|team.example.com/);
      return true;
    },
  );
});

test("verified email is required when allowlist is configured", async () => {
  const deps = createServiceDependencies({
    authConfig: readAuthConfig({
      ...baseEnv,
      AUTH_ALLOWED_DOMAINS: "example.com",
    }),
    verifiedIdentity: {
      providerKey: "example-oidc",
      providerSubject: "provider-subject-123",
      verifiedEmail: null,
      displayName: "Synthetic Owner",
      metadata: {},
    },
  });

  await assert.rejects(
    () =>
      handleAuthCallback(deps, {
        params: { code: "synthetic-auth-code", state: "synthetic-state" },
        now,
      }),
    (error) => {
      assert.equal(error instanceof AuthCallbackError, true);
      assert.equal(error.code, "verified_email_required");
      return true;
    },
  );
});

test("email allowlist passing does not grant app access or workspace membership automatically", async () => {
  const deps = createServiceDependencies({
    authConfig: readAuthConfig({
      ...baseEnv,
      AUTH_ALLOWED_EMAILS: "owner@example.com",
    }),
  });

  const result = await handleAuthCallback(deps, {
    params: { code: "synthetic-auth-code", state: "synthetic-state" },
    now,
  });

  assert.equal(result.workspaceMembershipGranted, false);
  assert.equal(result.appAccessGranted, false);
  assert.equal(Object.hasOwn(result, "workspaceId"), false);
  assert.equal(Object.hasOwn(result, "appKey"), false);
  assert.equal(Object.hasOwn(result, "role"), false);
});

test("existing app-access decision service remains separate", () => {
  const decision = decideAppAccess({
    now,
    session: null,
    user: null,
    selectedWorkspaceId: "workspace_koncept",
    workspaces: [],
    memberships: [],
    apps: [],
    entitlements: [],
    appKey: "kqag",
  });

  assert.equal(decision.result, "not_authenticated");
});

test("auth modules do not import DB, KQAG, frontend, or HTTP framework details", async () => {
  const authFiles = await listFiles("src/auth");

  for (const filePath of authFiles) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?|kqag)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono|node:http)/i);
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

function createServiceDependencies(options = {}) {
  const stateReferences = [];
  const authConfig = options.authConfig ?? readAuthConfig(baseEnv);
  const storedState =
    options.storedState === undefined ? createStoredState() : options.storedState;
  const verifiedIdentity =
    options.verifiedIdentity ?? {
      providerKey: "example-oidc",
      providerSubject: "provider-subject-123",
      verifiedEmail: "owner@example.com",
      displayName: "Synthetic Owner",
      metadata: { emailVerified: true },
    };
  const stateStore = {
    consumedInputs: [],
    async consumeState(input) {
      this.consumedInputs.push(input);
      return storedState;
    },
  };
  const oidcAdapter = {
    exchangedInputs: [],
    verifiedInputs: [],
    async buildAuthorizationUrl() {
      throw new Error("Not used by callback service tests.");
    },
    async exchangeCodeForTokens(input) {
      this.exchangedInputs.push(input);
      return {
        providerKey: input.providerKey,
        receivedAt: input.now,
        tokenSetRef: "adapter_internal",
        ...(options.includeUnsafeAdapterFields
          ? {
              accessToken: "do-not-leak-access-token",
              refreshToken: "do-not-leak-refresh-token",
              idToken: "do-not-leak-id-token",
              rawProviderResponse: { unsafe: true },
            }
          : {}),
      };
    },
    async verifyTokens(input) {
      this.verifiedInputs.push(input);
      return {
        ...verifiedIdentity,
        ...(options.includeUnsafeAdapterFields
          ? {
              rawClaims: { unsafe: true },
              claims: { unsafe: true },
              accessToken: "do-not-leak-access-token",
            }
          : {}),
      };
    },
  };
  const platformIdentityResolver = {
    resolvedInputs: [],
    async resolveAuthenticatedIdentity(input) {
      this.resolvedInputs.push(input);
      return {
        platformUserId: "user_owner",
        providerIdentityId: "provider_identity_1",
        session: {
          id: "session_auth_callback_1",
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
    authConfig,
    oidcAdapter,
    platformIdentityResolver,
    stateReferences,
    stateReferenceFactory(state) {
      stateReferences.push(state);
      return `hash:${state}`;
    },
    stateStore,
  };
}

function createStoredState(overrides = {}) {
  return {
    providerKey: "example-oidc",
    stateHash: "hash:synthetic-state",
    nonceHash: "hash:synthetic-nonce",
    redirectUri: "https://platform.example.invalid/auth/callback",
    createdAt: now,
    expiresAt: future,
    ...overrides,
  };
}

function assertServiceResultIsSafe(result) {
  const serialized = JSON.stringify(result);

  assert.doesNotMatch(serialized, /synthetic-auth-code/);
  assert.doesNotMatch(serialized, /synthetic-state/);
  assert.doesNotMatch(serialized, /synthetic-nonce/);
  assert.doesNotMatch(serialized, /access-token|refresh-token|id-token/);
  assert.doesNotMatch(serialized, /rawClaims|claims|rawProviderResponse/);
  assert.doesNotMatch(serialized, /synthetic-client-secret|synthetic-session-secret/);
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

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  AUTH_SESSION_SECRET_MIN_LENGTH,
  AuthConfigError,
  AuthCallbackError,
  createAuthProviderIdentity,
  createStoredAuthStateRecord,
  parseAuthCallbackParams,
  readAuthConfig,
} from "../dist/auth/index.js";

const validSyntheticAuthEnv = {
  AUTH_PROVIDER_KEY: " Example-OIDC ",
  AUTH_AUTHORIZATION_URL: "https://auth.example.invalid/oauth2/authorize",
  AUTH_TOKEN_URL: "https://auth.example.invalid/oauth2/token",
  AUTH_CLIENT_ID: "synthetic-client-id",
  AUTH_CLIENT_SECRET: "synthetic-client-secret-value",
  AUTH_REDIRECT_URI: "https://platform.example.invalid/auth/callback",
  SESSION_SECRET: "synthetic-session-secret-value-32",
};

test("readAuthConfig requires auth env without leaking secret-like values", () => {
  assert.throws(
    () =>
      readAuthConfig({
        AUTH_CLIENT_SECRET: "do-not-leak-client-secret",
        SESSION_SECRET: "do-not-leak-session-secret",
      }),
    (error) => {
      assert.equal(error instanceof AuthConfigError, true);
      assert.match(error.message, /AUTH_PROVIDER_KEY/);
      assert.doesNotMatch(error.message, /do-not-leak-client-secret/);
      assert.doesNotMatch(error.message, /do-not-leak-session-secret/);
      return true;
    },
  );
});

test("readAuthConfig rejects invalid URLs without leaking secrets", () => {
  assert.throws(
    () =>
      readAuthConfig({
        ...validSyntheticAuthEnv,
        AUTH_AUTHORIZATION_URL: "not a url",
        AUTH_CLIENT_SECRET: "do-not-leak-invalid-url-secret",
      }),
    (error) => {
      assert.equal(error instanceof AuthConfigError, true);
      assert.match(error.message, /AUTH_AUTHORIZATION_URL/);
      assert.doesNotMatch(error.message, /do-not-leak-invalid-url-secret/);
      assert.doesNotMatch(error.message, /synthetic-session-secret/);
      return true;
    },
  );
});

test("readAuthConfig parses valid synthetic config", () => {
  const config = readAuthConfig(validSyntheticAuthEnv);

  assert.equal(config.providerKey, "example-oidc");
  assert.equal(config.authorizationUrl, "https://auth.example.invalid/oauth2/authorize");
  assert.equal(config.tokenUrl, "https://auth.example.invalid/oauth2/token");
  assert.equal(config.clientId, "synthetic-client-id");
  assert.equal(config.clientSecret, "synthetic-client-secret-value");
  assert.equal(config.redirectUri, "https://platform.example.invalid/auth/callback");
  assert.equal(config.sessionSecret, "synthetic-session-secret-value-32");
  assert.deepEqual(config.allowedEmails, []);
  assert.deepEqual(config.allowedDomains, []);
});

test("readAuthConfig preserves issuer identifiers without adding a trailing slash", () => {
  const config = readAuthConfig({
    ...validSyntheticAuthEnv,
    AUTH_ISSUER_URL: " https://accounts.google.com ",
  });

  assert.equal(config.issuerUrl, "https://accounts.google.com");
});

test("readAuthConfig normalizes allowed emails and domains", () => {
  const config = readAuthConfig({
    ...validSyntheticAuthEnv,
    AUTH_ALLOWED_EMAILS: " Owner@Example.COM, MEMBER@Example.com ,,",
    AUTH_ALLOWED_DOMAINS: " Example.COM, @Team.Example.COM ,,",
  });

  assert.deepEqual(config.allowedEmails, ["owner@example.com", "member@example.com"]);
  assert.deepEqual(config.allowedDomains, ["example.com", "team.example.com"]);
});

test("readAuthConfig enforces session secret minimum length", () => {
  assert.throws(
    () =>
      readAuthConfig({
        ...validSyntheticAuthEnv,
        SESSION_SECRET: "too-short",
      }),
    (error) => {
      assert.equal(error instanceof AuthConfigError, true);
      assert.equal(error.code, "session_secret_too_short");
      assert.match(error.message, new RegExp(`${AUTH_SESSION_SECRET_MIN_LENGTH}`));
      assert.doesNotMatch(error.message, /too-short/);
      return true;
    },
  );
});

test("auth errors keep caller messages privacy-safe", () => {
  assert.throws(
    () =>
      readAuthConfig({
        ...validSyntheticAuthEnv,
        AUTH_TOKEN_URL: "not a url",
        AUTH_CLIENT_SECRET: "synthetic-secret-must-stay-hidden",
      }),
    (error) => {
      assert.equal(error instanceof AuthConfigError, true);
      assert.equal(error.publicMessage, "Authentication configuration is invalid.");
      assert.doesNotMatch(error.message, /synthetic-secret-must-stay-hidden/);
      return true;
    },
  );
});

test("OIDC adapter contract can return normalized identity without raw provider material", async () => {
  const fakeAdapter = {
    async buildAuthorizationUrl(input) {
      return {
        url: `${input.authorizationUrl}?client_id=${input.clientId}&state=synthetic`,
      };
    },
    async exchangeCodeForTokens(input) {
      return {
        providerKey: input.providerKey,
        receivedAt: input.now,
        tokenSetRef: "adapter_internal",
      };
    },
    async verifyTokens(input) {
      return {
        providerKey: input.providerKey,
        providerSubject: "provider-subject-123",
        verifiedEmail: "Owner@Example.COM",
        displayName: "Synthetic Owner",
        metadata: {
          emailVerified: true,
        },
      };
    },
  };

  const exchanged = await fakeAdapter.exchangeCodeForTokens({
    providerKey: "example-oidc",
    code: "synthetic-auth-code",
    redirectUri: "https://platform.example.invalid/auth/callback",
    now: "2026-06-27T00:00:00.000Z",
  });
  const verified = await fakeAdapter.verifyTokens({
    providerKey: "example-oidc",
    tokenExchange: exchanged,
  });
  const identity = createAuthProviderIdentity(verified);

  assert.equal(identity.providerKey, "example-oidc");
  assert.equal(identity.providerSubject, "provider-subject-123");
  assert.equal(identity.verifiedEmail, "owner@example.com");
  assert.equal(identity.displayName, "Synthetic Owner");
  assert.deepEqual(identity.metadata, { emailVerified: true });
  assert.equal(Object.hasOwn(identity, "accessToken"), false);
  assert.equal(Object.hasOwn(identity, "refreshToken"), false);
  assert.equal(Object.hasOwn(identity, "idToken"), false);
  assert.equal(Object.hasOwn(identity, "claims"), false);
  assert.equal(Object.hasOwn(identity, "rawClaims"), false);
});

test("parseAuthCallbackParams requires code and state", () => {
  assert.deepEqual(parseAuthCallbackParams({ code: "synthetic-code", state: "synthetic-state" }), {
    code: "synthetic-code",
    state: "synthetic-state",
  });

  assert.throws(
    () => parseAuthCallbackParams({ state: "synthetic-state" }),
    (error) => error instanceof AuthCallbackError && error.code === "missing_code",
  );
  assert.throws(
    () => parseAuthCallbackParams({ code: "synthetic-code" }),
    (error) => error instanceof AuthCallbackError && error.code === "missing_state",
  );
});

test("callback provider errors do not leak callback values", () => {
  assert.throws(
    () =>
      parseAuthCallbackParams({
        error: "access_denied",
        error_description: "do-not-leak-provider-description",
        code: "do-not-leak-code",
        state: "do-not-leak-state",
      }),
    (error) => {
      assert.equal(error instanceof AuthCallbackError, true);
      assert.equal(error.code, "provider_error");
      assert.doesNotMatch(error.message, /do-not-leak/);
      return true;
    },
  );
});

test("auth state records store hash references instead of raw state or nonce", () => {
  const storedState = createStoredAuthStateRecord({
    providerKey: "example-oidc",
    stateHash: "state-hash-reference",
    nonceHash: "nonce-hash-reference",
    redirectUri: "https://platform.example.invalid/auth/callback",
    createdAt: "2026-06-27T00:00:00.000Z",
    expiresAt: "2026-06-27T00:10:00.000Z",
  });

  assert.deepEqual(Object.keys(storedState).sort(), [
    "createdAt",
    "expiresAt",
    "nonceHash",
    "providerKey",
    "redirectUri",
    "stateHash",
  ]);
  assert.equal(Object.hasOwn(storedState, "state"), false);
  assert.equal(Object.hasOwn(storedState, "nonce"), false);
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

test("auth modules do not import DB, SQAG, frontend, or HTTP framework details", async () => {
  const authFiles = [
    "src/auth/callback.ts",
    "src/auth/config.ts",
    "src/auth/errors.ts",
    "src/auth/index.ts",
    "src/auth/oidc.ts",
  ];

  for (const filePath of authFiles) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?|sqag)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono|node:http)/i);
    assert.doesNotMatch(contents, /src\/db|\.{1,2}\/db|\.{1,2}\/\.{1,2}\/db/i);
  }
});

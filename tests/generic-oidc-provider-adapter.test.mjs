import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  AuthProviderError,
  createGenericOidcProviderAdapter,
  readAuthConfig,
} from "../dist/auth/index.js";

const now = "2026-06-28T00:00:00.000Z";
const future = "2026-06-28T00:05:00.000Z";
const accessTokenField = "access_" + "token";
const refreshTokenField = "refresh_" + "token";
const idTokenField = "id_" + "token";
const authConfig = readAuthConfig({
  AUTH_PROVIDER_KEY: "Example-OIDC",
  AUTH_AUTHORIZATION_URL: "https://auth.example.invalid/oauth2/authorize",
  AUTH_TOKEN_URL: "https://auth.example.invalid/oauth2/token",
  AUTH_USERINFO_URL: "https://auth.example.invalid/oauth2/userinfo",
  AUTH_JWKS_URL: "https://auth.example.invalid/.well-known/jwks.json",
  AUTH_ISSUER_URL: "https://issuer.example.invalid/",
  AUTH_CLIENT_ID: "synthetic-client-id",
  AUTH_CLIENT_SECRET: "synthetic-client-secret-value",
  AUTH_REDIRECT_URI: "https://platform.example.invalid/api/platform/auth/callback",
  SESSION_SECRET: "synthetic-session-secret-value-32",
});

test("generic OIDC adapter builds provider authorization URL without leaking secrets", async () => {
  const fixture = createAdapterFixture();
  const adapter = fixture.adapter;

  const result = await adapter.buildAuthorizationUrl({
    providerKey: authConfig.providerKey,
    authorizationUrl: authConfig.authorizationUrl,
    clientId: authConfig.clientId,
    redirectUri: authConfig.redirectUri,
    state: "synthetic-state-value",
    nonce: "synthetic-nonce-value",
  });

  const parsed = new URL(result.url);
  assert.equal(parsed.origin + parsed.pathname, authConfig.authorizationUrl);
  assert.equal(parsed.searchParams.get("response_type"), "code");
  assert.equal(parsed.searchParams.get("client_id"), "synthetic-client-id");
  assert.equal(parsed.searchParams.get("redirect_uri"), authConfig.redirectUri);
  assert.equal(parsed.searchParams.get("scope"), "openid email profile");
  assert.equal(parsed.searchParams.get("state"), "synthetic-state-value");
  assert.equal(parsed.searchParams.get("nonce"), "synthetic-nonce-value");
  assert.equal(fixture.httpCalls.length, 0);
  assertPrivacySafe(result);
});

test("generic OIDC adapter exchanges authorization code with injected HTTP client only on demand", async () => {
  const fixture = createAdapterFixture({
    tokenResponse: {
      [idTokenField]: "synthetic-id-token-placeholder",
      [accessTokenField]: "synthetic-access-token-placeholder",
      [refreshTokenField]: "synthetic-refresh-token-placeholder",
      token_type: "Bearer",
      expires_in: 300,
    },
  });

  assert.equal(fixture.httpCalls.length, 0);
  const exchange = await fixture.adapter.exchangeCodeForTokens({
    providerKey: authConfig.providerKey,
    code: "synthetic-auth-code-value",
    redirectUri: authConfig.redirectUri,
    now,
  });

  assert.equal(fixture.httpCalls.length, 1);
  const call = fixture.httpCalls[0];
  assert.equal(call.url, authConfig.tokenUrl);
  assert.equal(call.method, "POST");
  assert.equal(
    call.headers["content-type"],
    "application/x-www-form-urlencoded",
  );
  const form = new URLSearchParams(call.body);
  assert.equal(form.get("grant_type"), "authorization_code");
  assert.equal(form.get("code"), "synthetic-auth-code-value");
  assert.equal(form.get("redirect_uri"), authConfig.redirectUri);
  assert.equal(form.get("client_id"), "synthetic-client-id");
  assert.equal(form.get("client_secret"), "synthetic-client-secret-value");
  assert.deepEqual(exchange, {
    providerKey: "example-oidc",
    receivedAt: now,
    expiresAt: future,
    tokenSetRef: "adapter_internal",
  });
  assertPrivacySafe(exchange);
});

test("generic OIDC adapter token exchange failures are privacy-safe", async () => {
  const fixture = createAdapterFixture({
    tokenStatus: 500,
    tokenResponse: {
      error: "invalid_grant",
      error_description: "do-not-leak-provider-token-response-body",
    },
  });

  await assert.rejects(
    () =>
      fixture.adapter.exchangeCodeForTokens({
        providerKey: authConfig.providerKey,
        code: "do-not-leak-auth-code",
        redirectUri: authConfig.redirectUri,
        now,
      }),
    assertProviderErrorIsSafe,
  );
});

test("generic OIDC adapter delegates ID token verification and returns normalized safe identity", async () => {
  const fixture = createAdapterFixture({
    tokenResponse: {
      [idTokenField]: "synthetic-id-token-placeholder",
      [accessTokenField]: "synthetic-access-token-placeholder",
      token_type: "Bearer",
      expires_in: 300,
    },
    verifiedClaims: {
      subject: "provider-subject-123",
      email: "OWNER@Example.COM",
      emailVerified: true,
      displayName: " Synthetic Owner ",
      nonce: "synthetic-nonce-value",
      metadata: {
        tenant: "synthetic",
      },
    },
  });
  const exchange = await fixture.adapter.exchangeCodeForTokens({
    providerKey: authConfig.providerKey,
    code: "synthetic-auth-code-value",
    redirectUri: authConfig.redirectUri,
    now,
  });

  const identity = await fixture.adapter.verifyTokens({
    providerKey: authConfig.providerKey,
    tokenExchange: exchange,
    expectedNonceHash: "nonce-hash:synthetic-nonce-value",
  });

  assert.equal(fixture.verifierCalls.length, 1);
  assert.deepEqual(fixture.verifierCalls[0], {
    providerKey: "example-oidc",
    idToken: "synthetic-id-token-placeholder",
    issuerUrl: authConfig.issuerUrl,
    jwksUrl: authConfig.jwksUrl,
    clientId: authConfig.clientId,
    now,
  });
  assert.equal(identity.providerKey, "example-oidc");
  assert.equal(identity.providerSubject, "provider-subject-123");
  assert.equal(identity.verifiedEmail, "owner@example.com");
  assert.equal(identity.displayName, "Synthetic Owner");
  assert.deepEqual(identity.metadata, { tenant: "synthetic" });
  assertPrivacySafe(identity);
});

test("generic OIDC adapter rejects nonce mismatch without leaking token material", async () => {
  const fixture = createAdapterFixture({
    tokenResponse: {
      [idTokenField]: "synthetic-id-token-placeholder",
      token_type: "Bearer",
      expires_in: 300,
    },
    verifiedClaims: {
      subject: "provider-subject-123",
      email: "owner@example.test",
      emailVerified: true,
      displayName: "Synthetic Owner",
      nonce: "unexpected-nonce-value",
      metadata: {},
    },
  });
  const exchange = await fixture.adapter.exchangeCodeForTokens({
    providerKey: authConfig.providerKey,
    code: "synthetic-auth-code-value",
    redirectUri: authConfig.redirectUri,
    now,
  });

  await assert.rejects(
    () =>
      fixture.adapter.verifyTokens({
        providerKey: authConfig.providerKey,
        tokenExchange: exchange,
        expectedNonceHash: "nonce-hash:synthetic-nonce-value",
      }),
    assertProviderErrorIsSafe,
  );
});

test("generic OIDC adapter uses userinfo only after verifier succeeds", async () => {
  const fixture = createAdapterFixture({
    tokenResponse: {
      [idTokenField]: "synthetic-id-token-placeholder",
      [accessTokenField]: "synthetic-access-token-placeholder",
      token_type: "Bearer",
      expires_in: 300,
    },
    verifiedClaims: {
      subject: "provider-subject-123",
      email: null,
      emailVerified: false,
      displayName: null,
      nonce: "synthetic-nonce-value",
      metadata: {},
    },
    userinfoResponse: {
      sub: "provider-subject-123",
      email: "OWNER@Example.COM",
      email_verified: true,
      name: "Userinfo Owner",
    },
  });
  const exchange = await fixture.adapter.exchangeCodeForTokens({
    providerKey: authConfig.providerKey,
    code: "synthetic-auth-code-value",
    redirectUri: authConfig.redirectUri,
    now,
  });

  const identity = await fixture.adapter.verifyTokens({
    providerKey: authConfig.providerKey,
    tokenExchange: exchange,
    expectedNonceHash: "nonce-hash:synthetic-nonce-value",
  });

  assert.equal(fixture.httpCalls.length, 2);
  const userinfoCall = fixture.httpCalls[1];
  assert.equal(userinfoCall.url, authConfig.userinfoUrl);
  assert.equal(userinfoCall.method, "GET");
  assert.equal(userinfoCall.headers.authorization, "Bearer synthetic-access-token-placeholder");
  assert.equal(identity.verifiedEmail, "owner@example.com");
  assert.equal(identity.displayName, "Userinfo Owner");
  assertPrivacySafe(identity);
});

test("generic OIDC adapter rejects userinfo without an exact subject match", async () => {
  for (const userinfoResponse of [
    {
      email: "do-not-leak-userinfo@example.test",
      email_verified: true,
      name: "do-not-leak-userinfo-name",
    },
    {
      sub: "   ",
      email: "do-not-leak-userinfo@example.test",
      email_verified: true,
      name: "do-not-leak-userinfo-name",
    },
    {
      sub: "do-not-leak-different-subject",
      email: "do-not-leak-userinfo@example.test",
      email_verified: true,
      name: "do-not-leak-userinfo-name",
    },
  ]) {
    const fixture = createAdapterFixture({
      tokenResponse: {
        [idTokenField]: "synthetic-id-token-placeholder",
        [accessTokenField]: "synthetic-access-token-placeholder",
        token_type: "Bearer",
        expires_in: 300,
      },
      verifiedClaims: {
        subject: "provider-subject-123",
        email: null,
        emailVerified: false,
        displayName: null,
        nonce: "synthetic-nonce-value",
        metadata: {},
      },
      userinfoResponse,
    });
    const exchange = await fixture.adapter.exchangeCodeForTokens({
      providerKey: authConfig.providerKey,
      code: "synthetic-auth-code-value",
      redirectUri: authConfig.redirectUri,
      now,
    });

    await assert.rejects(
      () =>
        fixture.adapter.verifyTokens({
          providerKey: authConfig.providerKey,
          tokenExchange: exchange,
          expectedNonceHash: "nonce-hash:synthetic-nonce-value",
        }),
      assertProviderErrorIsSafe,
    );
    assert.equal(fixture.httpCalls.length, 2);
  }
});

test("generic OIDC adapter does not call userinfo when verifier fails", async () => {
  const fixture = createAdapterFixture({
    tokenResponse: {
      [idTokenField]: "synthetic-id-token-placeholder",
      [accessTokenField]: "synthetic-access-token-placeholder",
      token_type: "Bearer",
      expires_in: 300,
    },
    verifierError: new Error("do-not-leak-raw-claims"),
    userinfoResponse: {
      sub: "provider-subject-123",
      email: "do-not-leak-userinfo@example.test",
      email_verified: true,
      name: "do-not-leak-userinfo-name",
    },
  });
  const exchange = await fixture.adapter.exchangeCodeForTokens({
    providerKey: authConfig.providerKey,
    code: "synthetic-auth-code-value",
    redirectUri: authConfig.redirectUri,
    now,
  });

  await assert.rejects(
    () =>
      fixture.adapter.verifyTokens({
        providerKey: authConfig.providerKey,
        tokenExchange: exchange,
        expectedNonceHash: "nonce-hash:synthetic-nonce-value",
      }),
    assertProviderErrorIsSafe,
  );
  assert.equal(fixture.httpCalls.length, 1);
  assert.equal(fixture.httpCalls[0].url, authConfig.tokenUrl);
});

test("generic OIDC adapter module keeps provider and app boundaries clean", async () => {
  const contents = await readFile("src/auth/generic-oidc-provider-adapter.ts", "utf8");

  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:kqag|react|next|vite|express|fastify|hono)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:clerk|auth0|supabase|stripe)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?)/i);
  assert.doesNotMatch(contents, /DATABASE_URL|SESSION_SECRET|CSRF_TOKEN_HASH_SECRET|AUTH_STATE_HASH_SECRET/);
});

function createAdapterFixture(options = {}) {
  const httpCalls = [];
  const verifierCalls = [];
  const tokenStatus = options.tokenStatus ?? 200;
  const tokenResponse = options.tokenResponse ?? {
    [idTokenField]: "synthetic-id-token-placeholder",
    [accessTokenField]: "synthetic-access-token-placeholder",
    token_type: "Bearer",
    expires_in: 300,
  };
  const verifiedClaims = options.verifiedClaims ?? {
    subject: "provider-subject-123",
    email: "owner@example.com",
    emailVerified: true,
    displayName: "Synthetic Owner",
    nonce: "synthetic-nonce-value",
    metadata: {},
  };
  const userinfoResponse = options.userinfoResponse ?? null;
  const httpClient = async (request) => {
    httpCalls.push(request);

    if (request.url === authConfig.tokenUrl) {
      return jsonResponse(tokenStatus, tokenResponse);
    }

    if (request.url === authConfig.userinfoUrl && userinfoResponse) {
      return jsonResponse(200, userinfoResponse);
    }

    return jsonResponse(404, { error: "unexpected synthetic endpoint" });
  };
  const tokenVerifier = {
    async verify(input) {
      verifierCalls.push(input);

      if (options.verifierError) {
        throw options.verifierError;
      }

      return verifiedClaims;
    },
  };

  return {
    httpCalls,
    verifierCalls,
    adapter: createGenericOidcProviderAdapter({
      authConfig,
      httpClient,
      tokenVerifier,
      nonceReferenceFactory: (nonce) => `nonce-hash:${nonce}`,
    }),
  };
}

function jsonResponse(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return body;
    },
  };
}

function assertProviderErrorIsSafe(error) {
  assert.equal(error instanceof AuthProviderError, true);
  assert.equal(error.code, "provider_verification_failed");
  assert.equal(error.publicMessage, "Authentication provider verification failed.");
  assertPrivacySafe({
    message: error.message,
    code: error.code,
    publicMessage: error.publicMessage,
  });
  return true;
}

function assertPrivacySafe(value) {
  const serialized = JSON.stringify(value);

  assert.doesNotMatch(serialized, /synthetic-client-secret-value/);
  assert.doesNotMatch(serialized, /do-not-leak/);
  assert.doesNotMatch(serialized, /synthetic-auth-code-value/);
  assert.doesNotMatch(serialized, /synthetic-access-token-placeholder/);
  assert.doesNotMatch(serialized, /synthetic-refresh-token-placeholder/);
  assert.doesNotMatch(serialized, /synthetic-id-token-placeholder/);
  assert.doesNotMatch(serialized, /rawClaims|providerResponse|DATABASE_URL|private\.example/i);
}

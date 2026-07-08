import assert from "node:assert/strict";
import {
  createSign,
  generateKeyPairSync,
  randomUUID,
} from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  AuthProviderError,
  createGenericOidcJwksTokenVerifier,
  createGenericOidcProviderAdapter,
  readAuthConfig,
} from "../dist/auth/index.js";

const now = "2026-06-28T00:00:00.000Z";
const nowSeconds = Math.floor(Date.parse(now) / 1000);
const issuerUrl = "https://issuer.example.invalid/";
const googleIssuerUrl = "https://accounts.google.com";
const jwksUrl = "https://issuer.example.invalid/.well-known/jwks.json";
const clientId = "synthetic-client-id";
const providerKey = "example-oidc";
const accessTokenField = "access_" + "token";
const idTokenField = "id_" + "token";
const unsafeMetadataKeys = [
  "raw_claim",
  "rawClaims",
  "RawProfile",
  "raw_provider_response",
  "providerResponse",
  "access_token",
  "accessToken",
  "AccessToken",
  "access-token",
  "refresh_token",
  "refreshToken",
  "id_token",
  "idToken",
  "client_secret",
  "clientSecret",
  "auth_code",
  "authCode",
  "authorization_code",
  "authorizationCode",
  "api_key",
  "apiKey",
  "private_key",
  "privateKey",
  "password",
  "credential",
  "credentials",
  "token",
  "secret",
];

test("generic OIDC JWKS verifier verifies a synthetic signed ID token", async () => {
  const fixture = createVerifierFixture();
  const idToken = signJwt(fixture.keys, {
    iss: issuerUrl,
    aud: clientId,
    sub: "provider-subject-123",
    exp: nowSeconds + 300,
    iat: nowSeconds,
    nbf: nowSeconds - 10,
    email: "OWNER@Example.COM",
    email_verified: true,
    name: "Synthetic Owner",
    nonce: "synthetic-nonce-value",
    tenant: "synthetic-team",
    login_count: 7,
    raw_claim: "do-not-leak-raw-claim",
    raw_profile: { nested: "do-not-leak-raw-claim" },
  });

  assert.equal(fixture.httpCalls.length, 0);
  const claims = await fixture.verifier.verify(verifierInput({ idToken }));

  assert.equal(fixture.httpCalls.length, 1);
  assert.equal(fixture.httpCalls[0].url, jwksUrl);
  assert.equal(fixture.httpCalls[0].method, "GET");
  assert.equal(claims.subject, "provider-subject-123");
  assert.equal(claims.email, "OWNER@Example.COM");
  assert.equal(claims.emailVerified, true);
  assert.equal(claims.displayName, "Synthetic Owner");
  assert.equal(claims.nonce, "synthetic-nonce-value");
  assert.deepEqual(claims.metadata, {
    login_count: 7,
    tenant: "synthetic-team",
  });
  assertPrivacySafe(claims);
});

test("generic OIDC JWKS verifier accepts Google issuer identifier without trailing slash", async () => {
  const fixture = createVerifierFixture();
  const idToken = signJwt(fixture.keys, {
    ...baseClaims(),
    iss: googleIssuerUrl,
  });

  const claims = await fixture.verifier.verify(
    verifierInput({
      idToken,
      issuerUrl: googleIssuerUrl,
    }),
  );

  assert.equal(claims.subject, "provider-subject-123");
});

test("generic OIDC JWKS verifier keeps only safe primitive metadata", async () => {
  const fixture = createVerifierFixture();
  const blockedMetadata = Object.fromEntries(
    unsafeMetadataKeys.map((key, index) => [key, `blocked-value-${index}`]),
  );
  const idToken = signJwt(fixture.keys, {
    ...baseClaims(),
    tenant: "synthetic-team",
    login_count: 7,
    plan: "internal",
    workspace_hint: "workspace-alpha",
    nested_profile: {
      nested: "blocked-nested-value",
    },
    roles: ["blocked-array-value"],
    preferred_username: "blocked-standard-claim",
    azp: "blocked-authorized-party",
    ...blockedMetadata,
  });

  const claims = await fixture.verifier.verify(verifierInput({ idToken }));
  const serialized = JSON.stringify(claims.metadata);

  assert.deepEqual(claims.metadata, {
    login_count: 7,
    plan: "internal",
    tenant: "synthetic-team",
    workspace_hint: "workspace-alpha",
  });
  assert.doesNotMatch(serialized, /blocked-/);
});

test("generic OIDC JWKS verifier rejects bad signatures and unsafe algorithms", async () => {
  const fixture = createVerifierFixture();
  const validToken = signJwt(fixture.keys, baseClaims());
  const tampered = `${validToken.split(".").slice(0, 2).join(".")}.invalid-signature`;
  const noneToken = unsignedJwt({ alg: "none" }, baseClaims());
  const unsupportedToken = signJwt(fixture.keys, baseClaims(), { alg: "HS256" });

  for (const idToken of [tampered, noneToken, unsupportedToken]) {
    await assert.rejects(
      () => fixture.verifier.verify(verifierInput({ idToken })),
      assertProviderErrorIsSafe,
    );
  }
});

test("generic OIDC JWKS verifier validates issuer audience and time claims", async () => {
  const fixture = createVerifierFixture();

  for (const claims of [
    { ...baseClaims(), iss: "https://wrong-issuer.example.invalid/" },
    { ...baseClaims(), aud: "wrong-client-id" },
    { ...baseClaims(), exp: nowSeconds - 120 },
    { ...baseClaims(), nbf: nowSeconds + 120 },
    { ...baseClaims(), iat: nowSeconds + 120 },
  ]) {
    const idToken = signJwt(fixture.keys, claims);

    await assert.rejects(
      () => fixture.verifier.verify(verifierInput({ idToken })),
      assertProviderErrorIsSafe,
    );
  }
});

test("generic OIDC JWKS verifier requires issuer and JWKS configuration", async () => {
  const fixture = createVerifierFixture();
  const idToken = signJwt(fixture.keys, baseClaims());

  await assert.rejects(
    () => fixture.verifier.verify(verifierInput({ idToken, issuerUrl: null })),
    assertProviderErrorIsSafe,
  );
  await assert.rejects(
    () => fixture.verifier.verify(verifierInput({ idToken, jwksUrl: null })),
    assertProviderErrorIsSafe,
  );
});

test("generic OIDC JWKS verifier validates subject and email verification", async () => {
  const fixture = createVerifierFixture();

  for (const subject of [undefined, "", "   "]) {
    const idToken = signJwt(fixture.keys, {
      ...baseClaims(),
      sub: subject,
    });

    await assert.rejects(
      () => fixture.verifier.verify(verifierInput({ idToken })),
      assertProviderErrorIsSafe,
    );
  }

  const unverifiedEmailToken = signJwt(fixture.keys, {
    ...baseClaims(),
    email: "OWNER@Example.COM",
    email_verified: false,
  });
  const missingVerificationToken = signJwt(fixture.keys, {
    ...baseClaims(),
    email: "OWNER@Example.COM",
    email_verified: undefined,
  });

  assert.equal(
    (await fixture.verifier.verify(verifierInput({ idToken: unverifiedEmailToken }))).email,
    null,
  );
  assert.equal(
    (await fixture.verifier.verify(verifierInput({ idToken: missingVerificationToken }))).email,
    null,
  );
});

test("generic OIDC JWKS verifier errors are privacy-safe", async () => {
  const fixture = createVerifierFixture({
    jwksBody: {
      error: "do-not-leak-jwks-body",
    },
  });
  const idToken = signJwt(fixture.keys, {
    ...baseClaims(),
    raw_claim: "do-not-leak-raw-claim",
  });

  await assert.rejects(
    () => fixture.verifier.verify(verifierInput({ idToken })),
    assertProviderErrorIsSafe,
  );
});

test("generic OIDC provider adapter can use the JWKS verifier", async () => {
  const fixture = createVerifierFixture();
  const authConfig = readAuthConfig({
    AUTH_PROVIDER_KEY: providerKey,
    AUTH_AUTHORIZATION_URL: "https://auth.example.invalid/oauth2/authorize",
    AUTH_TOKEN_URL: "https://auth.example.invalid/oauth2/token",
    AUTH_JWKS_URL: jwksUrl,
    AUTH_ISSUER_URL: issuerUrl,
    AUTH_CLIENT_ID: clientId,
    AUTH_CLIENT_SECRET: "synthetic-client-secret-value",
    AUTH_REDIRECT_URI: "https://platform.example.invalid/api/platform/auth/callback",
    SESSION_SECRET: "synthetic-session-secret-value-32",
  });
  const idToken = signJwt(fixture.keys, {
    ...baseClaims(),
    nonce: "synthetic-nonce-value",
  });
  const httpCalls = [];
  const adapter = createGenericOidcProviderAdapter({
    authConfig,
    httpClient: async (request) => {
      httpCalls.push(request);

      if (request.url === authConfig.tokenUrl) {
        return jsonResponse(200, {
          [idTokenField]: idToken,
          [accessTokenField]: "synthetic-access-token-placeholder",
          token_type: "Bearer",
          expires_in: 300,
        });
      }

      return fixture.httpClient(request);
    },
    tokenVerifier: fixture.verifier,
    nonceReferenceFactory: (nonce) => `nonce-hash:${nonce}`,
  });

  const exchange = await adapter.exchangeCodeForTokens({
    providerKey,
    code: "synthetic-auth-code-value",
    redirectUri: authConfig.redirectUri,
    now,
  });
  const identity = await adapter.verifyTokens({
    providerKey,
    tokenExchange: exchange,
    expectedNonceHash: "nonce-hash:synthetic-nonce-value",
  });

  assert.equal(identity.providerSubject, "provider-subject-123");
  assert.equal(identity.verifiedEmail, "owner@example.com");
  assert.equal(identity.displayName, "Synthetic Owner");
  assert.equal(httpCalls.length, 1);
  assert.equal(fixture.httpCalls.length, 1);

  await assert.rejects(
    () =>
      adapter.verifyTokens({
        providerKey,
        tokenExchange: exchange,
        expectedNonceHash: "nonce-hash:wrong",
      }),
    assertProviderErrorIsSafe,
  );
});

test("generic OIDC JWKS verifier module keeps provider and app boundaries clean", async () => {
  const contents = await readFile("src/auth/generic-oidc-jwks-verifier.ts", "utf8");

  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:sqag|react|next|vite|express|fastify|hono)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:clerk|auth0|supabase|google|stripe)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?)/i);
  assert.doesNotMatch(contents, /DATABASE_URL|SESSION_SECRET|CSRF_TOKEN_HASH_SECRET|AUTH_STATE_HASH_SECRET/);
});

function createVerifierFixture(options = {}) {
  const keys = createSyntheticKeyPair();
  const httpCalls = [];
  const jwksBody = options.jwksBody ?? { keys: [keys.publicJwk] };
  const httpClient = async (request) => {
    httpCalls.push(request);

    if (request.url === jwksUrl) {
      return jsonResponse(200, jwksBody);
    }

    return jsonResponse(404, { error: "unexpected synthetic endpoint" });
  };

  return {
    httpCalls,
    httpClient,
    keys,
    verifier: createGenericOidcJwksTokenVerifier({ httpClient }),
  };
}

function createSyntheticKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const kid = `synthetic-${randomUUID()}`;
  const publicJwk = {
    ...publicKey.export({ format: "jwk" }),
    alg: "RS256",
    kid,
    use: "sig",
  };

  return {
    kid,
    privateKey,
    publicJwk,
  };
}

function baseClaims(overrides = {}) {
  return {
    iss: issuerUrl,
    aud: clientId,
    sub: "provider-subject-123",
    exp: nowSeconds + 300,
    iat: nowSeconds,
    nbf: nowSeconds - 10,
    email: "OWNER@Example.COM",
    email_verified: true,
    name: "Synthetic Owner",
    nonce: "synthetic-nonce-value",
    ...overrides,
  };
}

function verifierInput(overrides = {}) {
  return {
    providerKey,
    idToken: overrides.idToken,
    issuerUrl,
    jwksUrl,
    clientId,
    now,
    ...overrides,
  };
}

function signJwt(keys, claims, headerOverrides = {}) {
  const header = {
    alg: "RS256",
    kid: keys.kid,
    typ: "JWT",
    ...headerOverrides,
  };
  const signingInput = `${base64UrlJson(header)}.${base64UrlJson(claims)}`;
  const signature = createSign("RSA-SHA256")
    .update(signingInput)
    .end()
    .sign(keys.privateKey);

  return `${signingInput}.${base64Url(signature)}`;
}

function unsignedJwt(header, claims) {
  return `${base64UrlJson(header)}.${base64UrlJson(claims)}.`;
}

function base64UrlJson(value) {
  return base64Url(Buffer.from(JSON.stringify(value)));
}

function base64Url(value) {
  return Buffer.from(value).toString("base64url");
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
  assert.doesNotMatch(serialized, /synthetic-auth-code-value/);
  assert.doesNotMatch(serialized, /synthetic-access-token-placeholder/);
  assert.doesNotMatch(serialized, /do-not-leak/);
  assert.doesNotMatch(serialized, /raw_claim|raw_profile|private\.example|DATABASE_URL/i);
  assert.doesNotMatch(serialized, /eyJ[a-zA-Z0-9_-]+\./);
}

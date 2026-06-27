import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  HTTP_ROUTE_CONTRACTS,
  getHttpRouteContract,
  validateCsrfTokenForRoute,
  validateHttpRequestOrigin,
  validateHttpRequestSecurityForRoute,
} from "../dist/index.js";

const now = "2026-06-27T00:00:00.000Z";
const allowedOrigin = "https://platform.example.test";
const otherAllowedOrigin = "https://admin.example.test";
const sessionId = "session_owner_example";
const validToken = "csrf-token-valid-example";
const privateOrigin =
  "https://private.example.test";
const privateUrl =
  "https://private.example.test/path?token=raw-csrf-token&db=postgresql://private-host";

test("allowed Origin passes with normalized trailing slash config", () => {
  const result = validateHttpRequestOrigin({
    headers: {
      Origin: allowedOrigin,
    },
    config: {
      allowedOrigins: [`${allowedOrigin}/`],
    },
  });

  assert.deepEqual(result, {
    valid: true,
    origin: allowedOrigin,
    source: "origin",
  });
});

test("allowed Referer passes when Origin is missing", () => {
  const result = validateHttpRequestOrigin({
    headers: {
      Referer: `${allowedOrigin}/workspace?tab=apps#kqag`,
    },
    config: {
      allowedOrigins: [allowedOrigin],
    },
  });

  assert.deepEqual(result, {
    valid: true,
    origin: allowedOrigin,
    source: "referer",
  });
});

test("Referer path query and fragment are ignored during origin comparison", () => {
  const result = validateHttpRequestOrigin({
    headers: {
      Referer: `${allowedOrigin}/private/path?auth-code=secret#fragment`,
    },
    config: {
      allowedOrigins: [allowedOrigin],
    },
  });

  assert.equal(result.valid, true);
  assert.equal(result.origin, allowedOrigin);
});

test("Origin header is preferred over Referer", () => {
  const result = validateHttpRequestOrigin({
    headers: {
      Origin: "https://unapproved.example.test",
      Referer: `${allowedOrigin}/safe`,
    },
    config: {
      allowedOrigins: [allowedOrigin],
    },
  });

  assert.deepEqual(result, {
    valid: false,
    reason: "origin_not_allowed",
  });
});

test("missing Origin and Referer denies safely", () => {
  const result = validateHttpRequestOrigin({
    headers: {},
    config: {
      allowedOrigins: [allowedOrigin],
    },
  });

  assert.deepEqual(result, {
    valid: false,
    reason: "missing_origin",
  });
});

test("malformed Origin denies safely", () => {
  const result = validateHttpRequestOrigin({
    headers: {
      Origin: "not a url",
    },
    config: {
      allowedOrigins: [allowedOrigin],
    },
  });

  assert.deepEqual(result, {
    valid: false,
    reason: "invalid_origin",
  });
});

test("unapproved Origin denies safely without exposing private URL details", () => {
  const result = validateHttpRequestOrigin({
    headers: {
      Origin: privateOrigin,
    },
    config: {
      allowedOrigins: [allowedOrigin],
    },
  });
  const serialized = JSON.stringify(result);

  assert.deepEqual(result, {
    valid: false,
    reason: "origin_not_allowed",
  });
  assert.doesNotMatch(serialized, /private\.example\.test/);
  assert.doesNotMatch(serialized, /postgresql:\/\/private-host|raw-csrf-token/);
});

test("Origin header with path is malformed and denied safely", () => {
  const result = validateHttpRequestOrigin({
    headers: {
      Origin: privateUrl,
    },
    config: {
      allowedOrigins: [allowedOrigin],
    },
  });
  const serialized = JSON.stringify(result);

  assert.deepEqual(result, {
    valid: false,
    reason: "invalid_origin",
  });
  assert.doesNotMatch(serialized, /private\.example\.test/);
  assert.doesNotMatch(serialized, /postgresql:\/\/private-host|raw-csrf-token/);
});

test("invalid allowed origin config denies safely", () => {
  const result = validateHttpRequestOrigin({
    headers: {
      Origin: allowedOrigin,
    },
    config: {
      allowedOrigins: ["not a url"],
    },
  });

  assert.deepEqual(result, {
    valid: false,
    reason: "invalid_allowed_origin_config",
  });
});

test("allowed origin config rejects path-shaped origins", () => {
  const result = validateHttpRequestOrigin({
    headers: {
      Origin: allowedOrigin,
    },
    config: {
      allowedOrigins: [`${allowedOrigin}/private-path`],
    },
  });

  assert.deepEqual(result, {
    valid: false,
    reason: "invalid_allowed_origin_config",
  });
});

test("public base URL participates in allowed origin config", () => {
  const result = validateHttpRequestOrigin({
    headers: {
      Origin: allowedOrigin,
    },
    config: {
      allowedOrigins: [otherAllowedOrigin],
      publicBaseUrl: `${allowedOrigin}/app`,
    },
  });

  assert.deepEqual(result, {
    valid: true,
    origin: allowedOrigin,
    source: "origin",
  });
});

test("route without CSRF requirement passes without token or validator", async () => {
  const result = await validateCsrfTokenForRoute({
    route: getHttpRouteContract("platform_session_app_access"),
    headers: {},
    sessionId,
    now,
  });

  assert.deepEqual(result, { valid: true });
});

test("CSRF-required route denies missing token", async () => {
  const result = await validateCsrfTokenForRoute({
    route: getHttpRouteContract("platform_logout"),
    headers: {},
    sessionId,
    now,
    csrfTokenValidator: createTokenValidator(),
  });

  assert.deepEqual(result, {
    valid: false,
    reason: "missing_csrf_token",
  });
});

test("CSRF-required route denies invalid token without returning token value", async () => {
  const result = await validateCsrfTokenForRoute({
    route: getHttpRouteContract("platform_logout"),
    headers: {
      "x-csrf-token": "raw-csrf-token-private",
    },
    sessionId,
    now,
    csrfTokenValidator: createTokenValidator({ valid: false }),
  });
  const serialized = JSON.stringify(result);

  assert.deepEqual(result, {
    valid: false,
    reason: "invalid_csrf_token",
  });
  assert.doesNotMatch(serialized, /raw-csrf-token-private/);
});

test("CSRF-required route accepts valid token", async () => {
  const validator = createTokenValidator();
  const result = await validateCsrfTokenForRoute({
    route: getHttpRouteContract("platform_logout"),
    headers: {
      "X-CSRF-Token": validToken,
    },
    sessionId,
    now,
    csrfTokenValidator: validator,
  });

  assert.deepEqual(result, { valid: true });
  assert.deepEqual(validator.calls, [
    {
      csrfToken: validToken,
      sessionId,
      now,
    },
  ]);
});

test("CSRF validator exception returns privacy-safe failure", async () => {
  const result = await validateCsrfTokenForRoute({
    route: getHttpRouteContract("platform_logout"),
    headers: {
      "x-csrf-token": validToken,
    },
    sessionId,
    now,
    csrfTokenValidator: createTokenValidator({
      throwMessage: "validator exploded raw-csrf-token postgresql://private-host",
    }),
  });
  const serialized = JSON.stringify(result);

  assert.deepEqual(result, {
    valid: false,
    reason: "csrf_validation_failed",
  });
  assert.doesNotMatch(serialized, /raw-csrf-token|postgresql:\/\/private-host|exploded/);
});

test("platform_logout requires valid Origin or Referer and valid CSRF token", async () => {
  const result = await validateHttpRequestSecurityForRoute({
    route: getHttpRouteContract("platform_logout"),
    headers: {
      Origin: allowedOrigin,
      "x-csrf-token": validToken,
    },
    sessionId,
    now,
    originConfig: { allowedOrigins: [allowedOrigin] },
    csrfTokenValidator: createTokenValidator(),
  });

  assert.deepEqual(result, { allowed: true });
});

test("platform_logout denies valid Origin with missing CSRF token", async () => {
  const result = await validateHttpRequestSecurityForRoute({
    route: getHttpRouteContract("platform_logout"),
    headers: {
      Origin: allowedOrigin,
    },
    sessionId,
    now,
    originConfig: { allowedOrigins: [allowedOrigin] },
    csrfTokenValidator: createTokenValidator(),
  });

  assert.deepEqual(result, {
    allowed: false,
    reason: "missing_csrf_token",
    recommendedStatus: 403,
  });
});

test("platform_logout denies valid token with invalid Origin", async () => {
  const result = await validateHttpRequestSecurityForRoute({
    route: getHttpRouteContract("platform_logout"),
    headers: {
      Origin: "https://unapproved.example.test",
      "x-csrf-token": validToken,
    },
    sessionId,
    now,
    originConfig: { allowedOrigins: [allowedOrigin] },
    csrfTokenValidator: createTokenValidator(),
  });

  assert.deepEqual(result, {
    allowed: false,
    reason: "origin_not_allowed",
    recommendedStatus: 403,
  });
});

test("platform_session_app_access does not require CSRF security checks", async () => {
  const result = await validateHttpRequestSecurityForRoute({
    route: getHttpRouteContract("platform_session_app_access"),
    headers: {},
    sessionId,
    now,
    originConfig: { allowedOrigins: [] },
  });

  assert.deepEqual(result, { allowed: true });
});

test("combined request security check does not call repositories or inspect cookies", async () => {
  const repositories = {
    sessions: {
      async findById() {
        throw new Error("repository should not be called");
      },
    },
  };

  const result = await validateHttpRequestSecurityForRoute({
    route: getHttpRouteContract("platform_logout"),
    headers: {
      Origin: allowedOrigin,
      "x-csrf-token": validToken,
      Cookie: "swooshz_session=raw-session-token-private",
    },
    sessionId,
    now,
    originConfig: { allowedOrigins: [allowedOrigin] },
    csrfTokenValidator: createTokenValidator(),
    repositories,
  });

  assert.deepEqual(result, { allowed: true });
});

test("all non-GET browser-cookie routes require CSRF in the manifest", () => {
  const nonGetCookieRoutes = HTTP_ROUTE_CONTRACTS.filter(
    (route) => route.method !== "GET" && route.browserSession !== "none",
  );

  assert.ok(nonGetCookieRoutes.length > 0);
  for (const route of nonGetCookieRoutes) {
    assert.equal(route.csrf.required, true);
    assert.equal(route.csrf.strategy, "origin_referer_and_csrf_token");
  }
});

test("HTTP security modules do not import DB frontend KQAG provider SDK or live server modules", async () => {
  const files = [
    "src/http/origin-validation.ts",
    "src/http/csrf.ts",
    "src/http/request-security.ts",
  ];

  for (const filePath of files) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?|kqag)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono|node:http)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:clerk|auth0|supabase)/i);
    assert.doesNotMatch(contents, /src\/db|\.{1,2}\/db|\.{1,2}\/\.{1,2}\/db/i);
  }
});

test("pure domain modules do not import HTTP security modules", async () => {
  const pureDomainFiles = [
    "src/accounts/types.ts",
    "src/accounts/normalization.ts",
    "src/apps/types.ts",
    "src/access/decide-app-access.ts",
  ];

  for (const filePath of pureDomainFiles) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /src\/http|\.{1,2}\/http|\.{1,2}\/\.{1,2}\/http/);
    assert.doesNotMatch(contents, /origin-validation|request-security|csrf/);
  }
});

function createTokenValidator(options = {}) {
  const validator = {
    calls: [],
    async validate(input) {
      validator.calls.push(input);

      if (options.throwMessage) {
        throw new Error(options.throwMessage);
      }

      if (options.valid === false) {
        return { valid: false, reason: "synthetic_invalid_token" };
      }

      return { valid: true };
    },
  };

  return validator;
}

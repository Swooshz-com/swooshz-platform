import assert from "node:assert/strict";
import test from "node:test";

import {
  buildBrowserSessionClearCookie,
  buildAuthStateBindingClearCookie,
  buildAuthStateBindingCookie,
  buildBrowserSessionSetCookie,
  extractBrowserSessionIdFromCookieHeader,
  extractAuthStateBindingFromCookieHeader,
  parseCookieHeader,
} from "../dist/index.js";

const rawSessionReference = "session_owner_example";
const privateCookieValue = "raw-session-token session-secret provider-token auth-code";

test("parses a valid cookie header and extracts the platform session reference", () => {
  const parsed = parseCookieHeader(
    "theme=dark; swooshz_session=session_owner_example; prefs=compact",
  );
  const sessionId = extractBrowserSessionIdFromCookieHeader(
    "theme=dark; swooshz_session=session_owner_example; prefs=compact",
  );

  assert.equal(parsed.swooshz_session, rawSessionReference);
  assert.equal(sessionId, rawSessionReference);
});

test("missing session cookie returns null safely", () => {
  assert.equal(extractBrowserSessionIdFromCookieHeader(null), null);
  assert.equal(extractBrowserSessionIdFromCookieHeader("theme=dark"), null);
});

test("malformed session cookie returns null safely", () => {
  assert.equal(
    extractBrowserSessionIdFromCookieHeader("swooshz_session=bad value"),
    null,
  );
  assert.equal(
    extractBrowserSessionIdFromCookieHeader("swooshz_session=%E0%A4%A"),
    null,
  );
  assert.equal(
    extractBrowserSessionIdFromCookieHeader("swooshz_session=session;oops"),
    null,
  );
});

test("builds a session Set-Cookie header with secure browser defaults", () => {
  const header = buildBrowserSessionSetCookie(rawSessionReference, {
    secure: true,
    maxAgeSeconds: 3600,
  });

  assert.match(header, /^swooshz_session=session_owner_example;/);
  assert.match(header, /HttpOnly/);
  assert.match(header, /Path=\/api\/platform/);
  assert.match(header, /SameSite=Lax/);
  assert.match(header, /Secure/);
  assert.match(header, /Max-Age=3600/);
});

test("clearing cookie expires and removes the browser session reference safely", () => {
  const header = buildBrowserSessionClearCookie({ secure: true });

  assert.match(header, /^swooshz_session=;/);
  assert.match(header, /HttpOnly/);
  assert.match(header, /Path=\/api\/platform/);
  assert.match(header, /SameSite=Lax/);
  assert.match(header, /Secure/);
  assert.match(header, /Max-Age=0/);
  assert.match(header, /Expires=Thu, 01 Jan 1970 00:00:00 GMT/);
});

test("auth binding cookie is short-lived HttpOnly Lax Secure and callback-scoped", () => {
  const header = buildAuthStateBindingCookie("auth-state:v1:binding-reference", 600, {
    secure: true,
    sameSite: "Strict",
  });

  assert.match(header, /^swooshz_auth_state=auth-state%3Av1%3Abinding-reference;/);
  assert.match(header, /HttpOnly/);
  assert.match(header, /Path=\/api\/platform\/auth\/callback/);
  assert.match(header, /SameSite=Lax/);
  assert.match(header, /Secure/);
  assert.match(header, /Max-Age=600/);
  assert.equal(
    extractAuthStateBindingFromCookieHeader(
      "theme=dark; swooshz_auth_state=auth-state%3Av1%3Abinding-reference",
    ),
    "auth-state:v1:binding-reference",
  );
});

test("auth binding clear cookie uses matching security attributes", () => {
  const header = buildAuthStateBindingClearCookie({ secure: true });

  assert.match(header, /^swooshz_auth_state=;/);
  assert.match(header, /HttpOnly/);
  assert.match(header, /Path=\/api\/platform\/auth\/callback/);
  assert.match(header, /SameSite=Lax/);
  assert.match(header, /Secure/);
  assert.match(header, /Max-Age=0/);
  assert.match(header, /Expires=Thu, 01 Jan 1970 00:00:00 GMT/);
});

test("auth binding extraction rejects duplicates malformed values and session cookies", () => {
  assert.equal(extractAuthStateBindingFromCookieHeader("swooshz_auth_state=short"), null);
  assert.equal(extractAuthStateBindingFromCookieHeader("swooshz_auth_state=%E0%A4%A"), null);
  assert.equal(extractAuthStateBindingFromCookieHeader("swooshz_auth_state=valid-binding; swooshz_auth_state=other-binding"), null);
  assert.equal(extractAuthStateBindingFromCookieHeader("swooshz_session=session_owner_example"), null);
});

test("cookie helpers do not expose secret or provider material in safe results", () => {
  const parsed = parseCookieHeader(`swooshz_session=${encodeURIComponent(privateCookieValue)}`);
  const sessionId = extractBrowserSessionIdFromCookieHeader(
    `swooshz_session=${encodeURIComponent(privateCookieValue)}`,
  );
  const serialized = JSON.stringify({ parsed, sessionId });

  assert.equal(sessionId, null);
  assert.doesNotMatch(serialized, /provider-token|auth-code/i);
  assert.doesNotMatch(serialized, /session-secret|raw-session-token/i);
});

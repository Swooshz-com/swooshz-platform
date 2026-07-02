import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  renderAdminShellPage,
  renderAppShellPage,
  renderLandingPage,
} from "../dist/index.js";

test("landing page renders the platform name and login link", () => {
  const html = renderLandingPage();

  assert.match(html, /Swooshz Platform/);
  assert.match(html, /\/api\/platform\/auth\/start/);
  assert.doesNotMatch(html, /SESSION_SECRET|DATABASE_URL|postgresql:\/\//i);
});

test("app shell references only existing browser JSON APIs", () => {
  const html = renderAppShellPage();

  assert.match(html, /\/api\/platform\/session\/context/);
  assert.match(html, /\/api\/platform\/session\/csrf/);
  assert.match(html, /\/api\/platform\/apps\/launch\/open/);
  assert.match(html, /\/api\/platform\/logout/);
  assert.match(html, /\/app\/admin\?workspaceId=/);
  assert.match(html, /id="adminLink"[^>]*hidden/);
});

test("app shell keeps secret and raw-auth material out of static HTML", () => {
  const html = renderAppShellPage();

  assert.doesNotMatch(html, /swooshz_session=session_|session-secret/i);
  assert.doesNotMatch(html, /CSRF_TOKEN_HASH_SECRET|csrf-secret/i);
  assert.doesNotMatch(html, /app-launch:v1:hmac-sha256/i);
  assert.doesNotMatch(html, /auth-code|raw-state|raw-nonce|provider-token|raw-claim/i);
  assert.doesNotMatch(html, /DATABASE_URL|postgresql:\/\/|private\.example/i);
});

test("app shell does not persist launch tokens in browser storage or URLs", () => {
  const html = renderAppShellPage();

  assert.doesNotMatch(html, /localStorage|sessionStorage/);
  assert.doesNotMatch(html, /launchToken|token-box|clipboard/i);
  assert.doesNotMatch(html, /launchToken=.*location|location.*launchToken/s);
  assert.doesNotMatch(html, /URLSearchParams\([^)]*launchToken/s);
});

test("admin shell references protected admin APIs and CSRF-protected actions", () => {
  const html = renderAdminShellPage();

  assert.match(html, /\/api\/platform\/session\/context/);
  assert.match(html, /\/api\/platform\/session\/csrf/);
  assert.match(html, /\/api\/platform\/workspaces\//);
  assert.match(html, /\/members/);
  assert.match(html, /\/role\?role=/);
  assert.match(html, /\/disable/);
  assert.match(html, /\/app-entitlements/);
  assert.match(html, /\/kqag\/status\?status=/);
  assert.match(html, /\/api\/platform\/logout/);
  assert.match(html, /method: "POST"/);
  assert.match(html, /"x-csrf-token": csrfToken/);
});

test("admin shell limits usable controls to owner/admin workspace context", () => {
  const html = renderAdminShellPage();

  assert.match(html, /membershipRole === "owner" \|\| workspace\.membershipRole === "admin"/);
  assert.match(html, /Workspace admin is available to workspace owners and admins only\./);
  assert.match(html, /select\.disabled = isSelf \|\| member\.status !== "active"/);
  assert.match(html, /button\.disabled = isSelf \|\| member\.status !== "active"/);
});

test("admin shell keeps secret raw-auth and KQAG quote material out of static HTML", () => {
  const html = renderAdminShellPage();

  assert.doesNotMatch(html, /swooshz_session=session_|session-secret/i);
  assert.doesNotMatch(html, /CSRF_TOKEN_HASH_SECRET|csrf-secret/i);
  assert.doesNotMatch(html, /auth-code|raw-state|raw-nonce|provider-token|raw-claim/i);
  assert.doesNotMatch(html, /DATABASE_URL|postgresql:\/\/|private\.example/i);
  assert.doesNotMatch(html, /quote export|pricing|xlsx|quote session/i);
  assert.doesNotMatch(html, /localStorage|sessionStorage|clipboard/);
});

test("platform shell module does not import frontend frameworks provider SDKs DB KQAG or migrations", async () => {
  const contents = await readFile("src/http/platform-shell.ts", "utf8");

  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:kqag|clerk|auth0|supabase|stripe)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?)/i);
  assert.doesNotMatch(contents, /node:http|src\/db|\.{1,2}\/db|\.{1,2}\/\.{1,2}\/db/i);
});

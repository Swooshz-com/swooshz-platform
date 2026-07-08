import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const contractPath = "docs/app-access-contract.md";

test("app access contract documents role and product access matrix", async () => {
  const contract = await readContract();

  assert.match(contract, /## Role And Product Access Matrix/i);
  assert.match(contract, /\| `owner` \| Yes, for active memberships\. \| Yes/i);
  assert.match(contract, /\| `admin` \| Yes, for active memberships\. \| Yes/i);
  assert.match(contract, /\| `member` \| Yes, for active memberships\. \| No\. \| Allowed/i);
  assert.match(contract, /\| `viewer` \| Yes, for active memberships\. \| No\. \| Blocked unless a future app-specific read-only launch policy/i);
  assert.match(contract, /SQAG has no read-only launch mode/i);
  assert.match(contract, /Future apps inherit the same blocked viewer launch default/i);
});

test("app access contract documents fail-closed app and entitlement states", async () => {
  const contract = await readContract();

  assert.match(contract, /Only `available` and `private_preview` app statuses are launchable/i);
  assert.match(contract, /Unknown, inactive, unavailable, private-disabled, and globally disabled app states fail closed/i);
  assert.match(contract, /Only `enabled` and `trial` entitlement statuses are launchable/i);
  assert.match(contract, /missing, `disabled`, and `suspended` entitlements fail closed/i);
});

test("app access contract documents generic Platform services and SQAG route boundary", async () => {
  const contract = await readContract();

  assert.match(contract, /service-level entitlement mutation contract is generic by `appKey`/i);
  assert.match(contract, /current browser\/admin HTTP route and UI control remain deliberately SQAG-scoped/i);
  assert.match(contract, /short-lived app launch token/i);
  assert.match(contract, /header-only consume route/i);
  assert.match(contract, /does not move app-owned runtime data into Platform/i);
});

test("app access contract non-goals match the current implemented platform surface", async () => {
  const contract = await readContract();

  assert.doesNotMatch(contract, /No frontend app launcher in this PR/i);
  assert.doesNotMatch(contract, /No real auth provider integration in this PR/i);
  assert.match(contract, /No polished product launcher or dashboard redesign in this contract/i);
  assert.match(contract, /No fake login, hidden fallback auth, password auth, or 2FA in this contract/i);
  assert.match(contract, /No hosted deployment execution or hosted approval from this contract/i);
  assert.match(contract, /No SQAG code changes or SQAG-owned runtime data movement in this contract/i);
});

test("app access contract avoids private material and localhost examples", async () => {
  const contract = await readContract();

  assert.doesNotMatch(contract, /localhost/i);
  assert.doesNotMatch(contract, /sk-[A-Za-z0-9]{20,}/);
  assert.doesNotMatch(contract, /AKIA[0-9A-Z]{16}/);
  assert.doesNotMatch(contract, /-----BEGIN [A-Z ]*PRIVATE KEY-----/);
  assert.doesNotMatch(contract, /postgres(?:ql)?:\/\/[^\s>]+@/i);
  assert.doesNotMatch(contract, /ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/);
  assert.doesNotMatch(contract, /access_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(contract, /refresh_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(contract, /id_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(contract, /\/api\/platform\/auth\/callback\?/i);
});

async function readContract() {
  return readFile(contractPath, "utf8");
}

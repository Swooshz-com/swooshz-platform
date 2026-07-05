import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const contractPath = "docs/internal-alpha-platform-contract.md";

test("internal alpha platform contract covers required audit sections", async () => {
  const contract = await readContract();
  const headings = [
    "# Internal Alpha Platform Contract Audit",
    "## Executive Summary",
    "## Current State",
    "### Current Architecture Map",
    "## Internal Alpha Requirements",
    "## User And Team Management Gap Audit",
    "## Security Findings",
    "## Production And Deployment Readiness Audit",
    "## Platform And KQAG Boundary",
    "## Admin Foundation Runbook",
    "## UI And IA Requirements Before Google Stitch",
    "## Google Stitch Recommendation",
    "## Recommended PR Sequence",
  ];

  for (const heading of headings) {
    assert.match(contract, new RegExp(escapeRegExp(heading)));
  }
});

test("internal alpha platform contract classifies team and app access gaps", async () => {
  const contract = await readContract();
  const requiredPhrases = [
    "Listing workspace users",
    "Adding user by email",
    "Removing/deactivating user",
    "Changing role",
    "App access grant/revoke",
    "Invited/pending users",
    "Fail-closed access if role/app access is missing",
    "Blocker before internal alpha",
    "Future production enhancement",
    "Implemented",
    "Partial",
    "Missing",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(contract, new RegExp(escapeRegExp(phrase), "i"));
  }
});

test("internal alpha platform contract preserves Stitch and implementation boundaries", async () => {
  const contract = await readContract();

  assert.match(contract, /Do not start visual Stitch implementation/i);
  assert.match(contract, /screens based on the page inventory/i);
  assert.match(contract, /UI reference only/i);
  assert.match(contract, /not the source of truth for business logic/i);
  assert.match(contract, /does not approve UI implementation/i);
  assert.match(contract, /does not approve.*KQAG repository changes/i);
  assert.match(contract, /No KQAG app data responsibilities move into Platform/i);
});

test("internal alpha platform contract documents the admin foundation status", async () => {
  const contract = await readContract();

  assert.match(contract, /Owner\/admin service methods and protected HTTP routes can list workspace members/i);
  assert.match(contract, /disable and reactivate non-owner memberships/i);
  assert.match(contract, /change roles/i);
  assert.match(contract, /list app entitlements, and enable\/disable KQAG app entitlement/i);
  assert.match(contract, /addExistingWorkspaceUserByEmail/i);
  assert.match(contract, /existing active provider-backed user by normalized email/i);
  assert.match(contract, /\/api\/platform\/workspaces\/:workspaceId\/members\/add\?email=<email>&role=<role>/i);
  assert.match(contract, /workspace\.membership\.added/i);
  assert.match(contract, /reactivateWorkspaceMembership/i);
  assert.match(contract, /workspace\.membership\.reactivated/i);
  assert.match(contract, /no invitation delivery/i);
  assert.match(contract, /Full email invitation delivery remains future scope/i);
  assert.match(contract, /disabled non-owner workspace membership/i);
  assert.match(contract, /listWorkspaceAuditEventsForAdmin/i);
  assert.match(contract, /\/api\/platform\/workspaces\/:workspaceId\/audit-events\?limit=<number>/i);
  assert.match(contract, /Activity section shows recent workspace audit events/i);
  assert.match(contract, /Minimal Activity browsing is implemented in `\/app\/admin`/i);
  assert.match(contract, /Audit export\/filtering\/retention workflows/i);
  assert.match(contract, /Protected admin HTTP routes can list workspace members/i);
  assert.match(contract, /required query parameters for mutation inputs/i);
  assert.match(contract, /route manifest marks adapter-wired routes as implemented/i);
  assert.match(contract, /same transaction\/unit-of-work/i);
  assert.match(contract, /audit append failure cannot leave membership or entitlement state changed/i);
  assert.match(contract, /Quote operators remain mapped to `member`/i);
  assert.match(contract, /No polished product UI exists yet/i);
  assert.match(contract, /CSRF\/origin validation/i);
});

test("internal alpha platform contract uses placeholders and avoids private material", async () => {
  const contract = await readContract();

  assert.doesNotMatch(contract, /sk-[A-Za-z0-9]{20,}/);
  assert.doesNotMatch(contract, /AKIA[0-9A-Z]{16}/);
  assert.doesNotMatch(contract, /-----BEGIN [A-Z ]*PRIVATE KEY-----/);
  assert.doesNotMatch(contract, /postgres(?:ql)?:\/\/[^\s>]+@/i);
  assert.doesNotMatch(contract, /ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/);
  assert.doesNotMatch(contract, /access_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(contract, /refresh_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(contract, /id_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(contract, /@[A-Za-z0-9.-]+\.(?:com|net|org|io|co)\b/);
  assert.match(contract, /Koncept Images Pte Ltd/);
  assert.match(contract, /No real staff emails/);
});

async function readContract() {
  return readFile(contractPath, "utf8");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

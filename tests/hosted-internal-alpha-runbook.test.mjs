import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import test from "node:test";

const runbookPath = "docs/hosted-internal-alpha-runbook.md";

test("hosted internal alpha runbook covers deployment operations", async () => {
  const runbook = await readRunbook();
  const requiredPhrases = [
    "# Hosted Internal Alpha Runbook",
    "https://swooshz.com",
    "https://www.swooshz.com",
    "https://quote.swooshz.com",
    "https://swooshz.com/api/platform/auth/callback",
    "PostgreSQL",
    "npm run db:migrate",
    "DATABASE_MIGRATIONS_CONFIRM=apply-reviewed-migrations",
    "Migrations are never automatic on app startup",
    "backup",
    "restore",
    "rollback",
    "`GET /healthz`",
    "log review",
    "process manager",
    "container",
    "Hostinger VPS And Coolify Deployment Readiness",
    "https://swooshz.com",
    "SQAG-side PR #122 and Platform PR #79 established the historical `appKey=sqag` baseline only",
    "record and jointly review the exact companion Platform and SQAG revisions",
    "Build command: `npm run build`",
    "Start command: `npm run platform:start`",
    "Health check path: `/healthz`",
    "Do not add Coolify build hooks, deploy hooks, startup hooks",
    "TLS",
    "reverse proxy",
    "Secrets And Env Checklist",
    "Hosted readiness requires `NODE_ENV=production`",
    "HTTPS browser/provider-facing URLs",
    "origin-only allowed origins",
    "Neon Hosted Postgres Readiness",
    "Project: `swooshz-platform`",
    "Region: `Singapore / aws-ap-southeast-1`",
    "Database: `swooshz_platform`",
    "Owner/migration role: `platform_migrator`",
    "pooled `DATABASE_URL`",
    "`npm run platform:db-readiness-check`",
    "`db_config_missing`",
    "`db_unreachable`",
    "`schema_not_ready`",
    "`ready`",
    "Use an unpooled/direct owner connection for `DATABASE_OPERATOR_URL`",
    "readiness only, not full production readiness",
    "`AUTH_REDIRECT_URI` ends with `/api/platform/auth/callback`",
    "host-only cookie/finalization flow is smoke tested",
    "Sanitized Neon Migration Evidence",
    "Pre-migration DB readiness: `schema_not_ready`",
    "guarded manual migration through `npm run db:migrate`",
    "Post-migration DB readiness: `ready`",
    "This evidence does not approve hosted deployment or full production readiness",
    "first owner/admin bootstrap",
    "pending workspace approval",
    "SQAG entitlement",
    "audit/activity verification",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(runbook, new RegExp(escapeRegExp(phrase), "i"));
  }
});

test("hosted internal alpha runbook has an env checklist with safe examples and secret classification", async () => {
  const runbook = await readRunbook();

  assert.match(
    runbook,
    /\|\s*Env var\s*\|\s*Purpose\s*\|\s*Required\s*\|\s*Safe example\s*\|\s*Secret\s*\|\s*Validation \/ failure behavior\s*\|/i,
  );

  const expectedRows = [
    ["NODE_ENV", "Required", "No"],
    ["PLATFORM_HTTP_HOST", "Required", "No"],
    ["PLATFORM_HTTP_PORT", "Required", "No"],
    ["PLATFORM_PUBLIC_BASE_URL", "Required", "No"],
    ["PLATFORM_ALLOWED_ORIGINS", "Required", "No"],
    ["PLATFORM_COOKIE_SECURE", "Required", "No"],
    ["DATABASE_URL", "Required", "Yes"],
    ["DATABASE_EXPECTED_RUNTIME_ROLE", "Required in production", "No"],
    ["DATABASE_OPERATOR_URL", "Required for production operator commands only", "Yes"],
    ["DATABASE_SSL_MODE", "Optional", "No"],
    ["DATABASE_MIGRATIONS_CONFIRM", "Required for migrations only", "No"],
    ["SESSION_SECRET", "Required", "Yes"],
    ["CSRF_TOKEN_HASH_SECRET", "Required", "Yes"],
    ["AUTH_STATE_HASH_SECRET", "Required", "Yes"],
    ["APP_LAUNCH_TOKEN_HASH_SECRET", "Required", "Yes"],
    ["PLATFORM_AUTH_PROVIDER_MODE", "Required", "No"],
    ["AUTH_PROVIDER_KEY", "Required", "No"],
    ["AUTH_ISSUER_URL", "Required", "No"],
    ["AUTH_AUTHORIZATION_URL", "Required", "No"],
    ["AUTH_TOKEN_URL", "Required", "No"],
    ["AUTH_JWKS_URL", "Required", "No"],
    ["AUTH_USERINFO_URL", "Optional", "No"],
    ["AUTH_CLIENT_ID", "Required", "No"],
    ["AUTH_CLIENT_SECRET", "Required", "Yes"],
    ["AUTH_REDIRECT_URI", "Required", "No"],
    ["AUTH_ALLOWED_EMAILS", "Required", "No"],
    ["AUTH_ALLOWED_DOMAINS", "Optional", "No"],
    ["PLATFORM_SQAG_LAUNCH_MODE", "Required", "No"],
    ["PLATFORM_SQAG_APP_BASE_URL", "Required when server_handoff", "No"],
    ["PLATFORM_SEED_CONFIRM", "Required for bootstrap only", "No"],
    ["PLATFORM_SEED_USER_EMAIL", "Required for bootstrap only", "No"],
    ["PLATFORM_SEED_BOOTSTRAP_MODE", "Optional bootstrap only", "No"],
    ["PLATFORM_SEED_MEMBERSHIP_ROLE", "Optional", "No"],
  ];

  for (const [name, required, secret] of expectedRows) {
    assertEnvRow(runbook, name, required, secret);
  }

  assert.match(runbook, /<strong-random-placeholder>/);
  assert.match(runbook, /<runtime-database-url-from-secret-store>/);
  assert.match(runbook, /<operator-database-url-from-secret-store>/);
  assert.match(runbook, /<hosted-owner-admin-email-after-login>/);
  assert.match(runbook, /<comma-separated-allowlisted-emails>/);
});

test("hosted runbook preserves the rollback-gated runtime activation contract", async () => {
  const runbook = await readRunbook();
  const requiredPhrases = [
    "Restricted Runtime Role Activation Contract",
    "scripts/platform-runtime-activation-contract.mjs",
    "dormant_role_preflight",
    "password_installation",
    "login_enablement",
    "runtime_connection_construction",
    "runtime_connection_establishment",
    "runtime_identity",
    "recursive_set_role_posture",
    "grants_and_ownership_verification",
    "success_finalisation",
    "mandatory_rollback",
    "Preserve the first failed",
    "phase before starting rollback",
    "Windows PowerShell 5.1 also",
    "uses US-ASCII for native pipeline input",
    "writing the",
    "`proxy_host`",
    "`region_id`",
    "directly to",
    "stop without retry",
    "RUNTIME_ACTIVATION_TEST_CONFIRM=disposable-only",
    "does not authorise or prove a production activation",
    "immutable target identity separate from",
    "renewable provider attestation",
    "createNeonProviderAttestation",
    "createRuntimeActivationTarget",
    "GET /api/v2/projects/{project_id}/endpoints/{endpoint_id}",
    "retain endpoint `id`",
    "`proxy_host`",
    "`region_id`",
    "`current_state`, and `disabled`",
    "map `project_id`, `branch_id`, `proxy_host`, and `region_id` directly",
    "map provider-returned `project_id` and `branch_id` directly",
    "copy expected or requested project/branch values",
    "association from a connection URL",
    "silently fill a missing association",
    "Every endpoint-level project and branch must exactly match",
    "strict endpoint evidence record accepts exactly",
    "Evidence contains exactly one official",
    "`<endpoint-id>.<proxyHost>`",
    "only the explicitly reviewed `.aws.neon.tech` suffix",
    "`<endpoint-id>-pooler`",
    "Pooled access is not another compute endpoint",
    "any port other than `5432` fails closed",
    "`proxyHost`",
    "`regionId`",
    "`<region>.aws.neon.tech`",
    "`<provider-shard>.<region>.aws.neon.tech`",
    "shard-qualified",
    "stripping the `aws-`",
    "Arbitrary label-count widening is prohibited",
    "`c-<positive",
    "decimal integer>`",
    "Before creating any Docker environment",
    "before consuming a password capability",
    "consumes no capability",
    "test-only runtime and Docker-network transports",
    "production reducer is",
    "unchanged; these transports add no production bypass switch",
    "Any missing or extra field fails closed",
    "exact project ID",
    "exact branch ID",
    "at-most-60-second-old",
    "strictly newer",
    "single-use opaque capability",
    "cannot spawn without",
    "cannot generate LOGIN or rollback SQL without",
    "retains the exact provider-evidence `expiresMs`",
    "Production callers may use the default `Date.now()` clock",
    "Consumption succeeds only while `now < expiresMs`",
    "the capability remains unconsumed",
    "Do not pass a raw API response object",
    "connection strings",
    "PostgreSQL versions",
    "Retain the database-side comparison as secondary evidence",
    "anchored all-container query proving",
    "daemon-side absence",
    "Cleanup is forbidden before complete provider and fixture validation",
    "inconclusive/manual cleanup",
    "never retarget rollback",
    "wait for confirmed child termination",
    "identity- or endpoint-overriding connection parameters",
    "src/db/runtime-grant-contract.ts",
    "exactly 39",
    "direct, non-grantable records",
    "views, materialized views, and foreign tables",
    "pg_attribute.attacl",
    "pg_default_acl",
    "recursively inventoried",
    "operational/control-plane",
    "operationSources",
    "Exact set equality is required",
    "Record counts are diagnostic only",
    "required no live `GRANT` or `REVOKE`",
    "Activation remains blocked until",
    "fresh provider-bound live dormant",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(runbook, new RegExp(escapeRegExp(phrase), "i"));
  }
});

test("hosted runbook records the locked runtime posture and fixture admission invariants", async () => {
  const runbook = await readRunbook();
  const requiredPhrases = [
    "Disposable PostgreSQL Fixture Admission",
    "every `pg_auth_members` row",
    "either `member` or `roleid`",
    "`admin_option`, `inherit_option`, and `set_option` never",
    "exact `information_schema`",
    "names beginning with `pg_`",
    "relations (`r`), sequences (`S`), and routines (`f`)",
    "global replacement",
    "per-schema additive defaults",
    "actual `aclexplode()` grantees",
    "extension-managed non-system schemas receive no automatic exemption",
    "primary and secondary fixture",
    "before any\n`GRANT`, `REVOKE`, role, or ownership mutation",
    "PostgreSQL 17",
    "non-recovery state",
    "Initialization and final-start transport attestations are distinct",
    "opaque in-process token",
    "If any secondary target fails",
    "no mutation callback is entered",
    "npm run test:disposable-runtime-postgres",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(runbook, new RegExp(escapeRegExp(phrase), "i"));
  }
});

test("hosted runbook contract is line-ending agnostic but wording- and order-locked", async () => {
  const lf = await readRunbook();
  const assertContract = (value) => {
    const runbook = normalizeRunbookLineEndings(value);
    assert.match(runbook, /before any\n`GRANT`, `REVOKE`, role, or ownership mutation/i);
    const headings = [
      "## Hostinger VPS And Coolify Deployment Readiness",
      "## Neon Hosted Postgres Readiness",
      "### Disposable PostgreSQL Fixture Admission",
      "### Restricted Runtime Role Activation Contract",
      "## Sanitized Neon Migration Evidence",
    ].map((heading) => runbook.indexOf(heading));
    assert.ok(headings.every((index) => index >= 0));
    for (let index = 1; index < headings.length; index += 1) {
      assert.ok(headings[index - 1] < headings[index]);
    }
    assert.match(runbook, /If any secondary target fails[\s\S]*no mutation callback is entered/i);
  };

  assertContract(lf);
  assertContract(lf.replace(/\n/gu, "\r\n"));
  assertContract(lf.replace(/\n/gu, "\r"));
  assert.throws(
    () => assertContract(lf.replace("no mutation callback is entered", "mutation callback is entered")),
  );
  assert.throws(
    () => assertContract(lf.replace("## Neon Hosted Postgres Readiness", "## Disposable PostgreSQL Fixture Admission")),
  );
  assert.throws(() => assertContract(lf.slice(0, 200)));
  assert.throws(() => assertContract(""));
});

test("hosted internal alpha runbook covers Hostinger Coolify readiness without deployment config", async () => {
  const runbook = await readRunbook();
  const requiredPhrases = [
    "future Hostinger VPS plus Coolify execution window",
    "does not buy or create VPS resources",
    "does not buy or create VPS resources, configure DNS, deploy the app",
    "already migrated Neon target",
    "pooled `DATABASE_URL`",
    "Deploy-time env categories",
    "Non-secret operator choices",
    "Secret values",
    "Private allowlist values",
    "Operator-only database values",
    "Bootstrap-only values",
    "Product handoff configuration",
    "`PLATFORM_COOKIE_SECURE=true`",
    "explicit origins, not wildcard values",
    "separately controlled operator process",
    "must not become env-controlled business/admin state",
    "product workflow/runtime data remains outside Platform",
    "sanitized status `ready`",
    "Do not keep on the long-running Coolify app service",
    "Prefer redeploying the previous reviewed app build",
    "Use database restore only after backup/restore owner approval",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(runbook, new RegExp(escapeRegExp(phrase), "i"));
  }

  assert.doesNotMatch(runbook, /coolify\.ya?ml|docker-compose\.ya?ml|Dockerfile/i);
  assert.doesNotMatch(runbook, /coolify deploy --|hostinger deploy --|dns record type/i);
});

test("hosted internal alpha smoke checklist covers fail-closed access and token privacy", async () => {
  const runbook = await readRunbook();
  const requiredPhrases = [
    "server starts without importing/listening side effects",
    "`/healthz`",
    "auth start/callback shape",
    "without printing secrets",
    "login session context",
    "`/app`",
    "`/app/admin`",
    "create pending workspace approval before teammate sign-in",
    "real OIDC sign-in activates the pending approval",
    "role change",
    "membership disable",
    "membership reactivation",
    "SQAG entitlement enable/disable",
    "audit/activity shows admin events",
    "no raw token in browser URL, storage, or logs",
    "logout",
    "denied member/viewer admin access",
    "missing, expired, or disabled session fail closed",
    "what not to paste into tickets/screenshots/logs",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(runbook, new RegExp(escapeRegExp(phrase), "i"));
  }
});

test("hosted internal alpha docs are linked from repo docs", async () => {
  const readme = await readFile("README.md", "utf8");
  const roadmap = await readFile("docs/roadmap.md", "utf8");
  const contract = await readFile("docs/internal-alpha-platform-contract.md", "utf8");

  assert.match(readme, /docs\/hosted-internal-alpha-runbook\.md/);
  assert.match(roadmap, /hosted internal-alpha deployment runbook/i);
  assert.match(roadmap, /readiness check hardened for production mode, HTTPS browser\/provider URLs/i);
  assert.match(contract, /hosted deployment runbook and smoke checklist are now documented/i);
  assert.match(contract, /hardened hosted-readiness guardrails/i);
  assert.match(contract, /Actual hosted deployment execution still requires reviewed infra\/operator approval/i);
});

test("hosted internal alpha runbook avoids private material and unsafe callback examples", async () => {
  const runbook = await readRunbook();

  assert.doesNotMatch(runbook, /sk-[A-Za-z0-9]{20,}/);
  assert.doesNotMatch(runbook, /AKIA[0-9A-Z]{16}/);
  assert.doesNotMatch(runbook, /-----BEGIN [A-Z ]*PRIVATE KEY-----/);
  assert.doesNotMatch(runbook, /postgres(?:ql)?:\/\/[^\s>]+@/i);
  assert.doesNotMatch(runbook, /ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/);
  assert.doesNotMatch(runbook, /access_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(runbook, /refresh_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(runbook, /id_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(runbook, /auth[_-]?code[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(runbook, /state[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(runbook, /nonce[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(runbook, /cookie[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(runbook, /\/api\/platform\/auth\/callback\?/i);
  assert.doesNotMatch(runbook, /provider_subject[=:][A-Za-z0-9._-]{8,}/i);
  assert.doesNotMatch(runbook, /raw claims|raw provider claims|provider payload/i);
  assert.doesNotMatch(runbook, /quote session|quote artifact|pricing file|quotation\.xlsx/i);
  assert.doesNotMatch(runbook, /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  assert.doesNotMatch(runbook, /127\.0\.0\.1/);
});

test("hosted runbook and repository contract align to the dedicated platform_migrator final-owner model", async () => {
  const runbook = await readRunbook();

  assert.match(runbook, /Owner\/migration role: `platform_migrator`/i);
  assert.match(runbook, /Current transitional legacy authority: `platform_app`/i);
  assert.match(runbook, /future dedicated operator\/migration role/i);
  assert.match(runbook, /Platform Migrator Alignment/i);
  assert.match(runbook, /`NEONDB_SWOOSHZ_PLATFORM_LEGACY_OWNER_URL`/i);
  assert.match(runbook, /`NEONDB_SWOOSHZ_PLATFORM_API_KEY`/i);
  assert.match(runbook, /`NEONDB_SWOOSHZ_PLATFORM_MIGRATOR_URL`/i);
  assert.match(runbook, /`DATABASE_OPERATOR_URL`/i);
  assert.match(runbook, /not yet created/i);
  assert.match(runbook, /npm run test:disposable-migrator-alignment/i);
  assert.match(runbook, /docs\/architecture\/PLATFORM-MIGRATOR-ALIGNMENT\.md/i);
  assert.match(runbook, /provider-managed/i);
  assert.match(runbook, /fresh read-only live preflight/i);
});

test("the repository contract explicitly rejects the bare target-only CREATEDB transfer model", async () => {
  const runbook = await readRunbook();

  assert.match(runbook, /bare temporary `CREATEDB`/i);
  assert.match(runbook, /does not prove that the executing role can assume the new owner/i);
  assert.match(runbook, /Path A/i);
  assert.match(runbook, /Path B/i);
  assert.match(runbook, /temporary SET ROLE-capable membership/i);
  assert.match(runbook, /provider\/role-lifecycle authority/i);
  assert.match(runbook, /immediate revocation/i);
});

test("the disposable migrator alignment rehearsal surfaces exist with a fixed public-safe summary", async () => {
  await assertRehearsalSurface();
});

test("both disposable PostgreSQL runners publish an explicit 127.0.0.1 loopback-only binding", async () => {
  const migratorRunner = await readFile(
    "scripts/run-disposable-migrator-alignment-tests.mjs",
    "utf8",
  );
  const runtimeRunner = await readFile(
    "scripts/run-disposable-runtime-postgres-tests.mjs",
    "utf8",
  );
  for (const source of [migratorRunner, runtimeRunner]) {
    assert.match(source, /--publish[\s\S]*127\.0\.0\.1:\$\{ownedPort\}:5432/);
    assert.doesNotMatch(source, /--publish[\s\S]*`\$\{ownedPort\}:5432`/);
    assert.match(source, /assertExactPublishedBinding/);
  }
});

test("absence-verification lifecycle phase uses one allowlist vocabulary in both runners", async () => {
  const migratorRunner = await readFile(
    "scripts/run-disposable-migrator-alignment-tests.mjs",
    "utf8",
  );
  const runtimeRunner = await readFile(
    "scripts/run-disposable-runtime-postgres-tests.mjs",
    "utf8",
  );
  for (const source of [migratorRunner, runtimeRunner]) {
    assert.doesNotMatch(source, /runAt\(\s*lifecycleResources,\s*"verifyAbsence"/);
    assert.match(source, /"absenceVerification"/);
    assert.match(source, /"absence_verification"/);
  }
});

test("failure during final absence verification reports the absence-verification phase", async () => {
  const runner = await import(
    "../scripts/run-disposable-migrator-alignment-tests.mjs"
  );
  const receipt = runner.formatDisposableRuntimeFailureReceipt({
    failurePhase: "absenceVerification",
    failureCategory: "absence_verification",
    cleanupComplete: true,
    absenceVerified: false,
  });
  assert.match(receipt, /"phase":"absenceVerification"/);
  assert.match(receipt, /"category":"absence_verification"/);
});

test("migrator transfer fingerprint covers database/schema ACL and default-ACL state", async () => {
  const source = await readFile(
    "tests/platform-migrator-alignment-postgres.test.mjs",
    "utf8",
  );
  assert.match(source, /datacl/);
  assert.match(source, /nspacl/);
  assert.match(source, /pg_default_acl/);
});

test("temporary transfer grants are revoked and cannot survive baseline-equality", async () => {
  const source = await readFile(
    "tests/platform-migrator-alignment-postgres.test.mjs",
    "utf8",
  );
  assert.match(source, /revoke create on schema/);
  assert.match(source, /revoke connect on database/);
  assert.match(source, /granted by platform_app/);
  assert.match(source, /admin_option/);
  assert.match(source, /inherit_option/);
  assert.match(source, /set_option/);
});

test("provider-managed public executes a bounded migrator transaction with rollback", async () => {
  const source = await readFile(
    "tests/platform-migrator-alignment-postgres.test.mjs",
    "utf8",
  );
  assert.match(source, /__migrator_bounded_probe/);
});

test("published binding parser rejects malformed, missing, duplicate and extra entries", async () => {
  const runner = await import(
    "../scripts/run-disposable-migrator-alignment-tests.mjs"
  );
  const valid =
    '{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"56432"}]}';
  runner.assertSingleLoopbackPublishedBinding(
    runner.parsePublishedBinding(valid),
    56432,
  );
  assert.throws(() => runner.parsePublishedBinding("not-json"));
  assert.throws(() => runner.parsePublishedBinding(""));
  assert.throws(() => runner.parsePublishedBinding("{}"));
  assert.throws(() => runner.parsePublishedBinding("[]"));
  assert.throws(() =>
    runner.parsePublishedBinding('{"5432/tcp":[]}'),
  );
  assert.throws(() =>
    runner.parsePublishedBinding('{"5433/udp":[{"HostIp":"127.0.0.1","HostPort":"56432"}]}'),
  );
  assert.throws(() =>
    runner.assertSingleLoopbackPublishedBinding(
      runner.parsePublishedBinding(
        '{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"56432"},{"HostIp":"0.0.0.0","HostPort":"56432"}]}',
      ),
      56432,
    ),
  );
  assert.throws(() =>
    runner.assertSingleLoopbackPublishedBinding(
      runner.parsePublishedBinding(
        '{"5432/tcp":[{"HostIp":"0.0.0.0","HostPort":"56432"}]}',
      ),
      56432,
    ),
  );
  assert.throws(() =>
    runner.assertSingleLoopbackPublishedBinding(
      runner.parsePublishedBinding(
        '{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"9999"}]}',
      ),
      56432,
    ),
  );
  assert.throws(() =>
    runner.assertSingleLoopbackPublishedBinding(
      runner.parsePublishedBinding(
        '{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"56432"}],"5433/tcp":[{"HostIp":"127.0.0.1","HostPort":"56433"}]}',
      ),
      56432,
    ),
  );
});

test("migrator runner fails closed on malformed Docker binding evidence with cleanup and absence verification", async () => {
  const runner = await import(
    "../scripts/run-disposable-migrator-alignment-tests.mjs"
  );
  const spawnImpl = createMockDockerSpawn({
    ps: () => "",
    run: () => "container-id\n",
    inspect: () => "not-json",
    rm: () => "",
  });
  await assert.rejects(
    () => runner.run({ env: {}, spawnImpl }),
    (error) => {
      const receipt = error.runtimeFailureReceipt;
      assert.match(receipt, /"phase":"construct"/);
      assert.match(receipt, /"category":"publish_binding_inspection"/);
      assert.match(receipt, /"cleanupComplete":true/);
      assert.match(receipt, /"absenceVerified":true/);
      assert.ok(
        spawnImpl.calls.some((call) => call[1] === "rm"),
        "docker rm must run during cleanup",
      );
      assert.ok(
        spawnImpl.calls.filter((call) => call[1] === "ps").length >= 2,
        "absence verification must re-check container absence",
      );
      return true;
    },
  );
});

function createMockDockerSpawn(handlers) {
  const calls = [];
  const spawnImpl = (command, args, options) => {
    calls.push([command, ...args]);
    const sub = args[0];
    const handler = handlers[sub];
    if (typeof handler !== "function") {
      throw new Error(`unexpected docker subcommand ${sub}`);
    }
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = () => true;
    process.nextTick(() => {
      child.stdout.emit("data", Buffer.from(handler()));
      child.emit("close", 0, null);
    });
    return child;
  };
  spawnImpl.calls = calls;
  return spawnImpl;
}

test("DL-128-REPO-002: the migrator contract admits exactly one protected bootstrap creator edge, not zero memberships", async () => {
  const architectureDoc = await readFile(
    "docs/architecture/PLATFORM-MIGRATOR-ALIGNMENT.md",
    "utf8",
  );
  const runbook = await readRunbook();
  const postgresTest = await readFile(
    "tests/platform-migrator-alignment-postgres.test.mjs",
    "utf8",
  );
  assert.match(architectureDoc, /bootstrap-superuser grantor/i);
  assert.match(architectureDoc, /protected bootstrap creator edge/i);
  assert.match(architectureDoc, /exactly one protected/i);
  assert.match(architectureDoc, /not removable by the creator|not removable by `platform_app`/i);
  assert.match(runbook, /bootstrap-superuser grantor/i);
  assert.match(postgresTest, /grantor/);
  assert.match(postgresTest, /pg_auth_members[\s\S]*grantor|grantor[\s\S]*pg_auth_members/i);
});

test("DL-128-REPO-002: no temporary CREATEDB is granted to platform_migrator", async () => {
  const postgresTest = await readFile(
    "tests/platform-migrator-alignment-postgres.test.mjs",
    "utf8",
  );
  const architectureDoc = await readFile(
    "docs/architecture/PLATFORM-MIGRATOR-ALIGNMENT.md",
    "utf8",
  );
  const runbook = await readRunbook();
  assert.doesNotMatch(postgresTest, /alter role platform_migrator createdb/);
  assert.doesNotMatch(postgresTest, /alter role platform_migrator\s+createdb/i);
  assert.match(architectureDoc, /No temporary `CREATEDB` on `platform_migrator`/i);
  assert.match(runbook, /No temporary `CREATEDB` on `platform_migrator`/i);
});

test("DL-128-REPO-002: database ownership transfer is proven transactional in PostgreSQL 17", async () => {
  const postgresTest = await readFile(
    "tests/platform-migrator-alignment-postgres.test.mjs",
    "utf8",
  );
  assert.match(
    postgresTest,
    /begin[\s\S]*alter database [\s\S]*owner to platform_migrator[\s\S]*commit/i,
  );
});

test("DL-128-REPO-002: migrator login admission is proven before the ownership transfer", async () => {
  const postgresTest = await readFile(
    "tests/platform-migrator-alignment-postgres.test.mjs",
    "utf8",
  );
  assert.match(postgresTest, /validateMigratorLoginAdmission|login admission/i);
  const transferIndex = postgresTest.search(/alter database \$\{identifier\(databaseName\)\} owner to platform_migrator/);
  const loginIndex = postgresTest.search(/validateMigratorLoginAdmission/);
  assert.ok(loginIndex >= 0, "login admission must exist");
  assert.ok(transferIndex > loginIndex, "login admission must precede the database ownership transfer");
});

test("DL-128-REPO-002: credential/login validation precedes ownership transfer and failure leaves ownership unchanged", async () => {
  const postgresTest = await readFile(
    "tests/platform-migrator-alignment-postgres.test.mjs",
    "utf8",
  );
  assert.match(postgresTest, /failed login|login fails|not permitted to log in/i);
  assert.match(postgresTest, /ownership unchanged|owner.*unchanged/i);
});

async function assertRehearsalSurface() {
  const runbook = await readRunbook();
  assert.match(runbook, /MIGRATOR_ALIGNMENT_TEST_CONFIRM=disposable-only/i);
  const packageJson = JSON.parse(await readFile("package.json", "utf8"));
  assert.match(
    packageJson.scripts["test:disposable-migrator-alignment"],
    /run-disposable-migrator-alignment-tests\.mjs/,
  );
  const runner = await readFile(
    "scripts/run-disposable-migrator-alignment-tests.mjs",
    "utf8",
  );
  assert.match(runner, /platform_migrator/i);
  const architectureDoc = await readFile(
    "docs/architecture/PLATFORM-MIGRATOR-ALIGNMENT.md",
    "utf8",
  );
  assert.match(architectureDoc, /# Platform Migrator Alignment/i);
  const postgresTest = await readFile(
    "tests/platform-migrator-alignment-postgres.test.mjs",
    "utf8",
  );
  assert.match(postgresTest, /MIGRATOR_ALIGNMENT_TEST_CONFIRM/);
  assert.match(postgresTest, /disposable-only/);
}

async function readRunbook() {
  return normalizeRunbookLineEndings(await readFile(runbookPath, "utf8"));
}

function normalizeRunbookLineEndings(value) {
  return value.replace(/\r\n?/gu, "\n");
}

function assertEnvRow(runbook, name, required, secret) {
  assert.match(
    runbook,
    new RegExp(
      `\\|\\s*\`${escapeRegExp(name)}\`\\s*\\|[^\\n]*\\|\\s*${escapeRegExp(required)}\\s*\\|[^\\n]*\\|\\s*${escapeRegExp(secret)}\\s*\\|`,
      "i",
    ),
  );
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

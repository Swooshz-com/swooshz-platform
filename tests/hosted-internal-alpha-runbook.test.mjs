import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import {
  access,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
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
    "runner-owned empty PGPASSFILE",
    "hostile ambient default password file",
    "omitted-password rejection at the real focused-child boundary",
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

test("the runbook distinguishes mechanical DROP rejection from controller-gated NOLOGIN", async () => {
  const runbook = await readRunbook();
  assert.match(runbook, /\x60DROP ROLE platform_app\x60 is mechanically rejected while dependent objects or ownership remain/i);
  assert.match(runbook, /\x60ALTER ROLE platform_app NOLOGIN\x60 is not mechanically prevented by PostgreSQL/i);
  assert.match(runbook, /controller-sequenced and separately live-authorised/i);
  assert.match(runbook, /disposable rehearsal deliberately proves only reversible NOLOGIN behaviour/i);
  assert.match(runbook, /no live NOLOGIN authority is granted/i);
  assert.match(runbook, /legacy authority remains available for rollback until the completion point/i);
});
test("Run-12 dedicated migrator volume finality contract is complete", async () => {
  const runner = await readFile(
    "scripts/run-disposable-migrator-alignment-tests.mjs",
    "utf8",
  );
  const architectureDoc = await readFile(
    "docs/architecture/PLATFORM-MIGRATOR-ALIGNMENT.md",
    "utf8",
  );
  const runbook = await readRunbook();
  const volumeName = "deepseek-platform128-pg17-data";
  const checks = [
    {
      label: "exact named volume identity",
      satisfied: new RegExp(
        `const ownedVolumeName = ["']${volumeName}["']`,
      ).test(runner),
    },
    {
      label: "pre-existing exact-volume rejection",
      satisfied:
        /volume_preexistence/.test(runner) &&
        /assertExactVolumeAbsent\(spawnImpl\)/.test(runner),
    },
    {
      label: "explicit named-volume mount",
      satisfied:
        /--mount/.test(runner) &&
        /type=volume,source=\$\{ownedVolumeName\},destination=\$\{ownedPgDataPath\}/.test(
          runner,
        ),
    },
    {
      label: "exact mount destination",
      satisfied: /const ownedPgDataPath = ["']\/var\/lib\/postgresql\/data["']/.test(
        runner,
      ),
    },
    {
      label: "exact mount identity check",
      satisfied:
        /assertExactVolumeMount\(spawnImpl\)/.test(runner) &&
        /assertSingleOwnedVolumeMount\(parseContainerMounts\(output\)\)/.test(
          runner,
        ) &&
        /mount\.Type !== ["']volume["']/.test(runner) &&
        /mount\.Name !== ownedVolumeName/.test(runner) &&
        /mount\.Destination !== ownedPgDataPath/.test(runner) &&
        /mount\.RW !== true/.test(runner),
    },
    {
      label: "exact owned volume removal",
      satisfied: /["']volume["'],\s*["']rm["'],\s*ownedVolumeName/.test(
        runner,
      ),
    },
    {
      label: "exact post-cleanup volume absence proof",
      satisfied:
        /volumeAbsenceVerified/.test(runner) &&
        (runner.match(/assertExactVolumeAbsent\(spawnImpl\)/g) ?? [])
          .length >= 2,
    },
    {
      label: "architecture documentation parity",
      satisfied:
        new RegExp(
          `exact named PostgreSQL data volume[\\s\\S]*${volumeName}`,
          "i",
        ).test(architectureDoc) &&
        /exact volume removal/i.test(architectureDoc) &&
        /exact volume absence/i.test(architectureDoc),
    },
    {
      label: "hosted runbook documentation parity",
      satisfied:
        new RegExp(
          `exact named PostgreSQL data volume[\\s\\S]*${volumeName}`,
          "i",
        ).test(runbook) &&
        /exact volume removal/i.test(runbook) &&
        /exact volume absence/i.test(runbook),
    },
    {
      label: "fresh per-run ownership token",
      satisfied:
        /randomUUID\(\)/.test(runner) &&
        /volumeOwnershipTokenLabelKey/.test(runner) &&
        /volumeOwnershipToken: createVolumeOwnershipToken\(\)/.test(runner) &&
        /resources\.volumeOwnershipToken/.test(runner) &&
        !/volumeOwnershipToken.*formatDisposableRuntimeFailureReceipt/.test(runner),
    },
    {
      label: "single bounded owned-volume removal path",
      satisfied:
        /resources\.volumeCreateAttempted && !resources\.volumeRemoved/.test(runner) &&
        (runner.match(/\[\s*"volume",\s*"rm",\s*ownedVolumeName\s*\]/g) ?? [])
          .length === 1 &&
        /once `volumeRemoved=true`, no second attempt/i.test(architectureDoc) &&
        /no second attempt after `volumeRemoved=true`/i.test(runbook),
    },
    {
      label: "token and retirement documentation parity",
      satisfied:
        /fresh in-memory ownership token/i.test(architectureDoc) &&
        /fresh in-memory ownership token/i.test(runbook) &&
        /DROP ROLE platform_app[\s\S]*NOLOGIN.*controller-gated/i.test(runbook),
    },
    {
      label: "broad/global volume pruning prohibition",
      satisfied:
        /broad\/global Docker volume\s+pruning\s+is\s+prohibited/i.test(
          architectureDoc,
        ) &&
        /broad\/global Docker volume\s+pruning\s+is\s+prohibited/i.test(runbook) &&
        !/docker\s+(?:volume|system)\s+prune/i.test(runner),
    },
  ];
  const missing = checks.filter((check) => !check.satisfied).map((check) => check.label);
  assert.deepEqual(
    missing,
    [],
    `Run-12 named-volume contract missing: ${JSON.stringify(missing)}`,
  );
});

test("disposable PostgreSQL runners use loopback binding with runtime ephemeral allocation", async () => {
  const migratorRunner = await readFile(
    "scripts/run-disposable-migrator-alignment-tests.mjs",
    "utf8",
  );
  const runtimeRunner = await readFile(
    "scripts/run-disposable-runtime-postgres-tests.mjs",
    "utf8",
  );
  assert.match(
    migratorRunner,
    /--publish[\s\S]*127\.0\.0\.1:\$\{ownedPort\}:5432/,
  );
  assert.match(migratorRunner, /assertExactPublishedBinding/);
  assert.match(runtimeRunner, /--publish[\s\S]*127\.0\.0\.1::5432/);
  assert.doesNotMatch(runtimeRunner, /\b55432\b/);
  assert.match(runtimeRunner, /fixtureUrls\(resources\.observedPort\)/);
  assert.match(runtimeRunner, /assertPortAbsent\(resources\.observedPort\)/);
  assert.match(runtimeRunner, /resources\.observedPort/);
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

test("structured migrator failure receipts use an out-of-band sidecar at the actual child boundary", async () => {
  const runner = await import(
    "../scripts/run-disposable-migrator-alignment-tests.mjs"
  );
  const result = await runStructuredReceiptTransportChild(runner, "child-boundary");
  const expected = {
    version: 1,
    test_id: "DL-128-REPO-011-A3-child-boundary",
    phase: "post_reverse_exact_fingerprint",
    assertion_category: "exact_reverse_rollback",
    fingerprint_fields: ["databaseAcl"],
    tuple_counts: ["databaseAcl:1/1"],
    cleanup_phase: "complete",
  };
  assert.equal(result.exitCode, 1);
  assert.equal(result.signal, null);
  assert.deepEqual(result.receipt, expected);
  assert.deepEqual(result.progress, {
    ...expected,
    transport_state: "failure_receipt_write_armed",
  });
  assert.deepEqual(result.diagnostics, { kind: "final", receipt: expected });
  assert.match(result.stdout, /TAP-looking|spec|not ok/i);
  assert.match(
    result.stdout + result.stderr,
    /spec-looking|failure|not ok/i,
  );
  assert.doesNotMatch(
    result.stdout + result.stderr,
    /PLATFORM_MIGRATOR_FAILURE_V1=/,
  );
  const runnerSource = await readFile(
    "scripts/run-disposable-migrator-alignment-tests.mjs",
    "utf8",
  );
  const childSource = await readFile(
    "tests/platform-migrator-alignment-postgres.test.mjs",
    "utf8",
  );
  assert.match(
    runnerSource,
    /PLATFORM_MIGRATOR_FAILURE_RECEIPT_FILE/,
  );
  assert.match(runnerSource, /PLATFORM_MIGRATOR_FAILURE_PROGRESS_FILE/);
  assert.match(childSource, /renameSync\(temporaryPath, filePath\)/);
  assert.doesNotMatch(
    runnerSource,
    /parseStructuredFailureReceipt\(\s*Buffer\.concat/,
  );
  assert.match(childSource, /flag: "wx"/);
  assert.doesNotMatch(
    childSource,
    /structuredFailureReceiptPrefix[^\\n]*process\\.stdout|process\\.stderr[^\\n]*structuredFailureReceiptPrefix/,
  );
  assert.equal(result.filePresentAfterCleanup, false);
  assert.equal(result.directoryPresentAfterCleanup, false);
  assert.ok(resolve(result.filePath).startsWith(resolve(tmpdir())));
  assert.notEqual(
    relative(resolve(process.cwd()), resolve(result.filePath)).startsWith(".."),
    false,
    "sidecar must be outside the repository",
  );
  assert.equal(
    runner.parseStructuredFailureReceipt(
      "TAP version 13\nnot ok 1 - reporter noise\n" +
        result.sidecarContent,
    ),
    null,
  );

  const publicReceipt = runner.formatDisposableRuntimeFailureReceipt({
    failurePhase: "runFocusedTests",
    failureCategory: "child_test_failure",
    childExitCode: result.exitCode,
    childSignal: false,
    structuredChildReceipt: {
      ...expected,
      child_exit_code: result.exitCode,
      child_signal: null,
      runner_category: "child_test_failure",
      sidecar_path: result.filePath,
      sidecar_content: result.sidecarContent,
      unknown: "do-not-leak",
    },
    structuredChildProgress: {
      ...result.progress,
      progress_path: result.progressFilePath,
      progress_content: result.progressSidecarContent,
      unknown: "do-not-leak",
    },
  });
  assert.doesNotMatch(publicReceipt, new RegExp(escapeRegExp(result.filePath)));
  assert.doesNotMatch(publicReceipt, new RegExp(escapeRegExp(result.sidecarContent)));
  assert.doesNotMatch(publicReceipt, new RegExp(escapeRegExp(result.progressFilePath)));
  assert.doesNotMatch(publicReceipt, new RegExp(escapeRegExp(result.progressSidecarContent)));
  assert.doesNotMatch(publicReceipt, /PLATFORM_MIGRATOR_FAILURE_V1=|do-not-leak/i);
  assert.match(publicReceipt, /"test_id":"DL-128-REPO-011-A3-child-boundary"/);
  assert.match(publicReceipt, /"child_exit_code":1/);
  assert.match(publicReceipt, /"child_signal":null/);
  assert.match(publicReceipt, /"transport_state":"failure_receipt_write_armed"/);
});

test("abrupt child exit leaves durable progress without a final receipt", async () => {
  const runner = await import(
    "../scripts/run-disposable-migrator-alignment-tests.mjs"
  );
  const result = await runStructuredReceiptTransportChild(
    runner,
    "abrupt-exit-boundary",
  );
  assert.notEqual(result.exitCode, 0);
  assert.equal(result.signal, null);
  assert.equal(result.receipt, null);
  assert.deepEqual(result.progress, {
    version: 1,
    test_id: "DL-128-REPO-011-A3-abrupt-exit",
    phase: "post_reverse_exact_fingerprint",
    assertion_category: "exact_reverse_rollback",
    fingerprint_fields: ["databaseAcl"],
    tuple_counts: ["databaseAcl:1/1"],
    cleanup_phase: "complete",
    transport_state: "phase_armed",
  });
  assert.deepEqual(result.diagnostics, {
    kind: "progress",
    progress: result.progress,
  });
  assert.doesNotMatch(
    result.stdout + result.stderr,
    /PLATFORM_MIGRATOR_FAILURE_V1=|C:\\|\\Users\\/i,
  );
  assert.equal(result.filePresentAfterCleanup, false);
  assert.equal(result.progressFilePresentAfterCleanup, false);
  assert.equal(result.directoryPresentAfterCleanup, false);
});

test("final receipt writer failure preserves the causal progress checkpoint", async () => {
  const runner = await import(
    "../scripts/run-disposable-migrator-alignment-tests.mjs"
  );
  const result = await runStructuredReceiptTransportChild(
    runner,
    "writer-failure-boundary",
  );
  assert.equal(result.exitCode, 1);
  assert.equal(result.signal, null);
  assert.equal(result.receipt, null);
  assert.deepEqual(result.progress, {
    version: 1,
    test_id: "DL-128-REPO-011-A3-writer-failure",
    phase: "post_reverse_exact_fingerprint",
    assertion_category: "exact_reverse_rollback",
    fingerprint_fields: ["databaseAcl"],
    tuple_counts: ["databaseAcl:1/1"],
    cleanup_phase: "complete",
    transport_state: "failure_receipt_write_armed",
  });
  assert.deepEqual(result.diagnostics, {
    kind: "progress",
    progress: result.progress,
  });
  assert.doesNotMatch(
    result.stdout + result.stderr,
    /PLATFORM_MIGRATOR_FAILURE_V1=|EACCES|EEXIST|permission denied/i,
  );
  assert.equal(result.filePresentAfterCleanup, false);
  assert.equal(result.progressFilePresentAfterCleanup, false);
  assert.equal(result.directoryPresentAfterCleanup, false);
});

test("structured sidecar duplicate, malformed, missing, oversized, and unknown fields fail closed", async () => {
  const runner = await import(
    "../scripts/run-disposable-migrator-alignment-tests.mjs"
  );
  const prefix = "PLATFORM_MIGRATOR_FAILURE_V1=";
  const receipt = {
    version: 1,
    test_id: "DL-128-REPO-011-A3-sidecar-fixture",
    phase: "post_reverse_exact_fingerprint",
    assertion_category: "exact_reverse_rollback",
    fingerprint_fields: ["databaseAcl", "memberships"],
    tuple_counts: ["databaseAcl:3/4", "memberships:0/0"],
    cleanup_phase: "complete",
  };
  const serialized = prefix + JSON.stringify(receipt) + "\n";
  const progress = {
    version: 1,
    test_id: receipt.test_id,
    phase: receipt.phase,
    assertion_category: receipt.assertion_category,
    fingerprint_fields: receipt.fingerprint_fields,
    tuple_counts: receipt.tuple_counts,
    cleanup_phase: receipt.cleanup_phase,
    transport_state: "phase_armed",
  };
  const serializedProgress = JSON.stringify(progress) + "\n";

  const validSidecar = await runner.createStructuredFailureReceiptSidecar();
  try {
    await writeFile(validSidecar.filePath, serialized, {
      encoding: "utf8",
      flag: "wx",
    });
    await assert.rejects(
      () => writeFile(validSidecar.filePath, prefix + "replacement\n", {
        encoding: "utf8",
        flag: "wx",
      }),
      (error) => error?.code === "EEXIST",
    );
    assert.deepEqual(
      await runner.readStructuredFailureReceiptFile(validSidecar.filePath),
      receipt,
    );
    assert.equal(
      await runner.readStructuredFailureReceiptFile(
        validSidecar.filePath + ".missing",
      ),
      null,
    );
  } finally {
    await runner.cleanupStructuredFailureReceiptSidecar(validSidecar);
  }

  const malformedSidecar = await runner.createStructuredFailureReceiptSidecar();
  try {
    await writeFile(malformedSidecar.filePath, prefix + "{\n", "utf8");
    assert.equal(
      await runner.readStructuredFailureReceiptFile(malformedSidecar.filePath),
      null,
    );
  } finally {
    await runner.cleanupStructuredFailureReceiptSidecar(malformedSidecar);
  }

  const duplicateSentinelSidecar = await runner.createStructuredFailureReceiptSidecar();
  try {
    await writeFile(
      duplicateSentinelSidecar.filePath,
      serialized + serialized,
      "utf8",
    );
    assert.equal(
      await runner.readStructuredFailureReceiptFile(
        duplicateSentinelSidecar.filePath,
      ),
      null,
    );
  } finally {
    await runner.cleanupStructuredFailureReceiptSidecar(
      duplicateSentinelSidecar,
    );
  }

  const oversizedSidecar = await runner.createStructuredFailureReceiptSidecar();
  try {
    await writeFile(
      oversizedSidecar.filePath,
      serialized + "x".repeat(16 * 1024),
      "utf8",
    );
    await writeFile(oversizedSidecar.progressFilePath, serializedProgress, { flag: "wx" });
    assert.equal(
      await runner.readStructuredFailureReceiptFile(oversizedSidecar.filePath),
      null,
    );
    assert.deepEqual(
      await runner.readStructuredChildFailureDiagnostics(oversizedSidecar),
      { kind: "final_invalid" },
    );
  } finally {
    await runner.cleanupStructuredFailureReceiptSidecar(oversizedSidecar);
  }

  const unknownFieldsSidecar = await runner.createStructuredFailureReceiptSidecar();
  try {
    await writeFile(
      unknownFieldsSidecar.filePath,
      prefix + JSON.stringify({
        ...receipt,
        sidecar_path: unknownFieldsSidecar.filePath,
        secret: "do-not-leak",
        nested: { token: "do-not-leak" },
      }) + "\n",
      "utf8",
    );
    assert.deepEqual(
      await runner.readStructuredFailureReceiptFile(
        unknownFieldsSidecar.filePath,
      ),
      receipt,
    );
  } finally {
    await runner.cleanupStructuredFailureReceiptSidecar(
      unknownFieldsSidecar,
    );
  }

  const precedenceSidecar = await runner.createStructuredFailureReceiptSidecar();
  try {
    await writeFile(precedenceSidecar.filePath, serialized, { flag: "wx" });
    await writeFile(precedenceSidecar.progressFilePath, serializedProgress, { flag: "wx" });
    assert.deepEqual(
      await runner.readStructuredChildFailureDiagnostics(precedenceSidecar),
      { kind: "final", receipt },
    );
  } finally {
    await runner.cleanupStructuredFailureReceiptSidecar(precedenceSidecar);
  }

  const progressFallbackSidecar = await runner.createStructuredFailureReceiptSidecar();
  try {
    await writeFile(progressFallbackSidecar.progressFilePath, JSON.stringify({
      ...progress,
      private_path: progressFallbackSidecar.progressFilePath,
      private_value: "do-not-leak",
    }) + "\n", { flag: "wx" });
    assert.deepEqual(
      await runner.readStructuredChildFailureDiagnostics(progressFallbackSidecar),
      { kind: "progress", progress },
    );
  } finally {
    await runner.cleanupStructuredFailureReceiptSidecar(progressFallbackSidecar);
  }

  const malformedFinalSidecar = await runner.createStructuredFailureReceiptSidecar();
  try {
    await writeFile(malformedFinalSidecar.filePath, prefix + "{\n", { flag: "wx" });
    await writeFile(malformedFinalSidecar.progressFilePath, serializedProgress, { flag: "wx" });
    assert.deepEqual(
      await runner.readStructuredChildFailureDiagnostics(malformedFinalSidecar),
      { kind: "final_invalid" },
    );
  } finally {
    await runner.cleanupStructuredFailureReceiptSidecar(malformedFinalSidecar);
  }

  const malformedProgressSidecar = await runner.createStructuredFailureReceiptSidecar();
  try {
    await writeFile(malformedProgressSidecar.progressFilePath, "{\n", { flag: "wx" });
    assert.deepEqual(
      await runner.readStructuredChildFailureDiagnostics(malformedProgressSidecar),
      { kind: "progress_invalid" },
    );
  } finally {
    await runner.cleanupStructuredFailureReceiptSidecar(malformedProgressSidecar);
  }

  const oversizedProgressSidecar = await runner.createStructuredFailureReceiptSidecar();
  try {
    await writeFile(oversizedProgressSidecar.progressFilePath, "x".repeat(16 * 1024 + 1), { flag: "wx" });
    assert.deepEqual(
      await runner.readStructuredChildFailureDiagnostics(oversizedProgressSidecar),
      { kind: "progress_invalid" },
    );
  } finally {
    await runner.cleanupStructuredFailureReceiptSidecar(oversizedProgressSidecar);
  }

  const missingReceipt = runner.formatDisposableRuntimeFailureReceipt({
    failurePhase: "runFocusedTests",
    failureCategory: "structured_child_context_missing",
    structuredChildProgress: null,
  });
  assert.match(missingReceipt, /"category":"structured_child_context_missing"/);
  assert.doesNotMatch(missingReceipt, /do-not-leak|PLATFORM_MIGRATOR_FAILURE_V1=/i);
});

test("duplicate child receipt writes preserve the first sidecar receipt", async () => {
  const runner = await import(
    "../scripts/run-disposable-migrator-alignment-tests.mjs"
  );
  const result = await runStructuredReceiptTransportChild(
    runner,
    "duplicate-boundary",
  );
  assert.equal(result.exitCode, 1);
  assert.equal(result.signal, null);
  assert.equal(result.receipt?.test_id, "DL-128-REPO-011-A3-first-receipt");
  assert.equal(result.diagnostics?.kind, "final");
  assert.equal(result.filePresentAfterCleanup, false);
  assert.equal(result.directoryPresentAfterCleanup, false);
});

test("zero child exit succeeds without a failure sidecar", async () => {
  const runner = await import(
    "../scripts/run-disposable-migrator-alignment-tests.mjs"
  );
  const result = await runStructuredReceiptTransportChild(runner, "zero");
  assert.equal(result.exitCode, 0);
  assert.equal(result.signal, null);
  assert.equal(result.receipt, null);
  assert.equal(result.progress, null);
  assert.equal(result.diagnostics.kind, "missing");
  assert.equal(result.sidecarContent, null);
  assert.equal(result.progressSidecarContent, null);
  assert.equal(result.filePresentAfterCleanup, false);
  assert.equal(result.directoryPresentAfterCleanup, false);
});

test("zero-exit migrator child summary validation fails closed except for the exact seven-test shape", async () => {
  const runner = await import("../scripts/run-disposable-migrator-alignment-tests.mjs");
  const summary = ({
    tests = 7,
    suites = 0,
    passed = 7,
    failed = 0,
    cancelled = 0,
    skipped = 0,
    todo = 0,
    duration = "12.5",
  } = {}) =>
    [
      "# tests " + tests,
      "# suites " + suites,
      "# pass " + passed,
      "# fail " + failed,
      "# cancelled " + cancelled,
      "# skipped " + skipped,
      "# todo " + todo,
      "# duration_ms " + duration,
    ].join("\n");
  const exactSummary = summary();
  const controls = [
    ["zero exit + missing summary", ""],
    ["zero exit + malformed summary", "# tests 7\n# suites 0\n# pass 7"],
    ["zero exit + wrong totals", summary({ tests: 6, passed: 6 })],
    ["zero exit + unexpected skipped count", summary({ passed: 6, skipped: 1 })],
    ["zero exit + duplicated summary", exactSummary + "\n" + exactSummary],
    ["zero exit + inconsistent totals", summary({ failed: 1 })],
  ];
  for (const [label, output] of controls) {
    assert.equal(
      runner.validateDisposableMigratorAlignmentChildSummary({ code: 0, signal: null, output }),
      null,
      label,
    );
  }
  assert.deepEqual(
    runner.validateDisposableMigratorAlignmentChildSummary({ code: 0, signal: null, output: exactSummary }),
    { cancelled: 0, failed: 0, passed: 7, skipped: 0, todo: 0, total: 7 },
  );
});
async function runStructuredReceiptTransportChild(runner, mode) {
  const sidecar = await runner.createStructuredFailureReceiptSidecar();
  const output = { stdout: "", stderr: "" };
  let childResult = null;
  let receipt = null;
  let progress = null;
  let diagnostics = null;
  let sidecarContent = null;
  let progressSidecarContent = null;
  const childEnv = {
    NODE_ENV: "test",
    PLATFORM_MIGRATOR_FAILURE_RECEIPT_FILE: sidecar.filePath,
    PLATFORM_MIGRATOR_FAILURE_PROGRESS_FILE: sidecar.progressFilePath,
  };
  for (const key of ["PATH", "SystemRoot", "WINDIR"]) {
    if (typeof process.env[key] === "string") childEnv[key] = process.env[key];
  }
  try {
    let child;
    if (mode === "zero") {
      child = spawn(
        process.execPath,
        ["--input-type=module", "-e", "process.exit(0)"],
        { cwd: process.cwd(), env: childEnv, stdio: ["ignore", "pipe", "pipe"], windowsHide: true },
      );
    } else {
      childEnv.PLATFORM_MIGRATOR_FAILURE_RECEIPT_TEST = mode;
      child = spawn(
        process.execPath,
        [
          "--test-reporter=spec",
          "--test",
          "tests/platform-migrator-alignment-postgres.test.mjs",
        ],
        { cwd: process.cwd(), env: childEnv, stdio: ["ignore", "pipe", "pipe"], windowsHide: true },
      );
    }
    child.stdout?.on("data", (chunk) => {
      if (output.stdout.length < 8 * 1024) {
        output.stdout += Buffer.from(chunk).toString("utf8");
      }
    });
    child.stderr?.on("data", (chunk) => {
      if (output.stderr.length < 8 * 1024) {
        output.stderr += Buffer.from(chunk).toString("utf8");
      }
    });
    childResult = await new Promise((resolvePromise, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => {
        resolvePromise({ exitCode: code, signal });
      });
    });
    receipt = await runner.readStructuredFailureReceiptFile(sidecar.filePath);
    progress = await runner.readStructuredFailureProgressFile(sidecar.progressFilePath);
    diagnostics = await runner.readStructuredChildFailureDiagnostics(sidecar);
    try {
      sidecarContent = await readFile(sidecar.filePath, "utf8");
    } catch {
      sidecarContent = null;
    }
    try {
      progressSidecarContent = await readFile(sidecar.progressFilePath, "utf8");
    } catch {
      progressSidecarContent = null;
    }
  } finally {
    await runner.cleanupStructuredFailureReceiptSidecar(sidecar);
  }
  let filePresentAfterCleanup = false;
  let directoryPresentAfterCleanup = false;
  try {
    await access(sidecar.filePath);
    filePresentAfterCleanup = true;
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  try {
    await access(sidecar.directory);
    directoryPresentAfterCleanup = true;
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  return {
    ...childResult,
    ...output,
    receipt,
    sidecarContent,
    progressSidecarContent,
    progress,
    diagnostics,
    filePath: sidecar.filePath,
    progressFilePath: sidecar.progressFilePath,
    filePresentAfterCleanup,
    progressFilePresentAfterCleanup: await pathIsPresent(sidecar.progressFilePath),
    directoryPresentAfterCleanup,
  };
}
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

test("dynamic runtime binding validates the assigned port and propagates it", async () => {
  const runner = await import(
    "../scripts/run-disposable-runtime-postgres-tests.mjs"
  );
  const valid =
    '{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"49152"}]}';
  assert.equal(
    runner.assertSingleLoopbackPublishedBinding(
      runner.parsePublishedBinding(valid),
    ),
    49152,
  );
  const urls = runner.fixtureUrls(49152);
  assert.ok(Object.values(urls).every((value) => value.includes(":49152/")));
  const receipt = runner.formatDisposableRuntimeFailureReceipt({
    observedPort: 49152,
  });
  assert.match(receipt, /"publishedBindingVerified":true/);
  assert.match(receipt, /"observedPort":49152/);
  for (const raw of [
    "not-json",
    "",
    "{}",
    "[]",
    '{"5432/tcp":null}',
    '{"5432/tcp":[]}',
    '{"5433/udp":[{"HostIp":"127.0.0.1","HostPort":"49152"}]}',
    '{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"49152"},{"HostIp":"127.0.0.1","HostPort":"49153"}]}',
    '{"5432/tcp":[{"HostIp":"0.0.0.0","HostPort":"49152"}]}',
    '{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"not-a-port"}]}',
    '{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":""}]}',
    '{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"1.5"}]}',
    '{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"0"}]}',
    '{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"65536"}]}',
    '{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"49152"}],"5433/tcp":[{"HostIp":"127.0.0.1","HostPort":"49153"}]}',
  ]) {
    assert.throws(() =>
      runner.assertSingleLoopbackPublishedBinding(
        runner.parsePublishedBinding(raw),
      ),
    );
  }
  assert.throws(() => runner.fixtureUrls(0));
  assert.throws(() => runner.fixtureUrls(65_536));
});

test("migrator runner fails closed on malformed Docker binding evidence with cleanup and absence verification", async () => {
  const runner = await import(
    "../scripts/run-disposable-migrator-alignment-tests.mjs"
  );
  let mockVolumeCreated = false;
  let mockVolumeLabels = {};
  const spawnImpl = createMockDockerSpawn({
    ps: () => "",
    volume: (operation, ...rest) => {
      const operationArgs = [operation, ...rest];
      const action = operationArgs[0];
      if (action === "create") {
        mockVolumeLabels = parseVolumeCreateLabels(operationArgs);
        mockVolumeCreated = true;
        return `${run14OwnedVolumeName}\n`;
      }
      if (action === "ls") return mockVolumeCreated ? `${run14OwnedVolumeName}\n` : "";
      if (action === "inspect") {
        return `${JSON.stringify({
          Name: run14OwnedVolumeName,
          Labels: mockVolumeLabels,
        })}\n`;
      }
      if (action === "rm") mockVolumeCreated = false;
      return "";
    },
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
      assert.ok(
        spawnImpl.calls.some(
          (call) =>
            call[1] === "volume" &&
            call[2] === "rm" &&
            call[3] === "deepseek-platform128-pg17-data",
        ),
        "docker volume rm must run during cleanup",
      );
      assert.ok(
        spawnImpl.calls.filter(
          (call) => call[1] === "volume" && call[2] === "ls",
        ).length >= 2,
        "volume absence must be checked before and after the run",
      );
      return true;
    },
  );
});

test("Run-18 production runner reconciles daemon-created nonzero volume once with final absence", async () => {
  const runner = await import(
    "../scripts/run-disposable-migrator-alignment-tests.mjs",
  );
  const ownershipTokens = [];

  for (let attempt = 0; attempt < 2; attempt += 1) {
    const spawnImpl = createDaemonCreatedNonzeroVolumeSpawn();
    await assert.rejects(
      () => runner.run({ env: {}, spawnImpl }),
      (error) => {
        const receipt = error.runtimeFailureReceipt;
        assert.match(receipt, /"category":"volume_create"/);
        assert.match(receipt, /"cleanupComplete":true/);
        assert.match(receipt, /"absenceVerified":true/);
        assert.match(receipt, /"volumeRemoved":true/);
        assert.match(receipt, /"volumeAbsenceVerified":true/);
        assert.equal(spawnImpl.volumeRmCalls(), 1);
        assert.equal(spawnImpl.volumeExists(), false);
        assert.equal(spawnImpl.volumeLsCalls(), 3);
        assert.doesNotMatch(
          receipt,
          new RegExp(escapeRegExp(spawnImpl.ownershipToken)),
        );
        ownershipTokens.push(spawnImpl.ownershipToken);
        return true;
      },
    );
  }

  assert.notEqual(
    ownershipTokens[0],
    ownershipTokens[1],
    "each runner invocation must use a fresh ownership token",
  );
});

function createDaemonCreatedNonzeroVolumeSpawn() {
  let volumeExists = false;
  let volumeLabels = {};
  const calls = [];
  const spawnImpl = (command, args, options = {}) => {
    calls.push({ command, args: [...args], options });
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    queueMicrotask(() => {
      let stdout = "";
      let code = 0;
      if (args[0] === "ps") {
        stdout = "";
      } else if (args[0] === "volume") {
        const action = args[1];
        if (action === "ls") {
          stdout = volumeExists ? `${run14OwnedVolumeName}\n` : "";
        } else if (action === "create") {
          volumeLabels = parseVolumeCreateLabels(args);
          volumeExists = true;
          code = 1;
        } else if (action === "inspect") {
          stdout = `${JSON.stringify({
            Name: run14OwnedVolumeName,
            Labels: volumeLabels,
          })}\n`;
        } else if (action === "rm") {
          volumeExists = false;
          stdout = `${run14OwnedVolumeName}\n`;
        } else {
          throw new Error(`unexpected volume action ${action}`);
        }
      } else {
        throw new Error(`unexpected docker command ${args[0]}`);
      }
      if (stdout) child.stdout.emit("data", Buffer.from(stdout));
      child.emit("close", code, null);
    });
    return child;
  };
  spawnImpl.calls = calls;
  spawnImpl.volumeExists = () => volumeExists;
  spawnImpl.volumeRmCalls = () => calls.filter(
    ({ args }) => args[0] === "volume" && args[1] === "rm",
  ).length;
  spawnImpl.volumeLsCalls = () => calls.filter(
    ({ args }) => args[0] === "volume" && args[1] === "ls",
  ).length;
  Object.defineProperty(spawnImpl, "ownershipToken", {
    get: () => volumeLabels[run18VolumeOwnershipTokenLabelKey],
  });
  return spawnImpl;
}

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
      child.stdout.emit("data", Buffer.from(handler(...args.slice(1))));
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

test("DL-128-REPO-003: SET=false and INHERIT=false with ADMIN=true is documented as accident protection, not a security boundary", async () => {
  const architectureDoc = await readFile(
    "docs/architecture/PLATFORM-MIGRATOR-ALIGNMENT.md",
    "utf8",
  );
  const runbook = await readRunbook();
  const decisions = await readFile(
    "docs/hosted-internal-alpha-operator-decisions.md",
    "utf8",
  );
  for (const source of [architectureDoc, runbook]) {
    assert.match(
      source,
      new RegExp(
        whitespaceTolerant("`SET=false` and `INHERIT=false` do not create a security boundary while `ADMIN=true` remains"),
        "i",
      ),
    );
    assert.match(
      source,
      new RegExp(whitespaceTolerant("The automatic edge protects against accidents only"), "i"),
    );
    assert.match(
      source,
      new RegExp(whitespaceTolerant("Provider revocation is mandatory before final acceptance"), "i"),
    );
    assert.match(
      source,
      new RegExp(whitespaceTolerant("Final migrator membership is zero"), "i"),
    );
  }
  assert.match(decisions, /`DL-128-REPO-003`/i);
  assert.match(decisions, /final migrator membership is zero|zero migrator membership/i);
  assert.match(decisions, /provider\/bootstrap authority then revokes the automatic edge/i);
});

test("DL-128-REPO-003: the repository no longer accepts the protected bootstrap edge as the final state", async () => {
  const architectureDoc = await readFile(
    "docs/architecture/PLATFORM-MIGRATOR-ALIGNMENT.md",
    "utf8",
  );
  const runbook = await readRunbook();
  for (const source of [architectureDoc, runbook]) {
    assert.match(
      source,
      new RegExp(
        whitespaceTolerant("the automatic bootstrap edge may exist only during creation, credential admission and ownership transfer"),
        "i",
      ),
    );
    assert.match(
      source,
      new RegExp(
        whitespaceTolerant("revokes the automatic edge after successful transfer/read-back"),
        "i",
      ),
    );
    assert.match(
      source,
      new RegExp(
        whitespaceTolerant("final accepted `platform_migrator` membership posture is zero edges across granted-role, member and grantor positions"),
        "i",
      ),
    );
  }
});

test("DL-128-REPO-003: the disposable rehearsal proves latent self-escalation and provider final revocation before denial", async () => {
  const postgresTest = await readFile(
    "tests/platform-migrator-alignment-postgres.test.mjs",
    "utf8",
  );
  assert.match(
    postgresTest,
    /grant platform_migrator to platform_app with set true, inherit false/i,
  );
  assert.match(postgresTest, /set role platform_migrator/i);
  assert.match(postgresTest, /current_user::text as cu, session_user::text as su/i);
  assert.match(
    postgresTest,
    /revoke platform_migrator from platform_app granted by platform_app/i,
  );
  assert.match(
    postgresTest,
    /select count\(\*\)::int as c[\s\S]*from pg_auth_members[\s\S]*granted_role\.rolname = 'platform_migrator'[\s\S]*member_role\.rolname = 'platform_migrator'[\s\S]*grantor_role\.rolname = 'platform_migrator'/i,
  );
  const escalationIndex = postgresTest.search(
    /grant platform_migrator to platform_app with set true, inherit false/i,
  );
  const revocationIndex = postgresTest.search(
    /revoke platform_migrator from platform_app granted by platform_app/i,
  );
  const providerRevocationIndex = postgresTest.search(
    /adminPool\.query\(\s*`revoke platform_migrator from platform_app`/i,
  );
  const denialIndex = postgresTest.search(/permission denied to grant role/i);
  assert.ok(escalationIndex >= 0, "self-grant proof must exist");
  assert.ok(revocationIndex >= 0, "self-granted edge revocation must exist");
  assert.ok(providerRevocationIndex >= 0, "provider revocation must exist");
  assert.ok(denialIndex >= 0, "post-revocation denial proof must exist");
  assert.ok(
    escalationIndex < providerRevocationIndex,
    "self-escalation proof must precede provider revocation",
  );
  assert.ok(
    providerRevocationIndex < denialIndex,
    "provider revocation must precede the denial proof",
  );
});

test("DL-128-REPO-003: zero-membership finality and post-revocation denial are proven in the disposable rehearsal", async () => {
  const postgresTest = await readFile(
    "tests/platform-migrator-alignment-postgres.test.mjs",
    "utf8",
  );
  assert.match(
    postgresTest,
    /permission denied to grant role/i,
  );
  assert.match(
    postgresTest,
    /permission denied to set role/i,
  );
  assert.match(
    postgresTest,
    /final platform_migrator membership inventory must be zero across granted-role, member and grantor positions/i,
  );
  assert.match(
    postgresTest,
    /platform_migrator default-privilege records must be removed before the role drop/i,
  );
  assert.match(
    postgresTest,
    /drop owned by platform_migrator[\s\S]*pg_default_acl[\s\S]*drop role platform_migrator/i,
  );
});

test("DL-128-REPO-004: migrator credential admission enforces real password authentication", async () => {
  const postgresTest = await readFile(
    "tests/platform-migrator-alignment-postgres.test.mjs",
    "utf8",
  );
  const runner = await readFile(
    "scripts/run-disposable-migrator-alignment-tests.mjs",
    "utf8",
  );
  const architectureDoc = await readFile(
    "docs/architecture/PLATFORM-MIGRATOR-ALIGNMENT.md",
    "utf8",
  );
  const runbook = await readRunbook();

  assert.match(runner, /scram-sha-256/);
  assert.match(runner, /pg_hba\.conf/);
  assert.match(runner, /pg_reload_conf/);
  assert.match(postgresTest, /scram-sha-256/);
  assert.match(postgresTest, /password authentication failed/i);
  assert.match(
    postgresTest,
    /client password must be a string|no password supplied/i,
  );
  assert.match(postgresTest, /validateMigratorLoginAdmission/i);
  assert.match(postgresTest, /direct migrator login fails before activation/i);
  assert.match(architectureDoc, /scram-sha-256/);
  assert.match(runbook, /scram-sha-256/);
  assert.match(runbook, /wrong-password rejection/i);
  assert.match(
    runbook,
    /omitted-password rejection at the real focused-child boundary/i,
  );
  assert.match(runner, /controlledPassfilePath/);
  assert.match(postgresTest, /assertFocusedPassfileIsolation/i);
  assert.match(postgresTest, /APPDATA/i);
  assert.match(runbook, /hostile ambient default password file/i);
});

test("DL-128-REPO-004: intermediate membership windows validate the complete inventory across granted-role, member and grantor positions", async () => {
  const postgresTest = await readFile(
    "tests/platform-migrator-alignment-postgres.test.mjs",
    "utf8",
  );
  assert.doesNotMatch(
    postgresTest,
    /\.filter\(\(edge\) => edge\.granted_role === "platform_migrator"\)/,
  );
  assert.match(postgresTest, /grantor_role\.rolname = any/);
  assert.match(postgresTest, /complete membership inventory must contain exactly/i);
});

test("DL-128-REPO-004: the corrected negative control keeps platform_migrator NOCREATEDB and uses the missing SET-capable authority", async () => {
  const architectureDoc = await readFile(
    "docs/architecture/PLATFORM-MIGRATOR-ALIGNMENT.md",
    "utf8",
  );
  const postgresTest = await readFile(
    "tests/platform-migrator-alignment-postgres.test.mjs",
    "utf8",
  );
  const runbook = await readRunbook();
  assert.doesNotMatch(architectureDoc, /receiving `CREATEDB`/);
  assert.doesNotMatch(postgresTest, /alter role platform_migrator createdb/);
  assert.match(
    architectureDoc,
    /target-role assumption\/SET-capable authority|SET-capable authority/,
  );
  assert.match(postgresTest, /must be able to SET ROLE|permission denied/i);
  assert.match(runbook, /remains `NOCREATEDB`/i);
});

test("DL-128-REPO-004: the pre-completion legacy-retirement guard is mechanically exercised", async () => {
  const postgresTest = await readFile(
    "tests/platform-migrator-alignment-postgres.test.mjs",
    "utf8",
  );
  const architectureDoc = await readFile(
    "docs/architecture/PLATFORM-MIGRATOR-ALIGNMENT.md",
    "utf8",
  );
  const runbook = await readRunbook();
  assert.match(postgresTest, /drop role platform_app/);
  assert.match(postgresTest, /depends on it|cannot be dropped/i);
  assert.match(postgresTest, /legacy authority remains available|assertLegacyAuthorityAvailable/i);
  assert.match(postgresTest, /initialRole[\s\S]*rolcanlogin[\s\S]*true/);
  assert.match(postgresTest, /assertFreshPlatformAppLogin\(primary\)/);
  assert.match(postgresTest, /assertFreshPlatformAppLoginRejected\(primary\)/);
  assert.match(postgresTest, /noLoginAttempted/);
  assert.match(runbook, /DROP ROLE platform_app[\s\S]*mechanically[\s\S]*NOLOGIN[\s\S]*controller-gated[\s\S]*fresh login/i);
  assert.match(architectureDoc, /cannot be retired/i);
});

test("DL-128-REPO-004: the rehearsal models real pg_database_owner semantics with before/after and rollback authority proof", async () => {
  const postgresTest = await readFile(
    "tests/platform-migrator-alignment-postgres.test.mjs",
    "utf8",
  );
  const architectureDoc = await readFile(
    "docs/architecture/PLATFORM-MIGRATOR-ALIGNMENT.md",
    "utf8",
  );
  const runbook = await readRunbook();
  assert.match(postgresTest, /pg_database_owner/);
  assert.match(postgresTest, /assertCanCreateInPublic/);
  assert.match(architectureDoc, /pg_database_owner/);
  assert.match(architectureDoc, /implicit member/);
  assert.match(architectureDoc, /current database owner/);
  assert.match(runbook, /pg_database_owner/);
  assert.match(runbook, /implicit member/);
  assert.match(runbook, /current database owner/);
});

test("DL-128-REPO-004: the repository states one public-ownership starting fact and no application-controlled branch", async () => {
  const architectureDoc = await readFile(
    "docs/architecture/PLATFORM-MIGRATOR-ALIGNMENT.md",
    "utf8",
  );
  const runbook = await readRunbook();
  assert.doesNotMatch(architectureDoc, /application-controlled `public` that can be transferred/i);
  assert.doesNotMatch(architectureDoc, /fresh live read-back proves `public` is application-controlled/i);
  assert.match(architectureDoc, /one current starting fact/);
  assert.match(architectureDoc, /not an unrelated independent provider role|independent provider role/);
  assert.doesNotMatch(runbook, /application-controlled-`public` branch|application-controlled `public`/i);
  assert.match(runbook, /known live starting fact/);
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

async function pathIsPresent(path) {
  try {
    await access(path);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const run14OwnedVolumeName = "deepseek-platform128-pg17-data";
const run29OwnedContainerName = "deepseek-platform128-pg17";
const run18VolumeOwnershipToken = "run18-owned-token";
const run18VolumeOwnershipTokenLabelKey = "com.swooshz.platform.runner-token";

function parseVolumeCreateLabels(operation) {
  if (!Array.isArray(operation)) return {};
  const labels = {};
  for (let index = 0; index < operation.length; index += 1) {
    if (operation[index] !== "--label") continue;
    const [key, ...valueParts] = String(operation[index + 1] ?? "").split("=");
    labels[key] = valueParts.join("=");
    index += 1;
  }
  return labels;
}

function createRun14VolumeSpawn({
  createExitCode = 0,
  signalOnCreate = false,
  createdBeforeStart = false,
  containerPresentBeforeStart = false,
  containerRemovalExitCode = 0,
  createdLabels = {
    "com.swooshz.platform.runner": "deepseek-platform128-migrator",
    [run18VolumeOwnershipTokenLabelKey]: run18VolumeOwnershipToken,
  },
  inspectOutput,
} = {}) {
  let exists = createdBeforeStart;
  let containerExists = containerPresentBeforeStart;
  let labels = { ...createdLabels };
  const calls = [];
  const spawnImpl = (command, args, options = {}) => {
    calls.push({ command, args: [...args], options });
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = () => {
      child.emit("close", null, "SIGTERM");
    };
    queueMicrotask(() => {
      let stdout = "";
      let code = 0;
      let signal = null;
      if (args[0] === "ps") {
        stdout = containerExists ? run29OwnedContainerName + "\n" : "";
      } else if (args[0] === "rm" && args[1] === "--force") {
        code = containerRemovalExitCode;
        if (code === 0) {
          containerExists = false;
          stdout = run29OwnedContainerName + "\n";
        }
      } else if (args.includes("ls")) {
        stdout = exists ? run14OwnedVolumeName + "\n" : "";
      } else if (args.includes("inspect")) {
        stdout = inspectOutput ?? `${JSON.stringify({ Name: run14OwnedVolumeName, Labels: labels })}\n`;
      } else if (args.includes("create")) {
        labels = parseVolumeCreateLabels(args);
        exists = true;
        code = createExitCode;
        if (signalOnCreate) {
          code = null;
          signal = "SIGTERM";
        }
      } else if (args.includes("rm")) {
        exists = false;
        stdout = `${run14OwnedVolumeName}\n`;
      }
      if (stdout) child.stdout.emit("data", Buffer.from(stdout));
      child.emit("close", code, signal);
    });
    return child;
  };
  spawnImpl.calls = calls;
  return spawnImpl;
}

function run14VolumeRmCalls(spawnImpl) {
  return spawnImpl.calls.filter(({ args }) => args[0] === "volume" && args[1] === "rm");
}

test("Run-14 named-volume cleanup reconciles daemon-side create ambiguity by exact ownership", async () => {
  const runner = await import("../scripts/run-disposable-migrator-alignment-tests.mjs");
  const ownedSpawn = createRun14VolumeSpawn();
  assert.equal(
    await runner.createOwnedVolume(ownedSpawn, run18VolumeOwnershipToken),
    run14OwnedVolumeName,
  );
  const ownedResources = {
    volumeCreateAttempted: true,
    volumeCreated: true,
    volumeOwned: true,
    volumeRemoved: false,
    containerStartAttempted: false,
    containerRemoved: false,
    volumeOwnershipToken: run18VolumeOwnershipToken,
  };
  await runner.cleanupOwnedVolumeAfterCreateAttempt(ownedSpawn, ownedResources);
  assert.equal(run14VolumeRmCalls(ownedSpawn).length, 1);
  assert.deepEqual(await runner.inspectOwnedVolumeOwnership(ownedSpawn, run18VolumeOwnershipToken), { state: "absent" });

  for (const createFailure of ["nonzero", "signal"]) {
    const failedSpawn = createRun14VolumeSpawn({
      createExitCode: createFailure === "nonzero" ? 1 : 0,
      signalOnCreate: createFailure === "signal",
    });
    await assert.rejects(() => runner.createOwnedVolume(failedSpawn, run18VolumeOwnershipToken));
    const failedResources = {
      volumeCreateAttempted: true,
      volumeCreated: false,
      volumeOwned: false,
      volumeRemoved: false,
      containerStartAttempted: false,
      containerRemoved: false,
      failureLabel: createFailure,
      volumeOwnershipToken: run18VolumeOwnershipToken,
    };
    await runner.cleanupOwnedVolumeAfterCreateAttempt(failedSpawn, failedResources);
    assert.equal(run14VolumeRmCalls(failedSpawn).length, 1);
    assert.deepEqual(await runner.inspectOwnedVolumeOwnership(failedSpawn, run18VolumeOwnershipToken), { state: "absent" });
  }

  const unownedSpawn = createRun14VolumeSpawn({
    createExitCode: 1,
    createdBeforeStart: true,
    createdLabels: { "com.swooshz.platform.runner": "deepseek-platform128-migrator" },
  });
  await assert.rejects(() => runner.cleanupOwnedVolumeAfterCreateAttempt(unownedSpawn, {
    volumeCreateAttempted: true,
    volumeCreated: false,
    volumeOwned: false,
    volumeRemoved: false,
    containerStartAttempted: false,
    containerRemoved: false,
    volumeOwnershipToken: run18VolumeOwnershipToken,
  }));
  assert.equal(run14VolumeRmCalls(unownedSpawn).length, 0);
  const mismatchedTokenSpawn = createRun14VolumeSpawn({
    createExitCode: 1,
    createdBeforeStart: true,
    createdLabels: {
      "com.swooshz.platform.runner": "deepseek-platform128-migrator",
      [run18VolumeOwnershipTokenLabelKey]: "other-run-token",
    },
  });
  await assert.rejects(() => runner.cleanupOwnedVolumeAfterCreateAttempt(
    mismatchedTokenSpawn,
    {
      volumeCreateAttempted: true,
      volumeCreated: false,
      volumeOwned: false,
      volumeRemoved: false,
      containerStartAttempted: false,
      containerRemoved: false,
      volumeOwnershipToken: run18VolumeOwnershipToken,
    },
  ));
  assert.equal(run14VolumeRmCalls(mismatchedTokenSpawn).length, 0);
});

test("Run-15 malformed and ambiguous volume inspection evidence fails closed", async () => {
  const runner = await import("../scripts/run-disposable-migrator-alignment-tests.mjs");
  const inspectionCases = [
    { label: "malformed JSON", inspectOutput: "not-json\n" },
    { label: "structurally invalid JSON", inspectOutput: "[]\n" },
    {
      label: "multiple inspection records",
      inspectOutput: JSON.stringify({ Name: run14OwnedVolumeName }) + "\n" +
        JSON.stringify({ Name: run14OwnedVolumeName }) + "\n",
    },
  ];

  for (const { label, inspectOutput } of inspectionCases) {
    const spawnImpl = createRun14VolumeSpawn({
      createdBeforeStart: true,
      inspectOutput,
    });

    assert.deepEqual(
      await runner.inspectOwnedVolumeOwnership(spawnImpl, run18VolumeOwnershipToken),
      { state: "ambiguous" },
      label,
    );
    await assert.rejects(
      () => runner.cleanupOwnedVolumeAfterCreateAttempt(spawnImpl, {
        volumeCreateAttempted: true,
        volumeCreated: false,
        volumeOwned: false,
        volumeRemoved: false,
        containerStartAttempted: false,
        containerRemoved: false,
        volumeOwnershipToken: run18VolumeOwnershipToken,
      }),
      /owned volume evidence was ambiguous/,
      label,
    );
    assert.equal(run14VolumeRmCalls(spawnImpl).length, 0, label);
    assert.equal(
      spawnImpl.calls.some(({ args }) => args.includes("prune")),
      false,
      label,
    );
    assert.deepEqual(
      await runner.inspectOwnedVolumeOwnership(spawnImpl, run18VolumeOwnershipToken),
      { state: "ambiguous" },
      label + " volume must remain present and unowned by proof",
    );
  }
});

test("Run-29 failed container-start cleanup reconciles exact absence before token-owned volume removal", async () => {
  const runner = await import("../scripts/run-disposable-migrator-alignment-tests.mjs");
  const spawnImpl = createRun14VolumeSpawn({ createdBeforeStart: true, containerRemovalExitCode: 1 });
  const resources = {
    constructionAuthority: null,
    configuredAdmission: null,
    childProcess: null,
    childExited: true,
    focusedCredentialIsolationSetupAttempted: false,
    ownedContainer: false,
    ownedDatabases: new Set(),
    containerStartAttempted: true,
    containerRemoved: false,
    volumeCreateAttempted: true,
    volumeCreated: true,
    volumeOwned: true,
    volumeRemoved: false,
    volumeOwnershipToken: run18VolumeOwnershipToken,
  };
  await runner.cleanupRunnerResources(resources, spawnImpl);
  assert.equal(resources.containerRemoved, true);
  assert.equal(resources.volumeRemoved, true);
  assert.equal(
    spawnImpl.calls.filter(({ args }) => args[0] === "rm" && args[1] === "--force").length,
    1,
  );
  assert.equal(
    spawnImpl.calls.some(
      ({ args }) =>
        args[0] === "ps" &&
        args.includes("name=^/" + run29OwnedContainerName + "$"),
    ),
    true,
  );
  assert.equal(run14VolumeRmCalls(spawnImpl).length, 1);
  await runner.verifyRunnerAbsence(resources, spawnImpl, async () => {});
  assert.deepEqual(
    await runner.inspectOwnedVolumeOwnership(spawnImpl, run18VolumeOwnershipToken),
    { state: "absent" },
  );
});
test("Run-14 focused child environment replaces PostgreSQL password-file discovery and retains benign env", async () => {
  const { buildFocusedTestEnvironment } = await import(
    "../scripts/run-disposable-migrator-alignment-tests.mjs",
  );
  const pgKeys = [
    "PGUSER",
    "PGDATABASE",
    "PGHOST",
    "PGHOSTADDR",
    "PGPORT",
    "PGPASSWORD",
    "PGPASSFILE",
    "PGSERVICE",
    "PGSERVICEFILE",
    "PGOPTIONS",
    "PGAPPNAME",
    "PGCONNECT_TIMEOUT",
    "PGSSLMODE",
    "PGSSLNEGOTIATION",
    "PGSSLCERT",
    "PGSSLKEY",
    "PGSSLROOTCERT",
    "PGREQUIRESSL",
    "PGCHANNELBINDING",
    "PGTARGETSESSIONATTRS",
    "PGCLIENTENCODING",
    "PGDATESTYLE",
    "PGTZ",
    "PGGEQO",
    "PGSYSCONFDIR",
    "PGLOCALEDIR",
    "PGPASS_NO_DEESCAPE",
    "PGSYNTHETIC",
    "NODE_PG_FORCE_NATIVE",
  ];
  const directory = await mkdtemp(
    join(tmpdir(), "swooshz-platform-run24-pgpass-env-"),
  );
  const controlledPassfilePath = join(directory, "controlled-empty-pgpass");
  const hostilePassfilePath = join(directory, "hostile-inherited-pgpass");
  try {
    await writeFile(controlledPassfilePath, "", {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    const input = {
      PATH: "retained",
      NODE_ENV: "test",
      HOME: join(directory, "home"),
      APPDATA: join(directory, "appdata"),
      PGPASSWORD: "hostile-inherited-password",
      PGPASSFILE: hostilePassfilePath,
      ...Object.fromEntries(
        pgKeys
          .filter((key) => key !== "PGPASSWORD" && key !== "PGPASSFILE")
          .map((key) => [key, key]),
      ),
    };
    const output = buildFocusedTestEnvironment(input, controlledPassfilePath);
    for (const key of pgKeys) {
      if (key === "PGPASSFILE") {
        assert.equal(
          output.PGPASSFILE === controlledPassfilePath,
          true,
          "controlled PGPASSFILE must replace inherited password-file selection",
        );
      } else {
        assert.equal(
          Object.hasOwn(output, key),
          false,
          "inherited PostgreSQL environment must be removed",
        );
      }
    }
    assert.equal(output.PATH, "retained");
    assert.equal(output.NODE_ENV, "test");
    assert.equal(output.HOME, input.HOME);
    assert.equal(output.APPDATA, input.APPDATA);
    assert.equal(Object.hasOwn(input, "PGPASSWORD"), true);
    assert.equal(Object.hasOwn(input, "PGPASSFILE"), true);
    assert.equal((await readFile(controlledPassfilePath, "utf8")).length, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
    await assert.rejects(
      () => access(controlledPassfilePath),
      "controlled passfile must be absent after the unit seam",
    );
  }
});

test("Run-15 actual focused child receives a runner-owned empty passfile seam under hostile ambient defaults", async () => {
  const runner = await import("../scripts/run-disposable-migrator-alignment-tests.mjs");
  const focusedChildRuns = [];
  const runnerEnvironment = {
    ...process.env,
    PGPASSWORD: "hostile-inherited-password",
    PGPASSFILE: "hostile-inherited-pgpass",
  };
  assert.equal(Object.hasOwn(runnerEnvironment, "PGPASSWORD"), true, "hostile PGPASSWORD must exist before sanitisation");
  assert.equal(Object.hasOwn(runnerEnvironment, "PGPASSFILE"), true, "hostile PGPASSFILE must exist before sanitisation");
  for (const key of [
    "MIGRATOR_ALIGNMENT_TEST_DATABASE_URL",
    "MIGRATOR_ALIGNMENT_TEST_OPERATOR_URL",
    "MIGRATOR_ALIGNMENT_TEST_SECONDARY_DATABASE_URL",
    "MIGRATOR_ALIGNMENT_TEST_SECONDARY_OPERATOR_URL",
    "MIGRATOR_ALIGNMENT_TEST_CONFIRM",
  ]) {
    delete runnerEnvironment[key];
  }

  const spawnImpl = (command, args, options = {}) => {
    if (
      command === process.execPath &&
      args.includes("tests/platform-migrator-alignment-postgres.test.mjs")
    ) {
      const childEnv = { ...(options.env ?? {}) };
      delete childEnv.NODE_TEST_CONTEXT;
      const childArgs = [args[0], "--test-reporter=spec", ...args.slice(1)];
      const child = spawn(command, childArgs, { ...options, env: childEnv });
      const record = {
        args: childArgs,
        childEnv,
        controlledPassfilePath: childEnv.PGPASSFILE,
        exitCode: null,
        signal: null,
      };
      focusedChildRuns.push(record);
      child.once("close", (code, signal) => {
        record.exitCode = code;
        record.signal = signal;
      });
      return child;
    }
    return spawn(command, args, options);
  };

  const resources = await runner.run({
    env: runnerEnvironment,
    spawnImpl,
  });

  assert.equal(focusedChildRuns.length, 1);
  const focusedChild = focusedChildRuns[0];
  assert.equal(
    Object.hasOwn(focusedChild.childEnv, "PGPASSWORD"),
    false,
    "focused child must not receive inherited PGPASSWORD",
  );
  assert.equal(
    Object.hasOwn(focusedChild.childEnv, "PGPASSFILE"),
    true,
    "focused child must receive the controlled PGPASSFILE",
  );
  assert.equal(
    typeof focusedChild.controlledPassfilePath === "string" &&
      focusedChild.controlledPassfilePath.length > 0,
    true,
    "focused child controlled PGPASSFILE must be present",
  );
  assert.equal(
    focusedChild.controlledPassfilePath === runnerEnvironment.PGPASSFILE,
    false,
    "focused child PGPASSFILE must replace the inherited value",
  );
  assert.equal(Object.hasOwn(focusedChild.childEnv, "HOME"), true);
  assert.equal(Object.hasOwn(focusedChild.childEnv, "APPDATA"), true);
  assert.equal(
    Object.keys(focusedChild.childEnv).some(
      (key) => key.startsWith("PG") && key !== "PGPASSFILE",
    ),
    false,
  );
  assert.equal(
    Object.hasOwn(
      focusedChild.childEnv,
      "PLATFORM_MIGRATOR_FAILURE_RECEIPT_FILE",
    ),
    true,
  );
  assert.equal(
    Object.hasOwn(
      focusedChild.childEnv,
      "PLATFORM_MIGRATOR_FAILURE_PROGRESS_FILE",
    ),
    true,
  );
  assert.equal(focusedChild.args.includes("--test"), true);
  assert.equal(
    focusedChild.args.includes(
      "tests/platform-migrator-alignment-postgres.test.mjs",
    ),
    true,
  );
  assert.ok(
    isRunnerFixtureUrl(
      focusedChild.childEnv.MIGRATOR_ALIGNMENT_TEST_DATABASE_URL,
      "platform_app",
      "migrator_alignment_test",
    ),
    "primary target fixture URL must come from the runner",
  );
  assert.ok(
    isRunnerFixtureUrl(
      focusedChild.childEnv.MIGRATOR_ALIGNMENT_TEST_OPERATOR_URL,
      "postgres",
      "migrator_alignment_test",
    ),
    "primary operator fixture URL must come from the runner",
  );
  assert.ok(
    isRunnerFixtureUrl(
      focusedChild.childEnv.MIGRATOR_ALIGNMENT_TEST_SECONDARY_DATABASE_URL,
      "platform_app",
      "migrator_alignment_test_secondary",
    ),
    "secondary target fixture URL must come from the runner",
  );
  assert.ok(
    isRunnerFixtureUrl(
      focusedChild.childEnv.MIGRATOR_ALIGNMENT_TEST_SECONDARY_OPERATOR_URL,
      "postgres",
      "migrator_alignment_test_secondary",
    ),
    "secondary operator fixture URL must come from the runner",
  );
  assert.equal(
    focusedChild.childEnv.MIGRATOR_ALIGNMENT_TEST_CONFIRM,
    "disposable-only",
  );
  assert.equal(focusedChild.exitCode, 0);
  assert.equal(focusedChild.signal, null);

  assert.equal(resources.focusedCredentialIsolationPreSanitization, true);
  assert.equal(resources.focusedCredentialChildBoundary, true);
  assert.equal(resources.focusedCredentialIsolationCleaned, true);
  assert.equal(resources.focusedCredentialIsolationAbsent, true);
  assert.equal(resources.childTestsStarted, true);
  assert.equal(resources.childExited, true);
  assert.equal(resources.childExitCode, 0);
  assert.equal(resources.childSignal, false);
  assert.equal(resources.childSummaryParsed, true);
  assert.equal(resources.cleanupComplete, true);
  assert.equal(resources.absenceVerified, true);
  assert.equal(resources.containerRemoved, true);
  assert.equal(resources.volumeRemoved, true);
  assert.equal(resources.volumeAbsenceVerified, true);

  await assert.rejects(
    () => access(focusedChild.controlledPassfilePath),
    "controlled passfile must be absent after focused-child cleanup",
  );
  await assert.rejects(
    () => access(join(focusedChild.childEnv.HOME, ".pgpass")),
    "synthetic HOME passfile must be absent after focused-child cleanup",
  );
  await assert.rejects(
    () => access(join(
      focusedChild.childEnv.APPDATA,
      "postgresql",
      "pgpass.conf",
    )),
    "synthetic APPDATA passfile must be absent after focused-child cleanup",
  );

  const publicReceipt = runner.formatDisposableRuntimeFailureReceipt(resources);
  assert.doesNotMatch(
    publicReceipt,
    /swooshz-platform-pgpass-isolation-|hostile-inherited|synthetic-hostile|controlled-empty-pgpass|hostile-explicit-pgpass|synthetic-migrator-password/i,
  );
});
function isRunnerFixtureUrl(value, expectedUser, expectedDatabase) {
  if (typeof value !== "string") return false;
  try {
    const parsed = new URL(value);
    return (
      (parsed.protocol === "postgres:" || parsed.protocol === "postgresql:") &&
      parsed.username === expectedUser &&
      parsed.password === "" &&
      parsed.hostname === "127.0.0.1" &&
      parsed.port === "56432" &&
      parsed.pathname === "/" + expectedDatabase &&
      parsed.search === "" &&
      parsed.hash === ""
    );
  } catch {
    return false;
  }
}

function whitespaceTolerant(value) {
  return escapeRegExp(value).replaceAll(" ", "\\s+");
}

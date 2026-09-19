import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";

import * as schema from "../dist/db/schema.js";
import { createDrizzlePlatformRepositories } from "../dist/db/repositories.js";
import { removeWorkspaceMembership } from "../dist/platform/workspace-admin-service.js";

const rootDir = resolve(".");
const isStandalone =
  process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);

async function proveRoleCollapseMigration({
  databaseUrl,
  migrateTo0009Impl,
  runRepositoryMigratorImpl,
}) {
  assert.ok(databaseUrl);
  const pool = new Pool({ connectionString: databaseUrl, max: 4 });
  let baseline;

  try {
    await migrateTo0009Impl(databaseUrl);
    const historicalAuditMetadata = await seedLegacyState(pool);
    baseline = await captureState(pool);

    assert.deepEqual(baseline.roleLabels, ["owner", "admin", "member", "viewer"]);
    assert.equal(baseline.roleOldCount, 0);
    assert.equal(baseline.journal.length, 9);
    assert.equal(baseline.audit.length, 1);
    assert.equal(baseline.audit[0].id, "audit_historical_role");
    assert.match(baseline.audit[0].metadataText, /historical role evidence/);
    assert.match(baseline.audit[0].metadataText, /"owner"/);
    assert.match(baseline.audit[0].metadataText, /"member"/);

    const invalidCases = [
      "invalid_nullable_requester",
      "invalid_duplicate_bootstrap",
      "invalid_missing_bootstrap",
      "invalid_no_active_admin",
    ];

    for (const invalidCase of invalidCases) {
      await installInvalidCase(pool, invalidCase);
      const beforeFailure = await captureState(pool);
      const result = await runRepositoryMigratorImpl(databaseUrl);
      assert.notEqual(result.code, 0);
      assert.equal(result.timedOut, false);
      assert.deepEqual(await captureState(pool), beforeFailure);
      await cleanupInvalidCase(pool, invalidCase);
    }

    const successfulMigration = await runRepositoryMigratorImpl(databaseUrl);
    assert.equal(successfulMigration.code, 0);
    assert.equal(successfulMigration.timedOut, false);

    const migrated = await captureState(pool);
    assert.deepEqual(migrated.roleLabels, ["admin", "operator", "viewer"]);
    assert.equal(migrated.roleOldCount, 0);
    assert.deepEqual(migrated.memberships, [
      { id: "membership_admin", role: "admin" },
      { id: "membership_member", role: "operator" },
      { id: "membership_owner", role: "admin" },
      { id: "membership_viewer", role: "viewer" },
    ]);
    assert.deepEqual(migrated.approvals, [
      { id: "approval_admin", role: "admin" },
      { id: "approval_bootstrap", role: "admin" },
      { id: "approval_member", role: "operator" },
      { id: "approval_owner", role: "admin" },
      { id: "approval_viewer", role: "viewer" },
    ]);
    assert.deepEqual(migrated.invitations, [
      { id: "inv_admin", role: "admin" },
      { id: "inv_member", role: "operator" },
      { id: "inv_owner", role: "admin" },
      { id: "inv_viewer", role: "viewer" },
    ]);
    assert.deepEqual(migrated.audit, baseline.audit);
    assert.equal(migrated.journal.length, 10);
    assert.deepEqual(
      migrated.journal.map((row) => row.hash),
      await repositoryMigrationHashes(),
    );
    assert.equal(Number(migrated.journal.at(-1).createdAt), 1787479999088);

    const bootstrap = await pool.query(
      "select role::text as role from workspace_membership_approvals where id = $1",
      ["approval_bootstrap"],
    );
    assert.deepEqual(bootstrap.rows, [{ role: "admin" }]);

    const bootstrapMemberships = await pool.query(
      "select count(*)::int as count from memberships where workspace_id = $1",
      ["ws_bootstrap"],
    );
    assert.equal(bootstrapMemberships.rows[0].count, 0);
  } finally {
    await pool.end();
  }
}

async function proveRoleCollapseConcurrency({ databaseUrl, migrateToLatestImpl }) {
  assert.ok(databaseUrl);
  await migrateToLatestImpl(databaseUrl);

  const seedPool = new Pool({ connectionString: databaseUrl, max: 8 });
  const clientA = createProductionClient(databaseUrl);
  const clientB = createProductionClient(databaseUrl);
  let blocker;
  let blockedOperation;
  let blockedOperationSettled = false;
  let blockerCommitted = false;

  try {
    await seedConcurrencyState(seedPool);
    const pidA = Number((await clientA.pool.query("select pg_backend_pid() as pid")).rows[0].pid);
    const pidB = Number((await clientB.pool.query("select pg_backend_pid() as pid")).rows[0].pid);
    assert.notEqual(pidA, pidB);

    const now = "2026-08-23T15:00:00.000Z";
    const simultaneous = await Promise.allSettled([
      removeWorkspaceMembership(clientA.repositories, {
        sessionId: "session_race_a",
        workspaceId: "ws_race",
        membershipId: "membership_race_b",
        auditEventId: "audit_race_a",
        now,
      }),
      removeWorkspaceMembership(clientB.repositories, {
        sessionId: "session_race_b",
        workspaceId: "ws_race",
        membershipId: "membership_race_a",
        auditEventId: "audit_race_b",
        now,
      }),
    ]);

    assert.equal(simultaneous.filter((result) => result.status === "fulfilled").length, 1);
    assert.equal(simultaneous.filter((result) => result.status === "rejected").length, 1);

    const remainingRaceAdmins = await activeAdminCount(seedPool, "ws_race");
    assert.equal(remainingRaceAdmins, 1);

    blocker = await seedPool.connect();
    await blocker.query("begin");
    await blocker.query(
      "select id from workspaces where id = $1 for update",
      ["ws_lock"],
    );

    blockedOperation = removeWorkspaceMembership(clientA.repositories, {
      sessionId: "session_race_a",
      workspaceId: "ws_lock",
      membershipId: "membership_lock_b",
      auditEventId: "audit_lock",
      now,
    }).then(
      (value) => {
        blockedOperationSettled = true;
        return value;
      },
      (error) => {
        blockedOperationSettled = true;
        throw error;
      },
    );

    let lockWaitObserved = false;
    const deadline = Date.now() + 5_000;
    while (Date.now() < deadline && !blockedOperationSettled) {
      const waiting = await seedPool.query(
        "select count(*)::int as count " +
          "from pg_stat_activity " +
          "where datname = current_database() " +
          "and wait_event_type = 'Lock'",
      );
      if (waiting.rows[0].count > 0) {
        lockWaitObserved = true;
        break;
      }
      await delay(50);
    }

    assert.equal(lockWaitObserved, true);
    assert.equal(blockedOperationSettled, false);
    await blocker.query("commit");
    blockerCommitted = true;
    await blockedOperation;

    assert.equal(await activeAdminCount(seedPool, "ws_lock"), 1);
  } finally {
    if (blocker) {
      if (!blockerCommitted) {
        await blocker.query("rollback").catch(() => {});
      }
      blocker.release();
    }
    if (blockedOperation && !blockedOperationSettled) {
      await blockedOperation.catch(() => {});
    }
    await clientA.pool.end();
    await clientB.pool.end();
    await seedPool.end();
  }
}

export async function runRoleCollapseProofs({
  migrationDatabaseUrl,
  concurrencyDatabaseUrl,
  migrateTo0009Impl,
  migrateToLatestImpl,
  runRepositoryMigratorImpl,
} = {}) {
  if (
    typeof migrateTo0009Impl !== "function" ||
    typeof migrateToLatestImpl !== "function" ||
    typeof runRepositoryMigratorImpl !== "function"
  ) {
    throw new Error();
  }
  const startedAt = Date.now();
  await proveRoleCollapseMigration({
    databaseUrl: migrationDatabaseUrl,
    migrateTo0009Impl,
    runRepositoryMigratorImpl,
  });
  await proveRoleCollapseConcurrency({
    databaseUrl: concurrencyDatabaseUrl,
    migrateToLatestImpl,
  });
  return {
    cancelled: 0,
    durationMs: Date.now() - startedAt,
    failed: 0,
    passed: 2,
    skipped: 0,
    suites: 0,
    todo: 0,
    total: 2,
  };
}

if (isStandalone) {
  test("PostgreSQL 17 proves the real 0009 to 0010 role-collapse migration", {
    skip: "requires runner-owned fixture migration orchestration",
  }, () => {});

  test("PostgreSQL 17 proves concurrent last-admin protection and FOR UPDATE waiting", {
    skip: "requires runner-owned fixture migration orchestration",
  }, () => {});
}

async function seedLegacyState(pool) {
  const users = [
    ["user_admin", "admin@example.invalid", "Admin Example"],
    ["user_member", "member@example.invalid", "Member Example"],
    ["user_owner", "owner@example.invalid", "Owner Example"],
    ["user_viewer", "viewer@example.invalid", "Viewer Example"],
  ];
  for (const [id, email, displayName] of users) {
    await pool.query(
      "insert into users (id, email, display_name, status) values ($1, $2, $3, $4)",
      [id, email, displayName, "active"],
    );
  }

  await insertWorkspaces(pool, [
    ["ws_admins", "admins", "Admins"],
    ["ws_bootstrap", "bootstrap", "Bootstrap"],
  ]);

  const membershipRows = [
    ["membership_owner", "ws_admins", "user_owner", "owner"],
    ["membership_admin", "ws_admins", "user_admin", "admin"],
    ["membership_member", "ws_admins", "user_member", "member"],
    ["membership_viewer", "ws_admins", "user_viewer", "viewer"],
  ];
  for (const [id, workspaceId, userId, role] of membershipRows) {
    await pool.query(
      "insert into memberships (id, workspace_id, user_id, role, status) " +
        "values ($1, $2, $3, $4, $5)",
      [id, workspaceId, userId, role, "active"],
    );
  }

  const approvalRows = [
    ["approval_owner", "owner-request@example.invalid", "owner", "user_admin"],
    ["approval_admin", "admin-request@example.invalid", "admin", "user_admin"],
    ["approval_member", "member-request@example.invalid", "member", "user_admin"],
    ["approval_viewer", "viewer-request@example.invalid", "viewer", "user_admin"],
  ];
  for (const [id, email, role, requestedByUserId] of approvalRows) {
    await pool.query(
      "insert into workspace_membership_approvals " +
        "(id, workspace_id, email, role, status, requested_by_user_id) " +
        "values ($1, $2, $3, $4, $5, $6)",
      [id, "ws_admins", email, role, "pending", requestedByUserId],
    );
  }
  await pool.query(
    "insert into workspace_membership_approvals " +
      "(id, workspace_id, email, role, status, requested_by_user_id) " +
      "values ($1, $2, $3, $4, $5, $6)",
    [
      "approval_bootstrap",
      "ws_bootstrap",
      "bootstrap@example.invalid",
      "owner",
      "pending",
      null,
    ],
  );

  const invitationRows = [
    ["inv_owner", "owner-invite@example.invalid", "owner"],
    ["inv_admin", "admin-invite@example.invalid", "admin"],
    ["inv_member", "member-invite@example.invalid", "member"],
    ["inv_viewer", "viewer-invite@example.invalid", "viewer"],
  ];
  for (const [id, email, role] of invitationRows) {
    await pool.query(
      "insert into invitations " +
        "(id, workspace_id, email, role, status, invited_by_user_id, expires_at) " +
        "values ($1, $2, $3, $4, $5, $6, $7)",
      [
        id,
        "ws_admins",
        email,
        role,
        "pending",
        "user_admin",
        "2099-01-01T00:00:00.000Z",
      ],
    );
  }

  const historicalAuditMetadata = {
    historicalRoleEvidence: [
      { role: "owner", source: "legacy-membership" },
      { role: "member", source: "legacy-invitation" },
    ],
    note: "historical role evidence remains unchanged",
  };
  await pool.query(
    "insert into audit_events " +
      "(id, workspace_id, actor_user_id, event_type, target_type, target_id, metadata) " +
      "values ($1, $2, $3, $4, $5, $6, $7)",
    [
      "audit_historical_role",
      "ws_admins",
      "user_admin",
      "workspace.role-history",
      "membership",
      "membership_owner",
      JSON.stringify(historicalAuditMetadata),
    ],
  );

  return historicalAuditMetadata;
}

async function captureState(pool) {
  const roleLabels = (
    await pool.query(
      "select enumlabel from pg_enum " +
        "join pg_type on pg_type.oid = pg_enum.enumtypid " +
        "where pg_type.typname = 'role' " +
        "order by pg_enum.enumsortorder",
    )
  ).rows.map((row) => row.enumlabel);

  const memberships = (
    await pool.query(
      "select id, role::text as role from memberships order by id",
    )
  ).rows;
  const approvals = (
    await pool.query(
      "select id, role::text as role " +
        "from workspace_membership_approvals order by id",
    )
  ).rows;
  const invitations = (
    await pool.query("select id, role::text as role from invitations order by id")
  ).rows;
  const audit = (
    await pool.query(
      "select id, metadata::text as metadata_text from audit_events order by id",
    )
  ).rows.map((row) => ({ id: row.id, metadataText: row.metadata_text }));
  const journal = (
    await pool.query(
      "select id::int as id, hash, created_at::bigint as created_at " +
        "from drizzle.__drizzle_migrations order by id",
    )
  ).rows.map((row) => ({
    id: Number(row.id),
    hash: row.hash,
    createdAt: String(row.created_at),
  }));
  const roleOldCount = Number(
    (
      await pool.query(
        "select count(*)::int as count from pg_type where typname = 'role_old'",
      )
    ).rows[0].count,
  );

  return {
    roleLabels,
    memberships,
    approvals,
    invitations,
    audit,
    journal,
    roleOldCount,
  };
}

async function repositoryMigrationHashes() {
  const journal = JSON.parse(
    await readFile(join(rootDir, "drizzle", "migrations", "meta", "_journal.json"), "utf8"),
  );
  const hashes = [];
  for (const entry of journal.entries) {
    const sql = await readFile(
      join(rootDir, "drizzle", "migrations", entry.tag + ".sql"),
    );
    hashes.push(createHash("sha256").update(sql).digest("hex"));
  }
  return hashes;
}

async function insertWorkspaces(pool, workspaces) {
  for (const [id, slug, displayName] of workspaces) {
    await pool.query(
      "insert into workspaces (id, slug, display_name, status) values ($1, $2, $3, $4)",
      [id, slug, displayName, "active"],
    );
  }
}

async function installInvalidCase(pool, invalidCase) {
  if (invalidCase === "invalid_nullable_requester") {
    await insertWorkspaces(pool, [
      ["ws_invalid_nullable", "invalid-nullable", "Invalid Nullable"],
    ]);
    await pool.query(
      "insert into workspace_membership_approvals " +
        "(id, workspace_id, email, role, status, requested_by_user_id) " +
        "values ($1, $2, $3, $4, $5, $6)",
      [
        "approval_invalid_nullable",
        "ws_invalid_nullable",
        "invalid-nullable@example.invalid",
        "viewer",
        "pending",
        null,
      ],
    );
    return;
  }

  if (invalidCase === "invalid_duplicate_bootstrap") {
    await insertWorkspaces(pool, [
      ["ws_invalid_duplicate", "invalid-duplicate", "Invalid Duplicate"],
    ]);
    for (const [id, email, role] of [
      ["approval_invalid_duplicate_a", "duplicate-a@example.invalid", "owner"],
      ["approval_invalid_duplicate_b", "duplicate-b@example.invalid", "admin"],
    ]) {
      await pool.query(
        "insert into workspace_membership_approvals " +
          "(id, workspace_id, email, role, status, requested_by_user_id) " +
          "values ($1, $2, $3, $4, $5, $6)",
        [id, "ws_invalid_duplicate", email, role, "pending", null],
      );
    }
    return;
  }

  if (invalidCase === "invalid_missing_bootstrap") {
    await insertWorkspaces(pool, [
      ["ws_invalid_missing", "invalid-missing", "Invalid Missing"],
    ]);
    return;
  }

  if (invalidCase === "invalid_no_active_admin") {
    await insertWorkspaces(pool, [
      ["ws_invalid_no_admin", "invalid-no-admin", "Invalid No Admin"],
    ]);
    await pool.query(
      "insert into memberships (id, workspace_id, user_id, role, status) " +
        "values ($1, $2, $3, $4, $5)",
      [
        "membership_invalid_no_admin",
        "ws_invalid_no_admin",
        "user_member",
        "member",
        "active",
      ],
    );
    return;
  }

  throw new Error("unknown invalid migration fixture");
}

async function cleanupInvalidCase(pool, invalidCase) {
  const workspaceByCase = {
    invalid_nullable_requester: "ws_invalid_nullable",
    invalid_duplicate_bootstrap: "ws_invalid_duplicate",
    invalid_missing_bootstrap: "ws_invalid_missing",
    invalid_no_active_admin: "ws_invalid_no_admin",
  };
  const workspaceId = workspaceByCase[invalidCase];
  await pool.query(
    "delete from workspace_membership_approvals where workspace_id = $1",
    [workspaceId],
  );
  await pool.query("delete from memberships where workspace_id = $1", [workspaceId]);
  await pool.query("delete from workspaces where id = $1", [workspaceId]);
}

async function seedConcurrencyState(pool) {
  for (const [id, email, displayName] of [
    ["race_admin_a", "race-a@example.invalid", "Race Admin A"],
    ["race_admin_b", "race-b@example.invalid", "Race Admin B"],
    ["race_admin_c", "race-c@example.invalid", "Race Admin C"],
  ]) {
    await pool.query(
      "insert into users (id, email, display_name, status) values ($1, $2, $3, $4)",
      [id, email, displayName, "active"],
    );
  }
  await insertWorkspaces(pool, [
    ["ws_race", "race", "Race"],
    ["ws_lock", "lock", "Lock"],
  ]);

  for (const [id, workspaceId, userId] of [
    ["membership_race_a", "ws_race", "race_admin_a"],
    ["membership_race_b", "ws_race", "race_admin_b"],
    ["membership_lock_a", "ws_lock", "race_admin_a"],
    ["membership_lock_b", "ws_lock", "race_admin_b"],
  ]) {
    await pool.query(
      "insert into memberships (id, workspace_id, user_id, role, status) " +
        "values ($1, $2, $3, $4, $5)",
      [id, workspaceId, userId, "admin", "active"],
    );
  }

  for (const [id, userId] of [
    ["session_race_a", "race_admin_a"],
    ["session_race_b", "race_admin_b"],
  ]) {
    await pool.query(
      "insert into sessions " +
        "(id, user_id, expires_at, last_seen_at) values ($1, $2, $3, $4)",
      [id, userId, "2099-01-01T00:00:00.000Z", "2026-08-23T14:00:00.000Z"],
    );
  }
}

async function activeAdminCount(pool, workspaceId) {
  const result = await pool.query(
    "select count(*)::int as count " +
      "from memberships " +
      "where workspace_id = $1 and status = 'active' and role::text = 'admin'",
    [workspaceId],
  );
  return result.rows[0].count;
}

function createProductionClient(databaseUrl) {
  const pool = new Pool({ connectionString: databaseUrl, max: 1 });
  return {
    pool,
    repositories: createDrizzlePlatformRepositories(drizzle(pool, { schema })),
  };
}

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { types as nodeUtilTypes } from "node:util";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { DrizzleQueryError } from "drizzle-orm";
import { drizzle } from "drizzle-orm/node-postgres";
import { DatabaseError, Pool } from "pg";

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
  let blockerCommitted = false;
  let outcomesPromise;
  let outcomesSettled = false;

  try {
    await seedConcurrencyState(seedPool);
    const directSignalEvidence = await proveDirectPostgresSerializationRetry(seedPool);
    assert.equal(directSignalEvidence.signalKind, "DIRECT_PG");
    assert.equal(directSignalEvidence.transactionAttempts, 2);
    assert.equal(directSignalEvidence.operationCalls, 2);

    const pidA = Number((await clientA.pool.query("select pg_backend_pid() as pid")).rows[0].pid);
    const pidB = Number((await clientB.pool.query("select pg_backend_pid() as pid")).rows[0].pid);
    assert.notEqual(pidA, pidB);

    const now = "2026-08-23T15:00:00.000Z";
    const sessionIds = ["session_race_a", "session_race_b", "session_race_c"];
    const sessionsBefore = await captureSessionStates(seedPool, sessionIds);
    blocker = await seedPool.connect();
    await blocker.query("begin");
    await blocker.query(
      "select id from workspaces where id = $1 for update",
      ["ws_race"],
    );

    const raceOperations = [
      {
        client: clientA,
        actorUserId: "race_admin_a",
        actorMembershipId: "membership_race_a",
        sessionId: "session_race_a",
        targetMembershipId: "membership_race_b",
        auditEventId: "audit_race_a",
      },
      {
        client: clientB,
        actorUserId: "race_admin_b",
        actorMembershipId: "membership_race_b",
        sessionId: "session_race_b",
        targetMembershipId: "membership_race_a",
        auditEventId: "audit_race_b",
      },
    ];
    outcomesPromise = Promise.allSettled(
      raceOperations.map((operation) =>
        removeWorkspaceMembership(operation.client.repositories, {
          sessionId: operation.sessionId,
          workspaceId: "ws_race",
          membershipId: operation.targetMembershipId,
          auditEventId: operation.auditEventId,
          now,
        }),
      ),
    ).then((outcomes) => {
      outcomesSettled = true;
      return outcomes;
    });

    let waitingBackendCount = 0;
    const lockDeadline = Date.now() + 10_000;
    while (Date.now() < lockDeadline && !outcomesSettled) {
      const waiting = await seedPool.query(
        "select count(*)::int as count " +
          "from pg_stat_activity " +
          "where datname = current_database() " +
          "and pid = any($1::int[]) " +
          "and wait_event_type = 'Lock'",
        [[pidA, pidB]],
      );
      waitingBackendCount = waiting.rows[0].count;
      if (waitingBackendCount === 2) break;
      await delay(50);
    }

    assert.equal(waitingBackendCount, 2);
    assert.equal(outcomesSettled, false);
    await blocker.query("commit");
    blockerCommitted = true;
    blocker.release();
    blocker = null;

    const simultaneous = await outcomesPromise;
    assert.equal(simultaneous.filter((result) => result.status === "fulfilled").length, 1);
    assert.equal(simultaneous.filter((result) => result.status === "rejected").length, 1);

    const winnerIndex = simultaneous.findIndex((result) => result.status === "fulfilled");
    const loserIndex = 1 - winnerIndex;
    const winner = raceOperations[winnerIndex];
    const loser = raceOperations[loserIndex];
    const loserOutcome = simultaneous[loserIndex];
    assert.equal(loserOutcome.reason.code, "not_authorized");
    assert.notEqual(loserOutcome.reason.code, "repository_failure");
    assert.notEqual(loserOutcome.reason.code, "last_admin_required");
    assert.equal(winner.client.transactionEvidence.transactionAttempts, 1);
    assert.equal(loser.client.transactionEvidence.transactionAttempts, 2);

    const observedSerializationErrors =
      loser.client.transactionEvidence.transactionErrors
        .map((error) => ({
          error,
          signalKind: observedSerializationSignalKind(error),
        }))
        .filter((record) => record.signalKind !== null);
    assert.equal(observedSerializationErrors.length, 1);
    assert.equal(
      observedSerializationErrors[0].signalKind,
      "ONE_EDGE_DRIZZLE_TO_PG",
    );

    assert.equal(await activeAdminCount(seedPool, "ws_race"), 1);
    const activeRaceAdmins = await seedPool.query(
      "select id from memberships " +
        "where workspace_id = $1 and status = 'active' and role::text = 'admin' " +
        "order by id",
      ["ws_race"],
    );
    assert.deepEqual(activeRaceAdmins.rows, [{ id: winner.actorMembershipId }]);

    const removalAudits = await seedPool.query(
      "select id, actor_user_id, event_type, target_type, target_id " +
        "from audit_events " +
        "where workspace_id = $1 and event_type = $2 " +
        "order by id",
      ["ws_race", "workspace.membership.removed"],
    );
    assert.equal(removalAudits.rows.length, 1);
    assert.deepEqual(removalAudits.rows[0], {
      id: winner.auditEventId,
      actor_user_id: winner.actorUserId,
      event_type: "workspace.membership.removed",
      target_type: "membership",
      target_id: winner.targetMembershipId,
    });
    const losingAudit = await seedPool.query(
      "select id from audit_events where id = $1",
      [loser.auditEventId],
    );
    assert.equal(losingAudit.rowCount, 0);

    const otherWorkspaceMemberships = await seedPool.query(
      "select id from memberships " +
        "where workspace_id = $1 and status = 'active' " +
        "order by id",
      ["ws_other"],
    );
    assert.deepEqual(otherWorkspaceMemberships.rows, [
      { id: "membership_other_a" },
      { id: "membership_other_b" },
    ]);
    assert.deepEqual(
      await captureSessionStates(seedPool, sessionIds),
      sessionsBefore,
    );

    const soleAdminBefore = await captureMembershipRemovalState(
      seedPool,
      "ws_sole",
      ["session_race_c"],
    );
    await assert.rejects(
      () =>
        removeWorkspaceMembership(clientA.repositories, {
          sessionId: "session_race_c",
          workspaceId: "ws_sole",
          membershipId: "membership_sole_c",
          auditEventId: "audit_sole_control",
          now,
        }),
      (error) => error?.code === "last_admin_required",
    );
    const soleAdminAfter = await captureMembershipRemovalState(
      seedPool,
      "ws_sole",
      ["session_race_c"],
    );
    assert.deepEqual(soleAdminAfter, soleAdminBefore);

    blocker = await seedPool.connect();
    blockerCommitted = false;
    await blocker.query("begin");
    await blocker.query(
      "select id from workspaces where id = $1 for update",
      ["ws_lock"],
    );

    let blockedOperationSettled = false;
    const blockedOperation = removeWorkspaceMembership(clientA.repositories, {
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
    if (outcomesPromise && !outcomesSettled) {
      await outcomesPromise.catch(() => {});
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
    ["ws_other", "other", "Other Workspace"],
    ["ws_sole", "sole", "Sole Admin Control"],
    ["ws_direct_pg", "direct-pg", "Direct PostgreSQL Serialization"],
  ]);

  for (const [id, workspaceId, userId, role] of [
    ["membership_race_a", "ws_race", "race_admin_a", "admin"],
    ["membership_race_b", "ws_race", "race_admin_b", "admin"],
    ["membership_lock_a", "ws_lock", "race_admin_a", "admin"],
    ["membership_lock_b", "ws_lock", "race_admin_b", "admin"],
    ["membership_other_a", "ws_other", "race_admin_a", "operator"],
    ["membership_other_b", "ws_other", "race_admin_b", "operator"],
    ["membership_sole_c", "ws_sole", "race_admin_c", "admin"],
  ]) {
    await pool.query(
      "insert into memberships (id, workspace_id, user_id, role, status) " +
        "values ($1, $2, $3, $4, $5)",
      [id, workspaceId, userId, role, "active"],
    );
  }

  for (const [id, userId] of [
    ["session_race_a", "race_admin_a"],
    ["session_race_b", "race_admin_b"],
    ["session_race_c", "race_admin_c"],
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

async function captureSessionStates(pool, sessionIds) {
  const result = await pool.query(
    "select id, revoked_at::text as revoked_at, last_seen_at::text as last_seen_at " +
      "from sessions where id = any($1::text[]) order by id",
    [sessionIds],
  );
  return result.rows;
}

async function captureMembershipRemovalState(pool, workspaceId, sessionIds) {
  const [memberships, audits, sessions] = await Promise.all([
    pool.query(
      "select id, user_id, role::text as role, status " +
        "from memberships where workspace_id = $1 order by id",
      [workspaceId],
    ),
    pool.query(
      "select id, actor_user_id, event_type, target_type, target_id " +
        "from audit_events where workspace_id = $1 order by id",
      [workspaceId],
    ),
    captureSessionStates(pool, sessionIds),
  ]);
  return {
    memberships: memberships.rows,
    audits: audits.rows,
    sessions,
  };
}

async function proveDirectPostgresSerializationRetry(pool) {
  const first = await pool.connect();
  const second = await pool.connect();
  let firstTransactionOpen = false;
  let secondTransactionOpen = false;
  try {
    await first.query("begin isolation level serializable");
    firstTransactionOpen = true;
    await second.query("begin isolation level serializable");
    secondTransactionOpen = true;
    await Promise.all([
      first.query("select display_name from workspaces where id = $1", ["ws_direct_pg"]),
      second.query("select display_name from workspaces where id = $1", ["ws_direct_pg"]),
    ]);

    await first.query(
      "update workspaces set display_name = display_name || $1 where id = $2",
      [" first", "ws_direct_pg"],
    );
    await first.query("commit");
    firstTransactionOpen = false;

    let serializationError;
    try {
      await second.query(
        "update workspaces set display_name = display_name || $1 where id = $2",
        [" second", "ws_direct_pg"],
      );
    } catch (error) {
      serializationError = error;
    }
    if (!serializationError) {
      try {
        await second.query("commit");
        secondTransactionOpen = false;
      } catch (error) {
        serializationError = error;
      }
    }
    if (serializationError && secondTransactionOpen) {
      await second.query("rollback");
      secondTransactionOpen = false;
    }

    const signalKind = observedSerializationSignalKind(serializationError);
    assert.equal(signalKind, "DIRECT_PG");

    let transactionAttempts = 0;
    let operationCalls = 0;
    const retryDb = {
      async transaction(operation, config) {
        transactionAttempts += 1;
        assert.deepEqual(config, { isolationLevel: "serializable" });
        await operation(retryDb);
        if (transactionAttempts === 1) throw serializationError;
        return "retried";
      },
    };
    const result = await createDrizzlePlatformRepositories(retryDb)
      .workspaceAdminTransactions.run(async () => {
        operationCalls += 1;
      });

    assert.equal(result, "retried");
    return {
      signalKind,
      transactionAttempts,
      operationCalls,
    };
  } finally {
    if (firstTransactionOpen) await first.query("rollback").catch(() => {});
    if (secondTransactionOpen) await second.query("rollback").catch(() => {});
    first.release();
    second.release();
  }
}

function observedSerializationSignalKind(error) {
  if (
    error === null ||
    typeof error !== "object" ||
    nodeUtilTypes.isProxy(error) ||
    !nodeUtilTypes.isNativeError(error)
  ) {
    return null;
  }

  const prototype = Object.getPrototypeOf(error);
  if (
    prototype === DatabaseError.prototype &&
    hasOwnDataPropertyValue(error, "code", "40001")
  ) {
    return "DIRECT_PG";
  }
  if (prototype !== DrizzleQueryError.prototype) {
    return null;
  }

  const causeDescriptor = Object.getOwnPropertyDescriptor(error, "cause");
  if (
    causeDescriptor !== undefined &&
    Object.hasOwn(causeDescriptor, "value") &&
    isDirectPgSerializationFailure(causeDescriptor.value)
  ) {
    return "ONE_EDGE_DRIZZLE_TO_PG";
  }
  return null;
}

function isDirectPgSerializationFailure(error) {
  return (
    error !== null &&
    typeof error === "object" &&
    !nodeUtilTypes.isProxy(error) &&
    nodeUtilTypes.isNativeError(error) &&
    Object.getPrototypeOf(error) === DatabaseError.prototype &&
    hasOwnDataPropertyValue(error, "code", "40001")
  );
}

function hasOwnDataPropertyValue(candidate, key, expectedValue) {
  const descriptor = Object.getOwnPropertyDescriptor(candidate, key);
  return (
    descriptor !== undefined &&
    Object.hasOwn(descriptor, "value") &&
    descriptor.value === expectedValue
  );
}

function createProductionClient(databaseUrl) {
  const pool = new Pool({ connectionString: databaseUrl, max: 1 });
  const db = drizzle(pool, { schema });
  const transactionEvidence = {
    transactionAttempts: 0,
    transactionErrors: [],
  };
  const runDrizzleTransaction = db.transaction.bind(db);
  db.transaction = async (operation, config) => {
    transactionEvidence.transactionAttempts += 1;
    try {
      return await runDrizzleTransaction(operation, config);
    } catch (error) {
      transactionEvidence.transactionErrors.push(error);
      throw error;
    }
  };

  return {
    pool,
    repositories: createDrizzlePlatformRepositories(db),
    transactionEvidence,
  };
}

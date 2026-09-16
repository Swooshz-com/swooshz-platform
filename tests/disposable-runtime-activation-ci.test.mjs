import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { readFile, rm } from "node:fs/promises";
import test from "node:test";
import { PassThrough } from "node:stream";

import {
  ACTIVATION_CREATOR_EDGE_EVIDENCE_CONTRACT,
  ACTIVATION_READINESS_CONNECTION_TIMEOUT_MS,
  ACTIVATION_READINESS_ERROR_BACKOFF_MS,
  ACTIVATION_READINESS_EVIDENCE_CONTRACT,
  ACTIVATION_READINESS_MAX_ATTEMPTS,
  ACTIVATION_RUNNER_FAILURE_CONTRACT,
  ACTIVATION_TOPOLOGY_EVIDENCE_CONTRACT,
  ACTIVATION_TOPOLOGY_SAMPLE_TIMES_MS,
  activationRunnerFailure,
  assertActivationMigrationEntries,
  assertContainersAbsent,
  assertExactDockerResourcesAbsent,
  assertNetworksAbsent,
  assertNoCallerSuppliedActivationInputs,
  assertOwnedDockerTopology,
  aggregateReadinessProbeCategory,
  classifyActivationTestSummary,
  classifyCommandOutcome,
  classifyCreatorEdgeMembershipReadback,
  classifyEnginePosture,
  classifyOperationalBinding,
  classifyPortQuery,
  classifyHostTcpError,
  classifyInternalPgIsReady,
  classifyReadinessContainerState,
  classifyReadinessProbeError,
  classifyRequestBinding,
  classifyTerminalTopologyBinding,
  collectActivationTopologyEvidence,
  createActivationMigrationPrefix,
  executeActivationCleanupActions,
  executeActivationReadinessChecks,
  establishCreatorEdge,
  formatActivationCreatorEdgeEvidence,
  formatActivationReadinessEvidence,
  formatActivationRunnerFailure,
  formatActivationTopologyEvidence,
  isUnsafeInitialOperationalBinding,
  ownedContainerDockerArguments,
  ownedNetworkCreateArguments,
  parentPostgresClientConfig,
  parseActivationTestSummary,
  runActivationChild,
  sanitizeActivationChildDiagnostics,
  settleCreatorEdgeProvisioning,
  waitForPostgresReadiness,
} from "../scripts/run-disposable-runtime-activation-postgres-tests.mjs";
import {
  executeDisposableCleanupActions,
} from "../scripts/run-disposable-runtime-postgres-tests.mjs";

const primaryContainer =
  "codex-platform169-activation-primary-pg17";
const secondaryContainer =
  "codex-platform169-activation-secondary-pg17";
const primaryNetwork =
  "codex-platform169-activation-primary-net";
const secondaryNetwork =
  "codex-platform169-activation-secondary-net";
const networkAlias =
  "ep-disposable-primary-001-pooler.us-east-2.aws.neon.tech";
const primaryOperatorUrl =
  "postgresql://platform_app@127.0.0.1:41001/runtime_posture_test";

test("activation runner rejects every caller-owned activation input", () => {
  assert.doesNotThrow(() =>
    assertNoCallerSuppliedActivationInputs({ NODE_ENV: "test" }));
  for (const value of ["", "disposable-only", "caller-secret"]) {
    assert.throws(() =>
      assertNoCallerSuppliedActivationInputs({
        RUNTIME_ACTIVATION_TEST_OPERATOR_URL: value,
      }));
  }
});

test("activation runner owns exactly two ordinary bridges and two password-safe PostgreSQL 17 containers", () => {
  assert.deepEqual(ownedNetworkCreateArguments(primaryNetwork), [
    "network", "create", "--driver", "bridge", primaryNetwork,
  ]);
  assert.deepEqual(ownedNetworkCreateArguments(secondaryNetwork), [
    "network", "create", "--driver", "bridge", secondaryNetwork,
  ]);

  const primary = ownedContainerDockerArguments(
    primaryContainer,
    primaryNetwork,
  );
  const secondary = ownedContainerDockerArguments(
    secondaryContainer,
    secondaryNetwork,
  );
  for (const [args, containerName, networkName] of [
    [primary, primaryContainer, primaryNetwork],
    [secondary, secondaryContainer, secondaryNetwork],
  ]) {
    assert.equal(args[0], "run");
    assert.equal(args[args.indexOf("--name") + 1], containerName);
    assert.equal(args[args.indexOf("--network") + 1], networkName);
    assert.equal(args[args.indexOf("--network-alias") + 1], networkAlias);
    assert.equal(args[args.indexOf("--publish") + 1], "127.0.0.1::5432");
    assert.equal(args.at(-1), "postgres:17");
    assert.ok(args.includes("POSTGRES_PASSWORD"));
    assert.equal(args.some((value) => /Operator_A1|Runtime_A1/u.test(value)), false);
    assert.equal(args.some((value) => /POSTGRES_HOST_AUTH_METHOD=trust/u.test(value)), false);
  }
  assert.throws(() =>
    ownedContainerDockerArguments(primaryContainer, secondaryNetwork));
});

test("activation migration prefix contains exactly journal entries and SQL 0000 through 0009", async () => {
  const prefix = await createActivationMigrationPrefix();
  try {
    assertActivationMigrationEntries(prefix.entries);
    assert.equal(prefix.entries.length, 9);
    assert.equal(prefix.entries.at(-1).tag, "0009_wonderful_star_brand");
    assert.equal(
      prefix.entries.some((entry) =>
        entry.tag === "0010_admin_operator_viewer_role_collapse"),
      false,
    );
    const journal = JSON.parse(
      await readFile(`${prefix.migrationsFolder}/meta/_journal.json`, "utf8"),
    );
    assert.equal(journal.entries.length, 9);
  } finally {
    await rm(prefix.temporaryRoot, { recursive: true, force: true });
  }
});

test("activation summary parser accepts only strict 45 of 45 zero-negative TAP summaries", () => {
  const valid = activationSummary();
  assert.deepEqual(parseActivationTestSummary(valid), {
    total: 45,
    passed: 45,
    failed: 0,
    cancelled: 0,
    skipped: 0,
    todo: 0,
  });
  for (const invalid of [
    activationSummary({ tests: 44, pass: 44 }),
    activationSummary({ fail: 1, pass: 44 }),
    activationSummary({ skipped: 1, pass: 44 }),
    activationSummary({ cancelled: 1, pass: 44 }),
    activationSummary({ todo: 1, pass: 44 }),
    activationSummary({ duration_ms: "180001" }),
    valid.replace("# todo 0\n", ""),
    `${valid}\n${activationSummary()}`,
    `${valid}\nnot-summary`,
  ]) {
    assert.equal(parseActivationTestSummary(invalid), null);
  }
});

test("activation failure contract emits every closed phase and category for every fixed target", () => {
  const targets = ["NONE", "PRIMARY", "SECONDARY", "BOTH"];
  for (const [phase, categories] of Object.entries(
    ACTIVATION_RUNNER_FAILURE_CONTRACT,
  )) {
    for (const category of categories) {
      for (const target of targets) {
        const error = activationRunnerFailure(phase, category, target);
        assert.equal(
          formatActivationRunnerFailure(error),
          `ACTIVATION_RUNNER_FAILURE phase=${phase} ` +
            `category=${category} target=${target}`,
        );
        assert.equal(error.message, "");
        assert.equal(error.cause, undefined);
      }
    }
  }
  assert.throws(() => activationRunnerFailure("UNKNOWN", "UNKNOWN"));
  assert.throws(() => activationRunnerFailure(
    "NETWORK_CREATE", "COMMAND_NONZERO", "DYNAMIC_TARGET",
  ));
  assert.throws(() => activationRunnerFailure(
    "POSTGRES_READINESS",
    "READINESS_TIMEOUT",
    "BOTH",
    "",
    null,
    [{}, {}, {}],
  ));
});

test("creator-edge diagnostics classify every substep without leaking raw failures", async () => {
  const cases = [
    ["POOL_ACQUISITION", ["POOL_ACQUISITION"], "FAILED"],
    ["SESSION_AUTHORIZATION_SET", ["SESSION_AUTHORIZATION_SET"], "FAILED"],
    ["CREATOR_EDGE_GRANT", ["CREATOR_EDGE_GRANT"], "FAILED"],
    ["SESSION_AUTHORIZATION_RESET", ["SESSION_AUTHORIZATION_RESET"], "FAILED"],
    ["CREATOR_EDGE_MEMBERSHIP_READBACK", ["CREATOR_EDGE_MEMBERSHIP_READBACK"], "UNAVAILABLE"],
  ];
  for (const [expectedSubstep, failures, expectedResult] of cases) {
    const fixture = diagnosticCreatorEdgePool({ failures });
    await assert.rejects(
      () => establishCreatorEdge(fixture.pool, "SECONDARY"),
      (error) => {
        assert.equal(
          formatActivationRunnerFailure(error),
          "ACTIVATION_RUNNER_FAILURE phase=FIXTURE_PROVISION " +
            "category=CREATOR_EDGE_FAILED target=SECONDARY",
        );
        const [evidence] = error.activationCreatorEdgeEvidence;
        assert.deepEqual(evidence, {
          TARGET: "SECONDARY",
          SUBSTEP: expectedSubstep,
          RESULT: expectedResult,
        });
        const receipt = formatActivationCreatorEdgeEvidence(evidence);
        assert.equal(
          receipt,
          `ACTIVATION_CREATOR_EDGE_EVIDENCE TARGET=SECONDARY ` +
            `SUBSTEP=${expectedSubstep} RESULT=${expectedResult}`,
        );
        assert.doesNotMatch(
          `${receipt}\n${formatActivationRunnerFailure(error)}`,
          /private-password|postgresql:\/\/|raw-cause|raw-stack/u,
        );
        assert.equal(error.message, "");
        assert.equal(error.cause, undefined);
        return true;
      },
    );
  }
});

test("creator-edge membership readback preserves the exact accepted edge", async () => {
  const exact = diagnosticCreatorEdgePool();
  assert.deepEqual(await establishCreatorEdge(exact.pool, "PRIMARY"), {
    TARGET: "PRIMARY",
    SUBSTEP: "CREATOR_EDGE_MEMBERSHIP_READBACK",
    RESULT: "EXACT",
  });
  assert.deepEqual(exact.calls.map(classifyCreatorEdgeCall), [
    "POOL_ACQUISITION",
    "SESSION_AUTHORIZATION_SET",
    "CREATOR_EDGE_GRANT",
    "SESSION_AUTHORIZATION_RESET",
    "CLIENT_RELEASE_DESTROY",
    "CREATOR_EDGE_MEMBERSHIP_READBACK",
  ]);

  for (const [rows, result] of [
    [[], "ABSENT"],
    [[{ ...exactCreatorEdgeRow(), grantor: "platform_app" }], "MISMATCH"],
    [[exactCreatorEdgeRow(), exactCreatorEdgeRow()], "MISMATCH"],
  ]) {
    const fixture = diagnosticCreatorEdgePool({ rows });
    await assert.rejects(
      () => establishCreatorEdge(fixture.pool, "PRIMARY"),
      (error) => {
        assert.deepEqual(error.activationCreatorEdgeEvidence, [{
          TARGET: "PRIMARY",
          SUBSTEP: "CREATOR_EDGE_MEMBERSHIP_READBACK",
          RESULT: result,
        }]);
        return true;
      },
    );
  }
  assert.deepEqual(
    classifyCreatorEdgeMembershipReadback({}, "PRIMARY"),
    {
      TARGET: "PRIMARY",
      SUBSTEP: "CREATOR_EDGE_MEMBERSHIP_READBACK",
      RESULT: "UNAVAILABLE",
    },
  );
});

test("creator-edge provisioning settles both targets before ordered evidence", async () => {
  let releasePrimary;
  let settlementFinished = false;
  const primaryGate = new Promise((resolve) => { releasePrimary = resolve; });
  const secondaryFailure = diagnosticCreatorEdgePool({
    failures: ["SESSION_AUTHORIZATION_SET"],
  });
  const settlementPromise = settleCreatorEdgeProvisioning([
    {
      target: "PRIMARY",
      operation: async () => {
        await primaryGate;
        return classifyCreatorEdgeMembershipReadback(
          { rows: [exactCreatorEdgeRow()] },
          "PRIMARY",
        );
      },
    },
    {
      target: "SECONDARY",
      operation: () => establishCreatorEdge(
        secondaryFailure.pool,
        "SECONDARY",
      ),
    },
  ]).then((value) => {
    settlementFinished = true;
    return value;
  });
  await Promise.resolve();
  assert.equal(settlementFinished, false);
  releasePrimary();
  const settlement = await settlementPromise;
  assert.deepEqual(settlement.evidence, [
    {
      TARGET: "PRIMARY",
      SUBSTEP: "CREATOR_EDGE_MEMBERSHIP_READBACK",
      RESULT: "EXACT",
    },
    {
      TARGET: "SECONDARY",
      SUBSTEP: "SESSION_AUTHORIZATION_SET",
      RESULT: "FAILED",
    },
  ]);
  assert.equal(formatActivationRunnerFailure(settlement.error),
    "ACTIVATION_RUNNER_FAILURE phase=FIXTURE_PROVISION " +
      "category=CREATOR_EDGE_FAILED target=SECONDARY");
});

test("creator-edge provisioning retains both failures in target order", async () => {
  let releasePrimary;
  const primaryGate = new Promise((resolve) => { releasePrimary = resolve; });
  const primaryFailure = diagnosticCreatorEdgePool({
    failures: ["CREATOR_EDGE_GRANT"],
  });
  const secondaryFailure = diagnosticCreatorEdgePool({
    failures: ["SESSION_AUTHORIZATION_RESET"],
  });
  const settlementPromise = settleCreatorEdgeProvisioning([
    {
      target: "PRIMARY",
      operation: async () => {
        await primaryGate;
        return establishCreatorEdge(primaryFailure.pool, "PRIMARY");
      },
    },
    {
      target: "SECONDARY",
      operation: () => establishCreatorEdge(
        secondaryFailure.pool,
        "SECONDARY",
      ),
    },
  ]);
  await Promise.resolve();
  releasePrimary();
  const settlement = await settlementPromise;
  assert.deepEqual(settlement.evidence, [
    {
      TARGET: "PRIMARY",
      SUBSTEP: "CREATOR_EDGE_GRANT",
      RESULT: "FAILED",
    },
    {
      TARGET: "SECONDARY",
      SUBSTEP: "SESSION_AUTHORIZATION_RESET",
      RESULT: "FAILED",
    },
  ]);
  assert.deepEqual(
    formatActivationRunnerFailure(settlement.error).split("\n"),
    [
      "ACTIVATION_RUNNER_FAILURE phase=FIXTURE_PROVISION " +
        "category=CREATOR_EDGE_FAILED target=PRIMARY",
      "ACTIVATION_RUNNER_FAILURE phase=FIXTURE_PROVISION " +
        "category=CREATOR_EDGE_FAILED target=SECONDARY",
    ],
  );
});

test("creator-edge evidence is closed and bounded", () => {
  assert.deepEqual(Object.keys(ACTIVATION_CREATOR_EDGE_EVIDENCE_CONTRACT), [
    "TARGET", "SUBSTEP", "RESULT",
  ]);
  for (const target of ACTIVATION_CREATOR_EDGE_EVIDENCE_CONTRACT.TARGET) {
    for (const substep of ACTIVATION_CREATOR_EDGE_EVIDENCE_CONTRACT.SUBSTEP) {
      for (const result of ACTIVATION_CREATOR_EDGE_EVIDENCE_CONTRACT.RESULT) {
        const receipt = formatActivationCreatorEdgeEvidence({
          TARGET: target,
          SUBSTEP: substep,
          RESULT: result,
        });
        assert.ok(Buffer.byteLength(receipt, "utf8") < 192);
        assert.match(receipt, /^ACTIVATION_CREATOR_EDGE_EVIDENCE [A-Z_= ]+$/u);
      }
    }
  }
  assert.throws(() => formatActivationCreatorEdgeEvidence({
    TARGET: "PRIMARY",
    SUBSTEP: "CREATOR_EDGE_GRANT",
    RESULT: "FAILED",
    raw: "postgresql://private-password@127.0.0.1:54321/private",
  }));
});

test("activation readiness evidence binds every closed category without raw fields", () => {
  const base = {
    OUTCOME: "TIMEOUT",
    ATTEMPTS: ACTIVATION_READINESS_MAX_ATTEMPTS,
    AGGREGATE_PROBE: "CONNECTION_REFUSED",
    LAST_PROBE: "CONNECTION_REFUSED",
    CONTAINER_STATE: "RUNNING",
    INTERNAL_PG_ISREADY: "ACCEPTING",
    HOST_TCP: "CONNECTED",
    TOPOLOGY_BINDING: "EXACT",
    TARGET: "PRIMARY",
  };
  for (const [field, categories] of Object.entries(
    ACTIVATION_READINESS_EVIDENCE_CONTRACT,
  )) {
    for (const category of categories) {
      const receipt = formatActivationReadinessEvidence({
        ...base,
        [field]: category,
        raw: "postgresql://private@127.0.0.1:54321/private container-id",
      });
      assert.match(receipt, new RegExp(`${field}=${category}(?: |$)`, "u"));
      assert.doesNotMatch(
        receipt,
        /postgresql:\/\/|127\.0\.0\.1|54321|private|container-id/u,
      );
      assert.ok(Buffer.byteLength(receipt, "utf8") < 512);
    }
  }
  assert.throws(() => formatActivationReadinessEvidence({
    ...base,
    ATTEMPTS: ACTIVATION_READINESS_MAX_ATTEMPTS + 1,
  }));
  assert.throws(() => formatActivationReadinessEvidence({
    ...base,
    HOST_TCP: "RAW_NETWORK_ERROR",
  }));
});

test("activation readiness classifiers cover every causal evidence category", () => {
  const errorCases = [
    ["ECONNREFUSED", "CONNECTION_REFUSED"],
    ["ETIMEDOUT", "CONNECTION_TIMEOUT"],
    [undefined, "CONNECTION_TIMEOUT", "Connection terminated due to connection timeout"],
    ["ENETUNREACH", "NETWORK_UNREACHABLE"],
    ["28P01", "AUTH_REJECTED"],
    ["57P03", "SERVER_STARTING"],
    ["08006", "PROTOCOL_OR_SERVER_ERROR"],
    ["42P01", "QUERY_FAILED"],
    ["not-a-code", "UNKNOWN"],
  ];
  for (const [code, category, message] of errorCases) {
    assert.equal(classifyReadinessProbeError({ code, message }), category);
  }
  assert.equal(
    aggregateReadinessProbeCategory([
      "CONNECTION_REFUSED", "AUTH_REJECTED", "AUTH_REJECTED",
    ]),
    "AUTH_REJECTED",
  );
  assert.equal(aggregateReadinessProbeCategory([]), "UNKNOWN");

  const containerCases = [
    [{ Status: "running" }, "RUNNING"],
    [{ Status: "restarting" }, "RESTARTING"],
    [{ Status: "exited" }, "EXITED"],
    [{ Status: "dead" }, "DEAD"],
    [{ Status: "exited", OOMKilled: true }, "OOM_KILLED"],
    [{ Status: "paused" }, "UNKNOWN"],
  ];
  for (const [state, category] of containerCases) {
    assert.equal(classifyReadinessContainerState(state), category);
  }
  assert.equal(classifyInternalPgIsReady({ code: 0 }), "ACCEPTING");
  assert.equal(classifyInternalPgIsReady({ code: 1 }), "REJECTING");
  assert.equal(classifyInternalPgIsReady({ code: 2 }), "NO_RESPONSE");
  assert.equal(classifyInternalPgIsReady({ code: 3 }), "COMMAND_FAILED");
  assert.equal(classifyHostTcpError({ code: "ECONNREFUSED" }), "REFUSED");
  assert.equal(classifyHostTcpError({ code: "ETIMEDOUT" }), "TIMEOUT");
  assert.equal(classifyHostTcpError({ code: "ENETUNREACH" }), "NETWORK_ERROR");

  const exact = {
    request: { category: "EXACT_DYNAMIC" },
    operational: { category: "EXACT", port: 41001 },
    portQuery: { category: "EXACT", port: 41001 },
    expectedPort: 41001,
  };
  assert.equal(classifyTerminalTopologyBinding(exact), "EXACT");
  assert.equal(classifyTerminalTopologyBinding({
    ...exact,
    operational: { category: "EXACT", port: 41002 },
  }), "CHANGED");
  assert.equal(classifyTerminalTopologyBinding({
    ...exact,
    operational: { category: "COMMAND_NONZERO" },
  }), "UNPROVEN");
});

test("activation readiness keeps the exact predicate and fixed retry budget", async () => {
  assert.equal(ACTIVATION_READINESS_MAX_ATTEMPTS, 240);
  assert.equal(ACTIVATION_READINESS_CONNECTION_TIMEOUT_MS, 1_000);
  assert.equal(ACTIVATION_READINESS_ERROR_BACKOFF_MS, 500);

  const poolOptions = [];
  class MismatchPool {
    constructor(options) { poolOptions.push(options); }
    async query() { return { rows: [{ admitted: true, postgres17: false }] }; }
    async end() {}
  }
  const mismatch = await waitForPostgresReadiness(
    primaryOperatorUrl,
    "private-password",
    { PoolImpl: MismatchPool, delayImpl: async () => assert.fail("no delay") },
  );
  assert.deepEqual(mismatch, {
    outcome: "TIMEOUT",
    attempts: 240,
    aggregateProbe: "IDENTITY_OR_VERSION_MISMATCH",
    lastProbe: "IDENTITY_OR_VERSION_MISMATCH",
  });
  assert.equal(poolOptions.length, 240);
  assert.equal(
    poolOptions.every((options) =>
      options.connectionTimeoutMillis === 1_000 &&
      options.max === 1 &&
      options.password === "private-password" &&
      options.user === "platform_app" &&
      options.host === "127.0.0.1" &&
      options.port === 41001 &&
      options.database === "runtime_posture_test" &&
      !Object.hasOwn(options, "connectionString")),
    true,
  );

  const readyQueries = [];
  class ReadyPool {
    async query(statement) {
      readyQueries.push(statement);
      return { rows: [{ admitted: true, postgres17: true }] };
    }
    async end() {}
  }
  assert.deepEqual(await waitForPostgresReadiness(primaryOperatorUrl, "private", {
    PoolImpl: ReadyPool,
  }), {
    outcome: "READY",
    attempts: 1,
    aggregateProbe: "UNKNOWN",
    lastProbe: "UNKNOWN",
  });
  assert.deepEqual(readyQueries, [
    "select current_user = 'platform_app' as admitted, current_setting('server_version_num')::integer / 10000 = 17 as postgres17",
  ]);

  class ReadyWithEndFailurePool extends ReadyPool {
    async end() { throw new Error("private pool end failure"); }
  }
  assert.deepEqual(await waitForPostgresReadiness(primaryOperatorUrl, "private", {
    PoolImpl: ReadyWithEndFailurePool,
  }), {
    outcome: "TIMEOUT",
    attempts: 1,
    aggregateProbe: "UNKNOWN",
    lastProbe: "UNKNOWN",
  });

  const delays = [];
  class RefusedPool {
    async query() { throw Object.assign(new Error(), { code: "ECONNREFUSED" }); }
    async end() {}
  }
  const refused = await waitForPostgresReadiness(
    primaryOperatorUrl,
    "private",
    {
    PoolImpl: RefusedPool,
    delayImpl: async (milliseconds) => delays.push(milliseconds),
    },
  );
  assert.equal(refused.attempts, 240);
  assert.equal(refused.aggregateProbe, "CONNECTION_REFUSED");
  assert.equal(delays.length, 240);
  assert.equal(delays.every((milliseconds) => milliseconds === 500), true);
});

test("parent PostgreSQL config keeps the generated password explicit without environment fallback", () => {
  const previousPassword = process.env.PGPASSWORD;
  delete process.env.PGPASSWORD;
  try {
    const generatedPassword = "Operator_A1!generated-private-value";
    const config = parentPostgresClientConfig(
      primaryOperatorUrl,
      generatedPassword,
    );
    assert.deepEqual(config, {
      user: "platform_app",
      host: "127.0.0.1",
      port: 41001,
      database: "runtime_posture_test",
      password: generatedPassword,
    });
    assert.equal(typeof config.password, "string");
    assert.equal(Object.hasOwn(config, "connectionString"), false);
    assert.equal(new URL(primaryOperatorUrl).password, "");
  } finally {
    if (previousPassword === undefined) delete process.env.PGPASSWORD;
    else process.env.PGPASSWORD = previousPassword;
  }
});

test("parent PostgreSQL config fails closed without exposing credentials", () => {
  const generatedPassword = "Operator_A1!never-emit-this";
  const invalidInputs = [
    "not-a-uri",
    "postgres://platform_app@127.0.0.1:41001/runtime_posture_test",
    "postgresql://platform_app:uri-secret@127.0.0.1:41001/runtime_posture_test",
    "postgresql://platform_app@localhost:41001/runtime_posture_test",
    "postgresql://platform_app@127.0.0.2:41001/runtime_posture_test",
    "postgresql://platform_app@127.0.0.1/runtime_posture_test",
    "postgresql://platform_app@127.0.0.1:0/runtime_posture_test",
    "postgresql://platform_app@127.0.0.1:65536/runtime_posture_test",
    "postgresql://platform_app@127.0.0.1:041001/runtime_posture_test",
    "postgresql://platform-app@127.0.0.1:41001/runtime_posture_test",
    "postgresql://postgres@127.0.0.1:41001/runtime_posture_test",
    "postgresql://platform_app@127.0.0.1:41001/runtime-posture-test",
    "postgresql://platform_app@127.0.0.1:41001/other_database",
    `${primaryOperatorUrl}?sslmode=disable`,
    `${primaryOperatorUrl}#fragment`,
  ];
  for (const connectionString of invalidInputs) {
    assert.throws(
      () => parentPostgresClientConfig(connectionString, generatedPassword),
      (error) => {
        const diagnostic = String(error);
        assert.equal(
          diagnostic,
          "TypeError: Invalid parent PostgreSQL client configuration",
        );
        assert.doesNotMatch(
          diagnostic,
          /never-emit-this|uri-secret|postgresql:\/\//u,
        );
        return true;
      },
    );
  }
  for (const password of [undefined, null, 42, ""]) {
    assert.throws(
      () => parentPostgresClientConfig(primaryOperatorUrl, password),
      /Invalid parent PostgreSQL client configuration/u,
    );
  }
});

test("all four parent PostgreSQL construction surfaces use the explicit config helper", async () => {
  const source = await readFile(
    "scripts/run-disposable-runtime-activation-postgres-tests.mjs",
    "utf8",
  );
  assert.equal(
    source.match(/\.\.\.parentPostgresClientConfig\(/gu)?.length,
    4,
  );
  assert.match(
    source,
    /clientFactory: async \(target\) => \{[\s\S]*?new Client\(\{[\s\S]*?\.\.\.parentPostgresClientConfig\(\s*target\.connectionString,\s*resources\.operatorPassword,/u,
  );
  assert.match(
    source,
    /async function provisionFixture\([\s\S]*?new Pool\(\{\s*\.\.\.parentPostgresClientConfig\(connectionString, operatorPassword\),/u,
  );
  assert.match(
    source,
    /async function assertFixtureIdentity\([\s\S]*?new Pool\(\{\s*\.\.\.parentPostgresClientConfig\(connectionString, operatorPassword\),/u,
  );
  assert.match(
    source,
    /export async function waitForPostgresReadiness\([\s\S]*?new PoolImpl\(\{\s*\.\.\.parentPostgresClientConfig\(connectionString, operatorPassword\),/u,
  );
  assert.doesNotMatch(
    source,
    /new (?:Client|Pool|PoolImpl)\(\{\s*connectionString,\s*password:/u,
  );
});

test("activation readiness settles both targets once and attributes terminal evidence independently", async () => {
  const waits = [];
  const collections = [];
  const evidenceFor = ({ probe, target }) => ({
    OUTCOME: probe.outcome,
    ATTEMPTS: probe.attempts,
    AGGREGATE_PROBE: probe.aggregateProbe,
    LAST_PROBE: probe.lastProbe,
    CONTAINER_STATE: target === "PRIMARY" ? "EXITED" : "RUNNING",
    INTERNAL_PG_ISREADY: target === "PRIMARY" ? "NO_RESPONSE" : "ACCEPTING",
    HOST_TCP: target === "PRIMARY" ? "REFUSED" : "CONNECTED",
    TOPOLOGY_BINDING: target === "PRIMARY" ? "UNPROVEN" : "EXACT",
    TARGET: target,
  });
  await assert.rejects(
    () => executeActivationReadinessChecks({
      operatorUrls: ["primary-private", "secondary-private"],
      operatorPassword: "private-password",
      ports: [41001, 41002],
      spawnImpl: () => assert.fail("not used"),
      waitForPostgresImpl: async (url) => {
        waits.push(url);
        if (url.startsWith("primary")) throw new Error("private primary error");
        await Promise.resolve();
        return {
          outcome: "READY",
          attempts: 3,
          aggregateProbe: "SERVER_STARTING",
          lastProbe: "SERVER_STARTING",
        };
      },
      collectTerminalEvidenceImpl: async (input) => {
        collections.push(input.target);
        return evidenceFor(input);
      },
    }),
    (error) => {
      const receipt = formatActivationRunnerFailure(error);
      assert.match(receipt, /category=READINESS_TIMEOUT target=PRIMARY/u);
      assert.match(receipt, /OUTCOME=TIMEOUT ATTEMPTS=1 .*TARGET=PRIMARY/u);
      assert.match(receipt, /OUTCOME=READY ATTEMPTS=3 .*TARGET=SECONDARY/u);
      assert.doesNotMatch(
        receipt,
        /private|primary-private|secondary-private|41001|41002/u,
      );
      return true;
    },
  );
  assert.deepEqual(waits.sort(), ["primary-private", "secondary-private"]);
  assert.deepEqual(collections, ["PRIMARY", "SECONDARY"]);

  let acceptanceCollections = 0;
  const accepted = await executeActivationReadinessChecks({
    operatorUrls: ["primary-private", "secondary-private"],
    operatorPassword: "private-password",
    ports: [41001, 41002],
    spawnImpl: () => assert.fail("not used"),
    waitForPostgresImpl: async () => ({
      outcome: "READY",
      attempts: 1,
      aggregateProbe: "UNKNOWN",
      lastProbe: "UNKNOWN",
    }),
    collectTerminalEvidenceImpl: async () => {
      acceptanceCollections += 1;
      return null;
    },
  });
  assert.equal(accepted.length, 2);
  assert.equal(acceptanceCollections, 0);
});

test("activation command outcomes have deterministic closed categories", () => {
  const cases = [
    [{ code: 0, signal: null, timedOut: false, outputOverflow: false }, null],
    [{ code: 7, signal: null, timedOut: false, outputOverflow: false }, "COMMAND_NONZERO"],
    [{ code: null, signal: "SIGTERM", timedOut: false, outputOverflow: false }, "SIGNAL"],
    [{ code: null, signal: "SIGTERM", timedOut: true, outputOverflow: false }, "TIMEOUT"],
    [{ code: 0, signal: null, timedOut: false, outputOverflow: true }, "OUTPUT_OVERFLOW"],
  ];
  for (const [outcome, expected] of cases) {
    assert.equal(classifyCommandOutcome(outcome), expected);
  }
});

test("activation topology classifiers cover the closed engine, binding, and query states", () => {
  const commandCategories = [
    "COMMAND_SPAWN_FAILED", "COMMAND_NONZERO", "SIGNAL", "TIMEOUT",
    "OUTPUT_OVERFLOW",
  ];
  assert.deepEqual(classifyEnginePosture({ stdout: "28.0.4\n" }), {
    category: "GE_28",
  });
  assert.deepEqual(classifyEnginePosture({ stdout: "27.5.1" }), {
    category: "LT_28",
  });
  assert.deepEqual(classifyEnginePosture({ stdout: "unknown" }), {
    category: "UNPARSEABLE",
  });
  for (const category of commandCategories) {
    for (const classify of [
      classifyEnginePosture,
      classifyRequestBinding,
      classifyOperationalBinding,
      classifyPortQuery,
    ]) {
      assert.deepEqual(classify({ commandCategory: category }), { category });
    }
  }

  const binding = (HostIp, HostPort) => ({
    stdout: JSON.stringify({ "5432/tcp": [{ HostIp, HostPort }] }),
  });
  assert.deepEqual(classifyRequestBinding(binding("127.0.0.1", "")), {
    category: "EXACT_DYNAMIC",
  });
  for (const port of ["1", "65535"]) {
    assert.deepEqual(classifyRequestBinding(binding("127.0.0.1", port)), {
      category: "EXACT_ASSIGNED", port: Number(port),
    });
    assert.deepEqual(classifyOperationalBinding(binding("127.0.0.1", port)), {
      category: "EXACT", port: Number(port),
    });
  }

  const sharedCases = [
    [{ stdout: "" }, "MISSING"],
    [{ stdout: "null" }, "MISSING"],
    [{ stdout: "{" }, "MALFORMED"],
    [{ stdout: "[]" }, "MALFORMED"],
    [{ stdout: "{}" }, "EXPECTED_PORT_MISSING"],
    [{ stdout: JSON.stringify({ "5433/tcp": [] }) }, "UNEXPECTED_PORT_PRESENT"],
    [{ stdout: JSON.stringify({ "5432/tcp": [], "5433/tcp": [] }) }, "UNEXPECTED_PORT_PRESENT"],
    [{ stdout: JSON.stringify({ "5432/tcp": null }) }, "BINDING_SHAPE_INVALID"],
    [{ stdout: JSON.stringify({ "5432/tcp": [] }) }, "BINDING_MISSING"],
    [{ stdout: JSON.stringify({ "5432/tcp": [{}, {}] }) }, "BINDING_MULTIPLE"],
    [{ stdout: JSON.stringify({ "5432/tcp": ["invalid"] }) }, "BINDING_SHAPE_INVALID"],
  ];
  for (const [observation, category] of sharedCases) {
    assert.equal(classifyRequestBinding(observation).category, category);
    assert.equal(classifyOperationalBinding(observation).category, category);
  }
  for (const host of [undefined, "", "0.0.0.0", "::"]) {
    assert.equal(
      classifyOperationalBinding(binding(host, "54321")).category,
      "HOST_WILDCARD_OR_MISSING",
    );
  }
  assert.equal(
    classifyOperationalBinding(binding("192.0.2.1", "54321")).category,
    "HOST_NONLOOPBACK",
  );
  for (const host of ["127.0.0.2", "::1"]) {
    assert.equal(
      classifyOperationalBinding(binding(host, "54321")).category,
      "HOST_LOOPBACK_MISMATCH",
    );
  }
  for (const HostPort of [undefined, ""]) {
    assert.equal(
      classifyOperationalBinding(binding("127.0.0.1", HostPort)).category,
      "HOST_PORT_MISSING",
    );
  }
  for (const HostPort of [null, 54321, "not-decimal"]) {
    assert.equal(
      classifyOperationalBinding(binding("127.0.0.1", HostPort)).category,
      "HOST_PORT_NONDECIMAL",
    );
  }
  for (const HostPort of ["0", "65536"]) {
    assert.equal(
      classifyOperationalBinding(binding("127.0.0.1", HostPort)).category,
      "PORT_OUT_OF_RANGE",
    );
    assert.equal(
      classifyRequestBinding(binding("127.0.0.1", HostPort)).category,
      "PORT_INVALID",
    );
  }

  const queryCases = [
    ["127.0.0.1:1\n", "EXACT", 1],
    ["127.0.0.1:65535\n", "EXACT", 65535],
    ["", "MISSING"],
    ["invalid", "MALFORMED"],
    ["127.0.0.1:1\n127.0.0.1:2\n", "MULTIPLE"],
    ["0.0.0.0:1", "HOST_WILDCARD_OR_MISSING"],
    ["[::]:1", "HOST_WILDCARD_OR_MISSING"],
    ["192.0.2.1:1", "HOST_NONLOOPBACK"],
    ["127.0.0.2:1", "HOST_LOOPBACK_MISMATCH"],
    ["[::1]:1", "HOST_LOOPBACK_MISMATCH"],
    ["127.0.0.1:not-decimal", "PORT_INVALID"],
    ["127.0.0.1:0", "PORT_INVALID"],
    ["127.0.0.1:65536", "PORT_INVALID"],
  ];
  for (const [stdout, category, port] of queryCases) {
    assert.deepEqual(
      classifyPortQuery({ stdout }),
      port ? { category, port } : { category },
    );
  }
});

test("activation topology accepts only GE_28 ordinary bridges and exact first loopback ports", async () => {
  const primaryCalls = [];
  const primaryPort = await assertOwnedDockerTopology(
    activationTopologySpawn({
      networkName: primaryNetwork,
      assignedPort: 41001,
      onCommand: (args) => primaryCalls.push(args),
    }),
    primaryContainer,
    primaryNetwork,
    "PRIMARY",
  );
  const secondaryPort = await assertOwnedDockerTopology(
    activationTopologySpawn({
      networkName: secondaryNetwork,
      assignedPort: 41002,
    }),
    secondaryContainer,
    secondaryNetwork,
    "SECONDARY",
  );
  assert.equal(primaryPort, 41001);
  assert.equal(secondaryPort, 41002);
  assert.notEqual(primaryPort, secondaryPort);
  assert.equal(
    primaryCalls.filter((args) =>
      args.includes("{{json .NetworkSettings.Ports}}")).length,
    1,
  );
  assert.equal(
    primaryCalls.filter((args) => args[0] === "port").length,
    1,
  );
});

test("activation topology rejects unproved engine, bridge, request, and port state", async () => {
  const cases = [
    ["ENGINE_INVALID", { version: "27.5.1" }],
    ["ENGINE_INVALID", { version: "unknown" }],
    ["NETWORK_INVALID", { network: { Driver: "bridge", Internal: true, Options: {} } }],
    ["NETWORK_INVALID", { network: { Driver: "overlay", Internal: false, Options: {} } }],
    ["NETWORK_INVALID", {
      network: {
        Driver: "bridge",
        Internal: false,
        Options: { "com.docker.network.bridge.gateway_mode_ipv4": "routed" },
      },
    }],
    ["NETWORK_INVALID", { network: { Driver: "bridge", Internal: false } }],
    ["NETWORK_INVALID", { networkOutput: "{" }],
    ["BINDING_INVALID", { requestPort: "41001" }],
    ["PORT_INVALID", { assignedPort: 41001, queriedPort: 41002 }],
  ];
  for (const [category, options] of cases) {
    await assert.rejects(
      () => assertOwnedDockerTopology(
        activationTopologySpawn(options),
        primaryContainer,
        primaryNetwork,
        "PRIMARY",
      ),
      (error) => error.phase === "TOPOLOGY_PORT_VERIFY" &&
        error.category === category && error.target === "PRIMARY",
    );
  }
});

test("activation topology sampling is bounded and never accepts a rejected first observation", async () => {
  assert.deepEqual(ACTIVATION_TOPOLOGY_SAMPLE_TIMES_MS, [0, 250, 500, 750, 1000]);
  const base = {
    observeEngine: async () => ({ category: "GE_28" }),
    observeRequest: async () => ({ category: "EXACT_DYNAMIC" }),
    observePortQuery: async () => ({ category: "EXACT", port: 41001 }),
  };
  const collect = async (samples, target = "PRIMARY") => {
    const delays = [];
    let index = 1;
    const evidence = await collectActivationTopologyEvidence({
      ...base,
      target,
      firstOperational: samples[0],
      observeOperational: async () => samples[index++],
      delayImpl: async (milliseconds) => delays.push(milliseconds),
    });
    return { evidence, delays, observations: index };
  };

  const stable = await collect(Array.from({ length: 5 }, () => ({
    category: "MISSING",
  })));
  assert.equal(stable.evidence.TEMPORAL, "STABLE");
  assert.equal(stable.evidence.OPERATIONAL_TERMINAL, "MISSING");
  assert.deepEqual(stable.delays, [250, 250, 250, 250]);
  assert.equal(stable.observations, 5);

  const converged = await collect([
    { category: "MISSING" },
    { category: "MISSING" },
    { category: "EXACT", port: 41001 },
    { category: "EXACT", port: 41001 },
    { category: "EXACT", port: 41001 },
  ]);
  assert.equal(converged.evidence.TEMPORAL, "CONVERGED_TO_EXACT");
  assert.equal(converged.evidence.PORT_MATCH, "YES");

  const changed = await collect([
    { category: "MISSING" },
    { category: "MALFORMED" },
    { category: "BINDING_MISSING" },
    { category: "MISSING" },
    { category: "MALFORMED" },
  ], "SECONDARY");
  assert.equal(changed.evidence.TEMPORAL, "CHANGED_NONEXACT");
  assert.equal(changed.evidence.TARGET, "SECONDARY");

  const unsafeCategories = [
    "UNEXPECTED_PORT_PRESENT", "BINDING_SHAPE_INVALID", "BINDING_MULTIPLE",
    "HOST_WILDCARD_OR_MISSING", "HOST_NONLOOPBACK",
    "HOST_PORT_NONDECIMAL", "PORT_OUT_OF_RANGE",
  ];
  for (const category of unsafeCategories) {
    assert.equal(isUnsafeInitialOperationalBinding({ category }), true);
    const unsafe = await collect([{ category }]);
    assert.equal(unsafe.evidence.TEMPORAL, "NOT_SAMPLED");
    assert.deepEqual(unsafe.delays, []);
    assert.equal(unsafe.observations, 1);
  }
});

test("activation topology evidence is categorical, body-first, target-bound, and secret-safe", () => {
  const evidence = {
    ENGINE: "GE_28",
    REQUEST: "EXACT_DYNAMIC",
    OPERATIONAL_FIRST: "MISSING",
    OPERATIONAL_TERMINAL: "EXACT",
    PORT_QUERY: "EXACT",
    TEMPORAL: "CONVERGED_TO_EXACT",
    PORT_MATCH: "YES",
    TARGET: "PRIMARY",
    raw: "private-docker-output 127.0.0.1:41001 container-id secret",
  };
  const receipt = formatActivationRunnerFailure(activationRunnerFailure(
    "TOPOLOGY_PORT_VERIFY", "BINDING_INVALID", "PRIMARY", "", evidence,
  ));
  const lines = receipt.split("\n");
  assert.equal(
    lines[0],
    "ACTIVATION_RUNNER_FAILURE phase=TOPOLOGY_PORT_VERIFY category=BINDING_INVALID target=PRIMARY",
  );
  assert.equal(lines[1], formatActivationTopologyEvidence(evidence));
  assert.match(lines[1], /^ACTIVATION_TOPOLOGY_EVIDENCE ENGINE=GE_28 /u);
  assert.doesNotMatch(
    receipt,
    /private-docker-output|41001|container-id|secret|127\.0\.0\.1/u,
  );
  assert.throws(() => formatActivationTopologyEvidence({
    ...evidence,
    TEMPORAL: "ACCEPTED_AFTER_RETRY",
  }));
  assert.deepEqual(
    Object.keys(ACTIVATION_TOPOLOGY_EVIDENCE_CONTRACT),
    [
      "ENGINE", "REQUEST", "OPERATIONAL_FIRST", "OPERATIONAL_TERMINAL",
      "PORT_QUERY", "TEMPORAL", "PORT_MATCH", "TARGET",
    ],
  );
});

test("activation topology wiring keeps converged-to-exact evidence on the failure path", async () => {
  let operationalReads = 0;
  const delays = [];
  const spawnImpl = fakeCommandSpawn((_command, args) => {
    const format = args[args.indexOf("--format") + 1];
    if (args[0] === "version") return "28.0.4\n";
    if (args[0] === "network") {
      return `${JSON.stringify({
        Driver: "bridge", Internal: false, Options: {},
      })}\n`;
    }
    if (args[0] === "port") return "127.0.0.1:41001\n";
    if (format === "{{.Config.Image}}") return "postgres:17\n";
    if (format === "{{json .NetworkSettings.Networks}}") {
      return `${JSON.stringify({
        [primaryNetwork]: { Aliases: [networkAlias] },
      })}\n`;
    }
    if (format === "{{json .HostConfig.PortBindings}}") {
      return `${JSON.stringify({
        "5432/tcp": [{ HostIp: "127.0.0.1", HostPort: "" }],
      })}\n`;
    }
    if (format === "{{json .NetworkSettings.Ports}}") {
      operationalReads += 1;
      return operationalReads === 1
        ? "null\n"
        : `${JSON.stringify({
          "5432/tcp": [{ HostIp: "127.0.0.1", HostPort: "41001" }],
        })}\n`;
    }
    throw new Error("unexpected diagnostic command");
  });
  await assert.rejects(
    () => assertOwnedDockerTopology(
      spawnImpl,
      primaryContainer,
      primaryNetwork,
      "PRIMARY",
      { delayImpl: async (milliseconds) => delays.push(milliseconds) },
    ),
    (error) => {
      const receipt = formatActivationRunnerFailure(error);
      assert.match(receipt, /OPERATIONAL_FIRST=MISSING/u);
      assert.match(receipt, /OPERATIONAL_TERMINAL=EXACT/u);
      assert.match(receipt, /TEMPORAL=CONVERGED_TO_EXACT/u);
      assert.match(receipt, /PORT_MATCH=YES/u);
      assert.doesNotMatch(receipt, /41001|127\.0\.0\.1/u);
      return true;
    },
  );
  assert.equal(operationalReads, 5);
  assert.deepEqual(delays, [250, 250, 250, 250]);
});

test("activation summary failures distinguish missing malformed duplicate and count mismatch", () => {
  const cases = [
    ["TAP version 13\n1..0\n", "SUMMARY_MISSING"],
    ["# tests nope\n", "SUMMARY_MALFORMED"],
    [`${activationSummary()}\n${activationSummary()}`, "SUMMARY_DUPLICATE"],
    [activationSummary({ tests: 44, pass: 44 }), "SUMMARY_COUNT_MISMATCH"],
  ];
  for (const [output, category] of cases) {
    assert.deepEqual(classifyActivationTestSummary(output), { category });
  }
  assert.deepEqual(classifyActivationTestSummary(activationSummary()), {
    summary: {
      total: 45,
      passed: 45,
      failed: 0,
      cancelled: 0,
      skipped: 0,
      todo: 0,
    },
  });
});

test("activation diagnostics redact runner values, URLs, tokens, and activation environment values", () => {
  const operatorPassword = "Operator_A1!private-value";
  const runtimePassword = "Runtime_A1!private-value";
  const operatorUrl =
    `postgresql://platform_app:${operatorPassword}@127.0.0.1:54321/runtime_posture_test`;
  const diagnostic = sanitizeActivationChildDiagnostics({
    stdout: [
      "TAP version 13",
      `# Subtest: ${operatorPassword}`,
      `message: ${runtimePassword}`,
      `error: ${operatorUrl}`,
      "actual: RUNTIME_ACTIVATION_TEST_RUNTIME_PASSWORD=private-value",
      "stack: Bearer ghp_abcdefghijklmnopqrstuvwxyz",
    ].join("\n"),
    secretValues: [operatorPassword, runtimePassword, operatorUrl],
  });
  assert.doesNotMatch(
    diagnostic,
    /private-value|Operator_A1|Runtime_A1|postgresql:\/\/|ghp_/u,
  );
  assert.match(diagnostic, /<redacted>/u);
  assert.match(diagnostic, /<redacted-url>/u);
  assert.match(diagnostic, /<redacted-token>/u);
});

test("activation cleanup attempts every owned action and preserves body and cleanup failures", async () => {
  const calls = [];
  const bodyError = new Error("body");
  const cleanupError = new Error("cleanup");
  await assert.rejects(
    () => executeDisposableCleanupActions([
      async () => { calls.push("first"); throw cleanupError; },
      async () => { calls.push("second"); },
      async () => { calls.push("third"); },
    ], bodyError),
    (error) => {
      assert.ok(error instanceof AggregateError);
      assert.deepEqual(error.errors, [bodyError, cleanupError]);
      return true;
    },
  );
  assert.deepEqual(calls, ["first", "second", "third"]);
  await assert.rejects(
    () => executeDisposableCleanupActions([async () => {}], bodyError),
    (error) => error === bodyError,
  );
});

test("activation receipt aggregation preserves body first and every cleanup in action order", async () => {
  const calls = [];
  const body = activationRunnerFailure(
    "ACTIVATION_CHILD", "EXIT_NONZERO", "BOTH", "not ok 1 - retained",
  );
  const actions = [
    {
      phase: "CLEANUP",
      category: "CHILD_TERMINATION_FAILED",
      target: "NONE",
      run: async () => { calls.push("child"); throw new Error("private"); },
    },
    {
      phase: "CLEANUP",
      category: "CONTAINER_REMOVAL_FAILED",
      target: "PRIMARY",
      run: async () => { calls.push("primary"); },
    },
    {
      phase: "FINAL_ABSENCE",
      category: "PORT_OPEN_OR_UNPROVEN",
      target: "SECONDARY",
      run: async () => { calls.push("port"); throw new Error("private"); },
    },
  ];
  await assert.rejects(
    () => executeActivationCleanupActions(actions, body),
    (error) => {
      const diagnostic = formatActivationRunnerFailure(error);
      assert.deepEqual(diagnostic.split("\n"), [
        "ACTIVATION_RUNNER_FAILURE phase=ACTIVATION_CHILD category=EXIT_NONZERO target=BOTH",
        "not ok 1 - retained",
        "ACTIVATION_RUNNER_FAILURE phase=CLEANUP category=CHILD_TERMINATION_FAILED target=NONE",
        "ACTIVATION_RUNNER_FAILURE phase=FINAL_ABSENCE category=PORT_OPEN_OR_UNPROVEN target=SECONDARY",
      ]);
      assert.doesNotMatch(diagnostic, /private/u);
      return true;
    },
  );
  assert.deepEqual(calls, ["child", "primary", "port"]);

  await assert.rejects(
    () => executeActivationCleanupActions([], body),
    (error) => error === body,
  );
  await assert.rejects(
    () => executeActivationCleanupActions([actions[0]]),
    /(?:)/u,
  );
});

test("activation child classifies injected spawn exit signal timeout overflow and summary failures", async () => {
  const secret = "Operator_A1!never-print-this";
  const runtimeSecret = "Runtime_A1!never-print-this";
  const resources = () => ({
    child: null,
    childEnvironment: null,
    childExited: true,
    operatorPassword: secret,
    runtimePassword: runtimeSecret,
  });
  const urls = [
    "postgresql://platform_app@127.0.0.1:41001/runtime_posture_test",
    "postgresql://platform_app@127.0.0.1:41002/runtime_posture_test",
  ];
  const cases = [
    ["SPAWN_FAILED", () => { throw new Error("raw spawn detail"); }],
    ["SPAWN_FAILED", fakeSpawn({ error: true })],
    ["EXIT_NONZERO", fakeSpawn({ code: 1, stdout: `not ok 1 - ${secret}` })],
    ["SIGNAL", fakeSpawn({ code: null, signal: "SIGKILL" })],
    ["TIMEOUT", fakeSpawn({ waitForKill: true }), { timeoutMs: 1 }],
    ["STDOUT_OVERFLOW", fakeSpawn({ stdout: "x".repeat(65_537) })],
    ["STDERR_OVERFLOW", fakeSpawn({ stderr: "x".repeat(65_537) })],
    ["SUMMARY_MISSING", fakeSpawn({ stdout: "TAP version 13\n1..0\n" })],
    ["SUMMARY_MALFORMED", fakeSpawn({ stdout: "# tests nope\n" })],
    ["SUMMARY_DUPLICATE", fakeSpawn({ stdout: `${activationSummary()}\n${activationSummary()}` })],
    ["SUMMARY_COUNT_MISMATCH", fakeSpawn({
      stdout: activationSummary({ tests: 44, pass: 44 }),
    })],
  ];
  for (const [category, spawnImpl, options] of cases) {
    await assert.rejects(
      () => runActivationChild(spawnImpl, resources(), urls, options),
      (error) => {
        const diagnostic = formatActivationRunnerFailure(error);
        assert.match(
          diagnostic,
          new RegExp(`phase=ACTIVATION_CHILD category=${category} target=BOTH`, "u"),
        );
        assert.doesNotMatch(
          diagnostic,
          /never-print-this|raw spawn detail|postgresql:\/\//u,
        );
        return true;
      },
    );
  }
  assert.deepEqual(
    await runActivationChild(
      fakeSpawn({ stdout: activationSummary() }), resources(), urls,
    ),
    {
      total: 45, passed: 45, failed: 0, cancelled: 0, skipped: 0, todo: 0,
    },
  );
});

test("activation exact-absence guard checks both containers and both networks", async () => {
  const calls = [];
  await assertExactDockerResourcesAbsent(async (command, args) => {
    calls.push([command, ...args]);
    return { code: 0, signal: null, stdout: "", stderr: "" };
  });
  assert.equal(calls.length, 4);
  assert.deepEqual(
    calls.map((args) => args.at(-2)),
    ["--format", "--format", "--format", "--format"],
  );
  assert.equal(
    calls.some((args) => args.includes(`name=^/${primaryContainer}$`)),
    true,
  );
  assert.equal(
    calls.some((args) => args.includes(`name=^/${secondaryContainer}$`)),
    true,
  );
  assert.equal(
    calls.some((args) => args.includes(`name=^${primaryNetwork}$`)),
    true,
  );
  assert.equal(
    calls.some((args) => args.includes(`name=^${secondaryNetwork}$`)),
    true,
  );
  await assert.rejects(() =>
    assertExactDockerResourcesAbsent(async () => ({
      code: 0,
      signal: null,
      stdout: "unexpected-owned-resource\n",
      stderr: "",
    })));
});

test("activation final absence failures identify container and network targets", async () => {
  await assert.rejects(
    () => assertContainersAbsent(async (_command, args) => ({
      code: 0,
      signal: null,
      stdout: args.some((value) => value.includes(primaryContainer))
        ? "present\n"
        : "",
      timedOut: false,
      outputOverflow: false,
    })),
    (error) => formatActivationRunnerFailure(error) ===
      "ACTIVATION_RUNNER_FAILURE phase=FINAL_ABSENCE " +
      "category=CONTAINER_PRESENT_OR_UNPROVEN target=PRIMARY",
  );
  await assert.rejects(
    () => assertNetworksAbsent(async (_command, args) => ({
      code: args.some((value) => value.includes(secondaryNetwork)) ? 1 : 0,
      signal: null,
      stdout: "",
      timedOut: false,
      outputOverflow: false,
    })),
    (error) => formatActivationRunnerFailure(error) ===
      "ACTIVATION_RUNNER_FAILURE phase=FINAL_ABSENCE " +
      "category=NETWORK_PRESENT_OR_UNPROVEN target=SECONDARY",
  );
});

test("activation runner source launches only the contracted child and clears credentials before absence proof", async () => {
  const source = await readFile(
    "scripts/run-disposable-runtime-activation-postgres-tests.mjs",
    "utf8",
  );
  assert.match(
    source,
    /\["--test", "tests\/platform-runtime-activation-postgres\.test\.mjs"\]/u,
  );
  assert.match(source, /RUNTIME_ACTIVATION_TEST_RUNTIME_PASSWORD/u);
  assert.match(source, /clearCredentialState/u);
  assert.match(source, /assertExactDockerResourcesAbsent/u);
  assert.match(source, /await executeActivationReadinessChecks\(\{/u);
  assert.match(source, /Promise\.allSettled\(operatorUrls\.map/u);
  assert.match(source, /Promise\.allSettled\(\s*operations\.map/u);
  assert.match(
    source,
    /grant platform_runtime to platform_app with admin true, set false, inherit false granted by cloud_admin/u,
  );
  assert.match(
    source,
    /granted_role\.rolname = 'platform_runtime'[\s\S]*member_role\.rolname = 'platform_runtime'[\s\S]*grantor_role\.rolname = 'platform_runtime'/u,
  );
  assert.match(
    source,
    /row\?\.granted_role === "platform_runtime"[\s\S]*row\.member === "platform_app"[\s\S]*row\.grantor === "cloud_admin"[\s\S]*row\.admin_option === true[\s\S]*row\.inherit_option === false[\s\S]*row\.set_option === false/u,
  );
  assert.equal(
    source.match(/await executeActivationReadinessChecks\(\{/gu)?.length,
    1,
  );
  assert.doesNotMatch(source, /ACCEPTED_AFTER_RETRY|acceptanceRetry/iu);
  assert.doesNotMatch(source, /docker push|deploy|DROP OWNED|REASSIGN OWNED|CASCADE/iu);
});

function exactCreatorEdgeRow() {
  return {
    granted_role: "platform_runtime",
    member: "platform_app",
    grantor: "cloud_admin",
    admin_option: true,
    inherit_option: false,
    set_option: false,
  };
}

function diagnosticCreatorEdgePool({ failures = [], rows } = {}) {
  const failedSubsteps = new Set(failures);
  const calls = [];
  const rawFailure = () => Object.assign(
    new Error("postgresql://private-password@127.0.0.1:54321/private"),
    {
      cause: new Error("raw-cause private-password"),
      stack: "raw-stack private-password",
    },
  );
  const client = {
    async query(statement) {
      calls.push(statement);
      if (
        statement === "set session authorization cloud_admin" &&
        failedSubsteps.has("SESSION_AUTHORIZATION_SET")
      ) {
        throw rawFailure();
      }
      if (
        statement.startsWith("grant platform_runtime to platform_app") &&
        failedSubsteps.has("CREATOR_EDGE_GRANT")
      ) {
        throw rawFailure();
      }
      if (
        statement === "reset session authorization" &&
        failedSubsteps.has("SESSION_AUTHORIZATION_RESET")
      ) {
        throw rawFailure();
      }
      return { rows: [] };
    },
    release(destroy) {
      calls.push(`release:${destroy}`);
    },
  };
  return {
    calls,
    pool: {
      async connect() {
        calls.push("pool.connect");
        if (failedSubsteps.has("POOL_ACQUISITION")) throw rawFailure();
        return client;
      },
      async query(statement) {
        calls.push(statement);
        if (failedSubsteps.has("CREATOR_EDGE_MEMBERSHIP_READBACK")) {
          throw rawFailure();
        }
        return { rows: rows ?? [exactCreatorEdgeRow()] };
      },
    },
  };
}

function classifyCreatorEdgeCall(call) {
  if (call === "pool.connect") return "POOL_ACQUISITION";
  if (call === "set session authorization cloud_admin") {
    return "SESSION_AUTHORIZATION_SET";
  }
  if (call.startsWith("grant platform_runtime to platform_app")) {
    return "CREATOR_EDGE_GRANT";
  }
  if (call === "reset session authorization") {
    return "SESSION_AUTHORIZATION_RESET";
  }
  if (call === "release:true") return "CLIENT_RELEASE_DESTROY";
  if (call.includes("from pg_auth_members membership")) {
    return "CREATOR_EDGE_MEMBERSHIP_READBACK";
  }
  throw new Error("Unexpected creator-edge test call");
}

function activationSummary(overrides = {}) {
  const values = {
    tests: 45,
    suites: 0,
    pass: 45,
    fail: 0,
    cancelled: 0,
    skipped: 0,
    todo: 0,
    duration_ms: "1234.5",
    ...overrides,
  };
  return [
    "TAP version 13",
    "1..9",
    `# tests ${values.tests}`,
    `# suites ${values.suites}`,
    `# pass ${values.pass}`,
    `# fail ${values.fail}`,
    `# cancelled ${values.cancelled}`,
    `# skipped ${values.skipped}`,
    `# todo ${values.todo}`,
    `# duration_ms ${values.duration_ms}`,
  ].join("\n");
}

function fakeSpawn({
  code = 0,
  error = false,
  signal = null,
  stderr = "",
  stdout = "",
  waitForKill = false,
} = {}) {
  return () => {
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = (killSignal) => {
      queueMicrotask(() => child.emit("close", null, killSignal));
      return true;
    };
    queueMicrotask(() => {
      if (error) {
        child.emit("error", new Error("raw child error"));
        return;
      }
      if (waitForKill) return;
      if (stdout) child.stdout.write(stdout);
      if (stderr) child.stderr.write(stderr);
      child.stdout.end();
      child.stderr.end();
      child.emit("close", code, signal);
    });
    return child;
  };
}

function fakeCommandSpawn(handler) {
  return (command, args) => {
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = (signal) => {
      queueMicrotask(() => child.emit("close", null, signal));
      return true;
    };
    queueMicrotask(() => {
      try {
        const stdout = handler(command, args);
        if (stdout) child.stdout.write(stdout);
        child.stdout.end();
        child.stderr.end();
        child.emit("close", 0, null);
      } catch (error) {
        child.emit("error", error);
      }
    });
    return child;
  };
}

function activationTopologySpawn({
  version = "28.0.4",
  network = { Driver: "bridge", Internal: false, Options: {} },
  networkOutput,
  networkName = primaryNetwork,
  assignedPort = 41001,
  queriedPort = assignedPort,
  requestPort = "",
  onCommand = () => {},
} = {}) {
  return fakeCommandSpawn((_command, args) => {
    onCommand(args);
    const formatIndex = args.indexOf("--format");
    const format = formatIndex >= 0 ? args[formatIndex + 1] : null;
    if (args[0] === "version") return `${version}\n`;
    if (args[0] === "network") {
      return `${networkOutput ?? JSON.stringify(network)}\n`;
    }
    if (args[0] === "port") return `127.0.0.1:${queriedPort}\n`;
    if (format === "{{.Config.Image}}") return "postgres:17\n";
    if (format === "{{json .NetworkSettings.Networks}}") {
      return `${JSON.stringify({
        [networkName]: { Aliases: [networkAlias] },
      })}\n`;
    }
    if (format === "{{json .HostConfig.PortBindings}}") {
      return `${JSON.stringify({
        "5432/tcp": [{ HostIp: "127.0.0.1", HostPort: requestPort }],
      })}\n`;
    }
    if (format === "{{json .NetworkSettings.Ports}}") {
      return `${JSON.stringify({
        "5432/tcp": [{
          HostIp: "127.0.0.1", HostPort: String(assignedPort),
        }],
      })}\n`;
    }
    throw new Error("unexpected topology command");
  });
}

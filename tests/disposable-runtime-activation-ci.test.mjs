import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { readFile, rm } from "node:fs/promises";
import test from "node:test";
import { PassThrough } from "node:stream";

import {
  ACTIVATION_RUNNER_FAILURE_CONTRACT,
  activationRunnerFailure,
  assertActivationMigrationEntries,
  assertContainersAbsent,
  assertExactDockerResourcesAbsent,
  assertNetworksAbsent,
  assertNoCallerSuppliedActivationInputs,
  classifyActivationTestSummary,
  classifyCommandOutcome,
  createActivationMigrationPrefix,
  executeActivationCleanupActions,
  formatActivationRunnerFailure,
  ownedContainerDockerArguments,
  ownedNetworkCreateArguments,
  parseActivationTestSummary,
  runActivationChild,
  sanitizeActivationChildDiagnostics,
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

test("activation runner owns exactly two internal networks and two password-safe PostgreSQL 17 containers", () => {
  assert.deepEqual(ownedNetworkCreateArguments(primaryNetwork), [
    "network", "create", "--driver", "bridge", "--internal", primaryNetwork,
  ]);
  assert.deepEqual(ownedNetworkCreateArguments(secondaryNetwork), [
    "network", "create", "--driver", "bridge", "--internal", secondaryNetwork,
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
  assert.doesNotMatch(source, /docker push|deploy|DROP OWNED|REASSIGN OWNED|CASCADE/iu);
});

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

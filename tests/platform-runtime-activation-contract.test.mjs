import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { Writable } from "node:stream";
import test from "node:test";

import {
  PLATFORM_RUNTIME_ACTIVATION_PHASES,
  PlatformRuntimeActivationError,
  PlatformRuntimeActivationMutationTracker,
  PlatformRuntimeActivationPhaseJournal,
  assertMatchingPostgresFixtureIdentities,
  assertRuntimeIdentity,
  buildRuntimeDatabaseUrl,
  buildRuntimeRoleStatement,
  createRuntimeActivationTarget,
  installRuntimePasswordWithDocker,
  readDockerPostgresFixtureIdentity,
  readPostgresFixtureIdentity,
  runtimeActivationMutationMayHaveBegun,
  runtimeActivationRole,
} from "../scripts/platform-runtime-activation-contract.mjs";

const operatorUrl =
  "postgresql://operator:synthetic@db.example.test:5544/platform?sslmode=require&channel_binding=require";
const runtimePassword = "SyntheticRuntime_2026!Lab_ExtraLength";

test("activation phase contract covers the complete rollback-gated sequence", () => {
  assert.deepEqual(PLATFORM_RUNTIME_ACTIVATION_PHASES, [
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
  ]);
});

test("activation phase journal preserves the original failure through rollback", () => {
  const journal = new PlatformRuntimeActivationPhaseJournal();
  journal.start("dormant_role_preflight");
  journal.pass();
  journal.start("password_installation");
  journal.fail();
  journal.start("mandatory_rollback");
  journal.pass();

  assert.deepEqual(journal.safeReport(), {
    failedPhase: "password_installation",
    rollbackTriggered: true,
    rollbackVerified: true,
    phases: {
      dormant_role_preflight: "passed",
      password_installation: "failed",
      login_enablement: "pending",
      runtime_connection_construction: "pending",
      runtime_connection_establishment: "pending",
      runtime_identity: "pending",
      recursive_set_role_posture: "pending",
      grants_and_ownership_verification: "pending",
      success_finalisation: "pending",
      mandatory_rollback: "passed",
    },
  });
});

test("activation phase journal rejects skipped or out-of-order phases", () => {
  const journal = new PlatformRuntimeActivationPhaseJournal();
  assert.throws(
    () => journal.start("login_enablement"),
    PlatformRuntimeActivationError,
  );
});

test("activation phase journal marks rollback as not required on success", () => {
  const journal = new PlatformRuntimeActivationPhaseJournal();
  for (const phase of PLATFORM_RUNTIME_ACTIVATION_PHASES.slice(0, -1)) {
    journal.start(phase);
    journal.pass();
  }
  journal.notRequired("mandatory_rollback");

  const report = journal.safeReport();
  assert.equal(report.failedPhase, null);
  assert.equal(report.rollbackTriggered, false);
  assert.equal(report.rollbackVerified, false);
  assert.equal(report.phases.success_finalisation, "passed");
  assert.equal(report.phases.mandatory_rollback, "not_required");
});

test("validated activation target binds every role-sensitive operation", async () => {
  const target = createRuntimeActivationTarget("platform_runtime");
  const otherTarget = createRuntimeActivationTarget("other_runtime");
  const tracker = new PlatformRuntimeActivationMutationTracker(target);
  const directIdentity = await fixtureIdentity("123456789", "16384");
  const dockerIdentity = await fixtureIdentity("123456789", "16384");
  const wrongIdentity = await fixtureIdentity("987654321", "16384");

  assert.equal(runtimeActivationRole(target), "platform_runtime");
  assert.equal(
    buildRuntimeRoleStatement(target, "enable_login"),
    'ALTER ROLE "platform_runtime" LOGIN',
  );
  assert.equal(
    buildRuntimeRoleStatement(target, "rollback"),
    'ALTER ROLE "platform_runtime" NOLOGIN PASSWORD NULL',
  );
  assert.throws(
    () => tracker.passwordInstallationStarted(target),
    PlatformRuntimeActivationError,
  );
  tracker.fixtureValidated(target, directIdentity, dockerIdentity);
  tracker.passwordInstallationStarted(target);
  assert.equal(tracker.rollbackRequired(target), true);
  assert.doesNotThrow(() =>
    tracker.assertRollbackFixture(target, directIdentity),
  );
  assert.throws(
    () => tracker.assertRollbackFixture(target, wrongIdentity),
    PlatformRuntimeActivationError,
  );
  assert.throws(
    () => tracker.rollbackRequired(otherTarget),
    PlatformRuntimeActivationError,
  );
  assert.throws(
    () => buildRuntimeRoleStatement({}, "rollback"),
    PlatformRuntimeActivationError,
  );
});

test("failed initial validation causes zero mutation and zero cleanup", () => {
  const target = createRuntimeActivationTarget("platform_runtime");
  const tracker = new PlatformRuntimeActivationMutationTracker(target);
  let mutationCount = 0;
  let cleanupCount = 0;

  assert.throws(() => {
    throw new PlatformRuntimeActivationError();
  }, PlatformRuntimeActivationError);
  assert.throws(
    () => tracker.passwordInstallationStarted(target),
    PlatformRuntimeActivationError,
  );
  if (tracker.rollbackRequired(target)) {
    cleanupCount += 1;
  }

  assert.equal(mutationCount, 0);
  assert.equal(cleanupCount, 0);
});

test("runtime URL construction encodes credentials and preserves only reviewed transport parameters", () => {
  const target = createRuntimeActivationTarget("platform_runtime");
  const result = buildRuntimeDatabaseUrl(
    operatorUrl,
    target,
    "Synthetic!éΩ:/?#[]@%_ExtraLength2026",
  );
  const parsed = new URL(result);

  assert.equal(decodeURIComponent(parsed.username), "platform_runtime");
  assert.equal(
    decodeURIComponent(parsed.password),
    "Synthetic!éΩ:/?#[]@%_ExtraLength2026",
  );
  assert.equal(parsed.hostname, "db.example.test");
  assert.equal(parsed.port, "5544");
  assert.equal(parsed.pathname, "/platform");
  assert.deepEqual([...parsed.searchParams.entries()], [
    ["channel_binding", "require"],
    ["sslmode", "require"],
  ]);
});

test("runtime URL construction rejects identity, endpoint, session, unknown, and repeated parameters", () => {
  const target = createRuntimeActivationTarget("platform_runtime");
  const prohibitedParameters = [
    "user=platform_app",
    "password=operator-secret",
    "host=other.example.test",
    "hostaddr=192.0.2.10",
    "port=6432",
    "dbname=other_database",
    "database=other_database",
    "service=other-service",
    "servicefile=other-service.conf",
    "options=-csearch_path%3Dprivate",
    "target_session_attrs=read-write",
    "application_name=unsafe",
    "sslmode=require&sslmode=verify-full",
    "channel_binding=require&channel_binding=require",
    "sslmode=disable",
    "channel_binding=prefer",
  ];

  for (const parameters of prohibitedParameters) {
    assert.throws(
      () =>
        buildRuntimeDatabaseUrl(
          `postgresql://operator:synthetic@db.example.test:5544/platform?${parameters}`,
          target,
          runtimePassword,
        ),
      PlatformRuntimeActivationError,
      parameters,
    );
  }
});

test("runtime identity assertion uses the immutable activation target", () => {
  const target = createRuntimeActivationTarget("platform_runtime");
  assert.doesNotThrow(() =>
    assertRuntimeIdentity(
      {
        current_database: "runtime_posture_test",
        current_user: "platform_runtime",
        session_user: "platform_runtime",
      },
      target,
      "runtime_posture_test",
    ),
  );
  assert.throws(
    () =>
      assertRuntimeIdentity(
        {
          current_database: "runtime_posture_test",
          current_user: "platform_app",
          session_user: "platform_app",
        },
        target,
        "runtime_posture_test",
      ),
    PlatformRuntimeActivationError,
  );
});

test("fixture identities are opaque and require exact cluster and database identity", async () => {
  const directIdentity = await fixtureIdentity("123456789", "16384");
  const sameIdentity = await fixtureIdentity("123456789", "16384");
  const differentCluster = await fixtureIdentity("987654321", "16384");
  const differentDatabase = await fixtureIdentity("123456789", "16385");

  assert.doesNotThrow(() =>
    assertMatchingPostgresFixtureIdentities(directIdentity, sameIdentity),
  );
  assert.throws(
    () =>
      assertMatchingPostgresFixtureIdentities(
        directIdentity,
        differentCluster,
      ),
    PlatformRuntimeActivationError,
  );
  assert.throws(
    () =>
      assertMatchingPostgresFixtureIdentities(
        directIdentity,
        differentDatabase,
      ),
    PlatformRuntimeActivationError,
  );
  assert.deepEqual(Object.keys(directIdentity), []);
});

test("Docker fixture identity inspection keeps the URL out of arguments and output", async () => {
  const captured = {};
  const identity = await readDockerPostgresFixtureIdentity({
    operatorUrl,
    timeoutMs: 1_000,
    spawnImpl(command, args, options) {
      captured.command = command;
      captured.args = args;
      captured.options = options;
      const child = fakeChild();
      child.stdout = new EventEmitter();
      queueMicrotask(() => {
        child.stdout.emit("data", Buffer.from("123456789:16384\n"));
        child.emit("close", 0, null);
      });
      return child;
    },
    terminationSpawnImpl(command, args) {
      assert.equal(command, "docker");
      assert.equal(args[0], "ps");
      const verifyChild = new EventEmitter();
      verifyChild.stdout = new EventEmitter();
      queueMicrotask(() => verifyChild.emit("close", 0, null));
      return verifyChild;
    },
  });
  const directIdentity = await fixtureIdentity("123456789", "16384");

  assert.doesNotThrow(() =>
    assertMatchingPostgresFixtureIdentities(directIdentity, identity),
  );
  assert.equal(captured.command, "docker");
  assert.equal(captured.args.includes(operatorUrl), false);
  assert.equal(captured.options.stdio[2], "ignore");
  const nameIndex = captured.args.indexOf("--name");
  assert.match(
    captured.args[nameIndex + 1],
    /^swooshz-runtime-identity-[0-9a-f-]{36}$/u,
  );
});

test("read-only timeout waits for graceful close and confirmed container absence", async () => {
  const harness = readOnlyTerminationHarness({
    onKill(signal, child) {
      if (signal === "SIGTERM") {
        setTimeout(() => child.emit("close", 0, null), 15);
      }
      return true;
    },
    terminationGraceMs: 40,
  });

  await delay(12);
  assert.equal(harness.settled(), false);
  await waitFor(() => harness.verificationCalls() === 1);
  assert.equal(harness.settled(), false);
  harness.completeVerification();
  await assert.rejects(harness.promise, PlatformRuntimeActivationError);
  assert.deepEqual(harness.signals, ["SIGTERM"]);
  assert.equal(harness.cleanupCalls(), 1);
  assert.equal(harness.settlementCount(), 1);
});

test("read-only timeout escalates and waits for child close plus exact-name removal", async () => {
  const harness = readOnlyTerminationHarness({
    onKill() {
      return true;
    },
    terminationGraceMs: 10,
  });

  await waitFor(() => harness.verificationCalls() === 1);
  harness.completeVerification();
  await delay(0);
  assert.equal(harness.settled(), false);
  harness.child.emit("close", null, "SIGKILL");
  await waitFor(() => harness.verificationCalls() === 2);
  assert.equal(harness.settled(), false);
  harness.completeVerification();
  await assert.rejects(harness.promise, PlatformRuntimeActivationError);
  assert.deepEqual(harness.signals, ["SIGTERM", "SIGKILL"]);
  assert.equal(harness.cleanupCalls(), 2);
  assert.equal(harness.settlementCount(), 1);
});

test("read-only Docker-client/container divergence forces exact-name cleanup", async () => {
  const harness = readOnlyTerminationHarness({
    onStart(child) {
      queueMicrotask(() => child.emit("close", 1, null));
    },
  });

  await waitFor(() => harness.verificationCalls() === 1);
  assert.equal(harness.settled(), false);
  harness.completeVerification();
  await assert.rejects(harness.promise, PlatformRuntimeActivationError);
  assert.equal(harness.cleanupCalls(), 1);
  assert.equal(harness.cleanupName(), harness.containerName());
  assert.equal(
    harness.verificationFilter(),
    `name=^/${harness.containerName()}$`,
  );
});

test("inconclusive read-only cleanup remains fail closed after bounded retries", async () => {
  const harness = readOnlyTerminationHarness({
    onKill(_signal, child) {
      queueMicrotask(() => child.emit("close", null, "SIGTERM"));
      return true;
    },
    onVerify(verifyChild) {
      queueMicrotask(() => {
        verifyChild.stdout.emit("data", Buffer.from("still-running\n"));
        verifyChild.emit("close", 0, null);
      });
    },
    terminationAttempts: 2,
    terminationRetryMs: 5,
  });

  await waitFor(() => harness.verificationCalls() === 2);
  await delay(15);
  assert.equal(harness.cleanupCalls(), 2);
  assert.equal(harness.settled(), false);
});

test("read-only stdin and output failures use confirmed termination", async (t) => {
  await t.test("stdin error", async () => {
    const harness = readOnlyTerminationHarness({
      onStart(child) {
        queueMicrotask(() => child.stdin.emit("error", new Error("synthetic")));
      },
      onKill(_signal, child) {
        queueMicrotask(() => child.emit("close", null, "SIGTERM"));
        return true;
      },
    });
    await waitFor(() => harness.verificationCalls() === 1);
    harness.completeVerification();
    await assert.rejects(harness.promise, PlatformRuntimeActivationError);
  });

  await t.test("synchronous stdin failure", async () => {
    const harness = readOnlyTerminationHarness({
      onStart(child) {
        child.stdin.end = () => {
          throw new Error("synthetic");
        };
      },
      onKill(_signal, child) {
        queueMicrotask(() => child.emit("close", null, "SIGTERM"));
        return true;
      },
    });
    await waitFor(() => harness.verificationCalls() === 1);
    harness.completeVerification();
    await assert.rejects(harness.promise, PlatformRuntimeActivationError);
  });

  await t.test("output overflow", async () => {
    const harness = readOnlyTerminationHarness({
      onStart(child) {
        queueMicrotask(() => child.stdout.emit("data", Buffer.alloc(257, 65)));
      },
      onKill(_signal, child) {
        queueMicrotask(() => child.emit("close", null, "SIGTERM"));
        return true;
      },
    });
    await waitFor(() => harness.verificationCalls() === 1);
    harness.completeVerification();
    await assert.rejects(harness.promise, PlatformRuntimeActivationError);
  });
});

test("read-only cleanup and verification spawn errors retry without leaking secrets", async (t) => {
  await t.test("cleanup spawn error", async () => {
    const harness = readOnlyTerminationHarness({
      cleanupSpawnErrors: 1,
      onKill(_signal, child) {
        queueMicrotask(() => child.emit("close", null, "SIGTERM"));
        return true;
      },
      terminationAttempts: 2,
    });
    await waitFor(() => harness.verificationCalls() === 1);
    harness.completeVerification();
    await assert.rejects(harness.promise, PlatformRuntimeActivationError);
    assert.equal(harness.cleanupCalls(), 1);
  });

  await t.test("verification spawn error", async () => {
    const harness = readOnlyTerminationHarness({
      verificationSpawnErrors: 1,
      onKill(_signal, child) {
        queueMicrotask(() => child.emit("close", null, "SIGTERM"));
        return true;
      },
      terminationAttempts: 2,
    });
    await waitFor(() => harness.verificationCalls() === 2);
    harness.completeVerification();
    const error = await captureFailure(() => harness.promise);
    assert.doesNotMatch(
      String(error),
      /operator|synthetic|platform_runtime|db\.example\.test|postgresql:\/\//iu,
    );
  });
});

test("read-only spawn, malformed, non-zero, signal, and duplicate events fail once", async (t) => {
  await t.test("spawn failure", async () => {
    const harness = readOnlyTerminationHarness({
      spawnError: true,
    });
    await waitFor(() => harness.verificationCalls() === 1);
    harness.completeVerification();
    await assert.rejects(harness.promise, PlatformRuntimeActivationError);
  });

  for (const [name, onStart] of [
    [
      "malformed identity",
      (child) => {
        child.stdout.emit("data", Buffer.from("not-an-identity\n"));
        child.emit("close", 0, null);
      },
    ],
    ["non-zero exit", (child) => child.emit("close", 1, null)],
    ["signal exit", (child) => child.emit("close", null, "SIGTERM")],
    [
      "duplicate events",
      (child) => {
        child.emit("error", new Error("synthetic"));
        child.emit("close", 1, null);
        child.emit("close", 0, null);
      },
    ],
  ]) {
    await t.test(name, async () => {
      const harness = readOnlyTerminationHarness({
        onStart(child) {
          queueMicrotask(() => onStart(child));
        },
      });
      await waitFor(() => harness.verificationCalls() === 1);
      harness.completeVerification();
      await assert.rejects(harness.promise, PlatformRuntimeActivationError);
      assert.equal(harness.settlementCount(), 1);
    });
  }
});

test("password transport rejects line breaks before spawning Docker", async () => {
  const target = createRuntimeActivationTarget("platform_runtime");
  const identity = await fixtureIdentity("123456789", "16384");
  let spawnCalled = false;
  await assert.rejects(
    () =>
      installRuntimePasswordWithDocker({
        operatorUrl,
        target,
        runtimePassword: "SyntheticRuntime_2026!ExtraLength\n\\q",
        expectedFixtureIdentity: identity,
        spawnImpl() {
          spawnCalled = true;
        },
      }),
    PlatformRuntimeActivationError,
  );
  assert.equal(spawnCalled, false);
});

test("Docker password installation ignores prompts and writes the guarded UTF-8 exchange", async () => {
  const target = createRuntimeActivationTarget("platform_runtime");
  const identity = await fixtureIdentity("123456789", "16384");
  const captured = {};
  const unicodePassword =
    "SyntheticRuntime_2026!éΩ漢字_ExtraLength";

  await installRuntimePasswordWithDocker({
    operatorUrl,
    target,
    runtimePassword: unicodePassword,
    expectedFixtureIdentity: identity,
    spawnImpl(command, args, options) {
      captured.command = command;
      captured.args = args;
      captured.options = options;
      captured.stdin = [];
      const child = fakeChild({
        onWrite(chunk) {
          captured.stdin.push(Buffer.from(chunk));
        },
      });
      queueMicrotask(() => child.emit("close", 0, null));
      return child;
    },
  });

  const input = Buffer.concat(captured.stdin).toString("utf8");
  assert.equal(captured.command, "docker");
  assert.equal(captured.options.stdio[2], "ignore");
  assert.equal(captured.options.windowsHide, true);
  assert.equal(captured.args.includes(operatorUrl), false);
  assert.equal(captured.args.includes(unicodePassword), false);
  assert.match(input, /expected_fixture_identity '123456789:16384'/);
  assert.match(input, /\\if :fixture_matches/);
  assert.match(input, /\\password platform_runtime/);
  assert.match(input, new RegExp(escapeRegExp(unicodePassword)));
});

test("fixture mismatch is classified as pre-mutation while later failure is mutation-possible", async () => {
  const target = createRuntimeActivationTarget("platform_runtime");
  const identity = await fixtureIdentity("123456789", "16384");

  const mismatch = await captureFailure(() =>
    installRuntimePasswordWithDocker({
      operatorUrl,
      target,
      runtimePassword,
      expectedFixtureIdentity: identity,
      spawnImpl() {
        const child = fakeChild();
        queueMicrotask(() => child.emit("close", 86, null));
        return child;
      },
    }),
  );
  const laterFailure = await captureFailure(() =>
    installRuntimePasswordWithDocker({
      operatorUrl,
      target,
      runtimePassword,
      expectedFixtureIdentity: identity,
      spawnImpl() {
        const child = fakeChild();
        queueMicrotask(() => child.emit("close", 1, null));
        return child;
      },
    }),
  );

  assert.equal(runtimeActivationMutationMayHaveBegun(mismatch), false);
  assert.equal(runtimeActivationMutationMayHaveBegun(laterFailure), true);
});

test("password installation exposes only a generic secret-safe failure", async () => {
  const target = createRuntimeActivationTarget("platform_runtime");
  const identity = await fixtureIdentity("123456789", "16384");
  const error = await captureFailure(() =>
    installRuntimePasswordWithDocker({
      operatorUrl,
      target,
      runtimePassword,
      expectedFixtureIdentity: identity,
      spawnImpl() {
        const child = fakeChild();
        queueMicrotask(() => child.emit("close", 1, null));
        return child;
      },
    }),
  );

  assert.equal(error.code, "runtime_activation_failed");
  assert.equal(error.message, "Runtime activation failed.");
  assert.doesNotMatch(
    String(error),
    /operator|synthetic|platform_runtime|postgresql:\/\//i,
  );
});

test("timeout waits for a normal child close during the termination grace period", async () => {
  const harness = await timeoutHarness({
    onKill(signal, child) {
      if (signal === "SIGTERM") {
        setTimeout(() => child.emit("close", 0, null), 20);
      }
      return true;
    },
    terminationGraceMs: 50,
  });

  await delay(15);
  assert.equal(harness.settled(), false);
  await assert.rejects(harness.promise, PlatformRuntimeActivationError);
  assert.equal(harness.signals.includes("SIGTERM"), true);
  assert.equal(harness.cleanupCalls(), 1);
  assert.equal(harness.verificationCalls(), 1);
});

test("timeout escalation waits for container removal and child close", async () => {
  const harness = await timeoutHarness({
    onKill(signal, child) {
      if (signal === "SIGKILL") {
        setTimeout(() => child.emit("close", null, "SIGKILL"), 15);
      }
      return true;
    },
    onCleanup(cleanupChild) {
      setTimeout(() => cleanupChild.emit("close", 0, null), 5);
    },
    terminationGraceMs: 10,
  });

  await delay(28);
  assert.equal(harness.settled(), false);
  await assert.rejects(harness.promise, PlatformRuntimeActivationError);
  assert.deepEqual(harness.signals, ["SIGTERM", "SIGKILL"]);
  assert.equal(harness.cleanupCalls(), 2);
});

test("failed termination cleanup remains unsettled until a later conclusive child exit", async () => {
  let finalVerification;
  const harness = await timeoutHarness({
    onKill() {
      return true;
    },
    onCleanup(cleanupChild) {
      queueMicrotask(() => cleanupChild.emit("close", 1, null));
    },
    onVerify(verifyChild, verificationCount) {
      if (verificationCount === 1) {
        queueMicrotask(() => {
          verifyChild.stdout.emit("data", Buffer.from("still-running\n"));
          verifyChild.emit("close", 0, null);
        });
      } else {
        finalVerification = verifyChild;
      }
    },
    terminationAttempts: 2,
    terminationGraceMs: 10,
    terminationRetryMs: 10,
  });

  await waitFor(() => harness.cleanupCalls() === 2);
  assert.equal(harness.cleanupCalls(), 2);
  assert.equal(harness.settled(), false);

  harness.child.emit("close", 0, null);
  await delay(0);
  assert.equal(harness.settled(), false);
  finalVerification.emit("close", 0, null);
  await assert.rejects(harness.promise, PlatformRuntimeActivationError);
});

test("late child events cannot settle password installation twice", async () => {
  const harness = await timeoutHarness({
    onKill(signal, child) {
      if (signal === "SIGTERM") {
        setTimeout(() => {
          child.emit("close", 0, null);
          child.emit("close", 1, "SIGTERM");
        }, 15);
      }
      return true;
    },
    terminationGraceMs: 50,
  });

  await assert.rejects(harness.promise, PlatformRuntimeActivationError);
  assert.equal(harness.settlementCount(), 1);
});

async function timeoutHarness({
  onKill,
  onCleanup,
  onVerify,
  terminationAttempts = 2,
  terminationGraceMs,
  terminationRetryMs = 5,
}) {
  const target = createRuntimeActivationTarget("platform_runtime");
  const identity = await fixtureIdentity("123456789", "16384");
  const signals = [];
  let cleanupCount = 0;
  let verificationCount = 0;
  let settled = false;
  let settlementCount = 0;
  const child = fakeChild();
  child.kill = (signal) => {
    signals.push(signal);
    return onKill(signal, child);
  };
  const promise = installRuntimePasswordWithDocker({
    operatorUrl,
    target,
    runtimePassword,
    expectedFixtureIdentity: identity,
    timeoutMs: 10,
    terminationGraceMs,
    terminationRetryMs,
    terminationAttempts,
    spawnImpl() {
      return child;
    },
    terminationSpawnImpl(command, args, options) {
      assert.equal(command, "docker");
      if (args[0] === "rm") {
        assert.deepEqual(args.slice(0, 2), ["rm", "--force"]);
        assert.equal(options.stdio[2], "ignore");
        const cleanupChild = new EventEmitter();
        cleanupCount += 1;
        if (onCleanup) {
          onCleanup(cleanupChild);
        } else {
          queueMicrotask(() => cleanupChild.emit("close", 0, null));
        }
        return cleanupChild;
      }
      assert.deepEqual(args.slice(0, 4), [
        "ps",
        "--all",
        "--quiet",
        "--filter",
      ]);
      assert.equal(options.stdio[1], "pipe");
      const verifyChild = new EventEmitter();
      verifyChild.stdout = new EventEmitter();
      verificationCount += 1;
      if (onVerify) {
        onVerify(verifyChild, verificationCount);
      } else {
        queueMicrotask(() => verifyChild.emit("close", 0, null));
      }
      return verifyChild;
    },
  });
  promise.then(
    () => {
      settled = true;
      settlementCount += 1;
    },
    () => {
      settled = true;
      settlementCount += 1;
    },
  );
  return {
    child,
    cleanupCalls: () => cleanupCount,
    promise,
    settled: () => settled,
    settlementCount: () => settlementCount,
    signals,
    verificationCalls: () => verificationCount,
  };
}

function readOnlyTerminationHarness({
  cleanupSpawnErrors = 0,
  onKill = (_signal, child) => {
    queueMicrotask(() => child.emit("close", null, "SIGTERM"));
    return true;
  },
  onStart,
  onVerify,
  spawnError = false,
  terminationAttempts = 2,
  terminationGraceMs = 10,
  terminationRetryMs = 5,
  verificationSpawnErrors = 0,
} = {}) {
  const signals = [];
  let capturedContainerName;
  let capturedCleanupName;
  let capturedVerificationFilter;
  let cleanupCount = 0;
  let verificationCount = 0;
  let pendingVerification;
  let settled = false;
  let settlementCount = 0;
  const child = fakeChild();
  child.stdout = new EventEmitter();
  child.kill = (signal) => {
    signals.push(signal);
    return onKill(signal, child);
  };

  const promise = readDockerPostgresFixtureIdentity({
    operatorUrl,
    timeoutMs: 10,
    terminationAttempts,
    terminationGraceMs,
    terminationRetryMs,
    spawnImpl(_command, args) {
      capturedContainerName = args[args.indexOf("--name") + 1];
      if (spawnError) {
        throw new Error("synthetic spawn failure");
      }
      onStart?.(child);
      return child;
    },
    terminationSpawnImpl(command, args, options) {
      assert.equal(command, "docker");
      assert.equal(options.windowsHide, true);
      if (args[0] === "rm") {
        cleanupCount += 1;
        capturedCleanupName = args[2];
        if (cleanupCount <= cleanupSpawnErrors) {
          throw new Error("synthetic cleanup spawn failure");
        }
        const cleanupChild = new EventEmitter();
        queueMicrotask(() => cleanupChild.emit("close", 0, null));
        return cleanupChild;
      }
      verificationCount += 1;
      assert.deepEqual(args.slice(0, 4), [
        "ps",
        "--all",
        "--quiet",
        "--filter",
      ]);
      capturedVerificationFilter = args[4];
      if (verificationCount <= verificationSpawnErrors) {
        throw new Error("synthetic verification spawn failure");
      }
      const verifyChild = new EventEmitter();
      verifyChild.stdout = new EventEmitter();
      pendingVerification = verifyChild;
      if (onVerify) {
        onVerify(verifyChild, verificationCount);
      }
      return verifyChild;
    },
  });
  promise.then(
    () => {
      settled = true;
      settlementCount += 1;
    },
    () => {
      settled = true;
      settlementCount += 1;
    },
  );
  return {
    child,
    cleanupCalls: () => cleanupCount,
    cleanupName: () => capturedCleanupName,
    completeVerification() {
      pendingVerification.emit("close", 0, null);
    },
    containerName: () => capturedContainerName,
    promise,
    settled: () => settled,
    settlementCount: () => settlementCount,
    signals,
    verificationCalls: () => verificationCount,
    verificationFilter: () => capturedVerificationFilter,
  };
}

function fakeChild({ onWrite } = {}) {
  const child = new EventEmitter();
  child.kill = () => true;
  child.stdin = new Writable({
    write(chunk, _encoding, callback) {
      onWrite?.(chunk);
      callback();
    },
  });
  return child;
}

async function fixtureIdentity(systemIdentifier, databaseOid) {
  return readPostgresFixtureIdentity({
    async query() {
      return {
        rows: [{ system_identifier: systemIdentifier, database_oid: databaseOid }],
      };
    },
  });
}

async function captureFailure(callback) {
  try {
    await callback();
  } catch (error) {
    assert.equal(error instanceof PlatformRuntimeActivationError, true);
    return error;
  }
  assert.fail("Expected activation failure.");
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function waitFor(predicate, timeoutMs = 1_000) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) {
      assert.fail("Timed out waiting for the deterministic harness state.");
    }
    await delay(5);
  }
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

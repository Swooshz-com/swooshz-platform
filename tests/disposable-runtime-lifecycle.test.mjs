import assert from "node:assert/strict";
import test from "node:test";

import {
  DisposableRuntimeLifecycleError,
  runDisposableRuntimeLifecycle,
} from "../scripts/disposable-runtime-lifecycle.mjs";

test("lifecycle harness cleans owned resources after normal success", async () => {
  const events = [];
  await runScenario(events);
  assert.deepEqual(events, [
    "construct",
    "raw-admission",
    "secondary-admission",
    "authority",
    "database-create",
    "provision",
    "configured-admission",
    "tests",
    "cleanup",
    "absence",
  ]);
});

test("lifecycle harness cleans after focused test failure", async () => {
  const events = [];
  await assert.rejects(
    () => runScenario(events, { failure: "tests" }),
    safeLifecycleError,
  );
  assert.deepEqual(events.slice(-2), ["cleanup", "absence"]);
});

test("lifecycle harness cleans after aggregate admission failure", async () => {
  const events = [];
  await assert.rejects(
    () => runScenario(events, { failure: "raw-admission" }),
    safeLifecycleError,
  );
  assert.deepEqual(events.slice(-2), ["cleanup", "absence"]);
});

test("secondary-target admission failure runs no provisioning and still cleans", async () => {
  const events = [];
  await assert.rejects(
    () => runScenario(events, { failure: "secondary-admission" }),
    safeLifecycleError,
  );
  assert.equal(events.includes("provision"), false);
  assert.deepEqual(events.slice(-2), ["cleanup", "absence"]);
  for (const failure of ["raw-admission", "authority"]) {
    const events = [];
    await assert.rejects(
      () => runScenario(events, { failure }),
      safeLifecycleError,
    );
    assert.equal(events.includes("database-create"), false, failure);
    assert.equal(events.includes("provision"), false, failure);
  }
});

test("lifecycle harness cleans after provisioning failure", async () => {
  const events = [];
  await assert.rejects(
    () => runScenario(events, { failure: "provision" }),
    safeLifecycleError,
  );
  assert.deepEqual(events.slice(-2), ["cleanup", "absence"]);
});

test("teardown command failure fails closed and still checks absence", async () => {
  const events = [];
  await assert.rejects(
    () => runScenario(events, { cleanupFailure: true }),
    safeLifecycleError,
  );
  assert.equal(events.at(-1), "absence");
});

test("inconclusive process or listener absence proof fails closed", async () => {
  for (const failure of ["process-absence", "listener-absence"]) {
    const events = [];
    await assert.rejects(
      () => runScenario(events, { absenceFailure: failure }),
      safeLifecycleError,
    );
    assert.equal(events.at(-1), "absence");
  }
});

async function runScenario(events, options = {}) {
  return runDisposableRuntimeLifecycle({
    construct: async () => {
      events.push("construct");
      return { primary: true, secondary: true };
    },
    admitConstruction: async () => {
      events.push("raw-admission");
      if (options.failure === "raw-admission") throw new Error();
      events.push("secondary-admission");
      if (options.failure === "secondary-admission") throw new Error();
      return {};
    },
    deriveProvisioning: async () => {
      events.push("authority");
      if (options.failure === "authority") throw new Error();
      return {};
    },
    provision: async () => {
      events.push("database-create");
      events.push("provision");
      if (options.failure === "provision") throw new Error();
    },
    admitConfigured: async () => {
      events.push("configured-admission");
      return {};
    },
    runFocusedTests: async () => {
      events.push("tests");
      if (options.failure === "tests") throw new Error();
    },
    cleanup: async () => {
      events.push("cleanup");
      if (options.cleanupFailure) throw new Error();
    },
    verifyAbsence: async () => {
      events.push("absence");
      if (options.absenceFailure) throw new Error();
    },
  });
}

function safeLifecycleError(error) {
  assert.equal(error instanceof DisposableRuntimeLifecycleError, true);
  assert.equal(error.code, "disposable_runtime_lifecycle_failed");
  assert.equal(error.message, "Disposable runtime lifecycle failed.");
  assert.doesNotMatch(error.message, /postgres|platform_|runtime_|127|55432/i);
  return true;
}

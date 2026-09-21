import assert from "node:assert/strict";
import test from "node:test";

import {
  migrationClosureNegativeControlIds,
  runFrozenMigrationClosure,
  runMigrationClosureNegativeControls,
} from "./support/disposable-postgres-migration-closure.mjs";
import {
  behavioralSecretSurfaceControlIds,
  behavioralSecretSurfaceScenarioIds,
  runSecretSurfaceBehavioralHarness,
} from "./support/disposable-postgres-secret-surface-harness.mjs";

const STATIC_IDS = Object.freeze([
  "NC01_REACHABLE_WRITE_HELPER",
  "NC02_REACHABLE_HASH_HELPER",
  "NC03_STATIC_ONLY_BRANCH",
  "NC04_ALIASED_SINK",
  "NC05_COMPUTED_SINK",
  "NC06_NEW_IMPORT",
  "NC07_UNRESOLVED_CALL",
  "NC08_TRANSIENT_ENV",
  "NC09_INNOCENT_AUTHORITY_FIELD",
  "NC10_CLEANUP_PUBLISH",
  "PROBE_ARROW_OUTPUT",
  "PROBE_ARRAY_SOME_OUTPUT",
  "PROBE_MODULE_IF_OUTPUT",
  "PROBE_PUBLIC_CREDENTIAL_RETURN",
  "PROBE_TRIMMED_PASSWORD",
  "PROBE_CLEANUP_CONCISE_OUTPUT",
  "PROBE_AUTHORITY_BRAND",
]);

const BEHAVIORAL_IDS = Object.freeze([
  "NC11_PUBLIC_CAUSE",
  "NC12_PUBLIC_NONENUM",
  "NC13_BROKEN_INSTALL",
  "NC14_BROKEN_RESTORE",
  "NC15_OUTER_RESTORE_FAILURE",
  "NC16_HIDDEN_AUTHORITY_METADATA",
  "NC17_DEEP_HIDDEN_SURFACE",
  "NC18_BOUNDED_HIDDEN_SURFACE",
  "NC19_SYMBOL_HIDDEN_SURFACE",
  "NC20_POOL_WRONG_PASSWORD",
  "NC21_POOL_BINDING_MISMATCH",
  "NC22_RUNTIME_PRE_EFFECT_CAPABILITY",
]);

const SCENARIO_IDS = Object.freeze([
  "SC01_ORDINARY_SUCCESS",
  "SC02_SUCCESS_CLEANUP_REJECT",
  "SC03_OPERATION_REJECT_CLEANUP_REJECT",
  "SC04_SECOND_IDENTITY_REJECT_CLEANUP_REJECT",
]);

test("SSC_BASELINE_SECRET_SURFACE", async (suite) => {
  let baseline;
  let staticControls;
  let behavioral;
  try {
    baseline = await runFrozenMigrationClosure();
    staticControls = await runMigrationClosureNegativeControls();
    behavioral = await runSecretSurfaceBehavioralHarness();
  } catch {
    assert.fail("SSC_ASSURANCE_BOUNDARY");
  }

  assert.equal(baseline.id, "SSC_STATIC_BASELINE");
  assert.equal(baseline.ok, true);

  assert.equal(staticControls.count, STATIC_IDS.length);
  assert.deepEqual(staticControls.ids, STATIC_IDS);
  assert.deepEqual(migrationClosureNegativeControlIds, STATIC_IDS);
  for (const control of staticControls.results) {
    await suite.test(control.id, () => {
      assert.equal(control.pass, true, control.id);
      assert.equal(control.id, STATIC_IDS.find((id) => id === control.id));
    });
  }

  assert.equal(behavioral.scenarioCount, SCENARIO_IDS.length);
  assert.deepEqual(behavioral.scenarioIds, SCENARIO_IDS);
  assert.deepEqual(behavioralSecretSurfaceScenarioIds, SCENARIO_IDS);
  assert.equal(behavioral.allScenariosPass, true);
  for (const scenario of behavioral.scenarios) {
    await suite.test(scenario.id, () => {
      assert.equal(scenario.pass, true, scenario.id);
      assert.equal(scenario.poolCount, 1, scenario.id);
      assert.equal(scenario.authorityCaptureCount, 1, scenario.id);
      assert.equal(scenario.authorityValidAtCapture, true, scenario.id);
      assert.equal(scenario.authorityRevoked, true, scenario.id);
      assert.equal(scenario.cleanupCalls, 1, scenario.id);
      assert.equal(scenario.publicSurfaceSafe, true, scenario.id);
      assert.equal(scenario.noRuntimeEffects, true, scenario.id);
      assert.equal(scenario.resourcesStable, true, scenario.id);
    });
  }

  assert.equal(behavioral.controls.count, BEHAVIORAL_IDS.length);
  assert.deepEqual(behavioral.controls.ids, BEHAVIORAL_IDS);
  assert.deepEqual(behavioralSecretSurfaceControlIds, BEHAVIORAL_IDS);
  assert.equal(behavioral.allControlsPass, true);
  for (const control of behavioral.controls.results) {
    await suite.test(control.id, () => {
      assert.equal(control.pass, true, control.id);
      assert.equal(control.id, BEHAVIORAL_IDS.find((id) => id === control.id));
    });
  }

  const restorationBoundary = await runSecretSurfaceBehavioralHarness({ forceRestoreMismatch: true });
  assert.equal(restorationBoundary.ok, false);
  assert.equal(restorationBoundary.code, "SSC_OBSERVER_RESTORE");
  assert.equal(restorationBoundary.detector, "RESTORE_LEDGER");
});

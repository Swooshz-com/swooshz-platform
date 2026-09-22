import assert from "node:assert/strict";
import test from "node:test";

import {
  migrationClosurePositiveControlIds,
  migrationClosureNegativeControlIds,
  analyzeMigrationClosureVariants,
  readFrozenMigrationClosureSource,
  runMigrationClosureAdversarialMatrix,
  runMigrationClosureF2,
  runMigrationClosureF3,
  runMigrationClosureOrthogonalRepresentationMatrix,
  runMigrationClosurePositiveControls,
  runFrozenMigrationClosure,
  runMigrationClosureNegativeControls,
} from "./support/disposable-postgres-migration-closure.mjs";
import {
  behavioralSecretSurfaceControlIds,
  behavioralSecretSurfaceScenarioIds,
  runSecretSurfaceF2,
  runSecretSurfaceF3,
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
  "PROBE_ARRAY_CREDENTIAL_RETURN",
  "PROBE_NESTED_ARRAY_CREDENTIAL_RETURN",
  "PROBE_JSON_ARRAY_CREDENTIAL_RETURN",
  "PROBE_SYMBOL_CREDENTIAL_RETURN",
  "PROBE_CLOSURE_ASSIGNMENT_RETURN",
  "PROBE_CALLBACK_ASSIGNMENT_RETURN",
  "PROBE_CONDITIONAL_AGGREGATE_RETURN",
  "PROBE_FOR_INITIALIZER_OUTPUT",
  "PROBE_WHILE_CONDITION_OUTPUT",
  "PROBE_DO_CONDITION_OUTPUT",
  "PROBE_CONSTRUCTOR_OUTPUT",
  "PROBE_CONSTRUCTOR_PROPERTY_RETURN",
  "PROBE_AUTHORITY_DATABASE_IDENTITY",
  "PROBE_AUTHORITY_USER_IDENTITY",
  "PROBE_AUTHORITY_CLUSTER_IDENTITY",
  "PROBE_AUTHORITY_LIFECYCLE_IDENTITY",
  "PROBE_AUTHORITY_MIGRATIONS_IDENTITY",
  "PROBE_AUTHORITY_PHASE_IDENTITY",
  "MATRIX_OBJECT_OUTPUT",
  "MATRIX_ARRAY_OUTPUT",
  "MATRIX_SET_OUTPUT",
  "MATRIX_MAP_OUTPUT",
  "MATRIX_WEAKMAP_OUTPUT",
  "MATRIX_CLASS_PROPERTY_OUTPUT",
  "MATRIX_CLASS_METHOD_OUTPUT",
  "MATRIX_OBJECT_METHOD_OUTPUT",
  "MATRIX_CALLBACK_OUTPUT",
  "MATRIX_MAP_CALLBACK_OUTPUT",
  "MATRIX_RETURN_OBJECT",
  "MATRIX_RETURN_SET",
  "MATRIX_RETURN_MAP",
  "MATRIX_RETURN_WEAKMAP",
  "MATRIX_RETURN_CLASS",
  "MATRIX_RETURN_METHOD",
  "MATRIX_RETURN_CALLBACK",
  "MATRIX_RETURN_ALIAS",
  "MATRIX_LATE_MUTATION_OUTPUT",
  "MATRIX_DELETE_HISTORY_OUTPUT",
  "MATRIX_CLEAR_HISTORY_OUTPUT",
  "MATRIX_FREEZE_OUTPUT",
  "MATRIX_COMPUTED_OBJECT_OUTPUT",
  "MATRIX_COMPUTED_ARRAY_OUTPUT",
  "MATRIX_RETAINED_CLOSURE_OUTPUT",
  "MATRIX_RETAINED_FUNCTION_OUTPUT",
  "MATRIX_CALLBACK_RETURN_OUTPUT",
  "MATRIX_WEAKMAP_GET_OUTPUT",
  "MATRIX_MAP_UNKNOWN_GET_OUTPUT",
  "MATRIX_STRING_TRANSFORM_OUTPUT",
  "MATRIX_JSON_SECRET_OUTPUT",
  "MATRIX_UNKNOWN_COMPUTED_OUTPUT",
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

const INDEPENDENT_POSITIVE_SNIPPETS = Object.freeze([
  ["INDEPENDENT_POSITIVE_OBJECT", "const independentObject = {}; independentObject[\"value\"] = \"safe\"; Object.freeze(independentObject);"],
  ["INDEPENDENT_POSITIVE_ARRAY", "const independentArray = [\"safe\"]; independentArray.map((value) => value);"],
  ["INDEPENDENT_POSITIVE_SET", "const independentSet = new Set([\"safe\"]); independentSet.has(\"safe\");"],
  ["INDEPENDENT_POSITIVE_MAP", "const independentMap = new Map([[\"safe\", \"value\"]]); independentMap.get(\"safe\");"],
  ["INDEPENDENT_POSITIVE_CLASS", "class IndependentCarrier { constructor(value) { this.value = value; } reveal() { return this.value; } } const independentCarrier = new IndependentCarrier(\"safe\"); independentCarrier.reveal();"],
  ["INDEPENDENT_POSITIVE_CLOSURE", "const independentClosure = () => \"safe\"; independentClosure();"],
  ["INDEPENDENT_POSITIVE_FREEZE", "const independentFrozen = Object.freeze({ value: \"safe\" }); Object.keys(independentFrozen);"],
  ["INDEPENDENT_POSITIVE_WEAKMAP", "const independentKey = {}; const independentWeakMap = new WeakMap(); independentWeakMap.set(independentKey, \"safe\"); independentWeakMap.get(independentKey);"],
]);

const INDEPENDENT_MATRIX_SNIPPETS = Object.freeze([
  ["INDEPENDENT_OBJECT_OUTPUT", "console.log({ secret: input.connectionPassword });", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_OUTPUT"],
  ["INDEPENDENT_ARRAY_OUTPUT", "console.log([input.connectionPassword]);", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_OUTPUT"],
  ["INDEPENDENT_SET_OUTPUT", "const independentSet = new Set([input.connectionPassword]); console.log(independentSet);", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_OUTPUT"],
  ["INDEPENDENT_MAP_OUTPUT", "const independentMap = new Map([[\"secret\", input.connectionPassword]]); console.log(independentMap);", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_OUTPUT"],
  ["INDEPENDENT_WEAKMAP_OUTPUT", "const independentKey = {}; const independentWeakMap = new WeakMap([[independentKey, input.connectionPassword]]); console.log(independentWeakMap);", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_OUTPUT"],
  ["INDEPENDENT_CLASS_PROPERTY", "class IndependentCarrier { constructor(value) { this.value = value; } } const independentCarrier = new IndependentCarrier(input.connectionPassword); console.log(independentCarrier);", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_STORAGE"],
  ["INDEPENDENT_CLASS_METHOD", "class IndependentCarrier { constructor(value) { this.value = value; } reveal() { return this.value; } } const independentCarrier = new IndependentCarrier(input.connectionPassword); console.log(independentCarrier.reveal());", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_STORAGE"],
  ["INDEPENDENT_OBJECT_METHOD", "const independentCarrier = { reveal() { return input.connectionPassword; } }; console.log(independentCarrier.reveal());", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_OUTPUT"],
  ["INDEPENDENT_CALLBACK_OUTPUT", "[input.connectionPassword].forEach((value) => console.log(value));", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_OUTPUT"],
  ["INDEPENDENT_MAP_CALLBACK", "new Map([[\"secret\", input.connectionPassword]]).forEach((value) => console.log(value));", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_OUTPUT"],
  ["INDEPENDENT_RETURN_OBJECT", "return { secret: input.connectionPassword };", "SSC_SECRET_FLOW_DENIED", "PUBLIC_RETURN"],
  ["INDEPENDENT_RETURN_SET", "return new Set([input.connectionPassword]);", "SSC_SECRET_FLOW_DENIED", "PUBLIC_RETURN"],
  ["INDEPENDENT_RETURN_MAP", "return new Map([[\"secret\", input.connectionPassword]]);", "SSC_SECRET_FLOW_DENIED", "PUBLIC_RETURN"],
  ["INDEPENDENT_RETURN_WEAKMAP", "const independentKey = {}; return new WeakMap([[independentKey, input.connectionPassword]]);", "SSC_SECRET_FLOW_DENIED", "PUBLIC_RETURN"],
  ["INDEPENDENT_RETURN_CLASS", "class IndependentCarrier { constructor(value) { this.value = value; } } return new IndependentCarrier(input.connectionPassword);", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_STORAGE"],
  ["INDEPENDENT_RETURN_METHOD", "return { reveal() { return input.connectionPassword; } };", "SSC_SECRET_FLOW_DENIED", "PUBLIC_RETURN"],
  ["INDEPENDENT_RETURN_CALLBACK", "return () => input.connectionPassword;", "SSC_SECRET_FLOW_DENIED", "PUBLIC_RETURN"],
  ["INDEPENDENT_RETURN_ALIAS", "const independentSecret = input.connectionPassword; return independentSecret;", "SSC_SECRET_FLOW_DENIED", "PUBLIC_RETURN"],
  ["INDEPENDENT_LATE_MUTATION", "const independentHolder = {}; const independentAlias = independentHolder; independentHolder.secret = input.connectionPassword; console.log(independentAlias);", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_STORAGE"],
  ["INDEPENDENT_DELETE_HISTORY", "const independentHolder = { secret: input.connectionPassword }; delete independentHolder.secret; console.log(independentHolder);", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_OUTPUT"],
  ["INDEPENDENT_CLEAR_HISTORY", "const independentSet = new Set([input.connectionPassword]); independentSet.clear(); console.log(independentSet);", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_OUTPUT"],
  ["INDEPENDENT_FREEZE_OUTPUT", "console.log(Object.freeze({ secret: input.connectionPassword }));", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_OUTPUT"],
  ["INDEPENDENT_COMPUTED_OBJECT", "const independentKey = \"secret\"; const independentObject = {}; independentObject[independentKey] = input.connectionPassword; console.log(independentObject);", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_STORAGE"],
  ["INDEPENDENT_COMPUTED_ARRAY", "const independentArray = [input.connectionPassword]; const independentIndex = 0; console.log(independentArray[independentIndex]);", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_OUTPUT"],
  ["INDEPENDENT_RETAINED_CLOSURE", "let independentLeak = \"safe\"; const independentCapture = () => { independentLeak = input.connectionPassword; }; independentCapture(); console.log(independentLeak);", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_OUTPUT"],
  ["INDEPENDENT_RETAINED_FUNCTION", "const independentCapture = () => input.connectionPassword; console.log(independentCapture());", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_OUTPUT"],
  ["INDEPENDENT_CALLBACK_RETURN", "const independentMapped = [input.connectionPassword].map((value) => value); console.log(independentMapped);", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_OUTPUT"],
  ["INDEPENDENT_WEAKMAP_GET", "const independentKey = {}; const independentWeakMap = new WeakMap(); independentWeakMap.set(independentKey, input.connectionPassword); console.log(independentWeakMap.get(independentKey));", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_STORAGE"],
  ["INDEPENDENT_MAP_UNKNOWN_GET", "const independentMap = new Map([[\"secret\", input.connectionPassword]]); console.log(independentMap.get(input.expectedUser));", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_OUTPUT"],
  ["INDEPENDENT_STRING_TRANSFORM", "console.log(input.connectionPassword.trim());", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_OUTPUT"],
  ["INDEPENDENT_JSON_OUTPUT", "console.log(JSON.stringify(input.connectionPassword));", "SSC_SECRET_FLOW_DENIED", "CAPABILITY_OUTPUT"],
  ["INDEPENDENT_UNKNOWN_COMPUTED", "const independentName = input.expectedUser; console[independentName](input.connectionPassword);", "SSC_COMPUTED_ACCESS", "COMPUTED_CAPABILITY"],
]);

function insertIndependentSnippet(source, snippet) {
  const rootStart = source.indexOf("export async function withDisposablePostgresFixtureMigration");
  const insertion = source.indexOf("{", rootStart) + 1;
  return `${source.slice(0, insertion)}${snippet}\n${source.slice(insertion)}`;
}

async function runIndependentSourceAssurance() {
  const frozen = await readFrozenMigrationClosureSource();
  const positiveVariants = INDEPENDENT_POSITIVE_SNIPPETS.map(([id, snippet]) => ({
    id,
    source: insertIndependentSnippet(frozen.source, snippet),
  }));
  const matrixVariants = INDEPENDENT_MATRIX_SNIPPETS.map(([id, snippet]) => ({
    id,
    source: insertIndependentSnippet(frozen.source, snippet),
  }));
  const positiveResults = await analyzeMigrationClosureVariants(positiveVariants);
  const matrixResults = await analyzeMigrationClosureVariants(matrixVariants);
  const positivePass = positiveResults.every((result) => result.ok && result.result.ok === true);
  const matrixPass = matrixResults.every((result, index) => {
    const [, , code, detector] = INDEPENDENT_MATRIX_SNIPPETS[index];
    return !result.ok && result.result.code === code && result.result.detector === detector;
  });
  return Object.freeze({ positivePass, matrixPass, positiveCount: positiveResults.length, matrixCount: matrixResults.length });
}

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

  const positiveControls = await runMigrationClosurePositiveControls();
  const adversarialMatrix = await runMigrationClosureAdversarialMatrix();
  const orthogonalMatrix = await runMigrationClosureOrthogonalRepresentationMatrix();
  const staticF2 = await runMigrationClosureF2();
  const staticF3 = await runMigrationClosureF3();
  const runtimeF2 = await runSecretSurfaceF2();
  const runtimeF3 = await runSecretSurfaceF3();
  const independentAssurance = await runIndependentSourceAssurance();

  assert.deepEqual(positiveControls.ids, migrationClosurePositiveControlIds);
  assert.equal(positiveControls.pass, true);
  assert.equal(adversarialMatrix.pass, true);
  assert.equal(orthogonalMatrix.pass, true);
  assert.equal(staticF2.pass, true);
  assert.equal(staticF3.pass, true);
  assert.equal(runtimeF2.pass, true);
  assert.equal(runtimeF3.pass, true);
  assert.equal(independentAssurance.positivePass, true);
  assert.equal(independentAssurance.matrixPass, true);
  assert.equal(independentAssurance.positiveCount, 8);
  assert.equal(independentAssurance.matrixCount, 32);

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

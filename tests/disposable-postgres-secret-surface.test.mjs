import assert from "node:assert/strict";
import test from "node:test";

import {
  MIGRATION_CLOSURE_OBLIGATION_IDS,
  MIGRATION_CLOSURE_RESULT_INTERFACE,
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
  runSecretSurfaceIndependentRuntimeCorpus,
  runSecretSurfaceRun660RuntimeControls,
} from "./support/disposable-postgres-secret-surface-harness.mjs";

const RUN658_OBLIGATION_IDS = Object.freeze([
  "CF_PUBLIC_ESCAPE",
  "CF_PUBLIC_THROW",
  "CF_NONCONVERGENCE",
  "CF_RECURSION",
  "TV_CHILD_UNDISPOSED",
  "TV_CALLBACK_UNMODELED",
  "TV_ITERATOR_UNMODELED",
  "TV_COERCION_UNMODELED",
  "PV_EXACT_RELATION",
  "AP_POOL_OPTIONS",
  "AP_IDENTITY_SQL",
  "AP_IDENTITY_ARGUMENTS",
  "AP_AUTHORITY_GUARD",
  "AP_FINGERPRINT_COMPARE",
  "AP_TOKEN",
  "AP_REVOCATION",
  "AP_MIGRATION",
  "AP_OPERATION",
  "AP_CLIENT_PROTOCOL",
  "AP_CLEANUP",
  "HS_SECRET_REACHABLE",
  "HS_ACCESSOR_UNSUPPORTED",
  "HS_INTERNAL_SLOT_UNSUPPORTED",
  "HS_DEPTH_BOUND",
  "HS_ENTRY_BOUND",
  "DP_CAPABILITY",
  "DP_RECEIVER",
  "DP_ARGUMENTS",
  "DP_STATE",
  "DP_MANIFEST",
]);

const RUN658_RESULT_INTERFACE = Object.freeze({
  successFields: Object.freeze([
    "id",
    "ok",
    "poolConstructs",
    "declassifications",
    "authoritySets",
    "graphNodes",
    "graphEdges",
    "graph",
    "dormantBodies",
    "summariesConverged",
    "totalTraversal",
    "provenanceComplete",
    "violations",
    "childInventory",
  ]),
  failureFields: Object.freeze([
    "code",
    "detector",
    "obligation",
    "violations",
    "coordinates",
  ]),
  violationOrdering: "lexicographic",
});

test("RUN658_RESULT_INTERFACE_IS_FROZEN", () => {
  assert.deepEqual(MIGRATION_CLOSURE_OBLIGATION_IDS, RUN658_OBLIGATION_IDS);
  assert.deepEqual(MIGRATION_CLOSURE_RESULT_INTERFACE, RUN658_RESULT_INTERFACE);
});

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
  "PROBE_EFFECTIVE_SQL_REBIND",
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
  "NC23_INHERITED_HIDDEN_SURFACE",
  "NC24_MAP_INTERNAL_HIDDEN_SURFACE",
  "NC25_POOL_WRONG_MAX",
  "NC26_POOL_WRONG_DATABASE",
  "NC27_QUERY_WRONG_IDENTITY_ARGUMENTS",
  "NC28_QUERY_WRONG_RECEIVER",
  "NC29_QUERY_UNKNOWN_SQL",
]);

const SCENARIO_IDS = Object.freeze([
  "SC01_ORDINARY_SUCCESS",
  "SC02_SUCCESS_CLEANUP_REJECT",
  "SC03_OPERATION_REJECT_CLEANUP_REJECT",
  "SC04_SECOND_IDENTITY_REJECT_CLEANUP_REJECT",
  "SC05_PASSWORD_ABSENT",
  "SC06_PRE_POOL_FAILURE",
  "SC07_MIGRATION_REJECT_CLEANUP",
  "SC08_MIGRATION_REJECT_CLEANUP_REJECT",
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

const PROVENANCE_IDENTITY_REGRESSION_CASES = Object.freeze([
  Object.freeze({
    id: "PROVENANCE_LITERAL_EXPECTED_DATABASE",
    property: "database",
    replacement: '"input.expectedDatabase"',
    code: "SSC_AUTHORITY_SHAPE",
    detector: "AUTHORITY_SCHEMA",
  }),
  Object.freeze({
    id: "PROVENANCE_LITERAL_QUERY_CATALOG",
    property: "clusterFingerprint",
    replacement: '"query.catalog_fingerprint"',
    code: "SSC_AUTHORITY_SHAPE",
    detector: "AUTHORITY_SCHEMA",
  }),
  Object.freeze({
    id: "PROVENANCE_LITERAL_QUERY_LIFECYCLE",
    property: "lifecycleFingerprint",
    replacement: '"query.lifecycle_fingerprint"',
    code: "SSC_AUTHORITY_SHAPE",
    detector: "AUTHORITY_SCHEMA",
  }),
  Object.freeze({
    id: "PROVENANCE_LITERAL_MIGRATIONS_FOLDER",
    property: "migrationsFolder",
    replacement: '"input.migrationsFolder"',
    code: "SSC_AUTHORITY_SHAPE",
    detector: "AUTHORITY_SCHEMA",
  }),
  Object.freeze({
    id: "PROVENANCE_LITERAL_INITIALIZATION",
    property: "phase",
    replacement: '"initialization"',
    code: "SSC_AUTHORITY_SHAPE",
    detector: "AUTHORITY_SCHEMA",
  }),
  Object.freeze({
    id: "PROVENANCE_LITERAL_EXPECTED_USER",
    property: "user",
    replacement: '"input.expectedUser"',
    code: "SSC_AUTHORITY_SHAPE",
    detector: "AUTHORITY_SCHEMA",
  }),
  Object.freeze({
    id: "PROVENANCE_LITERAL_BOOLEAN_TRUE",
    property: "valid",
    replacement: '"true"',
    code: "SSC_AUTHORITY_SHAPE",
    detector: "AUTHORITY_SCHEMA",
  }),
]);

function insertIndependentSnippet(source, snippet) {
  const rootStart = source.indexOf("export async function withDisposablePostgresFixtureMigration");
  const insertion = source.indexOf("{", rootStart) + 1;
  return `${source.slice(0, insertion)}${snippet}\n${source.slice(insertion)}`;
}

function replaceAuthorityProperty(source, property, replacement) {
  const authorityStart = source.indexOf("migrationAuthorityValues.set(authority, {");
  const propertyStart = source.indexOf(`      ${property}:`, authorityStart);
  const lineEnd = source.indexOf("\n", propertyStart);
  if (authorityStart < 0 || propertyStart < 0 || lineEnd < 0) {
    throw new Error(`PROVENANCE_MUTANT_ANCHOR:${property}`);
  }
  const originalLine = source.slice(propertyStart, lineEnd);
  const lineEnding = originalLine.endsWith("\r") ? "\r" : "";
  const line = originalLine.slice(0, originalLine.length - lineEnding.length);
  const updatedLine = line.replace(
    new RegExp(`^(\\s*${property}:)\\s*.*$`, "u"),
    `$1 ${replacement},`,
  );
  if (updatedLine === line) throw new Error(`PROVENANCE_MUTANT_REPLACE:${property}`);
  return `${source.slice(0, propertyStart)}${updatedLine}${lineEnding}${source.slice(lineEnd)}`;
}

async function runProvenanceIdentityRegressions() {
  const frozen = await readFrozenMigrationClosureSource();
  const authorityVariants = PROVENANCE_IDENTITY_REGRESSION_CASES.map((item) => ({
    id: item.id,
    source: replaceAuthorityProperty(frozen.source, item.property, item.replacement),
  }));
  const fakeIdentitySqlSource = insertIndependentSnippet(
    frozen.source.replaceAll("pool.query(identitySql,", "pool.query(fakeIdentitySql,"),
    'const fakeIdentitySql = "identitySql";',
  );
  const variants = [
    ...authorityVariants,
    { id: "PROVENANCE_LITERAL_IDENTITY_SQL", source: fakeIdentitySqlSource },
  ];
  const results = await analyzeMigrationClosureVariants(variants);
  const pass = results.every((result, index) => {
    const expected = index < PROVENANCE_IDENTITY_REGRESSION_CASES.length
      ? PROVENANCE_IDENTITY_REGRESSION_CASES[index]
      : { code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_QUERY" };
    return !result.ok && result.result.code === expected.code && result.result.detector === expected.detector;
  });
  return Object.freeze({ pass, count: results.length, results });
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

function replaceRun657AuthorityProperty(source, name, expression) {
  const start = source.indexOf("migrationAuthorityValues.set(authority, {");
  const end = source.indexOf("\n    });", start);
  if (start < 0 || end < 0) throw new Error("RUN657_AUTHORITY_ANCHOR:" + name);
  const original = source.slice(start, end);
  const pattern = new RegExp("      " + name + "(?:\\s*:[^\\n,]*|),", "u");
  const updated = original.replace(pattern, "      " + name + ": " + expression + ",");
  if (updated === original) throw new Error("RUN657_AUTHORITY_REPLACE:" + name);
  return source.slice(0, start) + updated + source.slice(end);
}

function buildRun657IndependentStaticVariants(source) {
  const variants = [];
  const add = (id, mutatedSource) => variants.push(Object.freeze({ id, source: mutatedSource }));
  const insert = (mutatedSource, snippet) => insertIndependentSnippet(mutatedSource, snippet);
  const returnExpression = (expression) =>
    source.replace("return await operation();", "return " + expression + ";");
  const property = (name, expression) => replaceRun657AuthorityProperty(source, name, expression);

  add("GENUINE_BASELINE", source);
  for (const [name, expression] of [
    ["database", "\"input.expectedDatabase\""],
    ["clusterFingerprint", "\"query.catalog_fingerprint\""],
    ["migrationsFolder", "\"input.migrationsFolder\""],
    ["phase", "\"initialization\""],
    ["user", "\"input.expectedUser\""],
    ["lifecycleFingerprint", "\"query.lifecycle_fingerprint\""],
    ["brand", "Symbol(\"migration-authority\")"],
    ["authority", "Object.freeze({})"],
    ["pool", "{}"],
  ]) add("LITERAL_" + name, property(name, expression));
  for (const [name, expression] of [
    ["database", "JSON.stringify(input.expectedDatabase)"],
    ["lifecycleFingerprint", "JSON.stringify(identity.lifecycleFingerprint)"],
    ["clusterFingerprint", "JSON.stringify(identity.catalogFingerprint)"],
    ["migrationsFolder", "JSON.stringify(target.migrationsFolder)"],
    ["user", "JSON.stringify(target.expectedUser)"],
    ["phase", "JSON.stringify(target.phase)"],
  ]) add("SERIALIZED_" + name, property(name, expression));
  for (const [id, setup, expression] of [
    ["ALIAS", "const impostor=\"input.expectedDatabase\";", "impostor"],
    ["OBJECT", "const impostor={v:\"input.expectedDatabase\"};", "impostor.v"],
    ["ARRAY", "const impostor=[\"input.expectedDatabase\"];", "impostor[0]"],
    ["SET", "const impostor=new Set([\"input.expectedDatabase\"]);", "impostor.values()[0]"],
    ["MAP", "const impostor=new Map([[\"k\",\"input.expectedDatabase\"]]);", "impostor.get(\"k\")"],
    ["WEAKMAP", "const key={}; const impostor=new WeakMap([[key,\"input.expectedDatabase\"]]);", "impostor.get(key)"],
    ["CLOSURE", "const impostor=()=>\"input.expectedDatabase\";", "impostor()"],
    ["CLASS", "class Impostor { value(){return \"input.expectedDatabase\";} } const impostor=new Impostor();", "impostor.value()"],
  ]) add("EQUAL_TEXT_" + id, insert(property("database", expression), setup));
  add("FORGED_DEFAULT_USER", property("user", "(() => { const expectedUser = input.expectedUser, ignored = 0; return expectedUser; })()"));
  add("DEFAULT_USER_WRONG_LHS", source
    .replace("const expectedUser = input.expectedUser ?? \"cloud_admin\";", "const expectedUser = \"intruder\" ?? \"cloud_admin\"; const additional = input.expectedUser;")
    .replace("      user: target.expectedUser,", "      user: target.expectedUser ?? input.expectedUser,"));
  add("SPOOF_DEFAULT_USER_ORIGIN", property("user", "(() => { const expectedUser = \"intruder\" ?? \"cloud_admin\"; return expectedUser ?? input.expectedUser; })()"));
  add("SPOOF_DEFAULT_PHASE_ORIGIN", property("phase", "(() => { const phase = \"final_start\" ?? \"initialization\"; return phase ?? input.phase; })()"));

  for (const [id, prefix, expression] of [
    ["PRIOR_CONDITIONAL_ASSIGN", "let leak=\"safe\"; input ? (leak=input.connectionPassword) : 0;", "leak"],
    ["PRIOR_CLOSURE_IF", "let leak=\"safe\"; const capture=()=>{if(input)leak=input.connectionPassword;};capture();", "leak"],
    ["PRIOR_CLOSURE_LOOP", "let leak=\"safe\"; const capture=()=>{while(input){leak=input.connectionPassword;break;}};capture();", "leak"],
    ["PRIOR_RETURN_CLOSURE", "", "()=>input.connectionPassword"],
    ["PRIOR_RETURN_SET", "", "new Set([input.connectionPassword])"],
    ["PRIOR_RETURN_MAP", "", "new Map([[\"x\",input.connectionPassword]])"],
    ["CONDITIONAL_CALLABLE", "", "input ? (()=>input.connectionPassword) : (()=>\"safe\")"],
    ["RETURN_CLASS", "", "class Carrier { constructor(){this.secret=input.connectionPassword;} }"],
    ["RETURN_AUTHORITY", "", "authority"],
    ["CLOSURE_SERIALIZE", "", "JSON.stringify({getSecret:()=>input.connectionPassword})"],
    ["COMMA_LAUNDER", "", "(0,input.connectionPassword)"],
    ["ARITHMETIC_LAUNDER", "", "input.connectionPassword * 1"],
    ["REGEXP_LAUNDER", "", "new RegExp(input.connectionPassword)"],
    ["CYCLE_CLEAN", "const c={};c.self=c;", "c"],
    ["LATE_ALIAS_CLOSURE", "const a={}; const f=()=>a.secret; const b=a; b.secret=()=>input.connectionPassword;", "f"],
    ["LOOP_SECOND_ITERATION", "let a=\"safe\";let b=\"safe\";for(let i=0;i<2;i++){a=b;b=input.connectionPassword;}", "a"],
    ["RECURSION", "function recurse(){return recurse();} recurse();", undefined],
    ["UNKNOWN_CALL", "nonexistent();", undefined],
    ["PROMISE_CALLBACK", "Promise.resolve().then(()=>console.log(input.connectionPassword));", undefined],
    ["CLASS_STATIC_BLOCK", "class Probe {static {console.log(input.connectionPassword);}}", undefined],
    ["CLASS_STATIC_FIELD", "class Probe {static value=console.log(input.connectionPassword);}", undefined],
    ["CLASS_INSTANCE_FIELD", "class Probe {value=console.log(input.connectionPassword);} new Probe();", undefined],
    ["STRING_REPLACEMENT_CALLBACK", "new URL(input.connectionString).pathname.replace(/x/,()=>{console.log(input.connectionPassword);return \"safe\";});", undefined],
    ["JSON_CALLBACK", "JSON.stringify({},()=>{console.log(input.connectionPassword);return \"safe\";});", undefined],
    ["IMPLICIT_COERCION", "String({toString(){console.log(input.connectionPassword);return \"safe\";}});", undefined],
    ["DELETE_KEY", "delete input[console.log(input.connectionPassword)];", undefined],
    ["PROPERTY_KEY", "const a={ [console.log(input.connectionPassword)]:0 };", undefined],
    ["ASSIGNMENT_KEY", "const a={};a[console.log(input.connectionPassword)]=0;", undefined],
    ["OPTIONAL_KEY", "const a={};a?.[console.log(input.connectionPassword)];", undefined],
    ["CALL_RECEIVER", "(console.log(input.connectionPassword),Object).keys({});", undefined],
    ["NEW_ARGUMENT", "new Set([console.log(input.connectionPassword)]);", undefined],
    ["FOROF_ASSIGN_TARGET", "const a={};for(a[console.log(input.connectionPassword)] of [1]){}", undefined],
    ["MODULE_ALIAS", "const captured=globalThis.fetch;", undefined],
    ["UNLISTED_RETURN", "", "globalThis.fetch"],
    ["UNLISTED_ACQUIRE", "const captured=globalThis.fetch;void captured;", undefined],
    ["UNLISTED_CALL", "globalThis.fetch(\"https://invalid.example\");", undefined],
    ["CONSTRUCTOR_CAPTURE", "class Carrier {constructor(){console.log(input.connectionPassword);}} new Carrier();", undefined],
  ]) add(id, insert(expression === undefined ? source : returnExpression(expression), prefix));

  for (const [id, before, after] of [
    ["PASSWORD_TRIM", "poolOptions.password = connectionPassword;", "poolOptions.password = connectionPassword.trim();"],
    ["PASSWORD_RECONSTRUCT", "poolOptions.password = connectionPassword;", "poolOptions.password = \"\" + connectionPassword;"],
    ["PASSWORD_EXTRA_STORAGE", "pool = new Pool(poolOptions);", "const extra={secret:connectionPassword}; pool = new Pool(poolOptions);"],
    ["PASSWORD_ABSENT", "poolOptions.password = connectionPassword;", "void connectionPassword;"],
    ["SECOND_POOL", "pool = new Pool(poolOptions);", "pool = new Pool(poolOptions);new Pool(poolOptions);"],
    ["WRONG_STRUCTURED_DATABASE", "database: target.expectedDatabase,\n      max: 1,", "database: \"different_database\",\n      max: 1,"],
    ["WRONG_MAX", "max: 1,", "max: 7,"],
    ["WRONG_QUERY_ARGS", "[target.expectedDatabase, target.expectedUser]", "[\"different_database\", \"different_user\"]"],
    ["FAKE_SQL_BINDING", "const identitySql = `", "const identitySql = \"select 1\"; const unusedSql = `"],
    ["NO_REVOKE", "if (value) value.valid = false;", "if (value) void 0;"],
    ["UNFROZEN_TOKEN", "authority = Object.freeze({});", "authority = {};"],
    ["NO_FINGERPRINT_COMPARE", "identity.catalogFingerprint !== value.clusterFingerprint ||\n    identity.lifecycleFingerprint !== value.lifecycleFingerprint", "false"],
    ["WRONG_MIGRATION_FOLDER", "await migrate(drizzle(pool), { migrationsFolder });", "await migrate(drizzle(pool), { migrationsFolder: \"different_folder\" });"],
    ["NO_MIGRATION", "await migrate(drizzle(pool), { migrationsFolder });", "void 0;"],
    ["OPERATION_EARLY", "    pool = new Pool(poolOptions);", "    await operation(); pool = new Pool(poolOptions);"],
    ["POOL_CONNECT_HELPER", "    pool = new Pool(poolOptions);", "    pool = new Pool(poolOptions); const c=await pool.connect(); c.release();"],
    ["POOL_END_EARLY", "    pool = new Pool(poolOptions);", "    pool = new Pool(poolOptions); await pool.end();"],
    ["PASSWORD_READBACK", "return await operation();", "return pool.options.password;"],
  ]) {
    if (!source.includes(before)) throw new Error("RUN657_STATIC_ANCHOR:" + id);
    if (id !== "NO_AUTHORITY_GUARD") add(id, source.replace(before, after));
  }
  add("NO_AUTHORITY_GUARD", source.replace(
    /  if \(\n    !value \|\|[\s\S]*?  \) throw new Error\(\);/u,
    "  if (false) throw new Error();",
  ));
  return Object.freeze(variants);
}

function buildRun657SupplementaryStaticVariants(source) {
  const variants = [];
  const rootInsert = (sourceText, snippet) => {
    const rootStart = sourceText.indexOf("export async function withDisposablePostgresFixtureMigration");
    const insertion = sourceText.indexOf("{", rootStart) + 1;
    return sourceText.slice(0, insertion) + snippet + sourceText.slice(insertion);
  };
  const add = (id, mutatedSource) => variants.push(Object.freeze({ id, source: mutatedSource }));
  const rootReturns = [
    ["ROOT_INPUT_ESCAPE", "input"],
    ["ROOT_INPUT_FROZEN_ESCAPE", "Object.freeze(input)"],
    ["PASSWORD_LENGTH", "input.connectionPassword.length"],
    ["DELETE_CLOSURE_HISTORY", "(()=>{const x={secret:()=>input.connectionPassword}; delete x.secret;return x;})()"],
    ["CLEAR_CLOSURE_HISTORY", "(()=>{const x=new Set([()=>input.connectionPassword]);x.clear();return x;})()"],
    ["OVERWRITE_CLOSURE_HISTORY", "(()=>{const x={secret:()=>input.connectionPassword};x.secret=\"safe\";return x;})()"],
    ["CLASS_PROTOTYPE_RETAINED", "class {value(){return input.connectionPassword;}}"],
  ];
  for (const [id, expression] of rootReturns) {
    add(id, source.replace("return await operation();", "return " + expression + ";"));
  }
  add("MODULE_CLASS_STATIC", "class GlobalProbe { static { console.log(\"synthetic\"); } }\n" + source);
  add("CALLABLE_DEFAULT_CHILD", rootInsert(source, "function f(v=console.log(input.connectionPassword)){}f(undefined);"));
  add("PRECAPTURED_UNLISTED", rootInsert("const capturedCapability=globalThis.fetch;\n" + source, ""));
  for (const [id, snippet] of [
    ["UNLISTED_STATIC_FIELD", "class C{static x=globalThis.crypto.subtle.importKey(\"raw\",input.connectionPassword,{},false,[]);}"],
    ["THROWN_CLOSURE", "throw ()=>input.connectionPassword;"],
    ["CATCH_ESCAPE", "try{throw input.connectionPassword;}catch(e){return e;}"],
    ["MUTUAL_RECURSION", "function a(){return b();}function b(){return a();}a();"],
    ["UNSUPPORTED_SYNTAX", "with(input){}"],
    ["UNKNOWN_RECEIVER", "unknownReceiver.run();"],
    ["CALLBACK_RECURSION", "function f(){[0].map(()=>f());}f();"],
  ]) add(id, rootInsert(source, snippet));
  for (const [id, expression] of rootReturns) {
    const raw = variants.find((variant) => variant.id === id);
    const anchor = "return " + expression + ";";
    if (!raw?.source.includes(anchor)) throw new Error("RUN657_PROTOCOL_ANCHOR:" + id);
    add(id + "_PROTOCOL", raw.source.replace(anchor, "await operation(); return " + expression + ";"));
  }
  const rawCycle = buildRun657IndependentStaticVariants(source).find((variant) => variant.id === "CYCLE_CLEAN");
  if (!rawCycle) throw new Error("RUN657_CYCLE_ANCHOR");
  add("CYCLE_CLEAN_PROTOCOL", rawCycle.source.replace("return c;", "await operation(); return c;"));
  return Object.freeze(variants);
}

const RUN657_STATIC_ORACLE_GROUPS = Object.freeze([
  ["SSC_AUTHORITY_SHAPE", "AUTHORITY_SCHEMA", "PV_EXACT_RELATION", [
    "LITERAL_database", "LITERAL_clusterFingerprint", "LITERAL_migrationsFolder", "LITERAL_user",
    "LITERAL_lifecycleFingerprint", "LITERAL_phase", "SERIALIZED_database", "SERIALIZED_user",
    "SERIALIZED_clusterFingerprint", "SERIALIZED_migrationsFolder", "SERIALIZED_lifecycleFingerprint",
    "SERIALIZED_phase", "EQUAL_TEXT_ALIAS", "EQUAL_TEXT_OBJECT",
    "EQUAL_TEXT_ARRAY", "EQUAL_TEXT_SET", "EQUAL_TEXT_MAP", "EQUAL_TEXT_WEAKMAP",
    "EQUAL_TEXT_CLOSURE", "EQUAL_TEXT_CLASS", "FORGED_DEFAULT_USER", "SPOOF_DEFAULT_USER_ORIGIN",
    "SPOOF_DEFAULT_PHASE_ORIGIN",
  ]],
  ["SSC_AUTHORITY_SHAPE", "AUTHORITY_SCHEMA", "AP_AUTHORITY_GUARD", [
    "LITERAL_brand", "LITERAL_authority", "LITERAL_pool", "NO_AUTHORITY_GUARD",
  ]],
  ["SSC_SECRET_FLOW_DENIED", "CAPABILITY_POOL", "AP_POOL_OPTIONS", ["DEFAULT_USER_WRONG_LHS"]],
  ["SSC_SECRET_FLOW_DENIED", "PUBLIC_RETURN", ["AP_OPERATION", "CF_PUBLIC_ESCAPE"], [
    "PRIOR_CONDITIONAL_ASSIGN", "PRIOR_CLOSURE_IF", "PRIOR_CLOSURE_LOOP", "PRIOR_RETURN_CLOSURE",
    "PRIOR_RETURN_SET", "PRIOR_RETURN_MAP", "CONDITIONAL_CALLABLE", "RETURN_AUTHORITY",
    "CLOSURE_SERIALIZE", "COMMA_LAUNDER", "LOOP_SECOND_ITERATION", "PASSWORD_READBACK",
    "ROOT_INPUT_ESCAPE", "ROOT_INPUT_FROZEN_ESCAPE", "DELETE_CLOSURE_HISTORY",
    "CLEAR_CLOSURE_HISTORY", "OVERWRITE_CLOSURE_HISTORY", "CLASS_PROTOTYPE_RETAINED",
  ]],
  ["SSC_SECRET_FLOW_DENIED", "PUBLIC_RETURN", ["AP_OPERATION", "CF_PUBLIC_ESCAPE"], ["RETURN_CLASS"]],
  ["SSC_SECRET_FLOW_DENIED", "CAPABILITY_STORAGE", "CF_PUBLIC_ESCAPE", ["LATE_ALIAS_CLOSURE", "PASSWORD_EXTRA_STORAGE"]],
  ["SSC_SECRET_FLOW_DENIED", "CAPABILITY_RECONSTRUCTION", "PV_EXACT_RELATION", ["ARITHMETIC_LAUNDER", "REGEXP_LAUNDER", "PASSWORD_RECONSTRUCT"]],
  ["SSC_SECRET_FLOW_DENIED", "CAPABILITY_CALLBACK", "AP_OPERATION", ["CYCLE_CLEAN", "OPERATION_EARLY", "NO_MIGRATION"]],
  ["SSC_SECRET_FLOW_DENIED", "PUBLIC_RETURN", "CF_PUBLIC_ESCAPE", [
    "ROOT_INPUT_ESCAPE_PROTOCOL", "ROOT_INPUT_FROZEN_ESCAPE_PROTOCOL",
    "DELETE_CLOSURE_HISTORY_PROTOCOL", "CLEAR_CLOSURE_HISTORY_PROTOCOL",
    "OVERWRITE_CLOSURE_HISTORY_PROTOCOL", "CLASS_PROTOTYPE_RETAINED_PROTOCOL",
  ]],
  ["SSC_SECRET_FLOW_DENIED", "CAPABILITY_PASSWORD", "AP_TOKEN", ["PASSWORD_TRIM", "PASSWORD_LENGTH", "PASSWORD_LENGTH_PROTOCOL"]],
  ["SSC_SECRET_FLOW_DENIED", "CAPABILITY_POOL", "AP_POOL_OPTIONS", [
    "SECOND_POOL", "WRONG_STRUCTURED_DATABASE", "WRONG_MAX",
  ]],
  ["SSC_SECRET_FLOW_DENIED", "CAPABILITY_QUERY", "AP_IDENTITY_ARGUMENTS", ["WRONG_QUERY_ARGS"]],
  ["SSC_SECRET_FLOW_DENIED", "CAPABILITY_QUERY", "AP_IDENTITY_SQL", ["FAKE_SQL_BINDING"]],
  ["SSC_AUTHORITY_SHAPE", "AUTHORITY_SCHEMA", "AP_REVOCATION", ["NO_REVOKE"]],
  ["SSC_AUTHORITY_SHAPE", "AUTHORITY_SCHEMA", "AP_TOKEN", ["UNFROZEN_TOKEN"]],
  ["SSC_AUTHORITY_SHAPE", "AUTHORITY_SCHEMA", "AP_FINGERPRINT_COMPARE", ["NO_FINGERPRINT_COMPARE"]],
  ["SSC_SECRET_FLOW_DENIED", "CAPABILITY_MIGRATE", "AP_MIGRATION", ["WRONG_MIGRATION_FOLDER"]],
  ["SSC_SECRET_FLOW_DENIED", "CAPABILITY_CONNECT", "AP_CLIENT_PROTOCOL", ["POOL_CONNECT_HELPER"]],
  ["SSC_SECRET_FLOW_DENIED", "CAPABILITY_CLEANUP", "AP_CLEANUP", ["POOL_END_EARLY"]],
  ["SSC_SECRET_FLOW_DENIED", "CAPABILITY_OUTPUT", "CF_PUBLIC_ESCAPE", [
    "CLASS_STATIC_BLOCK", "CLASS_STATIC_FIELD", "CLASS_INSTANCE_FIELD", "STRING_REPLACEMENT_CALLBACK",
    "JSON_CALLBACK", "IMPLICIT_COERCION", "DELETE_KEY", "PROPERTY_KEY", "ASSIGNMENT_KEY", "OPTIONAL_KEY",
    "CALL_RECEIVER", "NEW_ARGUMENT", "FOROF_ASSIGN_TARGET", "CONSTRUCTOR_CAPTURE",
    "MODULE_CLASS_STATIC", "CALLABLE_DEFAULT_CHILD",
  ]],
  ["SSC_CALL_UNRESOLVED", "CALL_RESOLUTION", "TV_CALLBACK_UNMODELED", [
    "UNKNOWN_CALL", "PROMISE_CALLBACK", "UNKNOWN_RECEIVER", "UNLISTED_STATIC_FIELD",
  ]],
  ["SSC_CALL_UNRESOLVED", "CALL_RESOLUTION", "DP_CAPABILITY", [
    "MODULE_ALIAS", "UNLISTED_RETURN", "UNLISTED_ACQUIRE", "UNLISTED_CALL", "PRECAPTURED_UNLISTED",
  ]],
  ["SSC_PUBLIC_SURFACE", "PUBLIC_CAUSE", "CF_PUBLIC_THROW", ["THROWN_CLOSURE"]],
  ["SSC_SECRET_FLOW_DENIED", "PUBLIC_RETURN", "CF_PUBLIC_ESCAPE", ["CATCH_ESCAPE"]],
  ["SSC_SECRET_FLOW_DENIED", "FIXED_POINT_RECURSION", "CF_RECURSION", [
    "RECURSION", "MUTUAL_RECURSION", "CALLBACK_RECURSION",
  ]],
  ["SSC_AST_UNSUPPORTED", "SYNTAX_POLICY", "TV_CHILD_UNDISPOSED", ["UNSUPPORTED_SYNTAX"]],
]);

function run657StaticExpectedResults() {
  const expected = new Map([
    ["GENUINE_BASELINE", Object.freeze({ ok: true })],
    ["PASSWORD_ABSENT", Object.freeze({ ok: true })],
    ["CYCLE_CLEAN_PROTOCOL", Object.freeze({ ok: true })],
  ]);
  for (const [code, detector, obligationOrViolations, ids] of RUN657_STATIC_ORACLE_GROUPS) {
    const obligation = Array.isArray(obligationOrViolations) ? null : obligationOrViolations;
    const violations = Array.isArray(obligationOrViolations)
      ? obligationOrViolations
      : [obligationOrViolations];
    for (const id of ids) {
      if (expected.has(id)) throw new Error("RUN657_DUPLICATE_ORACLE:" + id);
      expected.set(id, Object.freeze({
        ok: false,
        code,
        detector,
        obligation: obligation ?? violations[violations.length - 1],
        violations: Object.freeze([...violations].sort()),
      }));
    }
  }
  return expected;
}

const RUN657_MATRIX_REPRESENTATIONS = Object.freeze({
  direct: (fact) => [fact, fact],
  alias: (fact) => [
    "(()=>{const alias=" + fact + ";return alias;})()",
    "(()=>{const alias=" + fact + ";return alias;})()",
  ],
  closure: (fact) => ["()=>"+fact, "(()=>"+fact+")()"],
  object: (fact) => ["({v:"+fact+"})", "({v:"+fact+"}).v"],
  array: (fact) => ["["+fact+"]", "["+fact+"][0]"],
  Set: (fact) => ["new Set(["+fact+"])", "new Set(["+fact+"]).values()[0]"],
  Map: (fact) => [
    "new Map([[\"key\","+fact+"]])",
    "new Map([[\"key\","+fact+"]]).get(\"key\")",
  ],
  WeakMap: (fact) => [
    "(()=>{const key={};return new WeakMap([[key,"+fact+"]]);})()",
    "(()=>{const key={};const box=new WeakMap([[key,"+fact+"]]);return box.get(key);})()",
  ],
  class: (fact) => [
    "new (class {value(){return "+fact+";}})()",
    "new (class {value(){return "+fact+";}})().value()",
  ],
  callback: (fact) => ["[0].map(()=>()=>"+fact+")", "[0].map(()=>"+fact+")[0]"],
  functionReturn: (fact) => ["(()=>()=>"+fact+")()", "(()=>()=>"+fact+")()()"],
});

function buildRun657RepresentationMatrix(source, protocolPreserving = false) {
  const matrix = [];
  const facts = {
    credential: "input.connectionPassword",
    diagnostic: "error",
    authority: "authority",
    capability: "globalThis.crypto",
    clean: "\"safe\"",
  };
  const diagnosticAnchor =
    "if (error instanceof DisposablePostgresFixtureAdmissionError) throw error;\n" +
    "    throw new DisposablePostgresFixtureAdmissionError();";
  for (const [fact, expression] of Object.entries(facts)) {
    for (const [representation, make] of Object.entries(RUN657_MATRIX_REPRESENTATIONS)) {
      for (const [index, originalExpression] of make(expression).entries()) {
        const observation = index === 0 ? "retained" : "extracted";
        const id = (protocolPreserving ? "RUN659_PROTOCOL" : "RUN657_RAW") +
          "_" + fact + "_" + representation + "_" + observation;
        let mutated;
        if (!protocolPreserving && fact === "diagnostic") {
          if (!source.includes(diagnosticAnchor)) throw new Error("RUN657_MATRIX_DIAGNOSTIC_ANCHOR");
          mutated = source.replace(diagnosticAnchor, "return " + originalExpression + ";");
        } else if (!protocolPreserving) {
          mutated = source.replace("return await operation();", "return " + originalExpression + ";");
        } else if (fact === "diagnostic") {
          const syntheticError = "await operation(); " +
            "const syntheticError = new Error(\"synthetic\", { cause: input.connectionPassword }); " +
            "try { throw syntheticError; } catch (error) { return " + originalExpression + "; }";
          mutated = source.replace("return await operation();", syntheticError);
        } else {
          const preservedExpression = representation === "Set" && observation === "extracted"
            ? "(()=>{let selected;for(const item of new Set([" + expression +
              "]))selected=item;return selected;})()"
            : originalExpression;
          mutated = source.replace(
            "return await operation();",
            "await operation(); return " + preservedExpression + ";",
          );
        }
        if (mutated === source) throw new Error("RUN657_MATRIX_ANCHOR:" + id);
        matrix.push(Object.freeze({
          id,
          source: mutated,
          fact,
          representation,
          observation,
          protocolPreserving,
        }));
      }
    }
  }
  return Object.freeze(matrix);
}

function run657MatrixOracle(variant) {
  if (variant.protocolPreserving && variant.fact === "clean") {
    return Object.freeze({ ok: true });
  }
  if (variant.protocolPreserving && variant.fact === "diagnostic") {
    return Object.freeze({
      ok: false,
      code: "SSC_PUBLIC_SURFACE",
      detector: "PUBLIC_CAUSE",
      obligation: "CF_PUBLIC_THROW",
      violations: Object.freeze(["CF_PUBLIC_THROW"]),
    });
  }
  if (variant.fact === "capability" &&
      variant.observation === "extracted" &&
      ["array", "callback"].includes(variant.representation)) {
    return Object.freeze({
      ok: false,
      code: "SSC_COMPUTED_ACCESS",
      detector: "COMPUTED_CAPABILITY",
      obligation: "TV_CHILD_UNDISPOSED",
      violations: Object.freeze(["TV_CHILD_UNDISPOSED"]),
    });
  }
  if (variant.protocolPreserving) {
    return Object.freeze({
      ok: false,
      code: "SSC_SECRET_FLOW_DENIED",
      detector: "PUBLIC_RETURN",
      obligation: "CF_PUBLIC_ESCAPE",
      violations: Object.freeze(["CF_PUBLIC_ESCAPE"]),
    });
  }
  if (variant.fact === "diagnostic") {
    return Object.freeze({
      ok: false,
      code: "SSC_SECRET_FLOW_DENIED",
      detector: "PUBLIC_RETURN",
      obligation: "CF_PUBLIC_ESCAPE",
      violations: Object.freeze(["CF_PUBLIC_ESCAPE"]),
    });
  }
  if (variant.fact === "clean") {
    return Object.freeze({
      ok: false,
      code: "SSC_SECRET_FLOW_DENIED",
      detector: "CAPABILITY_CALLBACK",
      obligation: "AP_OPERATION",
      violations: Object.freeze(["AP_OPERATION"]),
    });
  }
  return Object.freeze({
    ok: false,
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "PUBLIC_RETURN",
    obligation: "CF_PUBLIC_ESCAPE",
    violations: Object.freeze(["AP_OPERATION", "CF_PUBLIC_ESCAPE"]),
  });
}

test("RUN657_INDEPENDENT_STATIC_CORPUS", async () => {
  const frozen = await readFrozenMigrationClosureSource();
  const independent = buildRun657IndependentStaticVariants(frozen.source);
  const supplementary = buildRun657SupplementaryStaticVariants(frozen.source);
  const variants = [...independent, ...supplementary];
  const expected = run657StaticExpectedResults();
  assert.equal(independent.length, 84);
  assert.equal(supplementary.length, 25);
  assert.equal(expected.size, variants.length);
  assert.equal(new Set(variants.map((variant) => variant.id)).size, variants.length);
  const results = [];
  for (const variant of variants) {
    const [result] = await analyzeMigrationClosureVariants([variant]);
    const oracle = expected.get(variant.id);
    assert.ok(oracle, "missing independent oracle: " + variant.id);
    assert.equal(result.id, variant.id);
    results.push(result);
    if (oracle.ok) {
      assert.equal(result.ok, true, result.id);
      assert.equal(result.result.ok, true, result.id);
      assert.deepEqual(result.result.violations, [], result.id);
      assert.equal(result.result.totalTraversal, true, result.id);
      assert.equal(result.result.summariesConverged, true, result.id);
      assert.equal(result.result.provenanceComplete, true, result.id);
      continue;
    }
    assert.equal(result.ok, false, result.id);
    assert.deepEqual({
      code: result.result.code,
      detector: result.result.detector,
      obligation: result.result.obligation,
      violations: result.result.violations,
    }, {
      code: oracle.code,
      detector: oracle.detector,
      obligation: oracle.obligation,
      violations: oracle.violations,
    }, result.id);
  }
  assert.equal(results.length, variants.length);
  assert.deepEqual(results.map((result) => result.id), variants.map((variant) => variant.id));
});

async function assertRun657RepresentationMatrix(source, protocolPreserving) {
  const variants = buildRun657RepresentationMatrix(source, protocolPreserving);
  const expectedCount = 110;
  assert.equal(variants.length, expectedCount);
  assert.equal(new Set(variants.map((variant) => variant.id)).size, expectedCount);
  const results = await analyzeMigrationClosureVariants(variants);
  assert.equal(results.length, expectedCount);
  let passes = 0;
  let failures = 0;
  for (const [index, result] of results.entries()) {
    const variant = variants[index];
    const oracle = run657MatrixOracle(variant);
    assert.equal(result.id, variant.id);
    if (oracle.ok) {
      passes += 1;
      assert.equal(result.ok, true, variant.id);
      assert.equal(result.result.ok, true, variant.id);
      assert.deepEqual(result.result.violations, [], variant.id);
      assert.equal(result.result.totalTraversal, true, variant.id);
      assert.equal(result.result.summariesConverged, true, variant.id);
      assert.equal(result.result.provenanceComplete, true, variant.id);
      continue;
    }
    failures += 1;
    assert.equal(result.ok, false, variant.id);
    assert.deepEqual({
      code: result.result.code,
      detector: result.result.detector,
      obligation: result.result.obligation,
      violations: result.result.violations,
    }, {
      code: oracle.code,
      detector: oracle.detector,
      obligation: oracle.obligation,
      violations: oracle.violations,
    }, variant.id);
  }
  return Object.freeze({ count: results.length, passes, failures });
}

test("RUN657_RAW_STATIC_REPRESENTATION_MATRIX", async () => {
  const frozen = await readFrozenMigrationClosureSource();
  assert.deepEqual(
    await assertRun657RepresentationMatrix(frozen.source, false),
    { count: 110, passes: 0, failures: 110 },
  );
});

test("RUN659_PROTOCOL_PRESERVING_REPRESENTATION_MATRIX", async () => {
  const frozen = await readFrozenMigrationClosureSource();
  assert.deepEqual(
    await assertRun657RepresentationMatrix(frozen.source, true),
    { count: 110, passes: 22, failures: 88 },
  );
});

test("RUN657_INDEPENDENT_RUNTIME_CORPUS", async () => {
  const result = await runSecretSurfaceIndependentRuntimeCorpus();
  const leakingSurfaces = new Set([
    "symbol", "symbol_key", "symbol_array", "nested_symbol", "nonenum",
    "inherited_long", "inherited", "inherited_nonenum", "map_internal",
    "set_internal", "boxed_symbol", "map_custom_inspect",
  ]);
  const invalidSurfaces = new Set([
    "getter", "throw_getter", "throw_descriptor", "wide_258", "wide_late_marker", "depth_7", "map_custom_inspect",
  ]);
  const surfaceIds = [
    "symbol", "symbol_key", "symbol_array", "nested_symbol", "nonenum",
    "getter", "throw_getter", "throw_descriptor", "inherited_long", "inherited",
    "inherited_nonenum", "wide_258", "wide_late_marker", "map_internal",
    "set_internal", "boxed_symbol", "map_custom_inspect", "depth_7",
  ];
  const expectedSurfaces = surfaceIds.map((id) => {
    const leak = leakingSurfaces.has(id);
    const invalid = invalidSurfaces.has(id);
    return {
      family: "F4A",
      id,
      safe: !leak && !invalid,
      leak,
      invalid,
      ...(id === "map_custom_inspect" ? { customRendererCalled: false } : {}),
    };
  });
  const expectedRestoration = [
    { family: "F2", id: "success", ok: true, restored: true },
    ...["mismatch", "throw", "verify_false", "verify_throw"].map((id) => ({
      family: "F2", id, code: "SSC_OBSERVER_RESTORE", detector: "RESTORE_LEDGER",
    })),
    { family: "F2", id: "reverse_order", pass: true },
    { family: "F2", id: "partial_install", pass: true },
    { family: "F2", id: "scenario_failure_restore", pass: true },
  ];
  const expectedPoolBindings = [
    { family: "F3", id: "good", pass: true },
    ...[
      "captured_password", "observed_password", "binding", "authority_pool",
      "authority_record_pool", "two_pools", "two_captures", "connectionString",
      "wrong_max", "wrong_database",
    ].map((id) => ({ family: "F3", id, rejected: true })),
  ];
  const expectedDependencies = [
    ...[
      "WRONG_HASH_ALGORITHM", "WRONG_HASH_RECEIVER", "POOL_FALLBACK_WRONG_RECEIVER",
      "UNLISTED_READ_PATH", "WRITE_OPEN_DENIED",
    ].map((id) => ({ family: "DEPENDENCY", id, effects: 0, threw: true, eventCount: 1 })),
    ...["UNEXPECTED_SQL", "WRONG_IDENTITY_PARAMETERS"].map((id) => ({
      family: "DEPENDENCY",
      id,
      threw: true,
      migrationQueries: 0,
      identityCalls: 0,
      queryRejected: true,
    })),
  ];
  const expected = [...expectedSurfaces, ...expectedRestoration, ...expectedPoolBindings, ...expectedDependencies];
  assert.equal(result.id, "RUN657_INDEPENDENT_RUNTIME_CORPUS");
  assert.equal(result.count, 44);
  assert.deepEqual(result.cases, expected);
});

test("RUN660_HS5_DP6_RUNTIME_BOUNDARY_CONTROLS", async () => {
  const result = await runSecretSurfaceRun660RuntimeControls();
  assert.equal(result.id, "RUN660_HS5_DP6_RUNTIME_CONTROLS");
  assert.equal(result.pass, true);
  assert.equal(result.hs.pass, true);
  assert.equal(result.hs.count, 14);
  assert.deepEqual(result.hs.effects, { getter: 0, callable: 0, thenable: 0, renderer: 0, iterator: 0, toJSON: 0 });
  for (const item of result.hs.cases) {
    assert.equal(item.safe, false, item.id);
    assert.equal(item.invalid, true, item.id);
    assert.equal(item.detector, "HS_INTERNAL_SLOT_UNSUPPORTED", item.id);
    assert.equal(item.authorityRejected, true, item.id);
    assert.equal(item.publicFailureRejected, true, item.id);
  }
  assert.equal(result.dp6.pass, true);
  assert.equal(result.dp6.count, 17);
  const byId = new Map(result.dp6.cases.map((item) => [item.id, item]));
  for (const [id, detector] of [
    ["RUN660_DP6_WRONG_RECEIVER", "DP_RECEIVER"],
    ["RUN660_DP6_NO_CURRENT_STATE", "DP_STATE"],
    ["RUN660_DP6_EXTRA_ARGUMENT", "DP_ARGUMENTS"],
    ["RUN660_DP6_NO_IDENTITY_AUTHORITY", "DP_STATE"],
    ["RUN660_DP6_WRONG_ALGORITHM", "DP_ARGUMENTS"],
  ]) {
    const item = byId.get(id);
    assert.ok(item, id);
    assert.equal(item.code, "SSC_RUNTIME_CAPABILITY", id);
    assert.equal(item.detector, detector, id);
    assert.equal(item.delegatedHashCalls, 0, id);
    assert.equal(item.pass, true, id);
  }
  const admitted = byId.get("RUN660_DP6_ADMITTED_REAL_MIGRATION_FILES");
  assert.ok(admitted);
  assert.ok(admitted.migrationFiles > 0);
  assert.equal(admitted.manifestExists, 1);
  assert.equal(admitted.manifestReads, 1);
  assert.equal(admitted.migrationReads, admitted.migrationFiles);
  assert.equal(admitted.delegatedHashCalls, admitted.migrationFiles * 3);
  assert.deepEqual(admitted.hashDelegations, {
    createHash: admitted.migrationFiles,
    update: admitted.migrationFiles,
    digest: admitted.migrationFiles,
  });
  assert.equal(admitted.hashOutputsMatch, true);
  assert.equal(admitted.pass, true);
  for (const [id, detector] of [
    ["RUN663_DP6_WRONG_HASH_RECEIVER", "DP_RECEIVER"],
    ["RUN663_DP6_WRONG_OPEN_RECEIVER", "DP_RECEIVER"],
    ["RUN663_DP6_WRONG_OPEN_ARGUMENTS", "DP_ARGUMENTS"],
    ["RUN663_DP6_POST_REVOCATION_FILE_OPEN", "DP_STATE"],
    ["RUN663_DP6_POST_CLEANUP_FILE_OPEN", "DP_STATE"],
    ["RUN663_DP6_POST_PUBLIC_COMPLETION_FILE_OPEN", "DP_STATE"],
    ["RUN663_DP6_CREATE_HASH_AFTER_TERMINAL", "DP_STATE"],
    ["RUN663_DP6_UPDATE_AFTER_REVOCATION", "DP_STATE"],
    ["RUN663_DP6_DIGEST_AFTER_CLEANUP", "DP_STATE"],
    ["RUN663_DP6_CROSS_RUN_HASH_REUSE", "DP_RECEIVER"],
    ["RUN663_DP6_CONSUMED_HASH_REPLAY", "DP_RECEIVER"],
  ]) {
    const item = byId.get(id);
    assert.ok(item, id);
    assert.equal(item.code, "SSC_RUNTIME_CAPABILITY", id);
    assert.equal(item.detector, detector, id);
    assert.equal(item.underlyingDelegateDelta, 0, id);
    assert.equal(item.pass, true, id);
  }
});

test("RUN668_RUN660_TO_F3_SAME_PROCESS_REGRESSION", async () => {
  const processId = process.pid;
  const run660 = await runSecretSurfaceRun660RuntimeControls();
  assert.equal(run660.id, "RUN660_HS5_DP6_RUNTIME_CONTROLS");
  assert.equal(run660.pass, true);
  assert.equal(run660.hs.pass, true);
  assert.equal(run660.dp6.pass, true);

  const f3 = await runSecretSurfaceF3();
  assert.equal(process.pid, processId);
  assert.equal(f3.id, "F3_RUNTIME_LIFECYCLE_SCENARIOS");
  assert.equal(f3.pass, true);
  assert.equal(f3.scenarios.length, 8);
  assert.deepEqual(f3.scenarios.map((scenario) => scenario.id), SCENARIO_IDS);
  for (const scenario of f3.scenarios) {
    const prePoolFailure = scenario.id === "SC06_PRE_POOL_FAILURE";
    assert.equal(scenario.pass, true, scenario.id);
    assert.equal(scenario.resourcesStable, true, scenario.id);
    assert.equal(scenario.poolCount, prePoolFailure ? 0 : 1, scenario.id);
  }
  assert.equal(f3.scenarios.filter((scenario) => scenario.poolCount === 1).length, 7);
});

function run660PrependRoot(source, statements) {
  const root = source.indexOf("export async function withDisposablePostgresFixtureMigration");
  const brace = source.indexOf("{", root);
  if (root < 0 || brace < 0) throw new Error("RUN660_ROOT_ANCHOR");
  return source.slice(0, brace + 1) + "\n" + statements + "\n" + source.slice(brace + 1);
}

function run660ReplaceOnce(source, needle, replacement) {
  const index = source.indexOf(needle);
  if (index < 0) {
    throw new Error("RUN660_SOURCE_ANCHOR");
  }
  return source.slice(0, index) + replacement + source.slice(index + needle.length);
}

function run660ShiftLoop(kind, hops, secret) {
  const names = Array.from({ length: hops + 1 }, (_item, index) => "run660Hop" + index);
  const declarations = names.map((name, index) => name + "=" +
    (index === 0 && secret ? "input.connectionPassword" : "\"clean\"")).join(",");
  const shift = names.slice(1).reverse().map((_name, reverseIndex) => {
    const index = hops - reverseIndex;
    return names[index] + "=" + names[index - 1] + ";";
  }).join("");
  const setup = "let " + declarations + ";";
  if (kind === "for") return setup + "for(let run660Index=0;run660Index<" + hops + ";run660Index++){" + shift + "}";
  if (kind === "while") return setup + "let run660Index=0;while(run660Index<" + hops + "){" + shift + "run660Index++;}";
  if (kind === "do") return setup + "let run660Index=0;do{" + shift + "run660Index++;}while(run660Index<" + hops + ");";
  throw new Error("RUN660_LOOP_KIND");
}

test("RUN660_CF1_TV2_PV3_AP4_STATIC_WITNESSES", async () => {
  const frozen = await readFrozenMigrationClosureSource();
  const variants = [];
  const cleanChecks = [];
  const loopCases = [];
  for (const kind of ["for", "while", "do"]) {
    for (const hops of [4, 12]) {
      const id = "RUN660_CF_" + kind.toUpperCase() + "_" + hops;
      const body = run660ShiftLoop(kind, hops, true);
      const returnExpression = "return run660Hop" + hops + ";";
      variants.push({ id, source: run660PrependRoot(frozen.source, body + returnExpression) });
      loopCases.push({ id, body, returnExpression });
    }
    const cleanId = "RUN660_CF_" + kind.toUpperCase() + "_CLEAN";
    const cleanBody = run660ShiftLoop(kind, 4, false);
    cleanChecks.push({ id: cleanId, source: run660PrependRoot(frozen.source, cleanBody) });
  }
  const add = (id, candidate) => variants.push({ id, source: candidate });
  add("RUN660_CF_CAUGHT_SAFE", run660PrependRoot(frozen.source,
    "try { throw input.connectionPassword; } catch {} return \"safe\";"));
  add("RUN660_CF_CAUGHT_RETURN", run660PrependRoot(frozen.source,
    "try { throw input.connectionPassword; } catch (caught) { return caught; } return \"safe\";"));
  add("RUN660_CF_UNCAUGHT_THROW", run660PrependRoot(frozen.source,
    "throw input.connectionPassword;"));

  const outputClass = "class Run660Parent { constructor() { console.log(input.connectionPassword); } } class Run660Child extends Run660Parent {} new Run660Child();";
  const cleanClass = "class Run660Parent { constructor() { this.value = \"safe\"; } } class Run660Child extends Run660Parent {} new Run660Child();";
  add("RUN660_TV_PARENT_OUTPUT", run660PrependRoot(frozen.source, outputClass));
  cleanChecks.push({ id: "RUN660_TV_PARENT_CLEAN", source: run660PrependRoot(frozen.source, cleanClass) });

  const recordAnchor = "migrationAuthorityValues.set(authority, {";
  const replaceAuthorityField = (candidate, field, original, replacement) => {
    const start = candidate.indexOf(recordAnchor);
    const tail = run660ReplaceOnce(candidate.slice(start), field + ": " + original + ",",
      field + ": " + replacement + ",");
    return candidate.slice(0, start) + tail;
  };
  const pvCases = [
    ["RUN660_PV_DATABASE_NUMBER", "database", "target.expectedDatabase", "Number(target.expectedDatabase)"],
    ["RUN660_PV_USER_NUMBER", "user", "target.expectedUser", "Number(target.expectedUser)"],
    ["RUN660_PV_CATALOG_NUMBER", "clusterFingerprint", "identity.catalogFingerprint", "Number(identity.catalogFingerprint)"],
    ["RUN660_PV_LIFECYCLE_NUMBER", "lifecycleFingerprint", "identity.lifecycleFingerprint", "Number(identity.lifecycleFingerprint)"],
    ["RUN660_PV_PHASE_NUMBER", "phase", "target.phase", "Number(target.phase)"],
  ];
  for (const [id, field, original, replacement] of pvCases) {
    add(id, replaceAuthorityField(frozen.source, field, original, replacement));
  }
  const aliasSource = run660ReplaceOnce(frozen.source, recordAnchor,
    "const run660DatabaseAlias = target.expectedDatabase;\n    " + recordAnchor);
  cleanChecks.push({ id: "RUN660_PV_ALIAS_CLEAN", source: replaceAuthorityField(
    aliasSource, "database", "target.expectedDatabase", "run660DatabaseAlias") });
  cleanChecks.push({ id: "RUN660_PV_PROPERTY_ROUNDTRIP_CLEAN", source: replaceAuthorityField(
    frozen.source, "database", "target.expectedDatabase", "({ value: target.expectedDatabase }).value") });
  const identitySource = run660ReplaceOnce(frozen.source, recordAnchor,
    "const run660Identity = (item) => item;\n    " + recordAnchor);
  cleanChecks.push({ id: "RUN660_PV_IDENTITY_CALL_CLEAN", source: replaceAuthorityField(
    identitySource, "database", "target.expectedDatabase", "run660Identity(target.expectedDatabase)") });

  add("RUN660_AP_OPERATION_FALSE", run660ReplaceOnce(frozen.source, "return await operation();",
    "if (false) { await operation(); }\n    return { ok: true };"));
  add("RUN660_AP_OPERATION_BEFORE_MIGRATION", run660ReplaceOnce(frozen.source,
    "await runScopedFixtureMigration(authority, pool, target.migrationsFolder, target);\n    return await operation();",
    "return await operation();\n    await runScopedFixtureMigration(authority, pool, target.migrationsFolder, target);"));
  add("RUN660_AP_REVOCATION_FALSE", run660ReplaceOnce(frozen.source,
    "if (value) value.valid = false;", "if (false) value.valid = false;"));
  add("RUN660_AP_CLEANUP_FALSE", run660ReplaceOnce(frozen.source,
    "if (pool) await pool.end().catch(() => {});", "if (false) await pool.end().catch(() => {});"));
  const guardPattern = /if\s*\(\s*identity\.catalogFingerprint\s*!==\s*value\.clusterFingerprint\s*\|\|\s*identity\.lifecycleFingerprint\s*!==\s*value\.lifecycleFingerprint\s*\)/u;
  if (!guardPattern.test(frozen.source)) throw new Error("RUN660_FINGERPRINT_GUARD_ANCHOR");
  add("RUN660_AP_FINGERPRINT_SHORT_CIRCUIT_FALSE", frozen.source.replace(guardPattern,
    "if (false && (identity.catalogFingerprint !== value.clusterFingerprint || identity.lifecycleFingerprint !== value.lifecycleFingerprint))"));

  const results = await analyzeMigrationClosureVariants([...variants, ...cleanChecks]);
  const byId = new Map(results.map((item) => [item.id, item]));
  assert.equal(results.length, variants.length + cleanChecks.length);
  for (const clean of cleanChecks) {
    assert.equal(byId.get(clean.id)?.ok, true, clean.id);
    assert.equal(byId.get(clean.id)?.result?.ok, true, clean.id);
  }
  for (const item of loopCases) {
    const observed = byId.get(item.id)?.result;
    assert.equal(byId.get(item.id)?.ok, false, item.id);
    assert.equal(observed.code, "SSC_SECRET_FLOW_DENIED", item.id);
    assert.equal(observed.detector, "PUBLIC_RETURN", item.id);
    assert.equal(observed.obligation, "CF_PUBLIC_ESCAPE", item.id);
    assert.deepEqual(observed.violations, ["AP_OPERATION", "CF_PUBLIC_ESCAPE"], item.id);
    const marker = "run660-synthetic-connection-marker";
    const result = new Function("input", item.body + item.returnExpression)({ connectionPassword: marker });
    assert.equal(result, marker, item.id + " runtime");
  }
  for (const [id, expected] of [
    ["RUN660_CF_CAUGHT_RETURN", ["SSC_SECRET_FLOW_DENIED", "PUBLIC_RETURN", "CF_PUBLIC_ESCAPE"]],
    ["RUN660_CF_UNCAUGHT_THROW", ["SSC_PUBLIC_SURFACE", "PUBLIC_CAUSE", "CF_PUBLIC_THROW"]],
    ["RUN660_TV_PARENT_OUTPUT", ["SSC_SECRET_FLOW_DENIED", "CAPABILITY_OUTPUT", "CF_PUBLIC_ESCAPE"]],
    ["RUN660_AP_OPERATION_FALSE", ["SSC_SECRET_FLOW_DENIED", "CAPABILITY_CALLBACK", "AP_OPERATION"]],
    ["RUN660_AP_OPERATION_BEFORE_MIGRATION", ["SSC_SECRET_FLOW_DENIED", "CAPABILITY_CALLBACK", "AP_OPERATION"]],
    ["RUN660_AP_REVOCATION_FALSE", ["SSC_AUTHORITY_SHAPE", "AUTHORITY_SCHEMA", "AP_REVOCATION"]],
    ["RUN660_AP_CLEANUP_FALSE", ["SSC_SECRET_FLOW_DENIED", "CAPABILITY_CLEANUP", "AP_CLEANUP"]],
    ["RUN660_AP_FINGERPRINT_SHORT_CIRCUIT_FALSE", ["SSC_AUTHORITY_SHAPE", "AUTHORITY_SCHEMA", "AP_FINGERPRINT_COMPARE"]],
  ]) {
    const observed = byId.get(id)?.result;
    assert.equal(byId.get(id)?.ok, false, id);
    assert.deepEqual([observed.code, observed.detector, observed.obligation], expected, id);
    assert.deepEqual(observed.violations, [expected[2]], id);
  }
  const caughtSafe = byId.get("RUN660_CF_CAUGHT_SAFE");
  assert.equal(caughtSafe.ok, false, "baseline lifecycle still applies to early public completion");
  assert.equal(caughtSafe.result.violations.includes("CF_PUBLIC_THROW"), false);
  assert.equal(caughtSafe.result.violations.includes("CF_PUBLIC_ESCAPE"), false);
  for (const [id, field] of pvCases) {
    const observed = byId.get(id)?.result;
    assert.equal(byId.get(id)?.ok, false, id);
    assert.deepEqual([observed.code, observed.detector, observed.obligation],
      ["SSC_AUTHORITY_SHAPE", "AUTHORITY_SCHEMA", "PV_EXACT_RELATION"], id);
    assert.deepEqual(observed.violations, ["PV_EXACT_RELATION"], id + " " + field);
  }
  const cleanCode = "class Run660Parent { constructor() { this.value = \"safe\"; } } class Run660Child extends Run660Parent {} const run660Child = new Run660Child(); return run660Child.value;";
  const child = new Function(cleanCode)();
  assert.equal(child, "safe");
  let attemptedOutput = 0;
  const externalOutput = [];
  const boundaryConsole = { log(...args) { attemptedOutput += 1; assert.deepEqual(args, ["run660-synthetic-connection-marker"]); } };
  new Function("input", "console", outputClass)({ connectionPassword: "run660-synthetic-connection-marker" }, boundaryConsole);
  assert.equal(attemptedOutput, 1);
  assert.deepEqual(externalOutput, []);
});

test("RUN663_CF1_DECLARATION_CELL_WITNESSES", async () => {
  const frozen = await readFrozenMigrationClosureSource();
  const replaceOperation = (body) => run660ReplaceOnce(frozen.source,
    "return await operation();", body);
  const fiveCell = "await operation(); let a=\"clean\", b=\"clean\", c=\"clean\", d=\"clean\", e=\"clean\"; " +
    "const move=()=>{ a=b; b=c; c=d; d=e; e=input.connectionPassword; }; " +
    "for(let k=0;k<7;k++){ move(); } return a;";
  const thirteenCell = "await operation(); let cell0=input.connectionPassword; " +
    Array.from({ length: 13 }, (_item, index) =>
      `function returnedCell${index + 1}(){ return ${index === 0 ? "cell0" : `returnedCell${index}()`}; }`,
    ).join(" ") + " return returnedCell13();";
  const nestedClosure = "await operation(); const outer=()=>{ let cell=input.connectionPassword; return ()=>cell; }; " +
    "const nested=outer(); return nested();";
  const propertyAlias = "await operation(); let cell=input.connectionPassword; const carry=()=>cell; " +
    "const box={inner:carry}; const alias=box.inner; return alias();";
  const cases = [
    ["RUN663_CF_FIVE_CELL", fiveCell, fiveCell.replace("input.connectionPassword", "\"clean\"").replace(" return a;", "")],
    ["RUN663_CF_THIRTEEN_CELL", thirteenCell, thirteenCell.replace("input.connectionPassword", "\"clean\"").replace(" return returnedCell13();", " const clean=returnedCell13(); if(clean!==\"clean\") throw new Error();")],
    ["RUN663_CF_NESTED_RETURNED_CLOSURE", nestedClosure, nestedClosure.replace("input.connectionPassword", "\"clean\"").replace(" return nested();", " const clean=nested(); if(clean!==\"clean\") throw new Error();")],
    ["RUN663_CF_ALIASED_PROPERTY_CALLABLE", propertyAlias, propertyAlias.replace("input.connectionPassword", "\"clean\"").replace(" return alias();", " const clean=alias(); if(clean!==\"clean\") throw new Error();")],
  ];
  const results = await analyzeMigrationClosureVariants([
    ...cases.map(([id, body]) => ({ id, source: replaceOperation(body) })),
    ...cases.map(([id, _body, cleanBody]) => ({ id: id + "_CLEAN", source: replaceOperation(cleanBody) })),
  ]);
  const byId = new Map(results.map((item) => [item.id, item]));
  assert.equal(results.length, cases.length * 2);
  for (const [id, body] of cases) {
    const observed = byId.get(id)?.result;
    assert.equal(byId.get(id)?.ok, false, id);
    assert.deepEqual([observed.code, observed.detector, observed.obligation],
      ["SSC_SECRET_FLOW_DENIED", "PUBLIC_RETURN", "CF_PUBLIC_ESCAPE"], id);
    const marker = "run663-synthetic-connection-marker";
    let operationCalls = 0;
    const run = new Function("input", "operation",
      `return (async () => { ${body} })();`);
    assert.equal(await run({ connectionPassword: marker }, async () => {
      operationCalls += 1;
      return undefined;
    }), marker, id + " runtime");
    assert.equal(operationCalls, 1, id + " operation count");
  }
  for (const [id] of cases) {
    assert.equal(byId.get(id + "_CLEAN")?.ok, true, id + " clean counterpart");
    assert.equal(byId.get(id + "_CLEAN")?.result?.ok, true, id + " clean result");
  }
});

test("RUN663_PV3_EXACT_RELATION_JOINS", async () => {
  const frozen = await readFrozenMigrationClosureSource();
  const recordAnchor = "migrationAuthorityValues.set(authority, {";
  const replaceField = (source, field, original, replacement) => {
    const start = source.indexOf(recordAnchor);
    if (start < 0) throw new Error("RUN663_PV_RECORD_ANCHOR");
    return source.slice(0, start) + run660ReplaceOnce(source.slice(start),
      `${field}: ${original},`, `${field}: ${replacement},`);
  };
  const joinedFields = [
    ["RUN663_PV_JOIN_DATABASE", "database", "target.expectedDatabase",
      "target.expectedDatabase === \"runtime_posture_test\" ? \"different\" : target.expectedDatabase"],
    ["RUN663_PV_JOIN_USER", "user", "target.expectedUser",
      "target.expectedUser === \"cloud_admin\" ? \"different\" : target.expectedUser"],
    ["RUN663_PV_JOIN_CLUSTER", "clusterFingerprint", "identity.catalogFingerprint",
      "identity.catalogFingerprint === \"100\" ? \"different\" : identity.catalogFingerprint"],
    ["RUN663_PV_JOIN_LIFECYCLE", "lifecycleFingerprint", "identity.lifecycleFingerprint",
      "identity.lifecycleFingerprint === \"200\" ? \"different\" : identity.lifecycleFingerprint"],
    ["RUN663_PV_JOIN_PHASE", "phase", "target.phase",
      "target.phase === \"initialization\" ? \"different\" : target.phase"],
  ];
  const negatives = joinedFields.map(([id, field, original, replacement]) => ({
    id,
    source: replaceField(frozen.source, field, original, replacement),
  }));
  negatives.push(
    { id: "RUN663_PV_TRUSTED_STRING_TRANSFORM", source: replaceField(frozen.source,
      "database", "target.expectedDatabase", "String(target.expectedDatabase)") },
    { id: "RUN663_PV_TRUSTED_UNKNOWN_PROPERTY", source: replaceField(frozen.source,
      "database", "target.expectedDatabase", "target.unresolvedAuthorityField") },
    { id: "RUN663_PV_SOURCE_A_SOURCE_B", source: replaceField(frozen.source,
      "database", "target.expectedDatabase",
      "input.expectedUser === target.expectedDatabase ? input.expectedUser : target.expectedDatabase") },
    { id: "RUN663_PV_SAME_TEXT_DIFFERENT_ORIGIN", source: replaceField(frozen.source,
      "database", "target.expectedDatabase",
      "target.expectedDatabase === \"runtime_posture_test\" ? \"runtime_posture_test\" : target.expectedDatabase") },
  );
  const aliasSource = run660ReplaceOnce(frozen.source, recordAnchor,
    "const run663DatabaseAlias = target.expectedDatabase;\n    " + recordAnchor);
  const identitySource = run660ReplaceOnce(frozen.source, recordAnchor,
    "const run663Identity = (item) => item;\n    " + recordAnchor);
  const positives = [
    { id: "RUN663_PV_EXACT_BASELINE", source: frozen.source },
    { id: "RUN663_PV_EXACT_ALIAS", source: replaceField(aliasSource,
      "database", "target.expectedDatabase", "run663DatabaseAlias") },
    { id: "RUN663_PV_EXACT_PROPERTY", source: replaceField(frozen.source,
      "database", "target.expectedDatabase", "({ value: target.expectedDatabase }).value") },
    { id: "RUN663_PV_EXACT_IDENTITY", source: replaceField(identitySource,
      "database", "target.expectedDatabase", "run663Identity(target.expectedDatabase)") },
  ];
  const results = await analyzeMigrationClosureVariants([...negatives, ...positives]);
  const byId = new Map(results.map((item) => [item.id, item]));
  assert.equal(results.length, negatives.length + positives.length);
  for (const item of negatives) {
    const observed = byId.get(item.id)?.result;
    assert.equal(byId.get(item.id)?.ok, false, item.id);
    assert.deepEqual([observed.code, observed.detector, observed.obligation],
      ["SSC_AUTHORITY_SHAPE", "AUTHORITY_SCHEMA", "PV_EXACT_RELATION"], item.id);
    assert.deepEqual(observed.violations, ["PV_EXACT_RELATION"], item.id);
  }
  for (const item of positives) {
    assert.equal(byId.get(item.id)?.ok, true, item.id);
    assert.equal(byId.get(item.id)?.result?.provenanceComplete, true, item.id);
    assert.equal(byId.get(item.id)?.result?.authoritySets, 1, item.id);
  }
});

test("RUN663_AP4_PER_COMPLETION_CLEANUP", async () => {
  const frozen = await readFrozenMigrationClosureSource();
  const migrationCall = "await runScopedFixtureMigration(authority, pool, target.migrationsFolder, target);";
  const cleanupCall = "if (pool) await pool.end().catch(() => {});";
  const variants = [
    { id: "RUN663_AP_THROW_BEFORE_CLEANUP", source: run660ReplaceOnce(frozen.source,
      cleanupCall, "if (input.expectedDatabase) throw new Error();\n    " + cleanupCall) },
    { id: "RUN663_AP_NESTED_FINALLY_BYPASS", source: run660ReplaceOnce(frozen.source,
      cleanupCall, "try { throw new Error(); } finally { throw new Error(); }\n    " + cleanupCall) },
    { id: "RUN663_AP_THROW_AFTER_POOL_ALLOCATION", source: run660ReplaceOnce(frozen.source,
      "pool = new Pool(poolOptions);", "pool = new Pool(poolOptions);\n    throw new Error();") },
    { id: "RUN663_AP_THROW_AFTER_MIGRATION", source: run660ReplaceOnce(frozen.source,
      "return await operation();", "throw new Error();") },
    { id: "RUN663_AP_MIGRATION_REJECTION", source: run660ReplaceOnce(frozen.source,
      migrationCall, "throw new Error();") },
    { id: "RUN663_AP_OPERATION_REJECTION", source: run660ReplaceOnce(frozen.source,
      "return await operation();", "await operation();\n    throw new Error();") },
    { id: "RUN663_AP_UNREACHABLE_THROW", source: run660PrependRoot(frozen.source,
      "if (false) throw new Error();") },
  ];
  const results = await analyzeMigrationClosureVariants([
    { id: "RUN663_AP_NORMAL_RETURN_CLEANUP", source: frozen.source },
    ...variants,
  ]);
  const byId = new Map(results.map((item) => [item.id, item]));
  assert.equal(results.length, variants.length + 1);
  for (const id of ["RUN663_AP_NORMAL_RETURN_CLEANUP", "RUN663_AP_UNREACHABLE_THROW"]) {
    assert.equal(byId.get(id)?.ok, true, id);
    assert.equal(byId.get(id)?.result?.ok, true, id);
  }
  for (const id of ["RUN663_AP_THROW_BEFORE_CLEANUP", "RUN663_AP_NESTED_FINALLY_BYPASS"]) {
    const observed = byId.get(id)?.result;
    assert.equal(byId.get(id)?.ok, false, id);
    assert.ok(observed.violations.includes("AP_CLEANUP"), id);
    assert.deepEqual([observed.code, observed.detector, observed.obligation],
      ["SSC_SECRET_FLOW_DENIED", "CAPABILITY_CLEANUP", "AP_CLEANUP"], id);
  }
  for (const id of ["RUN663_AP_THROW_AFTER_POOL_ALLOCATION", "RUN663_AP_THROW_AFTER_MIGRATION",
    "RUN663_AP_MIGRATION_REJECTION", "RUN663_AP_OPERATION_REJECTION"]) {
    const observed = byId.get(id)?.result;
    assert.equal(byId.get(id)?.ok, false, id);
    assert.equal(observed.violations.includes("AP_CLEANUP"), false, id);
    assert.equal(observed.violations.includes("AP_REVOCATION"), false, id);
  }
});

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
  const provenanceRegressions = await runProvenanceIdentityRegressions();

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
  assert.equal(provenanceRegressions.pass, true);
  assert.equal(provenanceRegressions.count, PROVENANCE_IDENTITY_REGRESSION_CASES.length + 1);

  for (const [index, regression] of provenanceRegressions.results.entries()) {
    const expected = index < PROVENANCE_IDENTITY_REGRESSION_CASES.length
      ? PROVENANCE_IDENTITY_REGRESSION_CASES[index]
      : { id: "PROVENANCE_LITERAL_IDENTITY_SQL", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_QUERY" };
    await suite.test(expected.id, () => {
      assert.equal(regression.ok, false, expected.id);
      assert.equal(regression.result.code, expected.code, expected.id);
      assert.equal(regression.result.detector, expected.detector, expected.id);
    });
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
      const prePoolFailure = scenario.id === "SC06_PRE_POOL_FAILURE";
      assert.equal(scenario.pass, true, scenario.id);
      assert.equal(scenario.poolCount, prePoolFailure ? 0 : 1, scenario.id);
      assert.equal(scenario.authorityCaptureCount, prePoolFailure ? 0 : 1, scenario.id);
      assert.equal(scenario.authorityValidAtCapture, !prePoolFailure, scenario.id);
      assert.equal(scenario.authorityRevoked, true, scenario.id);
      assert.equal(scenario.cleanupCalls, prePoolFailure ? 0 : 1, scenario.id);
      if (prePoolFailure) {
        assert.equal(scenario.cleanupEntryCount, 0, scenario.id);
        assert.equal(scenario.cleanupAttempted, false, scenario.id);
      }
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

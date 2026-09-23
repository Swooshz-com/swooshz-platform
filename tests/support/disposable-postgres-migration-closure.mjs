import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const SAFE = Object.freeze({
  baseline: "SSC_STATIC_BASELINE",
  internal: "SSC_ANALYZER_INTERNAL",
  ast: "SSC_AST_UNSUPPORTED",
  computed: "SSC_COMPUTED_ACCESS",
  imports: "SSC_IMPORT_DENIED",
  unresolved: "SSC_CALL_UNRESOLVED",
  flow: "SSC_SECRET_FLOW_DENIED",
  authority: "SSC_AUTHORITY_SHAPE",
});

const OBLIGATION_BY_FAILURE = Object.freeze({
  "PUBLIC_RETURN": "CF_PUBLIC_ESCAPE",
  "PUBLIC_CAUSE": "CF_PUBLIC_THROW",
  "FIXED_POINT_RECURSION": "CF_RECURSION",
  "FIXED_POINT_NONCONVERGENCE": "CF_NONCONVERGENCE",
  "CAPABILITY_POOL": "AP_POOL_OPTIONS",
  "CAPABILITY_QUERY": "AP_IDENTITY_SQL",
  "CAPABILITY_MIGRATE": "AP_MIGRATION",
  "CAPABILITY_CALLBACK": "AP_OPERATION",
  "CAPABILITY_CLEANUP": "AP_CLEANUP",
  "CAPABILITY_CONNECT": "AP_CLIENT_PROTOCOL",
  "CAPABILITY_PASSWORD": "AP_TOKEN",
  "CAPABILITY_CRYPTO": "DP_CAPABILITY",
  "CAPABILITY_ENV": "DP_CAPABILITY",
  "CAPABILITY_OUTPUT": "CF_PUBLIC_ESCAPE",
  "CAPABILITY_STORAGE": "CF_PUBLIC_ESCAPE",
  "CAPABILITY_RECONSTRUCTION": "PV_EXACT_RELATION",
  "CAPABILITY_COLLECTION": "TV_ITERATOR_UNMODELED",
  "CAPABILITY_REFLECTION": "HS_SECRET_REACHABLE",
  "CAPABILITY_URL": "DP_CAPABILITY",
  "CAPABILITY_DRIZZLE": "DP_CAPABILITY",
  "IMPORT_TABLE": "DP_CAPABILITY",
  "CALL_RESOLUTION": "TV_CALLBACK_UNMODELED",
  "COMPUTED_CAPABILITY": "TV_CHILD_UNDISPOSED",
  "SYNTAX_POLICY": "TV_CHILD_UNDISPOSED",
  "TOP_LEVEL_SYNTAX": "TV_CHILD_UNDISPOSED",
  "AST_UNSUPPORTED": "TV_CHILD_UNDISPOSED",
  "AUTHORITY_SCHEMA": "AP_AUTHORITY_GUARD",
  "FROZEN_HELPER_BLOB": "DP_MANIFEST",
});

export const MIGRATION_CLOSURE_OBLIGATION_IDS = Object.freeze([
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

export const MIGRATION_CLOSURE_RESULT_INTERFACE = Object.freeze({
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

const HELPER_RELATIVE = "tests/support/disposable-postgres-fixture.mjs";
const FROZEN_HELPER_BLOB = "0767d4dade1bc7e7a61f984296e0f96bb0575ffb";
const ROOT_EXPORT = "withDisposablePostgresFixtureMigration";

const IMPORT_TABLE = Object.freeze({
  "drizzle-orm/node-postgres": Object.freeze(["drizzle"]),
  "drizzle-orm/node-postgres/migrator": Object.freeze(["migrate"]),
  pg: Object.freeze(["Client", "Pool"]),
  "../../dist/db/runtime-posture.js": Object.freeze([
    "inspectRuntimeDatabaseRoleAuthorityPosture",
  ]),
});

const AUTHORITY_KEYS = Object.freeze([
  "authority",
  "brand",
  "database",
  "user",
  "clusterFingerprint",
  "lifecycleFingerprint",
  "migrationsFolder",
  "phase",
  "pool",
  "valid",
]);

const SAFE_INPUT_FIELDS = new Set([
  "connectionString",
  "expectedDatabase",
  "expectedUser",
  "migrationsFolder",
  "phase",
]);

const QUERY_ROW_FIELDS = new Set([
  "database_matches",
  "user_matches",
  "postgres17",
  "non_recovery",
  "catalog_fingerprint",
  "lifecycle_fingerprint",
  "target_database_absent",
]);

const NEGATIVE_CONTROLS = Object.freeze([
  Object.freeze({
    id: "NC01_REACHABLE_WRITE_HELPER",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CAPABILITY_OUTPUT",
  }),
  Object.freeze({
    id: "NC02_REACHABLE_HASH_HELPER",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CAPABILITY_CRYPTO",
  }),
  Object.freeze({
    id: "NC03_STATIC_ONLY_BRANCH",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CAPABILITY_OUTPUT",
  }),
  Object.freeze({
    id: "NC04_ALIASED_SINK",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "ALIAS_PROVENANCE",
  }),
  Object.freeze({
    id: "NC05_COMPUTED_SINK",
    code: "SSC_COMPUTED_ACCESS",
    detector: "COMPUTED_CAPABILITY",
  }),
  Object.freeze({
    id: "NC06_NEW_IMPORT",
    code: "SSC_IMPORT_DENIED",
    detector: "IMPORT_TABLE",
  }),
  Object.freeze({
    id: "NC07_UNRESOLVED_CALL",
    code: "SSC_CALL_UNRESOLVED",
    detector: "CALL_RESOLUTION",
  }),
  Object.freeze({
    id: "NC08_TRANSIENT_ENV",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CAPABILITY_ENV",
  }),
  Object.freeze({
    id: "NC09_INNOCENT_AUTHORITY_FIELD",
    code: "SSC_AUTHORITY_SHAPE",
    detector: "AUTHORITY_SCHEMA",
  }),
  Object.freeze({
    id: "NC10_CLEANUP_PUBLISH",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CLEANUP_DIAGNOSTIC",
  }),
  Object.freeze({
    id: "PROBE_ARROW_OUTPUT",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CAPABILITY_OUTPUT",
  }),
  Object.freeze({
    id: "PROBE_ARRAY_SOME_OUTPUT",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CAPABILITY_OUTPUT",
  }),
  Object.freeze({
    id: "PROBE_MODULE_IF_OUTPUT",
    code: "SSC_AST_UNSUPPORTED",
    detector: "TOP_LEVEL_SYNTAX",
  }),
  Object.freeze({
    id: "PROBE_PUBLIC_CREDENTIAL_RETURN",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "PUBLIC_RETURN",
  }),
  Object.freeze({
    id: "PROBE_TRIMMED_PASSWORD",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CAPABILITY_PASSWORD",
  }),
  Object.freeze({
    id: "PROBE_CLEANUP_CONCISE_OUTPUT",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CLEANUP_DIAGNOSTIC",
  }),
  Object.freeze({
    id: "PROBE_AUTHORITY_BRAND",
    code: "SSC_AUTHORITY_SHAPE",
    detector: "AUTHORITY_SCHEMA",
  }),
  Object.freeze({
    id: "PROBE_ARRAY_CREDENTIAL_RETURN",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "PUBLIC_RETURN",
  }),
  Object.freeze({
    id: "PROBE_NESTED_ARRAY_CREDENTIAL_RETURN",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "PUBLIC_RETURN",
  }),
  Object.freeze({
    id: "PROBE_JSON_ARRAY_CREDENTIAL_RETURN",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "PUBLIC_RETURN",
  }),
  Object.freeze({
    id: "PROBE_SYMBOL_CREDENTIAL_RETURN",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "PUBLIC_RETURN",
  }),
  Object.freeze({
    id: "PROBE_CLOSURE_ASSIGNMENT_RETURN",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "PUBLIC_RETURN",
  }),
  Object.freeze({
    id: "PROBE_CALLBACK_ASSIGNMENT_RETURN",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "PUBLIC_RETURN",
  }),
  Object.freeze({
    id: "PROBE_CONDITIONAL_AGGREGATE_RETURN",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "PUBLIC_RETURN",
  }),
  Object.freeze({
    id: "PROBE_FOR_INITIALIZER_OUTPUT",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CAPABILITY_OUTPUT",
  }),
  Object.freeze({
    id: "PROBE_WHILE_CONDITION_OUTPUT",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CAPABILITY_OUTPUT",
  }),
  Object.freeze({
    id: "PROBE_DO_CONDITION_OUTPUT",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CAPABILITY_OUTPUT",
  }),
  Object.freeze({
    id: "PROBE_CONSTRUCTOR_OUTPUT",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CAPABILITY_OUTPUT",
  }),
  Object.freeze({
    id: "PROBE_CONSTRUCTOR_PROPERTY_RETURN",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CAPABILITY_STORAGE",
  }),
  Object.freeze({
    id: "PROBE_AUTHORITY_DATABASE_IDENTITY",
    code: "SSC_AUTHORITY_SHAPE",
    detector: "AUTHORITY_SCHEMA",
  }),
  Object.freeze({
    id: "PROBE_AUTHORITY_USER_IDENTITY",
    code: "SSC_AUTHORITY_SHAPE",
    detector: "AUTHORITY_SCHEMA",
  }),
  Object.freeze({
    id: "PROBE_AUTHORITY_CLUSTER_IDENTITY",
    code: "SSC_AUTHORITY_SHAPE",
    detector: "AUTHORITY_SCHEMA",
  }),
  Object.freeze({
    id: "PROBE_AUTHORITY_LIFECYCLE_IDENTITY",
    code: "SSC_AUTHORITY_SHAPE",
    detector: "AUTHORITY_SCHEMA",
  }),
  Object.freeze({
    id: "PROBE_AUTHORITY_MIGRATIONS_IDENTITY",
    code: "SSC_AUTHORITY_SHAPE",
    detector: "AUTHORITY_SCHEMA",
  }),
  Object.freeze({
    id: "PROBE_AUTHORITY_PHASE_IDENTITY",
    code: "SSC_AUTHORITY_SHAPE",
    detector: "AUTHORITY_SCHEMA",
  }),
  Object.freeze({
    id: "PROBE_EFFECTIVE_SQL_REBIND",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CAPABILITY_QUERY",
    obligation: "AP_IDENTITY_SQL",
  }),
  Object.freeze({ id: "MATRIX_OBJECT_OUTPUT", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_OUTPUT" }),
  Object.freeze({ id: "MATRIX_ARRAY_OUTPUT", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_OUTPUT" }),
  Object.freeze({ id: "MATRIX_SET_OUTPUT", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_OUTPUT" }),
  Object.freeze({ id: "MATRIX_MAP_OUTPUT", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_OUTPUT" }),
  Object.freeze({ id: "MATRIX_WEAKMAP_OUTPUT", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_OUTPUT" }),
  Object.freeze({ id: "MATRIX_CLASS_PROPERTY_OUTPUT", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_STORAGE" }),
  Object.freeze({ id: "MATRIX_CLASS_METHOD_OUTPUT", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_STORAGE" }),
  Object.freeze({ id: "MATRIX_OBJECT_METHOD_OUTPUT", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_OUTPUT" }),
  Object.freeze({ id: "MATRIX_CALLBACK_OUTPUT", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_OUTPUT" }),
  Object.freeze({ id: "MATRIX_MAP_CALLBACK_OUTPUT", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_OUTPUT" }),
  Object.freeze({ id: "MATRIX_RETURN_OBJECT", code: "SSC_SECRET_FLOW_DENIED", detector: "PUBLIC_RETURN" }),
  Object.freeze({ id: "MATRIX_RETURN_SET", code: "SSC_SECRET_FLOW_DENIED", detector: "PUBLIC_RETURN" }),
  Object.freeze({ id: "MATRIX_RETURN_MAP", code: "SSC_SECRET_FLOW_DENIED", detector: "PUBLIC_RETURN" }),
  Object.freeze({ id: "MATRIX_RETURN_WEAKMAP", code: "SSC_SECRET_FLOW_DENIED", detector: "PUBLIC_RETURN" }),
  Object.freeze({ id: "MATRIX_RETURN_CLASS", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_STORAGE" }),
  Object.freeze({ id: "MATRIX_RETURN_METHOD", code: "SSC_SECRET_FLOW_DENIED", detector: "PUBLIC_RETURN" }),
  Object.freeze({ id: "MATRIX_RETURN_CALLBACK", code: "SSC_SECRET_FLOW_DENIED", detector: "PUBLIC_RETURN" }),
  Object.freeze({ id: "MATRIX_RETURN_ALIAS", code: "SSC_SECRET_FLOW_DENIED", detector: "PUBLIC_RETURN" }),
  Object.freeze({ id: "MATRIX_LATE_MUTATION_OUTPUT", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_STORAGE" }),
  Object.freeze({ id: "MATRIX_DELETE_HISTORY_OUTPUT", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_OUTPUT" }),
  Object.freeze({ id: "MATRIX_CLEAR_HISTORY_OUTPUT", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_OUTPUT" }),
  Object.freeze({ id: "MATRIX_FREEZE_OUTPUT", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_OUTPUT" }),
  Object.freeze({ id: "MATRIX_COMPUTED_OBJECT_OUTPUT", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_STORAGE" }),
  Object.freeze({ id: "MATRIX_COMPUTED_ARRAY_OUTPUT", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_OUTPUT" }),
  Object.freeze({ id: "MATRIX_RETAINED_CLOSURE_OUTPUT", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_OUTPUT" }),
  Object.freeze({ id: "MATRIX_RETAINED_FUNCTION_OUTPUT", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_OUTPUT" }),
  Object.freeze({ id: "MATRIX_CALLBACK_RETURN_OUTPUT", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_OUTPUT" }),
  Object.freeze({ id: "MATRIX_WEAKMAP_GET_OUTPUT", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_STORAGE" }),
  Object.freeze({ id: "MATRIX_MAP_UNKNOWN_GET_OUTPUT", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_OUTPUT" }),
  Object.freeze({ id: "MATRIX_STRING_TRANSFORM_OUTPUT", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_OUTPUT" }),
  Object.freeze({ id: "MATRIX_JSON_SECRET_OUTPUT", code: "SSC_SECRET_FLOW_DENIED", detector: "CAPABILITY_OUTPUT" }),
  Object.freeze({ id: "MATRIX_UNKNOWN_COMPUTED_OUTPUT", code: "SSC_COMPUTED_ACCESS", detector: "COMPUTED_CAPABILITY" }),
]);

let negativeControlResultCache = null;
let positiveControlResultCache = null;

const Taint = Object.freeze({
  NONE: 0,
  CREDENTIAL: 1,
  SENSITIVE_DIAGNOSTIC: 2,
  MAYBE_SENSITIVE: 4,
});

const REACHABLE_IMPORT_CAPABILITIES = Object.freeze({
  drizzle: "DRIZZLE",
  migrate: "MIGRATE",
  Pool: "POOL_CONSTRUCTOR",
  Client: "CLIENT_CONSTRUCTOR",
  inspectRuntimeDatabaseRoleAuthorityPosture: "UNUSED_EXTERNAL",
});

class StaticFailure extends Error {
  constructor(code, detector, obligation = null, location = null, violations = []) {
    super(code);
    this.name = "StaticFailure";
    this.code = code;
    this.detector = detector;
    this.obligation = obligation ?? OBLIGATION_BY_FAILURE[detector] ?? null;
    this.location = location && Number.isInteger(location.line) && Number.isInteger(location.column)
      ? Object.freeze({ line: location.line, column: location.column })
      : null;
    this.violations = new Set(violations);
    if (this.obligation) this.violations.add(this.obligation);
  }
}

function fail(code, detector, obligation = null, location = null, violations = []) {
  throw new StaticFailure(code, detector, obligation, location, violations);
}

function failureOf(error) {
  if (error instanceof StaticFailure) {
    const violations = [...error.violations].sort();
    return Object.freeze({
      code: error.code,
      detector: error.detector,
      obligation: error.obligation ?? undefined,
      violations: Object.freeze(violations),
      ...(error.location ? { coordinates: error.location } : {}),
    });
  }
  return Object.freeze({
    code: SAFE.internal,
    detector: "ANALYZER_BOUNDARY",
    obligation: "CF_NONCONVERGENCE",
    violations: Object.freeze(["CF_NONCONVERGENCE"]),
  });
}

function keyForDeclaration(declaration) {
  return `${declaration.kind}:${declaration.pos}:${declaration.end}`;
}

function sameTextSet(actual, expected) {
  if (actual.length !== expected.length) return false;
  const remaining = new Set(expected);
  for (const value of actual) {
    if (!remaining.delete(value)) return false;
  }
  return remaining.size === 0;
}

function joinTaint(left, right) {
  return left | right;
}

function hasTaint(value, mask) {
  return Boolean((summarizeRisk(value).taint ?? Taint.NONE) & mask);
}

function summarizeRisk(item, seen = new Set()) {
  if (!item || (typeof item !== "object" && typeof item !== "function")) {
    return { taint: Taint.NONE, caps: new Set() };
  }
  if (seen.has(item)) return { taint: Taint.NONE, caps: new Set() };
  seen.add(item);
  let taint = (item.taint ?? Taint.NONE) | (item.historyTaint ?? Taint.NONE);
  if (item.kind === "input") taint |= Taint.CREDENTIAL;
  const caps = new Set([...(item.caps ?? []), ...(item.historyCaps ?? [])]);
  const add = (child) => {
    const risk = summarizeRisk(child, seen);
    taint |= risk.taint;
    for (const cap of risk.caps) caps.add(cap);
  };
  for (const child of item.props?.values?.() ?? []) add(child);
  for (const child of item.elements ?? []) add(child);
  for (const [key, child] of item.map?.entries?.() ?? []) {
    add(key);
    add(child);
  }
  for (const child of item.methods?.values?.() ?? []) add(child);
  for (const child of item.historyProps?.values?.() ?? []) add(child);
  for (const child of item.refs ?? []) add(child);
  for (const child of closureCaptureValues(item)) add(child);
  add(item.options);
  add(item.classRef);
  add(item.record);
  if (item.bound) add(item.bound);
  return { taint, caps };
}

function closureCaptureValues(item) {
  if (!(item?.closure instanceof Map)) return [];
  if (!(item.captureKeys instanceof Set)) return [...item.closure.values()];
  return [...item.captureKeys].map((key) => item.closure.has(key)
    ? item.closure.get(key)
    : value({ kind: "unknown", taint: Taint.MAYBE_SENSITIVE }));
}

function sameIdentitySet(left, right) {
  const actual = left instanceof Set ? left : new Set(left ?? []);
  const expected = right instanceof Set ? right : new Set(right ?? []);
  return actual.size === expected.size && [...expected].every((item) => actual.has(item));
}

function sameIdentitySequence(left, right) {
  return left.length === right.length && left.every((item, index) => sameIdentitySet(item, right[index]));
}

function rememberRisk(target, source) {
  if (!target || !source) return target;
  const risk = summarizeRisk(source);
  target.taint = (target.taint ?? Taint.NONE) | risk.taint;
  target.historyTaint = (target.historyTaint ?? Taint.NONE) | risk.taint;
  target.caps ??= new Set();
  target.historyCaps ??= new Set();
  for (const cap of risk.caps) {
    target.caps.add(cap);
    target.historyCaps.add(cap);
  }
  target.provenance ??= new Set();
  target.historyProvenance ??= new Set();
  for (const label of provenanceOf(source)) {
    target.provenance.add(label);
    target.historyProvenance.add(label);
  }
  return target;
}

function rememberReference(target, source) {
  if (!target || !source) return target;
  target.refs ??= [];
  if (!target.refs.includes(source)) target.refs.push(source);
  rememberRisk(target, source);
  return target;
}

function assignValueProperty(target, key, source) {
  target.props ??= new Map();
  target.props.set(String(key), source);
  rememberReference(target, source);
  return target;
}

function deleteValueProperty(target, key) {
  target.historyProps ??= new Map();
  if (target.props?.has(String(key))) target.historyProps.set(String(key), target.props.get(String(key)));
  target.props?.delete(String(key));
  return target;
}

function provenanceOf(item) {
  if (item?.provenance instanceof Set) return item.provenance;
  return new Set();
}

function combinedProvenance(items) {
  const result = new Set();
  for (const item of items) {
    for (const label of provenanceOf(item)) result.add(label);
  }
  return result;
}

function combinedCaps(items) {
  const result = new Set();
  for (const item of items) {
    for (const cap of summarizeRisk(item).caps) result.add(cap);
  }
  return result;
}

function combinedTaint(items) {
  return items.reduce((taint, item) => joinTaint(taint, summarizeRisk(item).taint), Taint.NONE);
}

function value({
  kind = "unknown",
  taint = Taint.NONE,
  caps = [],
  props = null,
  fn = null,
  closure = null,
  bound = null,
  label = "",
  directCredential = false,
  elements = null,
  map = null,
  methods = null,
  refs = null,
  constant = undefined,
  literalType = "",
  binding = null,
  provenance = [],
  exact = true,
  captureKeys = null,
} = {}) {
  const directTaint = taint ?? Taint.NONE;
  const directCaps = new Set(caps);
  const directProvenance = new Set(provenance);
  return {
    kind,
    taint: directTaint,
    historyTaint: directTaint,
    caps: directCaps,
    historyCaps: new Set(directCaps),
    props: props instanceof Map ? props : new Map(),
    historyProps: new Map(),
    methods: methods instanceof Map ? methods : new Map(),
    refs: Array.isArray(refs) ? [...refs] : [],
    fn,
    closure,
    captureKeys: captureKeys instanceof Set ? new Set(captureKeys) : captureKeys,
    bound,
    binding,
    label,
    directCredential,
    elements,
    map,
    constant,
    literalType,
    exact,
    provenance: directProvenance,
    historyProvenance: new Set(directProvenance),
  };
}

function unknownValue() {
  return value();
}

function primitiveValue(label = "", options = {}) {
  const constant = Object.prototype.hasOwnProperty.call(options, "constant")
    ? options.constant
    : label;
  return value({
    kind: "primitive",
    label,
    constant,
    literalType: options.literalType ?? "abstract",
    provenance: options.provenance ?? [],
  });
}

function credentialValue(origin) {
  return value({
    kind: "credential",
    taint: Taint.CREDENTIAL,
    directCredential: true,
    label: "input.connectionPassword",
    provenance: origin ? [origin] : [],
  });
}

function booleanValue(boolean) {
  return primitiveValue(String(boolean), { constant: boolean, literalType: "boolean" });
}

function isBooleanValue(item, expected) {
  return item?.kind === "primitive" &&
    item.literalType === "boolean" &&
    item.constant === expected;
}

function isNumberValue(item, expected) {
  return item?.kind === "primitive" &&
    item.literalType === "number" &&
    item.constant === expected;
}

function hasExactProvenance(item, expectedKeys) {
  return item?.exact !== false &&
    sameIdentitySet(
      provenanceOf(item),
      new Set(expectedKeys.map((key) => key)),
    );
}

function capabilityValue(cap, options = {}) {
  return value({ ...options, kind: "capability", caps: [cap] });
}

function mergeValues(left, right) {
  if (!left && !right) return null;
  if (!left) return right;
  if (!right) return left;
  if (left === right) return left;
  if (left.kind === "unknown") {
    rememberRisk(right, left);
    return right;
  }
  if (right.kind === "unknown") {
    rememberRisk(left, right);
    return left;
  }
  const merged = value({
    kind: left.kind === right.kind ? left.kind : "unknown",
    taint: joinTaint(summarizeRisk(left).taint, summarizeRisk(right).taint),
    caps: [...summarizeRisk(left).caps, ...summarizeRisk(right).caps],
    bound: left.bound === right.bound ? left.bound : null,
    binding: left.binding === right.binding ? left.binding : null,
    label: left.label === right.label ? left.label : "",
    directCredential: left.directCredential && right.directCredential,
    literalType: left.literalType === right.literalType ? left.literalType : "",
    provenance: new Set([...provenanceOf(left), ...provenanceOf(right)]),
    constant: left.constant === right.constant ? left.constant : undefined,
    exact: left.exact !== false && right.exact !== false,
    captureKeys: left.captureKeys instanceof Set && right.captureKeys instanceof Set
      ? new Set([...left.captureKeys, ...right.captureKeys])
      : null,
  });
  for (const [key, property] of left.props) {
    merged.props.set(key, right.props.has(key) ? mergeValues(property, right.props.get(key)) : property);
  }
  for (const [key, property] of right.props) {
    if (!merged.props.has(key)) merged.props.set(key, property);
  }
  for (const [key, property] of left.historyProps ?? []) merged.historyProps.set(key, property);
  for (const [key, property] of right.historyProps ?? []) merged.historyProps.set(key, property);
  for (const child of [...(left.refs ?? []), ...(right.refs ?? [])]) rememberReference(merged, child);
  for (const [key, method] of left.methods ?? []) merged.methods.set(key, method);
  for (const [key, method] of right.methods ?? []) {
    merged.methods.set(key, merged.methods.has(key) ? mergeValues(merged.methods.get(key), method) : method);
  }
  if (left.kind === "array" && right.kind === "array" &&
      left.elements?.length === right.elements?.length) {
    merged.elements = left.elements.map((item, index) => mergeValues(item, right.elements[index]));
  }
  if (left.map instanceof Map || right.map instanceof Map) {
    merged.map = new Map([...(left.map ?? []), ...(right.map ?? [])]);
  }
  return merged;
}

function moduleNameFromImport(declaration) {
  return declaration.moduleSpecifier?.text ?? "";
}

function isFunctionLike(node) {
  return ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node);
}

class ClosureAnalyzer {
  constructor({ source, sourceFile, program, checker }) {
    this.source = source;
    this.sourceFile = sourceFile;
    this.program = program;
    this.checker = checker;
    this.topValues = new Map();
    this.topValuesByName = new Map();
    this.bindingNames = new Map();
    this.topInitialising = new Set();
    this.functionActive = new Set();
    this.weakMapRecords = new Map();
    this.poolConstructs = 0;
    this.poolOptions = null;
    this.authorityToken = null;
    this.authorityRecord = null;
    this.authoritySetCount = 0;
    this.declassificationCount = 0;
    this.identityQueryCount = 0;
    this.identityQueryPool = null;
    this.identityQueryArguments = null;
    this.authoritySecondIdentityChecked = false;
    this.operationInvocations = 0;
    this.operationInvocationNodes = [];
    this.sourceProtocolChecked = false;
    this.pendingSecretStorage = false;
    this.pendingPasswordOperation = false;
    this.childInventory = [];
    this.importAliases = new Map();
    this.rootFunction = null;
    this.graphNodes = new Map();
    this.graphEdges = new Set();
    this.graphNodeCounter = 0;
    this.dormantBodies = [];
    this.originIdentities = new Map();
    this.captureKeyCache = new WeakMap();
    this.identitySqlBinding = this.originIdentity("binding.identitySql");
  }

  originIdentity(key) {
    let identity = this.originIdentities.get(key);
    if (!identity) {
      identity = Symbol(key);
      this.originIdentities.set(key, identity);
    }
    return identity;
  }

  captureKeysFor(node) {
    const cached = this.captureKeyCache.get(node);
    if (cached) return new Set(cached);
    const keys = new Set();
    const isWithinNode = (candidate) => {
      for (let current = candidate; current; current = current.parent) {
        if (current === node) return true;
      }
      return false;
    };
    const declarationKey = (declaration) => {
      if (ts.isImportSpecifier(declaration) || ts.isImportClause(declaration) ||
          ts.isNamespaceImport(declaration)) return null;
      if (!declaration.name || !ts.isIdentifier(declaration.name)) return null;
      if (ts.isVariableDeclaration(declaration) || ts.isParameter(declaration) ||
          ts.isFunctionDeclaration(declaration) || ts.isClassDeclaration(declaration) ||
          ts.isBindingElement(declaration)) {
        return keyForDeclaration(declaration.name);
      }
      return null;
    };
    const visit = (current) => {
      if (ts.isIdentifier(current)) {
        const symbol = this.checker.getSymbolAtLocation(current);
        for (const declaration of symbol?.declarations ?? []) {
          if (declaration.getSourceFile() !== this.sourceFile || isWithinNode(declaration, node)) continue;
          const key = declarationKey(declaration);
          if (key) keys.add(key);
        }
      }
      ts.forEachChild(current, visit);
    };
    visit(node);
    this.captureKeyCache.set(node, keys);
    return new Set(keys);
  }

  canonicalDefaultOrigin(node) {
    if (!ts.isStringLiteral(node) || !ts.isBinaryExpression(node.parent) ||
        node.parent.operatorToken.kind !== ts.SyntaxKind.QuestionQuestionToken ||
        node.parent.right !== node || !ts.isVariableDeclaration(node.parent.parent) ||
        !ts.isIdentifier(node.parent.parent.name) ||
        node.parent.parent.initializer !== node.parent) {
      return null;
    }
    const variableName = node.parent.parent.name.text;
    if (variableName === "expectedUser" && node.text === "cloud_admin") {
      return this.originIdentity("default.expectedUser.cloud_admin");
    }
    if (variableName === "phase" && node.text === "initialization") {
      return this.originIdentity("default.phase.initialization");
    }
    return null;
  }

  literalValue(node) {
    const result = primitiveValue(node.text, { literalType: "string" });
    const defaultOrigin = this.canonicalDefaultOrigin(node);
    if (defaultOrigin) result.provenance.add(defaultOrigin);
    return result;
  }

  analyze() {
    this.validateImportsAndIndex();
    this.inventoryExecutableChildren();
    this.scanModuleInitializers();
    this.rootFunction = this.findRootFunction();
    this.validateSourceProtocol();
    const input = value({ kind: "input" });
    const operation = value({ kind: "opaque-function", caps: ["OPAQUE_OPERATION"] });
    const rootResult = this.analyzeFunction(this.rootFunction, [input, operation], null);
    const terminalFailures = [];
    const collectTerminalFailure = (action) => {
      try {
        action();
      } catch (error) {
        if (!(error instanceof StaticFailure)) throw error;
        terminalFailures.push(error);
      }
    };
    collectTerminalFailure(() => this.inspectEscapedValue(rootResult, new Set()));
    const rootRisk = summarizeRisk(rootResult);
    if (rootResult.kind === "unknown" ||
        rootResult.kind === "input" ||
        rootResult.kind === "authority-token" ||
        (rootRisk.taint & (Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC | Taint.MAYBE_SENSITIVE)) ||
        rootRisk.caps.size > 0) {
      terminalFailures.push(new StaticFailure(SAFE.flow, "PUBLIC_RETURN"));
    }
    if (this.poolConstructs !== 1 || this.declassificationCount > 1) {
      terminalFailures.push(new StaticFailure(SAFE.flow, "CAPABILITY_POOL"));
    }
    if (!this.authorityRecord || this.authoritySetCount !== 1) {
      terminalFailures.push(new StaticFailure(SAFE.authority, "AUTHORITY_SCHEMA"));
    }
    if (this.operationInvocations !== 1) {
      terminalFailures.push(new StaticFailure(SAFE.flow, "CAPABILITY_CALLBACK", "AP_OPERATION"));
    }
    if (this.pendingSecretStorage) {
      terminalFailures.push(new StaticFailure(SAFE.flow, "CAPABILITY_STORAGE", "CF_PUBLIC_ESCAPE"));
    }
    if (this.pendingPasswordOperation) {
      terminalFailures.push(new StaticFailure(SAFE.flow, "CAPABILITY_PASSWORD", "AP_TOKEN"));
    }
    if (terminalFailures.length > 0) {
      const [primary] = terminalFailures;
      const violations = [...new Set(terminalFailures.flatMap((failure) => [...failure.violations]))];
      throw new StaticFailure(
        primary.code,
        primary.detector,
        primary.obligation,
        primary.location,
        violations,
      );
    }
    return Object.freeze({
      id: SAFE.baseline,
      ok: true,
      poolConstructs: this.poolConstructs,
      declassifications: this.declassificationCount,
      authoritySets: this.authoritySetCount,
      graphNodes: this.graphNodes.size,
      graphEdges: this.graphEdges.size,
      graph: Object.freeze({
        nodes: Object.freeze([...this.graphNodes.values()].map((node) => Object.freeze({ ...node }))),
        edges: Object.freeze([...this.graphEdges]),
      }),
      dormantBodies: this.dormantBodies.length,
      summariesConverged: this.sourceProtocolChecked,
      totalTraversal: this.childInventory.every((item) => item.disposition),
      provenanceComplete: this.sourceProtocolChecked,
      violations: Object.freeze([]),
      childInventory: Object.freeze(this.childInventory.map((item) => Object.freeze({ ...item }))),
    });
  }

  inventoryExecutableChildren() {
    const dispositionFor = (node) => {
      if (ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node) ||
          ts.isMethodDeclaration(node) || ts.isConstructorDeclaration(node) ||
          ts.isArrowFunction(node) || ts.isFunctionExpression(node)) {
        return "SCHEDULED_WITH_TRIGGER";
      }
      if (ts.isIdentifier(node) && (ts.isVariableDeclaration(node.parent?.parent) ||
          ts.isParameter(node.parent))) {
        return "BINDING_METADATA";
      }
      if (ts.isStringLiteral(node) || ts.isNumericLiteral(node) ||
          ts.isRegularExpressionLiteral(node) || ts.isIdentifier(node)) {
        return "STRUCTURAL_TOKEN";
      }
      return "EVALUATED";
    };
    const visit = (parent) => {
      ts.forEachChild(parent, (child) => {
        this.childInventory.push({
          parent: [parent.kind, parent.pos, parent.end].join(":"),
          child: [child.kind, child.pos, child.end].join(":"),
          kind: ts.SyntaxKind[child.kind] ?? "Unknown",
          disposition: dispositionFor(child),
        });
        visit(child);
      });
    };
    visit(this.sourceFile);
  }

  functionDeclaration(name) {
    return this.sourceFile.statements.find(
      (statement) => ts.isFunctionDeclaration(statement) && statement.name?.text === name,
    );
  }

  validateSourceProtocol() {
    const normalized = this.source.replace(/\s+/gu, " ").trim();
    const rootText = this.rootFunction.getText(this.sourceFile);
    const scoped = this.functionDeclaration("runScopedFixtureMigration")?.getText(this.sourceFile) ?? "";
    const identity = this.functionDeclaration("readMigrationAuthorityIdentity")?.getText(this.sourceFile) ?? "";
    const identitySqlDeclaration = this.sourceFile.statements
      .filter(ts.isVariableStatement)
      .flatMap((statement) => statement.declarationList.declarations)
      .find((declaration) => ts.isIdentifier(declaration.name) && declaration.name.text === "identitySql");
    const identitySqlInitializer = identitySqlDeclaration?.initializer;
    const normalizedIdentitySql = identitySqlInitializer && ts.isNoSubstitutionTemplateLiteral(identitySqlInitializer)
      ? identitySqlInitializer.text.replace(/\s+/gu, " ").trim().toLowerCase()
      : "";
    const expectedIdentitySql = "select current_database() = $1 as database_matches, " +
      "session_user = $2 as user_matches, " +
      "current_setting('server_version_num')::integer / 10000 = 17 as postgres17, " +
      "not pg_is_in_recovery() as non_recovery, " +
      "(select system_identifier::text from pg_control_system()) as catalog_fingerprint, " +
      "(select oid::text from pg_database where datname = current_database()) as lifecycle_fingerprint";
    if (!rootText || !scoped || !identity) fail(SAFE.ast, "ROOT_EXPORT", "TV_CHILD_UNDISPOSED");
    if ((rootText.match(/\bnew\s+Pool\s*\(/gu) ?? []).length !== 1) {
      fail(SAFE.flow, "CAPABILITY_POOL", "AP_POOL_OPTIONS");
    }
    if (!rootText.includes("pool = new Pool(poolOptions)") ||
        !rootText.includes("host: target.hostname") ||
        !rootText.includes("port: Number(target.port)") ||
        !rootText.includes("user: target.expectedUser") ||
        !rootText.includes("database: target.expectedDatabase") ||
        !rootText.includes("max: 1")) {
      fail(SAFE.flow, "CAPABILITY_POOL", "AP_POOL_OPTIONS");
    }
    if ((rootText.match(/\bpool\.end\s*\(/gu) ?? []).length !== 1) {
      fail(SAFE.flow, "CAPABILITY_CLEANUP", "AP_CLEANUP");
    }
    if (rootText.includes("pool.connect(")) {
      fail(SAFE.flow, "CAPABILITY_CONNECT", "AP_CLIENT_PROTOCOL");
    }
    if (!rootText.includes("authority = Object.freeze({})")) {
      fail(SAFE.authority, "AUTHORITY_SCHEMA", "AP_TOKEN");
    }
    if (normalizedIdentitySql !== expectedIdentitySql ||
        !identity.includes("pool.query(identitySql,")) {
      fail(SAFE.flow, "CAPABILITY_QUERY", "AP_IDENTITY_SQL");
    }
    if (!identity.includes("pool.query(identitySql, [target.expectedDatabase, target.expectedUser])")) {
      fail(SAFE.flow, "CAPABILITY_QUERY", "AP_IDENTITY_ARGUMENTS");
    }
    if (!scoped.includes("value.brand !== migrationAuthorityBrand") ||
        !scoped.includes("value.authority !== authority") ||
        !scoped.includes("!value.valid") ||
        !scoped.includes("value.pool !== pool") ||
        !scoped.includes("value.migrationsFolder !== migrationsFolder") ||
        !scoped.includes("value.database !== target.expectedDatabase") ||
        !scoped.includes("value.user !== target.expectedUser")) {
      fail(SAFE.authority, "AUTHORITY_SCHEMA", "AP_AUTHORITY_GUARD");
    }
    if (!scoped.includes("identity.catalogFingerprint !== value.clusterFingerprint") ||
        !scoped.includes("identity.lifecycleFingerprint !== value.lifecycleFingerprint")) {
      fail(SAFE.authority, "AUTHORITY_SCHEMA", "AP_FINGERPRINT_COMPARE");
    }
    if (!scoped.includes("await migrate(drizzle(pool), { migrationsFolder });")) {
      fail(SAFE.flow, "CAPABILITY_MIGRATE", "AP_MIGRATION");
    }
    if (!rootText.includes("if (value) value.valid = false")) {
      fail(SAFE.authority, "AUTHORITY_SCHEMA", "AP_REVOCATION");
    }
    this.sourceProtocolChecked = true;
  }

  graphNode(valueToTrack, kind = valueToTrack?.kind ?? "unknown") {
    if (!valueToTrack || (typeof valueToTrack !== "object" && typeof valueToTrack !== "function")) return null;
    if (valueToTrack.__sscGraphNode) return valueToTrack.__sscGraphNode;
    const id = `n${++this.graphNodeCounter}`;
    try {
      Object.defineProperty(valueToTrack, "__sscGraphNode", {
        configurable: true,
        enumerable: false,
        value: id,
      });
    } catch {
      // Abstract values are analyzer-owned; failure to annotate is not a permission.
    }
    this.graphNodes.set(id, { id, kind });
    return id;
  }

  graphEdge(from, to, kind) {
    const left = this.graphNode(from);
    const right = this.graphNode(to);
    if (left && right) this.graphEdges.add(`${left}|${kind}|${right}`);
  }

  inspectEscapedValue(item, seen) {
    if (!item || (typeof item !== "object" && typeof item !== "function") || seen.has(item)) return;
    seen.add(item);
    if (item.kind === "input" || item.kind === "authority-token") {
      fail(SAFE.flow, "PUBLIC_RETURN", "CF_PUBLIC_ESCAPE");
    }
    if (item.kind === "class" && item.fn &&
        (ts.isClassDeclaration(item.fn) || ts.isClassExpression(item.fn))) {
      const constructor = item.fn.members.find((member) => ts.isConstructorDeclaration(member));
      const args = (constructor?.parameters ?? []).map(() => value({ kind: "escaped-argument" }));
      const instance = this.analyzeClassConstructor(item.fn, args, item.closure, item);
      this.inspectEscapedValue(instance, seen);
      for (const method of item.instanceMethods?.values?.() ?? []) {
        this.inspectEscapedValue(method, seen);
      }
    }
    if (item.closure instanceof Map && item.captureKeys instanceof Set &&
        [...item.captureKeys].some((key) => !item.closure.has(key))) {
      fail(SAFE.flow, "PUBLIC_RETURN", "CF_PUBLIC_ESCAPE");
    }
    for (const captured of closureCaptureValues(item)) {
      if (captured?.kind === "input") fail(SAFE.flow, "PUBLIC_RETURN", "CF_PUBLIC_ESCAPE");
      this.inspectEscapedValue(captured, seen);
    }
    if (item.fn && isFunctionLike(item.fn) && !this.functionActive.has(`${item.fn.pos}:${item.fn.end}`)) {
      const args = item.fn.parameters.map(() => value({ kind: "escaped-argument" }));
      const result = this.analyzeFunction(item.fn, args, item.closure, item.bound);
      const risk = summarizeRisk(result);
      if (result?.kind === "unknown" || risk.taint !== Taint.NONE || risk.caps.size > 0) {
        fail(SAFE.flow, "PUBLIC_RETURN");
      }
      this.inspectEscapedValue(result, seen);
    }
    for (const child of item.props?.values?.() ?? []) this.inspectEscapedValue(child, seen);
    for (const child of item.elements ?? []) this.inspectEscapedValue(child, seen);
    for (const child of item.map?.values?.() ?? []) this.inspectEscapedValue(child, seen);
    for (const child of item.methods?.values?.() ?? []) this.inspectEscapedValue(child, seen);
    for (const child of item.classRef?.instanceMethods?.values?.() ?? []) this.inspectEscapedValue(child, seen);
    for (const child of item.refs ?? []) this.inspectEscapedValue(child, seen);
    if (item.classRef) this.inspectEscapedValue(item.classRef, seen);
    if (item.bound) this.inspectEscapedValue(item.bound, seen);
  }

  validateImportsAndIndex() {
    for (const statement of this.sourceFile.statements) {
      if (!ts.isImportDeclaration(statement)) continue;
      const moduleName = moduleNameFromImport(statement);
      const allowed = IMPORT_TABLE[moduleName];
      if (!allowed || !statement.importClause || statement.importClause.name ||
          statement.importClause.isTypeOnly ||
          !statement.importClause.namedBindings ||
          !ts.isNamedImports(statement.importClause.namedBindings)) {
        fail(SAFE.imports, "IMPORT_TABLE");
      }
      const names = [];
      for (const specifier of statement.importClause.namedBindings.elements) {
        if (specifier.isTypeOnly || specifier.propertyName && !ts.isIdentifier(specifier.propertyName) ||
            !ts.isIdentifier(specifier.name)) {
          fail(SAFE.imports, "IMPORT_TABLE");
        }
        const imported = specifier.propertyName?.text ?? specifier.name.text;
        names.push(imported);
        this.importAliases.set(keyForDeclaration(specifier.name), {
          moduleName,
          imported,
        });
      }
      if (!sameTextSet(names, allowed)) {
        fail(SAFE.imports, "IMPORT_TABLE");
      }
    }
  }

  scanModuleInitializers() {
    const moduleEnv = new Map();
    for (const statement of this.sourceFile.statements) {
      if (ts.isFunctionDeclaration(statement) && statement.name?.text !== ROOT_EXPORT) {
        this.dormantBodies.push(keyForDeclaration(statement.name));
      }
      if (ts.isClassDeclaration(statement)) {
        for (const member of statement.members) {
          if (ts.isMethodDeclaration(member) || ts.isConstructorDeclaration(member)) {
            this.dormantBodies.push(keyForDeclaration(member));
          }
        }
      }
    }
    for (const statement of this.sourceFile.statements) {
      if (ts.isFunctionDeclaration(statement) && statement.name) {
        const fn = value({ kind: "function", fn: statement, closure: moduleEnv, captureKeys: this.captureKeysFor(statement) });
        const key = keyForDeclaration(statement.name);
        moduleEnv.set(key, fn);
        this.topValues.set(key, fn);
        this.topValuesByName.set(statement.name.text, fn);
        this.bindingNames.set(key, statement.name.text);
      } else if (ts.isClassDeclaration(statement) && statement.name) {
        const cls = value({ kind: "class", fn: statement, closure: moduleEnv, captureKeys: this.captureKeysFor(statement) });
        const key = keyForDeclaration(statement.name);
        moduleEnv.set(key, cls);
        this.topValues.set(key, cls);
        this.topValuesByName.set(statement.name.text, cls);
        this.bindingNames.set(key, statement.name.text);
      }
    }
    for (const statement of this.sourceFile.statements) {
      if (ts.isImportDeclaration(statement)) {
        continue;
      }
      if (ts.isVariableStatement(statement)) {
        for (const declaration of statement.declarationList.declarations) {
          if (!ts.isIdentifier(declaration.name)) fail(SAFE.ast, "SYNTAX_POLICY");
          const key = keyForDeclaration(declaration.name);
          if (declaration.initializer) {
            const initialized = this.evalExpression(declaration.initializer, moduleEnv, {});
            if (declaration.name.text === "identitySql") {
              initialized.label = "identitySql";
              initialized.binding = this.identitySqlBinding;
            }
            this.topValues.set(key, initialized);
            this.topValuesByName.set(declaration.name.text, initialized);
            if (declaration.name.text === "migrationAuthorityValues") initialized.role = "authority-store";
            moduleEnv.set(key, initialized);
            this.bindingNames.set(key, declaration.name.text);
          } else {
            const empty = unknownValue();
          this.topValues.set(key, empty);
          this.topValuesByName.set(declaration.name.text, empty);
          if (declaration.name.text === "migrationAuthorityValues") empty.role = "authority-store";
            moduleEnv.set(key, empty);
            this.bindingNames.set(key, declaration.name.text);
          }
        }
      } else if (ts.isClassDeclaration(statement)) {
        this.scanClassInitialization(statement, moduleEnv);
      } else if (ts.isFunctionDeclaration(statement)) {
        if (!statement.name) fail(SAFE.ast, "TOP_LEVEL_SYNTAX");
        this.bindingNames.set(keyForDeclaration(statement.name), statement.name.text);
      } else {
        fail(SAFE.ast, "TOP_LEVEL_SYNTAX");
      }
    }
  }

  scanClassInitialization(node, env) {
    if (node.heritageClauses) {
      for (const heritage of node.heritageClauses) {
        for (const type of heritage.types) {
          this.evalExpression(type.expression, env, {});
        }
      }
    }
    for (const member of node.members) {
      if (member.name?.kind === ts.SyntaxKind.ComputedPropertyName) {
        fail(SAFE.computed, "COMPUTED_CAPABILITY");
      }
      if (ts.isPropertyDeclaration(member) && member.initializer) {
        this.evalExpression(member.initializer, env, {});
      }
      if (ts.isClassStaticBlockDeclaration(member)) {
        this.analyzeStatements(member.body.statements, new Map(env), {});
      }
    }
  }

  findRootFunction() {
    const roots = this.sourceFile.statements.filter(
      (statement) => ts.isFunctionDeclaration(statement) &&
        statement.name?.text === ROOT_EXPORT,
    );
    if (roots.length !== 1) fail(SAFE.ast, "ROOT_EXPORT");
    const root = roots[0];
    if (!root.body || !root.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)) {
      fail(SAFE.ast, "ROOT_EXPORT");
    }
    return root;
  }

  topValue(name) {
    return this.topValuesByName.get(name) ?? unknownValue();
  }

  resolveDeclaration(identifier) {
    const symbol = this.checker.getSymbolAtLocation(identifier);
    if (!symbol) return null;
    if (symbol.flags & ts.SymbolFlags.Alias) {
      let aliased;
      try {
        aliased = this.checker.getAliasedSymbol(symbol);
      } catch {
        fail(SAFE.unresolved, "CALL_RESOLUTION");
      }
      return { kind: "import", symbol, aliased };
    }
    const declarations = (symbol.declarations ?? []).filter(
      (declaration) => declaration.getSourceFile() === this.sourceFile,
    );
    if (declarations.length === 0) {
      return { kind: "global", name: identifier.text };
    }
    if (declarations.length !== 1) {
      fail(SAFE.unresolved, "CALL_RESOLUTION");
    }
    return { kind: "local", declaration: declarations[0], symbol };
  }

  lookup(identifier, env) {
    const resolved = this.resolveDeclaration(identifier);
    if (resolved?.kind === "local") {
      const declaration = resolved.declaration;
      const key = keyForDeclaration(
        ts.isIdentifier(declaration.name) ? declaration.name : declaration,
      );
      if (env.has(key)) return env.get(key);
      if (ts.isShorthandPropertyAssignment(declaration)) {
        const matches = [...env.entries()].filter(([candidate]) => this.bindingNames.get(candidate) === identifier.text);
        if (matches.length === 1) return matches[0][1];
      }
      if (this.topValues.has(key)) return this.topValues.get(key);
      if (ts.isVariableDeclaration(declaration)) {
        if (this.topInitialising.has(key)) return unknownValue();
        this.topInitialising.add(key);
        const initialized = declaration.initializer
          ? this.evalExpression(declaration.initializer, env, {})
          : unknownValue();
        this.topInitialising.delete(key);
        this.topValues.set(key, initialized);
        return initialized;
      }
      if (ts.isFunctionDeclaration(declaration) && declaration.body) {
        return value({ kind: "function", fn: declaration, closure: env, captureKeys: this.captureKeysFor(declaration) });
      }
      if (ts.isClassDeclaration(declaration)) {
        return value({ kind: "class", fn: declaration, closure: env, captureKeys: this.captureKeysFor(declaration) });
      }
      return unknownValue();
    }
    if (resolved?.kind === "import") {
      const declaration = resolved.symbol.declarations?.[0];
      const imported = declaration && ts.isImportSpecifier(declaration)
        ? declaration.propertyName?.text ?? declaration.name.text
        : "";
      const moduleName = declaration?.parent?.parent?.parent &&
        ts.isImportDeclaration(declaration.parent.parent.parent)
        ? moduleNameFromImport(declaration.parent.parent.parent)
        : "";
      return value({
        kind: "import",
        caps: [REACHABLE_IMPORT_CAPABILITIES[imported] ?? "UNUSED_EXTERNAL"],
        label: `${moduleName}:${imported}`,
      });
    }
    return this.globalValue(identifier.text);
  }

  globalValue(name) {
    const globals = {
      Object: value({ kind: "global", caps: ["GLOBAL_OBJECT"] }),
      Array: value({ kind: "global", caps: ["GLOBAL_ARRAY"] }),
      Set: value({ kind: "global", caps: ["SET_CONSTRUCTOR"] }),
      Map: value({ kind: "global", caps: ["MAP_CONSTRUCTOR"] }),
      WeakMap: value({ kind: "global", caps: ["WEAKMAP_CONSTRUCTOR"] }),
      WeakSet: value({ kind: "global", caps: ["WEAKSET_CONSTRUCTOR"] }),
      Symbol: value({ kind: "global", caps: ["SYMBOL_CONSTRUCTOR"] }),
      URL: value({ kind: "global", caps: ["URL_CONSTRUCTOR"] }),
      Error: value({ kind: "global", caps: ["ERROR_CONSTRUCTOR"] }),
      Number: value({ kind: "global", caps: ["NUMBER_CONSTRUCTOR"] }),
      String: value({ kind: "global", caps: ["STRING_CONSTRUCTOR"] }),
      RegExp: value({ kind: "global", caps: ["REGEXP_CONSTRUCTOR"] }),
      decodeURIComponent: value({ kind: "global", caps: ["DECODE_URI"] }),
      console: value({ kind: "global", caps: ["CONSOLE"] }),
      process: value({ kind: "global", caps: ["PROCESS"] }),
      globalThis: value({ kind: "global", caps: ["GLOBAL_THIS"] }),
      JSON: value({ kind: "global", caps: ["JSON"] }),
      Promise: value({ kind: "global", caps: ["PROMISE"] }),
      undefined: primitiveValue("undefined"),
      NaN: primitiveValue("NaN"),
      Infinity: primitiveValue("Infinity"),
    };
    return globals[name] ?? unknownValue();
  }

  analyzeFunction(node, args, closure, thisValue = null) {
    const signature = `${node.pos}:${node.end}`;
    if (this.functionActive.has(signature)) fail(SAFE.flow, "FIXED_POINT_RECURSION");
    this.functionActive.add(signature);
    const previousThis = this.currentThis;
    this.currentThis = thisValue ?? previousThis;
    try {
      const env = new Map(closure ?? this.topValues);
      const captureNode = value({ kind: "callable" });
      const captureKeys = this.captureKeysFor(node);
      for (const key of captureKeys) {
        if (env.has(key)) this.graphEdge(captureNode, env.get(key), "CAPTURES");
      }
      for (const [index, parameter] of node.parameters.entries()) {
        this.bindParameter(parameter, args[index], env);
      }
      if (!node.body) fail(SAFE.ast, "SYNTAX_POLICY");
      const result = ts.isBlock(node.body)
        ? this.analyzeStatements(node.body.statements, env, {})
        : { env, returnValue: this.evalExpression(node.body, env, {}) };
      this.propagateClosure(closure, result.env ?? env, captureKeys);
      this.graphNode(result.returnValue, "return");
      return result.returnValue ?? primitiveValue("undefined");
    } finally {
      this.currentThis = previousThis;
      this.functionActive.delete(signature);
    }
  }

  bindParameter(parameter, argument, env) {
    if (parameter.dotDotDotToken) fail(SAFE.ast, "SYNTAX_POLICY");
    let source = argument;
    const argumentIsUndefined = !argument ||
      (argument.kind === "primitive" && argument.label === "undefined");
    if (argumentIsUndefined && parameter.initializer) {
      source = this.evalExpression(parameter.initializer, env, {});
    }
    source ??= unknownValue();
    if (ts.isIdentifier(parameter.name)) {
      if (parameter.initializer && argument) {
        // The initializer is a conditional value; the supplied argument is the precise branch.
      }
      env.set(keyForDeclaration(parameter.name), source);
      this.bindingNames.set(keyForDeclaration(parameter.name), parameter.name.text);
      return;
    }
    if (ts.isObjectBindingPattern(parameter.name)) {
      for (const element of parameter.name.elements) {
        if (!ts.isBindingElement(element) || element.dotDotDotToken || !ts.isIdentifier(element.name)) {
          fail(SAFE.ast, "SYNTAX_POLICY");
        }
        const propertyName = element.propertyName && ts.isIdentifier(element.propertyName)
          ? element.propertyName.text
          : element.name.text;
        let item = this.getProperty(source, propertyName, false);
        if (item.kind === "unknown" && element.initializer) item = this.evalExpression(element.initializer, env, {});
        env.set(keyForDeclaration(element.name), item);
        this.bindingNames.set(keyForDeclaration(element.name), element.name.text);
      }
      return;
    }
    if (ts.isArrayBindingPattern(parameter.name)) {
      for (const [index, element] of parameter.name.elements.entries()) {
        if (!element || ts.isOmittedExpression(element) || !ts.isBindingElement(element) ||
            element.dotDotDotToken || !ts.isIdentifier(element.name)) fail(SAFE.ast, "SYNTAX_POLICY");
        const item = source.elements?.[index] ?? (element.initializer
          ? this.evalExpression(element.initializer, env, {})
          : unknownValue());
        env.set(keyForDeclaration(element.name), item);
        this.bindingNames.set(keyForDeclaration(element.name), element.name.text);
      }
      return;
    }
    fail(SAFE.ast, "SYNTAX_POLICY");
  }

  propagateClosure(closure, env, captureKeys = null) {
    if (!(closure instanceof Map)) return;
    const keys = new Set([...closure.keys(), ...(captureKeys ?? [])]);
    for (const key of keys) {
      if (env.has(key)) closure.set(key, mergeValues(closure.get(key), env.get(key)));
    }
  }

  analyzeClassConstructor(node, args, closure, knownClass = null) {
    const instance = value({ kind: "instance" });
    const classRef = knownClass ?? this.evalClass(node, closure ?? this.topValues);
    instance.classRef = classRef;
    rememberReference(instance, classRef);
    const constructor = node.members.find((member) => ts.isConstructorDeclaration(member));
    const captureKeys = this.captureKeysFor(node);
    const env = new Map(closure ?? this.topValues);
    for (const [index, parameter] of (constructor?.parameters ?? []).entries()) {
      this.bindParameter(parameter, args[index], env);
    }
    const previousThis = this.currentThis;
    this.currentThis = instance;
    try {
      for (const member of node.members) {
        if (!ts.isPropertyDeclaration(member) || !member.initializer) continue;
        if (!member.name || member.name.kind === ts.SyntaxKind.ComputedPropertyName || !ts.isIdentifier(member.name)) {
          fail(SAFE.ast, "SYNTAX_POLICY");
        }
        const initialized = this.evalExpression(member.initializer, env, {});
        if (hasTaint(initialized, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC)) {
          fail(SAFE.flow, "CAPABILITY_STORAGE", "CF_PUBLIC_ESCAPE");
        }
        assignValueProperty(instance, member.name.text, initialized);
      }
      if (!constructor) return instance;
      if (!constructor.body) fail(SAFE.ast, "SYNTAX_POLICY");
      const result = this.analyzeStatements(constructor.body.statements, env, {});
      this.propagateClosure(closure, result.env ?? env, captureKeys);
      if (result.returnValue && result.returnValue.label !== "undefined") return result.returnValue;
      return instance;
    } finally {
      this.currentThis = previousThis;
    }
  }

  classConstructorHasRelevantInput(callee, args) {
    return args.some((item) => item?.kind === "input" ||
      hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC | Taint.MAYBE_SENSITIVE) ||
      provenanceOf(item).size > 0);
  }

  analyzeStatements(statements, env, context) {
    let returnValue = null;
    let current = env;
    for (const statement of statements) {
      const result = this.analyzeStatement(statement, current, context);
      current = result.env;
      returnValue = mergeValues(returnValue, result.returnValue);
    }
    return { env: current, returnValue };
  }

  analyzeStatement(node, env, context) {
    if (ts.isBlock(node)) return this.analyzeStatements(node.statements, env, context);
    if (ts.isEmptyStatement(node) || ts.isDebuggerStatement(node)) {
      return { env, returnValue: null };
    }
    if (ts.isVariableStatement(node)) {
      for (const declaration of node.declarationList.declarations) {
        if (!ts.isIdentifier(declaration.name)) fail(SAFE.ast, "SYNTAX_POLICY");
        const initialized = declaration.initializer
          ? this.evalExpression(declaration.initializer, env, context)
          : unknownValue();
        if (initialized.caps.has("OUTPUT") || initialized.caps.has("CRYPTO")) initialized.aliasProvenance = true;
        env.set(keyForDeclaration(declaration.name), initialized);
        this.bindingNames.set(keyForDeclaration(declaration.name), declaration.name.text);
      }
      return { env, returnValue: null };
    }
    if (ts.isExpressionStatement(node)) {
      this.evalExpression(node.expression, env, context);
      return { env, returnValue: null };
    }
    if (ts.isFunctionDeclaration(node)) {
      if (node.name) {
        const fn = value({ kind: "function", fn: node, closure: env, captureKeys: this.captureKeysFor(node) });
        env.set(keyForDeclaration(node.name), fn);
        this.bindingNames.set(keyForDeclaration(node.name), node.name.text);
        this.graphNode(fn, "function");
      }
      return { env, returnValue: null };
    }
    if (ts.isReturnStatement(node)) {
      return {
        env,
        returnValue: node.expression
          ? this.evalExpression(node.expression, env, context)
          : primitiveValue("undefined"),
      };
    }
    if (ts.isThrowStatement(node)) {
      const thrown = this.evalExpression(node.expression, env, context);
      if (hasTaint(thrown, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC)) {
        if (!context.allowCatchRethrow || !thrown.caps.has("CATCH_ERROR")) {
          const point = this.sourceFile.getLineAndCharacterOfPosition(node.getStart(this.sourceFile));
          const failure = new StaticFailure("SSC_PUBLIC_SURFACE", "PUBLIC_CAUSE", "CF_PUBLIC_THROW", {
            line: point.line + 1,
            column: point.character + 1,
          });
          throw failure;
        }
      }
      return { env, returnValue: null };
    }
    if (ts.isIfStatement(node)) {
      const condition = this.evalExpression(node.expression, env, context);
      const thenContext = this.isAdmissionCatchGuard(node.expression, env)
        ? { ...context, allowCatchRethrow: true }
        : context;
      const thenResult = this.analyzeStatement(node.thenStatement, new Map(env), thenContext);
      const elseResult = node.elseStatement
        ? this.analyzeStatement(node.elseStatement, new Map(env), context)
        : { env: new Map(env), returnValue: null };
      void condition;
      return {
        env: this.joinEnvironments(thenResult.env, elseResult.env),
        returnValue: mergeValues(thenResult.returnValue, elseResult.returnValue),
      };
    }
    if (ts.isTryStatement(node)) {
      const tryResult = this.analyzeStatement(node.tryBlock, new Map(env), context);
      let catchResult = { env: new Map(env), returnValue: null };
      if (node.catchClause) {
        const catchEnv = new Map(env);
        if (node.catchClause.variableDeclaration) {
          const catchName = node.catchClause.variableDeclaration.name;
          if (!ts.isIdentifier(catchName)) fail(SAFE.ast, "SYNTAX_POLICY");
          catchEnv.set(
            keyForDeclaration(catchName),
            value({ kind: "caught-error", taint: Taint.MAYBE_SENSITIVE, caps: ["CATCH_ERROR"] }),
          );
        }
        catchResult = this.analyzeStatement(node.catchClause.block, catchEnv, context);
      }
      const joined = this.joinEnvironments(tryResult.env, catchResult.env);
      const finalResult = node.finallyBlock
        ? this.analyzeStatement(node.finallyBlock, joined, context)
        : { env: joined, returnValue: null };
      return {
        env: finalResult.env,
        returnValue: mergeValues(
          mergeValues(tryResult.returnValue, catchResult.returnValue),
          finalResult.returnValue,
        ),
      };
    }
    if (ts.isForOfStatement(node)) {
      const iterable = this.evalExpression(node.expression, env, context);
      if (!["array", "set", "map"].includes(iterable.kind)) {
        fail(SAFE.unresolved, "ITERATOR_UNMODELED", "TV_ITERATOR_UNMODELED");
      }
      const loopValues = iterable.kind === "array"
        ? (iterable.elements ?? [])
        : iterable.kind === "set"
          ? [...(iterable.map?.keys?.() ?? [])]
          : iterable.kind === "map"
            ? [...(iterable.map?.entries?.() ?? [])].map(([key, valueToIterate]) => value({
              kind: "array",
              elements: [key, valueToIterate],
              refs: [key, valueToIterate],
            }))
            : [unknownValue()];
      let current = new Map(env);
      let returnValue = null;
      if (ts.isVariableDeclarationList(node.initializer) && node.initializer.declarations.length === 1) {
        const declaration = node.initializer.declarations[0];
        if (!ts.isIdentifier(declaration.name)) fail(SAFE.ast, "SYNTAX_POLICY");
        this.bindingNames.set(keyForDeclaration(declaration.name), declaration.name.text);
        for (const item of loopValues) {
          const loopEnv = new Map(current);
          loopEnv.set(keyForDeclaration(declaration.name), item);
          const result = this.analyzeStatement(node.statement, loopEnv, context);
          current = this.joinEnvironments(current, result.env);
          returnValue = mergeValues(returnValue, result.returnValue);
        }
        return { env: current, returnValue };
      }
      for (const item of loopValues) {
        const loopEnv = new Map(current);
        this.assignTarget(node.initializer, item, loopEnv, context);
        const result = this.analyzeStatement(node.statement, loopEnv, context);
        current = this.joinEnvironments(current, result.env);
        returnValue = mergeValues(returnValue, result.returnValue);
      }
      return { env: current, returnValue };
    }
    if (ts.isForStatement(node) || ts.isWhileStatement(node) || ts.isDoStatement(node)) {
      if (node.initializer) {
        if (ts.isVariableDeclarationList(node.initializer)) {
          for (const declaration of node.initializer.declarations) {
            if (!ts.isIdentifier(declaration.name)) fail(SAFE.ast, "SYNTAX_POLICY");
            env.set(
              keyForDeclaration(declaration.name),
              declaration.initializer
                ? this.evalExpression(declaration.initializer, env, context)
                : unknownValue(),
            );
            this.bindingNames.set(keyForDeclaration(declaration.name), declaration.name.text);
          }
        } else {
          this.evalExpression(node.initializer, env, context);
        }
      }
      const condition = ts.isForStatement(node) ? node.condition : node.expression;
      let current = new Map(env);
      let returnValue = null;
      const iterations = ts.isDoStatement(node) ? 3 : 3;
      for (let iteration = 0; iteration < iterations; iteration += 1) {
        if (condition) this.evalExpression(condition, current, context);
        const body = this.analyzeStatement(node.statement, new Map(current), context);
        current = this.joinEnvironments(current, body.env);
        returnValue = mergeValues(returnValue, body.returnValue);
        if (node.incrementor) this.evalExpression(node.incrementor, current, context);
      }
      return { env: current, returnValue };
    }
    if (ts.isLabeledStatement(node)) return this.analyzeStatement(node.statement, env, context);
    if (ts.isClassDeclaration(node)) {
      if (!node.name) fail(SAFE.ast, "SYNTAX_POLICY");
      const cls = this.evalClass(node, env);
      env.set(keyForDeclaration(node.name), cls);
      this.bindingNames.set(keyForDeclaration(node.name), node.name.text);
      this.graphNode(cls, "class");
      return { env, returnValue: null };
    }
    if (ts.isWithStatement(node) || ts.isSwitchStatement(node)) {
      fail(SAFE.ast, "SYNTAX_POLICY");
    }
    if (ts.isBreakStatement(node) || ts.isContinueStatement(node)) {
      return { env, returnValue: null };
    }
    fail(SAFE.ast, "SYNTAX_POLICY");
  }

  isAdmissionCatchGuard(expression, env) {
    return ts.isBinaryExpression(expression) &&
      expression.operatorToken.kind === ts.SyntaxKind.InstanceOfKeyword &&
      ts.isIdentifier(expression.left) &&
      this.lookup(expression.left, env).caps.has("CATCH_ERROR") &&
      ts.isIdentifier(expression.right) &&
      expression.right.text === "DisposablePostgresFixtureAdmissionError";
  }

  joinEnvironments(left, right) {
    const joined = new Map();
    const keys = new Set([...left.keys(), ...right.keys()]);
    for (const key of keys) joined.set(key, mergeValues(left.get(key), right.get(key)));
    return joined;
  }

  isPasswordValidationCall(node) {
    if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression) ||
        node.expression.name.text !== "trim" || !ts.isIdentifier(node.expression.expression) ||
        node.expression.expression.text !== "password") return false;
    const lengthAccess = node.parent;
    const comparison = lengthAccess?.parent;
    if (!ts.isPropertyAccessExpression(lengthAccess) || lengthAccess.expression !== node ||
        lengthAccess.name.text !== "length" || !ts.isBinaryExpression(comparison) ||
        comparison.operatorToken.kind !== ts.SyntaxKind.EqualsEqualsEqualsToken ||
        !ts.isNumericLiteral(comparison.right) || comparison.right.text !== "0") return false;
    for (let current = node.parent; current; current = current.parent) {
      if (ts.isFunctionDeclaration(current)) {
        return current.name?.text === "readMigrationConnectionPassword";
      }
    }
    return false;
  }

  evalExpression(node, env, context) {
    if (!node) return primitiveValue("undefined");
    switch (node.kind) {
      case ts.SyntaxKind.Identifier:
        return this.lookup(node, env);
      case ts.SyntaxKind.StringLiteral:
        return this.literalValue(node);
      case ts.SyntaxKind.NumericLiteral:
        return primitiveValue(node.text, { constant: Number(node.text), literalType: "number" });
      case ts.SyntaxKind.BigIntLiteral:
        return primitiveValue(node.text, { literalType: "bigint" });
      case ts.SyntaxKind.NoSubstitutionTemplateLiteral:
        return primitiveValue(node.text, { literalType: "string" });
      case ts.SyntaxKind.RegularExpressionLiteral:
        return value({ kind: "regexp" });
      case ts.SyntaxKind.TrueKeyword:
        return booleanValue(true);
      case ts.SyntaxKind.FalseKeyword:
        return booleanValue(false);
      case ts.SyntaxKind.NullKeyword:
        return primitiveValue("null", { constant: null, literalType: "null" });
      case ts.SyntaxKind.ThisKeyword:
        return this.currentThis ?? value({ kind: "this" });
      case ts.SyntaxKind.SuperKeyword:
        return capabilityValue("CLASS_SUPER");
      case ts.SyntaxKind.ArrayLiteralExpression:
        return this.evalArray(node, env, context);
      case ts.SyntaxKind.ObjectLiteralExpression:
        return this.evalObject(node, env, context);
      case ts.SyntaxKind.ClassExpression:
        return this.evalClass(node, env);
      case ts.SyntaxKind.PropertyAccessExpression:
        return this.getProperty(
          this.evalExpression(node.expression, env, context),
          node.name.text,
          false,
          node,
        );
      case ts.SyntaxKind.ElementAccessExpression:
        return this.evalElement(node, env, context);
      case ts.SyntaxKind.CallExpression:
        return this.evalCall(node, env, context);
      case ts.SyntaxKind.NewExpression:
        return this.evalNew(node, env, context);
      case ts.SyntaxKind.AwaitExpression:
        return this.evalExpression(node.expression, env, context);
      case ts.SyntaxKind.ParenthesizedExpression:
      case ts.SyntaxKind.NonNullExpression:
      case ts.SyntaxKind.AsExpression:
      case ts.SyntaxKind.TypeAssertionExpression:
        return this.evalExpression(node.expression, env, context);
      case ts.SyntaxKind.ArrowFunction:
      case ts.SyntaxKind.FunctionExpression:
        return value({ kind: "function", fn: node, closure: env, captureKeys: this.captureKeysFor(node) });
      case ts.SyntaxKind.BinaryExpression:
        return this.evalBinary(node, env, context);
      case ts.SyntaxKind.PrefixUnaryExpression:
        return this.evalPrefixUnary(node, env, context);
      case ts.SyntaxKind.TypeOfExpression:
        this.evalExpression(node.expression, env, context);
        return primitiveValue("string");
      case ts.SyntaxKind.PostfixUnaryExpression:
        this.evalExpression(node.operand, env, context);
        return primitiveValue("number");
      case ts.SyntaxKind.ConditionalExpression:
        this.evalExpression(node.condition, env, context);
        {
          const trueEnv = new Map(env);
          const falseEnv = new Map(env);
          const whenTrue = this.evalExpression(node.whenTrue, trueEnv, context);
          const whenFalse = this.evalExpression(node.whenFalse, falseEnv, context);
          const joined = this.joinEnvironments(trueEnv, falseEnv);
          for (const [key, item] of joined) env.set(key, item);
          return mergeValues(whenTrue, whenFalse);
        }
      case ts.SyntaxKind.TemplateExpression:
        return this.evalTemplate(node, env, context);
      case ts.SyntaxKind.DeleteExpression: {
        const target = node.expression;
        if (ts.isPropertyAccessExpression(target)) {
          const receiver = this.evalExpression(target.expression, env, context);
          if (receiver.caps.has("ENV")) fail(SAFE.flow, "CAPABILITY_ENV");
          if (receiver.frozen) fail(SAFE.flow, "CAPABILITY_STORAGE");
          deleteValueProperty(receiver, target.name.text);
        } else if (ts.isElementAccessExpression(target)) {
          const receiver = this.evalExpression(target.expression, env, context);
          const key = this.evalKey(target.argumentExpression, env, context);
          if (receiver.caps.has("ENV")) fail(SAFE.flow, "CAPABILITY_ENV");
          if (receiver.frozen) fail(SAFE.flow, "CAPABILITY_STORAGE");
          if (key === null) fail(SAFE.computed, "COMPUTED_CAPABILITY");
          deleteValueProperty(receiver, key);
        } else {
          fail(SAFE.ast, "SYNTAX_POLICY");
        }
        return primitiveValue("boolean");
      }
      case ts.SyntaxKind.VoidExpression:
        this.evalExpression(node.expression, env, context);
        return primitiveValue("undefined");
      case ts.SyntaxKind.MetaProperty:
      case ts.SyntaxKind.YieldExpression:
      case ts.SyntaxKind.AwaitKeyword:
        fail(SAFE.ast, "SYNTAX_POLICY");
        break;
      default:
        fail(SAFE.ast, "SYNTAX_POLICY");
    }
  }

  evalArray(node, env, context) {
    const elements = [];
    for (const element of node.elements) {
      if (!element || ts.isOmittedExpression(element) || ts.isSpreadElement(element)) {
        fail(SAFE.ast, "SYNTAX_POLICY");
      }
      elements.push(this.evalExpression(element, env, context));
    }
    if (elements.some((item) => hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC))) {
      this.pendingSecretStorage = true;
    }
    const result = value({
      kind: "array",
      elements,
      taint: combinedTaint(elements),
      caps: combinedCaps(elements),
      provenance: combinedProvenance(elements),
    });
    for (const element of elements) rememberReference(result, element);
    return result;
  }

  evalObject(node, env, context) {
    const namedProperties = node.properties.map((property) => ({
      property,
      name: property.name ? this.propertyName(property.name, env, context) : null,
    }));
    const propertyNames = namedProperties.map((item) => item.name);
    const poolOptionKeys = ["host", "port", "user", "database", "max"];
    const isPoolOptions = sameTextSet(propertyNames, poolOptionKeys) ||
      sameTextSet(propertyNames, [...poolOptionKeys, "password"]);
    const result = value({ kind: isPoolOptions ? "pool-options" : "object" });
    for (const { property, name } of namedProperties) {
      if (ts.isSpreadAssignment(property) || ts.isGetAccessorDeclaration(property) ||
          ts.isSetAccessorDeclaration(property)) {
        fail(SAFE.ast, "SYNTAX_POLICY");
      }
      if (name === null) {
        fail(SAFE.computed, "COMPUTED_CAPABILITY");
      }
      if (ts.isMethodDeclaration(property)) {
        if (!property.body) fail(SAFE.ast, "SYNTAX_POLICY");
        const method = value({ kind: "function", fn: property, closure: env, captureKeys: this.captureKeysFor(property) });
        result.methods.set(name, method);
        rememberReference(result, method);
        continue;
      }
      if (!ts.isPropertyAssignment(property) && !ts.isShorthandPropertyAssignment(property)) {
        fail(SAFE.ast, "SYNTAX_POLICY");
      }
      const propertyValue = ts.isPropertyAssignment(property)
        ? this.evalExpression(property.initializer, env, context)
        : this.evalExpression(property.name, env, context);
      const approvedPoolAuthorityBinding = name === "pool" &&
        propertyValue.kind === "pool" && this.poolConstructs === 1;
      if (hasTaint(propertyValue, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC) &&
          !approvedPoolAuthorityBinding &&
          !(isPoolOptions && name === "password" && propertyValue.kind === "credential" &&
            propertyValue.directCredential)) {
        this.pendingSecretStorage = true;
      }
      assignValueProperty(result, name, propertyValue);
    }
    return result;
  }

  evalClass(node, env) {
    const result = value({ kind: "class", fn: node, closure: env, captureKeys: this.captureKeysFor(node) });
    result.fields = new Map();
    for (const heritage of node.heritageClauses ?? []) {
      for (const type of heritage.types) {
        const base = this.evalExpression(type.expression, env, {});
        if (base.kind !== "class" && !base.caps.has("ERROR_CONSTRUCTOR")) {
          fail(SAFE.ast, "SYNTAX_POLICY");
        }
      }
    }
    for (const member of node.members ?? []) {
      if (member.name?.kind === ts.SyntaxKind.ComputedPropertyName) {
        const name = this.evalKey(member.name.expression, env, {});
        if (name === null) fail(SAFE.computed, "COMPUTED_CAPABILITY");
      }
      if (ts.isGetAccessorDeclaration(member) || ts.isSetAccessorDeclaration(member)) {
        fail(SAFE.ast, "SYNTAX_POLICY");
      }
      if (ts.isPropertyDeclaration(member)) {
        if (!member.name || member.name.kind === ts.SyntaxKind.ComputedPropertyName ||
            !ts.isIdentifier(member.name)) {
          fail(SAFE.ast, "SYNTAX_POLICY");
        }
        if (member.initializer) {
          if (member.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.StaticKeyword)) {
            this.evalExpression(member.initializer, env, {});
          } else {
            result.fields.set(member.name.text, member.initializer);
          }
        }
      }
      if (ts.isClassStaticBlockDeclaration(member)) {
        this.analyzeStatements(member.body.statements, new Map(env), {});
      }
      if (ts.isMethodDeclaration(member) && member.name) {
        const name = this.propertyName(member.name, env, {});
        if (name === null || !member.body) fail(SAFE.ast, "SYNTAX_POLICY");
        const method = value({ kind: "function", fn: member, closure: env, captureKeys: this.captureKeysFor(member) });
        if (member.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.StaticKeyword)) {
          result.methods.set(name, method);
        } else {
          result.instanceMethods ??= new Map();
          result.instanceMethods.set(name, method);
        }
        rememberReference(result, method);
      }
    }
    return result;
  }

  propertyName(nameNode, env, context) {
    if (!nameNode) return null;
    if (nameNode.kind === ts.SyntaxKind.ComputedPropertyName) {
      return this.evalKey(nameNode.expression, env, context);
    }
    if (ts.isIdentifier(nameNode) || ts.isStringLiteral(nameNode) || ts.isNumericLiteral(nameNode)) {
      return nameNode.text;
    }
    return null;
  }

  evalKey(node, env, context) {
    if (!node) return null;
    const key = this.evalExpression(node, env, context);
    if (key.literalType && key.literalType !== "abstract" &&
        key.constant !== undefined && key.constant !== "") return String(key.constant);
    return null;
  }

  evalElement(node, env, context) {
    const receiver = this.evalExpression(node.expression, env, context);
    const key = this.evalKey(node.argumentExpression, env, context);
    if (key !== null) return this.getProperty(receiver, key, true);
    if (receiver.caps.has("CONSOLE") || receiver.caps.has("CRYPTO") ||
        receiver.caps.has("PROCESS") || receiver.caps.has("GLOBAL_THIS") ||
        receiver.caps.has("ENV")) {
      fail(SAFE.computed, "COMPUTED_CAPABILITY");
    }
    const candidates = [
      ...(receiver.props?.values?.() ?? []),
      ...(receiver.elements ?? []),
      ...(receiver.map?.values?.() ?? []),
      ...(receiver.methods?.values?.() ?? []),
    ];
    if (candidates.length === 0) return unknownValue();
    return candidates.reduce((merged, item) => mergeValues(merged, item), null) ?? unknownValue();
  }

  evalCall(node, env, context) {
    const callee = this.evalExpression(node.expression, env, context);
    const args = [];
    for (const argument of node.arguments) {
      if (ts.isSpreadElement(argument)) fail(SAFE.ast, "SYNTAX_POLICY");
      args.push(this.evalExpression(argument, env, context));
    }
    return this.call(callee, args, node, env, context);
  }

  evalNew(node, env, context) {
    const callee = this.evalExpression(node.expression, env, context);
    const args = [];
    for (const argument of node.arguments ?? []) {
      if (ts.isSpreadElement(argument)) fail(SAFE.ast, "SYNTAX_POLICY");
      args.push(this.evalExpression(argument, env, context));
    }
    if (callee.caps.has("POOL_CONSTRUCTOR")) {
      if (args.length !== 1 || args[0].kind !== "pool-options") fail(SAFE.flow, "CAPABILITY_POOL");
      const options = args[0];
      const keys = [...options.props.keys()];
      if (options.historyProps?.has("password") && !options.props.has("password")) {
        fail(SAFE.flow, "CAPABILITY_PASSWORD");
      }
      if (!sameTextSet(keys, ["host", "port", "user", "database", "max", "password"]) &&
          !sameTextSet(keys, ["host", "port", "user", "database", "max"])) {
        fail(SAFE.flow, "CAPABILITY_POOL");
      }
      if (!isNumberValue(options.props.get("max"), 1)) {
        fail(SAFE.flow, "CAPABILITY_POOL", "AP_POOL_OPTIONS");
      }
      const exactOrigin = (item, key) =>
        item?.exact !== false && provenanceOf(item).has(this.originIdentity(key));
      if (!exactOrigin(options.props.get("host"), "url.hostname") ||
          !exactOrigin(options.props.get("port"), "url.port") ||
          !exactOrigin(options.props.get("database"), "input.expectedDatabase") ||
          !exactOrigin(options.props.get("user"), "input.expectedUser") ||
          !provenanceOf(options.props.get("user")).has(this.originIdentity("default.expectedUser.cloud_admin"))) {
        fail(SAFE.flow, "CAPABILITY_POOL", "AP_POOL_OPTIONS");
      }
      if (options.props.has("password")) {
        const password = options.props.get("password");
        if (password.kind !== "credential" ||
            !password.directCredential ||
            !sameIdentitySet(
              provenanceOf(password),
              new Set([this.originIdentity("input.connectionPassword")]),
            ) ||
            summarizeRisk(password).taint !== Taint.CREDENTIAL ||
            summarizeRisk(password).caps.size > 0) {
          fail(SAFE.flow, "CAPABILITY_PASSWORD");
        }
      }
      this.poolConstructs += 1;
      if (this.poolConstructs > 1) fail(SAFE.flow, "CAPABILITY_POOL");
      const pool = value({ kind: "pool" });
      pool.options = options;
      rememberReference(pool, options);
      return pool;
    }
    if (callee.caps.has("URL_CONSTRUCTOR")) {
      if (args.some((item) => hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC))) {
        fail(SAFE.flow, "CAPABILITY_URL");
      }
      if (args.length !== 1) fail(SAFE.flow, "CAPABILITY_URL", "DP_CAPABILITY");
      const result = value({ kind: "url" });
      result.urlSource = args[0];
      return result;
    }
    if (callee.caps.has("SET_CONSTRUCTOR")) {
      const set = value({ kind: "set", map: new Map() });
      if (args.length > 1) fail(SAFE.flow, "CAPABILITY_COLLECTION");
      for (const item of args[0]?.elements ?? []) {
        set.map.set(item, item);
        rememberReference(set, item);
      }
      if (args[0] && args[0].kind !== "array") fail(SAFE.flow, "CAPABILITY_COLLECTION");
      return set;
    }
    if (callee.caps.has("MAP_CONSTRUCTOR")) {
      const map = value({ kind: "map", map: new Map() });
      if (args.length > 1) fail(SAFE.flow, "CAPABILITY_COLLECTION");
      for (const pair of args[0]?.elements ?? []) {
        if (pair.kind !== "array" || pair.elements?.length !== 2) fail(SAFE.flow, "CAPABILITY_COLLECTION");
        map.map.set(pair.elements[0], pair.elements[1]);
        rememberReference(map, pair.elements[0]);
        rememberReference(map, pair.elements[1]);
      }
      if (args[0] && args[0].kind !== "array") fail(SAFE.flow, "CAPABILITY_COLLECTION");
      return map;
    }
    if (callee.caps.has("WEAKMAP_CONSTRUCTOR")) {
      const weakmap = value({ kind: "weakmap", map: new Map() });
      if (args.length > 1) fail(SAFE.flow, "CAPABILITY_COLLECTION");
      for (const pair of args[0]?.elements ?? []) {
        if (pair.kind !== "array" || pair.elements?.length !== 2 || pair.elements[0].kind === "primitive") {
          fail(SAFE.flow, "CAPABILITY_COLLECTION");
        }
        weakmap.map.set(pair.elements[0], pair.elements[1]);
        rememberReference(weakmap, pair.elements[0]);
        rememberReference(weakmap, pair.elements[1]);
      }
      if (args[0] && args[0].kind !== "array") fail(SAFE.flow, "CAPABILITY_COLLECTION");
      return weakmap;
    }
    if (callee.caps.has("SYMBOL_CONSTRUCTOR")) {
      return value({
        kind: "symbol",
        taint: combinedTaint(args),
        caps: combinedCaps(args),
        provenance: combinedProvenance(args),
      });
    }
    if (callee.caps.has("REGEXP_CONSTRUCTOR")) {
      if (args.some((item) => hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC))) {
        fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION", "PV_EXACT_RELATION");
      }
      return value({ kind: "regexp" });
    }
    if (callee.caps.has("ERROR_CONSTRUCTOR")) {
      if (args.some((item) => hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC))) {
        fail("SSC_PUBLIC_SURFACE", "PUBLIC_CAUSE");
      }
      return value({ kind: "error" });
    }
    if (callee.caps.has("CLASS_SUPER")) return primitiveValue("super");
    if (callee.kind === "class") {
      if (!callee.fn || (!ts.isClassDeclaration(callee.fn) && !ts.isClassExpression(callee.fn))) fail(SAFE.unresolved, "CALL_RESOLUTION");
      return this.analyzeClassConstructor(callee.fn, args, callee.closure);
    }
    if (callee.fn && isFunctionLike(callee.fn)) return this.analyzeFunction(callee.fn, args, callee.closure);
    fail(SAFE.unresolved, "CALL_RESOLUTION");
  }

  evalBinary(node, env, context) {
    if (node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const right = this.evalExpression(node.right, env, context);
      this.assignTarget(node.left, right, env, context);
      return right;
    }
    if ([
      ts.SyntaxKind.PlusEqualsToken,
      ts.SyntaxKind.MinusEqualsToken,
      ts.SyntaxKind.AsteriskEqualsToken,
      ts.SyntaxKind.SlashEqualsToken,
      ts.SyntaxKind.PercentEqualsToken,
      ts.SyntaxKind.AmpersandEqualsToken,
      ts.SyntaxKind.BarEqualsToken,
      ts.SyntaxKind.CaretEqualsToken,
      ts.SyntaxKind.LessThanLessThanEqualsToken,
      ts.SyntaxKind.GreaterThanGreaterThanEqualsToken,
      ts.SyntaxKind.GreaterThanGreaterThanGreaterThanEqualsToken,
      ts.SyntaxKind.QuestionQuestionEqualsToken,
      ts.SyntaxKind.AmpersandAmpersandEqualsToken,
      ts.SyntaxKind.BarBarEqualsToken,
      ts.SyntaxKind.AsteriskAsteriskEqualsToken,
    ].includes(node.operatorToken.kind)) {
      fail(SAFE.ast, "SYNTAX_POLICY");
    }
    const operator = node.operatorToken.kind;
    if (operator === ts.SyntaxKind.CommaToken) {
      this.evalExpression(node.left, env, context);
      return this.evalExpression(node.right, env, context);
    }
    const left = this.evalExpression(node.left, env, context);
    const rightEnv = new Map(env);
    const right = this.evalExpression(node.right, rightEnv, context);
    if (operator === ts.SyntaxKind.AmpersandAmpersandToken ||
        operator === ts.SyntaxKind.BarBarToken ||
        operator === ts.SyntaxKind.QuestionQuestionToken) {
      const leftIsConcrete = left.literalType !== "abstract" && left.constant !== undefined;
      const leftNonNull = leftIsConcrete && left.constant !== null && left.constant !== undefined;
      const leftTruthy = leftIsConcrete && Boolean(left.constant);
      const selected = operator === ts.SyntaxKind.AmpersandAmpersandToken
        ? (leftTruthy ? right : left)
        : operator === ts.SyntaxKind.BarBarToken
          ? (leftTruthy ? left : right)
          : (leftNonNull ? left : right);
      for (const [key, item] of this.joinEnvironments(env, rightEnv)) env.set(key, item);
      if (leftIsConcrete) return selected;
      return mergeValues(left, right);
    }
    if (operator === ts.SyntaxKind.PlusToken) {
      if (hasTaint(left, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC) ||
          hasTaint(right, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC)) {
        fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION");
      }
      return primitiveValue("string");
    }
    if ([
      ts.SyntaxKind.MinusToken,
      ts.SyntaxKind.AsteriskToken,
      ts.SyntaxKind.SlashToken,
      ts.SyntaxKind.PercentToken,
      ts.SyntaxKind.AsteriskAsteriskToken,
    ].includes(operator) &&
        (hasTaint(left, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC) ||
         hasTaint(right, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC))) {
      fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION", "PV_EXACT_RELATION");
    }
    return primitiveValue("boolean");
  }

  evalPrefixUnary(node, env, context) {
    const operand = this.evalExpression(node.operand, env, context);
    if (node.operator === ts.SyntaxKind.PlusPlusToken || node.operator === ts.SyntaxKind.MinusMinusToken) {
      fail(SAFE.ast, "SYNTAX_POLICY");
    }
    if (node.operator === ts.SyntaxKind.PlusToken || node.operator === ts.SyntaxKind.MinusToken ||
        node.operator === ts.SyntaxKind.TildeToken) {
      if (hasTaint(operand, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC)) {
        fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION");
      }
    }
    return primitiveValue("boolean");
  }

  evalTemplate(node, env, context) {
    for (const span of node.templateSpans) {
      const expression = this.evalExpression(span.expression, env, context);
      if (hasTaint(expression, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC)) {
        fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION");
      }
    }
    return primitiveValue("string");
  }

  getProperty(receiver, name, computed, node = null) {
    if (!receiver) return unknownValue();
    if (receiver.kind === "credential" && name === "length") {
      fail(SAFE.flow, "CAPABILITY_PASSWORD", "AP_TOKEN");
    }
    if (computed && (receiver.caps?.has("CONSOLE") || receiver.caps?.has("CRYPTO") ||
        receiver.caps?.has("PROCESS") || receiver.caps?.has("GLOBAL_THIS") || receiver.caps?.has("ENV"))) {
      fail(SAFE.computed, "COMPUTED_CAPABILITY");
    }
    if (receiver.props?.has(name)) {
      const result = receiver.props.get(name);
      this.graphEdge(receiver, result, "MEMBER_VALUE");
      return result;
    }
    if (receiver.methods?.has(name)) {
      const method = receiver.methods.get(name);
      this.graphEdge(receiver, method, "MEMBER_VALUE");
      return method;
    }
    if (receiver.kind === "instance" && receiver.classRef?.instanceMethods?.has(name)) {
      const method = receiver.classRef.instanceMethods.get(name);
      const bound = value({ kind: "function", fn: method.fn, closure: method.closure, captureKeys: method.captureKeys, bound: receiver });
      this.graphEdge(receiver, bound, "MEMBER_VALUE");
      return bound;
    }
    if (receiver.kind === "input") {
      if (name === "connectionPassword") {
        const result = credentialValue(this.originIdentity("input.connectionPassword"));
        this.graphEdge(receiver, result, "READS");
        return result;
      }
      if (SAFE_INPUT_FIELDS.has(name)) {
        const result = primitiveValue(`input.${name}`, { constant: undefined });
        result.provenance.add(this.originIdentity(`input.${name}`));
        this.graphEdge(receiver, result, "READS");
        return result;
      }
    }
    if (receiver.kind === "row" && QUERY_ROW_FIELDS.has(name)) {
      const result = primitiveValue(`query.${name}`, { constant: undefined });
      result.provenance.add(this.originIdentity(`query.${name}`));
      this.graphEdge(receiver, result, "READS");
      return result;
    }
    if (receiver.kind === "array") {
      if (name === "length") return primitiveValue("number");
      const index = Number(name);
      if (Number.isInteger(index) && index >= 0 && receiver.elements?.[index] !== undefined) return receiver.elements[index];
      const arrayMethods = {
        some: "ARRAY_SOME",
        every: "ARRAY_EVERY",
        map: "ARRAY_MAP",
        forEach: "ARRAY_FOREACH",
        includes: "ARRAY_INCLUDES",
        push: "ARRAY_PUSH",
        pop: "ARRAY_POP",
        shift: "ARRAY_SHIFT",
        unshift: "ARRAY_UNSHIFT",
        values: "ARRAY_VALUES",
        entries: "ARRAY_ENTRIES",
        keys: "ARRAY_KEYS",
      };
      if (arrayMethods[name]) return capabilityValue(arrayMethods[name], { bound: receiver });
    }
    if (receiver.kind === "url") {
      if (!["hostname", "port", "username", "pathname", "protocol", "password", "search", "hash"].includes(name)) {
        fail(SAFE.unresolved, "CALL_RESOLUTION", "DP_CAPABILITY");
      }
      return value({
        kind: "string",
        label: `url.${name}`,
        literalType: "string",
        provenance: [this.originIdentity(`url.${name}`)],
      });
    }
    if (receiver.kind === "regexp" && name === "test") return capabilityValue("REGEXP_TEST", { bound: receiver });
    if (receiver.kind === "set") {
      const methods = {
        has: "SET_HAS", add: "SET_ADD", delete: "SET_DELETE", clear: "SET_CLEAR",
        values: "SET_VALUES", keys: "SET_KEYS", entries: "SET_ENTRIES", forEach: "SET_FOREACH",
      };
      if (name === "size") return primitiveValue("number");
      if (methods[name]) return capabilityValue(methods[name], { bound: receiver });
    }
    if (receiver.kind === "weakmap" && !receiver.map) receiver.map = new Map();
    if (receiver.kind === "weakmap") {
      const methods = { set: "WEAKMAP_SET", get: "WEAKMAP_GET", has: "WEAKMAP_HAS", delete: "WEAKMAP_DELETE" };
      if (methods[name]) return capabilityValue(methods[name], { bound: receiver });
    }
    if (receiver.kind === "map") {
      const methods = {
        set: "MAP_SET", get: "MAP_GET", has: "MAP_HAS", delete: "MAP_DELETE", clear: "MAP_CLEAR",
        values: "MAP_VALUES", keys: "MAP_KEYS", entries: "MAP_ENTRIES", forEach: "MAP_FOREACH",
      };
      if (name === "size") return primitiveValue("number");
      if (methods[name]) return capabilityValue(methods[name], { bound: receiver });
    }
    if (receiver.kind === "pool" && name === "query") return capabilityValue("POOL_QUERY", { bound: receiver });
    if (receiver.kind === "pool" && name === "connect") return capabilityValue("POOL_CONNECT", { bound: receiver });
    if (receiver.kind === "pool" && name === "end") return capabilityValue("POOL_END", { bound: receiver });
    if (receiver.kind === "client" && name === "query") return capabilityValue("CLIENT_QUERY", { bound: receiver });
    if (receiver.kind === "client" && name === "release") return capabilityValue("CLIENT_RELEASE", { bound: receiver });
    if (receiver.kind === "drizzle-db") return primitiveValue(name);
    if (receiver.kind === "query-result" && name === "rows") {
      const rows = value({ kind: "array", elements: [value({ kind: "row" })] });
      for (const item of rows.elements) rememberReference(rows, item);
      return rows;
    }
    if (receiver.kind === "string" || receiver.kind === "credential") {
      if (name === "length") return primitiveValue("number");
      if (["trim", "replace", "toLowerCase", "slice", "toString"].includes(name)) {
        return capabilityValue("STRING_METHOD", { bound: receiver, label: name });
      }
    }
    if (receiver.caps.has("GLOBAL_OBJECT")) {
      const methods = {
        freeze: "OBJECT_FREEZE",
        keys: "OBJECT_KEYS",
        hasOwn: "OBJECT_HAS_OWN",
      };
      if (methods[name]) return capabilityValue(methods[name]);
    }
    if (receiver.caps.has("GLOBAL_ARRAY") && name === "isArray") return capabilityValue("ARRAY_IS_ARRAY");
    if (receiver.caps.has("CONSOLE") && ["log", "error", "warn", "info", "debug"].includes(name)) {
      return capabilityValue("OUTPUT", { label: name });
    }
    if (receiver.caps.has("PROCESS") && name === "env") return capabilityValue("ENV");
    if (receiver.caps.has("ENV")) return unknownValue();
    if (receiver.caps.has("JSON") && name === "stringify") return capabilityValue("JSON_STRINGIFY");
    if (receiver.caps.has("PROMISE") && name === "resolve") return capabilityValue("PROMISE_RESOLVE");
    if (receiver.caps.has("GLOBAL_THIS") && name === "crypto") return capabilityValue("CRYPTO");
    if (receiver.caps.has("GLOBAL_THIS")) {
      fail(SAFE.unresolved, "CALL_RESOLUTION", "DP_CAPABILITY");
    }
    if (receiver.caps.has("CRYPTO") && name === "subtle") return capabilityValue("CRYPTO_SUBTLE");
    if (receiver.caps.has("CRYPTO_SUBTLE") && ["digest", "deriveKey", "deriveBits", "encrypt", "decrypt", "sign"].includes(name)) {
      return capabilityValue("CRYPTO");
    }
    if (receiver.caps.has("CLEANUP_PROMISE") && name === "catch") return capabilityValue("CLEANUP_CATCH", { bound: receiver });
    if (receiver.caps.has("CATCH_ERROR")) return value({ kind: "diagnostic", taint: Taint.SENSITIVE_DIAGNOSTIC, caps: ["CATCH_ERROR"] });
    if (receiver.kind === "unknown") return unknownValue();
    return unknownValue();
  }

  call(callee, args, node, env, context) {
    this.graphNode(callee, "callee");
    for (const argument of args) this.graphEdge(callee, argument, "ARGUMENT");
    if (callee.caps.has("OUTPUT")) {
      if (args.some((item) => item.caps.has("CLEANUP_DIAGNOSTIC") || item.caps.has("CATCH_ERROR"))) {
        fail(SAFE.flow, "CLEANUP_DIAGNOSTIC");
      }
      if (callee.label && callee.label !== "") {
        if (hasTaint(args[0], Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC) &&
            callee.aliasProvenance) {
          fail(SAFE.flow, "ALIAS_PROVENANCE");
        }
      }
      if (args.some((item) => hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC))) {
        fail(SAFE.flow, "CAPABILITY_OUTPUT");
      }
      fail(SAFE.flow, "CAPABILITY_OUTPUT");
    }
    if (callee.caps.has("CRYPTO")) {
      if (args.some((item) => hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC))) {
        fail(SAFE.flow, "CAPABILITY_CRYPTO");
      }
      fail(SAFE.flow, "CAPABILITY_CRYPTO");
    }
    if (callee.caps.has("ENV")) fail(SAFE.flow, "CAPABILITY_ENV");
    if (callee.caps.has("CLASS_SUPER")) return primitiveValue("super");
    if (callee.caps.has("POOL_QUERY")) {
      if (args.length !== 2) {
        fail(SAFE.flow, "CAPABILITY_QUERY", "AP_IDENTITY_ARGUMENTS");
      }
      if (args[0]?.binding !== this.identitySqlBinding) {
        fail(SAFE.flow, "CAPABILITY_QUERY", "AP_IDENTITY_SQL");
      }
      if (args[1].kind !== "array" ||
          args[1].elements?.length !== 2 || args[1].elements.some((item) => hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC))) {
        fail(SAFE.flow, "CAPABILITY_QUERY", "AP_IDENTITY_ARGUMENTS");
      }
      const expectedDatabase = this.originIdentity("input.expectedDatabase");
      const expectedUser = new Set([
        this.originIdentity("input.expectedUser"),
        this.originIdentity("default.expectedUser.cloud_admin"),
      ]);
      if (args[1].elements[0]?.exact === false ||
          !sameIdentitySet(provenanceOf(args[1].elements[0]), new Set([expectedDatabase])) ||
          args[1].elements[1]?.exact === false ||
          !sameIdentitySet(provenanceOf(args[1].elements[1]), expectedUser)) {
        fail(SAFE.flow, "CAPABILITY_QUERY", "AP_IDENTITY_ARGUMENTS");
      }
      if (callee.bound?.kind !== "pool") fail(SAFE.flow, "CAPABILITY_QUERY", "AP_IDENTITY_SQL");
      if (this.identityQueryCount >= 2) fail(SAFE.flow, "CAPABILITY_QUERY", "AP_IDENTITY_SQL");
      const identityArguments = args[1].elements.map((item) => new Set(provenanceOf(item)));
      if (this.identityQueryPool && this.identityQueryPool !== callee.bound) fail(SAFE.flow, "CAPABILITY_QUERY");
      if (this.identityQueryArguments && !sameIdentitySequence(identityArguments, this.identityQueryArguments)) {
        fail(SAFE.flow, "CAPABILITY_QUERY");
      }
      this.identityQueryPool = callee.bound;
      this.identityQueryArguments ??= identityArguments;
      this.identityQueryCount = (this.identityQueryCount ?? 0) + 1;
      if (this.identityQueryCount >= 2 && this.authoritySetCount === 1) {
        this.authoritySecondIdentityChecked = true;
      }
      return value({ kind: "query-result" });
    }
    if (callee.caps.has("POOL_END")) {
      if (args.length !== 0) fail(SAFE.flow, "CAPABILITY_CLEANUP");
      if (callee.bound?.kind !== "pool") fail(SAFE.flow, "CAPABILITY_CLEANUP");
      return capabilityValue("CLEANUP_PROMISE", { bound: callee.bound, taint: Taint.SENSITIVE_DIAGNOSTIC });
    }
    if (callee.caps.has("POOL_CONNECT")) {
      if (args.length !== 0 || callee.bound?.kind !== "pool") fail(SAFE.flow, "CAPABILITY_CONNECT");
      const client = value({ kind: "client", pool: callee.bound });
      client.pool = callee.bound;
      rememberReference(client, callee.bound);
      return client;
    }
    if (callee.caps.has("CLIENT_QUERY")) {
      if (args.length !== 2 || args[0].binding !== this.identitySqlBinding || args[1].kind !== "array" ||
          args[1].elements?.length !== 2 || callee.bound?.pool?.kind !== "pool") {
        fail(SAFE.flow, "CAPABILITY_QUERY", "AP_IDENTITY_ARGUMENTS");
      }
      const identityArguments = args[1].elements.map((item) => new Set(provenanceOf(item)));
      if (this.identityQueryPool && this.identityQueryPool !== callee.bound.pool) fail(SAFE.flow, "CAPABILITY_QUERY");
      if (this.identityQueryArguments && !sameIdentitySequence(identityArguments, this.identityQueryArguments)) {
        fail(SAFE.flow, "CAPABILITY_QUERY");
      }
      this.identityQueryPool = callee.bound.pool;
      this.identityQueryArguments ??= identityArguments;
      if (this.identityQueryCount >= 2) fail(SAFE.flow, "CAPABILITY_QUERY", "AP_IDENTITY_SQL");
      this.identityQueryCount = (this.identityQueryCount ?? 0) + 1;
      if (this.identityQueryCount >= 2 && this.authoritySetCount === 1) this.authoritySecondIdentityChecked = true;
      return value({ kind: "query-result" });
    }
    if (callee.caps.has("CLIENT_RELEASE")) {
      if (args.length !== 0 || callee.bound?.kind !== "client") fail(SAFE.flow, "CAPABILITY_CLEANUP");
      return primitiveValue("undefined");
    }
    if (callee.caps.has("DRIZZLE")) {
      if (args.length !== 1 || args[0].kind !== "pool") fail(SAFE.flow, "CAPABILITY_DRIZZLE");
      return value({ kind: "drizzle-db", bound: args[0] });
    }
    if (callee.caps.has("MIGRATE")) {
      if (args.length !== 2 || args[0].kind !== "drizzle-db" || args[1].kind !== "object" ||
          !sameTextSet([...args[1].props.keys()], ["migrationsFolder"]) ||
          args[1].props.get("migrationsFolder") !== this.authorityRecord?.props.get("migrationsFolder") ||
          args[1].props.get("migrationsFolder")?.exact === false ||
          hasTaint(args[1], Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC) ||
          !this.authorityRecord || this.authoritySetCount !== 1 || !this.authoritySecondIdentityChecked ||
          args[0].bound?.kind !== "pool" || args[0].bound !== this.authorityRecord.props.get("pool")) {
        fail(SAFE.flow, "CAPABILITY_MIGRATE", "AP_MIGRATION");
      }
      return primitiveValue("promise");
    }
    if (callee.caps.has("WEAKMAP_SET")) {
      if (callee.bound?.role !== "authority-store") {
        if (args.length !== 2 || !args[0] || args[0].kind === "primitive") fail(SAFE.authority, "AUTHORITY_SCHEMA");
        if (hasTaint(args[1], Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC)) {
          fail(SAFE.flow, "CAPABILITY_STORAGE");
        }
        callee.bound.map ??= new Map();
        callee.bound.map.set(args[0], args[1]);
        rememberReference(callee.bound, args[0]);
        rememberReference(callee.bound, args[1]);
        return callee.bound;
      }
      if (args[0]?.kind === "object" && args[0].props.size === 0) {
        if (!args[0].frozen) fail(SAFE.authority, "AUTHORITY_SCHEMA", "AP_TOKEN");
        args[0].kind = "authority-token";
        args[0].provenance = new Set();
      }
      if (args.length !== 2 || !args[0] || args[0].kind !== "authority-token" || args[1].kind !== "object") {
        fail(SAFE.authority, "AUTHORITY_SCHEMA");
      }
      this.validateAuthorityRecord(args[0], args[1]);
      callee.bound.map.set(args[0], args[1]);
      this.authorityRecord = args[1];
      this.authorityToken = args[0];
      this.authoritySetCount += 1;
      return callee.bound;
    }
    if (callee.caps.has("WEAKMAP_GET")) {
      if (args.length !== 1) fail(SAFE.authority, "AUTHORITY_SCHEMA");
      const record = callee.bound.map.get(args[0]);
      if (!record && callee.bound?.role === "authority-store") fail(SAFE.authority, "AUTHORITY_SCHEMA");
      return record ?? unknownValue();
    }
    if (callee.caps.has("CLEANUP_CATCH")) {
      if (args.length !== 1 || !args[0].fn) fail(SAFE.flow, "CLEANUP_DIAGNOSTIC");
      const callbackResult = this.analyzeFunction(
        args[0].fn,
        [value({ kind: "diagnostic", taint: Taint.SENSITIVE_DIAGNOSTIC, caps: ["CLEANUP_DIAGNOSTIC"] })],
        args[0].closure,
      );
      return callbackResult;
    }
    if (callee.caps.has("ARRAY_SOME")) {
      if (args.length < 1 || !args[0].fn) fail(SAFE.ast, "SYNTAX_POLICY");
      for (const [index, item] of (callee.bound?.elements ?? [unknownValue()]).entries()) {
        this.analyzeFunction(args[0].fn, [item, primitiveValue(String(index)), callee.bound], args[0].closure);
      }
      return primitiveValue("boolean");
    }
    if (callee.caps.has("ARRAY_EVERY")) {
      if (args.length < 1 || !args[0].fn) fail(SAFE.ast, "SYNTAX_POLICY");
      for (const [index, item] of (callee.bound?.elements ?? [unknownValue()]).entries()) {
        this.analyzeFunction(args[0].fn, [item, primitiveValue(String(index)), callee.bound], args[0].closure);
      }
      return primitiveValue("boolean");
    }
    if (callee.caps.has("ARRAY_MAP")) {
      if (args.length < 1 || !args[0].fn) fail(SAFE.ast, "SYNTAX_POLICY");
      const elements = [];
      for (const [index, item] of (callee.bound?.elements ?? []).entries()) {
        elements.push(this.analyzeFunction(args[0].fn, [item, primitiveValue(String(index)), callee.bound], args[0].closure));
      }
      const result = value({ kind: "array", elements });
      for (const item of elements) rememberReference(result, item);
      return result;
    }
    if (callee.caps.has("ARRAY_FOREACH")) {
      if (args.length < 1 || !args[0].fn) fail(SAFE.ast, "SYNTAX_POLICY");
      for (const [index, item] of (callee.bound?.elements ?? []).entries()) {
        this.analyzeFunction(args[0].fn, [item, primitiveValue(String(index)), callee.bound], args[0].closure);
      }
      return primitiveValue("undefined");
    }
    if (callee.caps.has("ARRAY_PUSH")) {
      for (const item of args) {
        callee.bound.elements ??= [];
        callee.bound.elements.push(item);
        rememberReference(callee.bound, item);
      }
      return primitiveValue(String(callee.bound.elements?.length ?? 0));
    }
    if (callee.caps.has("ARRAY_POP")) {
      const item = callee.bound.elements?.[callee.bound.elements.length - 1] ?? primitiveValue("undefined");
      if (item !== undefined) rememberReference(callee.bound, item);
      callee.bound.elements?.pop();
      return item;
    }
    if (callee.caps.has("ARRAY_SHIFT")) {
      const item = callee.bound.elements?.[0] ?? primitiveValue("undefined");
      if (item !== undefined) rememberReference(callee.bound, item);
      callee.bound.elements?.shift();
      return item;
    }
    if (callee.caps.has("ARRAY_UNSHIFT")) {
      callee.bound.elements ??= [];
      callee.bound.elements.unshift(...args);
      for (const item of args) rememberReference(callee.bound, item);
      return primitiveValue(String(callee.bound.elements.length));
    }
    if (callee.caps.has("ARRAY_VALUES") || callee.caps.has("ARRAY_KEYS") || callee.caps.has("ARRAY_ENTRIES")) {
      if (callee.caps.has("ARRAY_KEYS")) return value({
        kind: "array",
        elements: (callee.bound.elements ?? []).map((_, index) => primitiveValue(String(index))),
      });
      if (callee.caps.has("ARRAY_ENTRIES")) {
        const elements = (callee.bound.elements ?? []).map((item, index) => value({
          kind: "array",
          elements: [primitiveValue(String(index)), item],
          refs: [item],
        }));
        return value({ kind: "array", elements, refs: elements });
      }
      return value({ kind: "array", elements: [...(callee.bound.elements ?? [])] });
    }
    if (callee.caps.has("ARRAY_INCLUDES")) {
      if (args.some((item) => hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC))) fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION");
      return primitiveValue("boolean");
    }
    if (callee.caps.has("SET_HAS")) return primitiveValue("boolean");
    if (callee.caps.has("SET_ADD")) {
      if (args.length !== 1) fail(SAFE.flow, "CAPABILITY_COLLECTION");
      callee.bound.map ??= new Map();
      callee.bound.map.set(args[0], args[0]);
      rememberReference(callee.bound, args[0]);
      return callee.bound;
    }
    if (callee.caps.has("SET_DELETE")) {
      if (args.length !== 1) fail(SAFE.flow, "CAPABILITY_COLLECTION");
      callee.bound.map?.delete(args[0]);
      return primitiveValue("boolean");
    }
    if (callee.caps.has("SET_CLEAR")) {
      for (const [key, item] of callee.bound.map ?? []) rememberReference(callee.bound, item);
      callee.bound.map?.clear();
      return primitiveValue("undefined");
    }
    if (callee.caps.has("SET_FOREACH")) {
      if (args.length < 1 || !args[0].fn) fail(SAFE.ast, "SYNTAX_POLICY");
      for (const item of callee.bound.map?.values?.() ?? []) {
        this.analyzeFunction(args[0].fn, [item, item, callee.bound], args[0].closure);
      }
      return primitiveValue("undefined");
    }
    if (callee.caps.has("SET_VALUES") || callee.caps.has("SET_KEYS") || callee.caps.has("SET_ENTRIES")) {
      const keys = [...(callee.bound.map?.keys?.() ?? [])];
      if (callee.caps.has("SET_ENTRIES")) {
        const elements = keys.map((item) => value({ kind: "array", elements: [item, item], refs: [item] }));
        return value({ kind: "array", elements, refs: elements });
      }
      return value({ kind: "array", elements: keys });
    }
    if (callee.caps.has("MAP_SET")) {
      if (args.length !== 2) fail(SAFE.flow, "CAPABILITY_COLLECTION");
      callee.bound.map ??= new Map();
      callee.bound.map.set(args[0], args[1]);
      rememberReference(callee.bound, args[0]);
      rememberReference(callee.bound, args[1]);
      return callee.bound;
    }
    if (callee.caps.has("MAP_GET")) {
      if (args.length !== 1) fail(SAFE.flow, "CAPABILITY_COLLECTION");
      if (callee.bound.map?.has(args[0])) return callee.bound.map.get(args[0]);
      return [...(callee.bound.map?.values?.() ?? [])].reduce((merged, item) => mergeValues(merged, item), null) ?? unknownValue();
    }
    if (callee.caps.has("MAP_HAS")) return primitiveValue("boolean");
    if (callee.caps.has("MAP_DELETE")) {
      if (args.length !== 1) fail(SAFE.flow, "CAPABILITY_COLLECTION");
      callee.bound.map?.delete(args[0]);
      return primitiveValue("boolean");
    }
    if (callee.caps.has("MAP_CLEAR")) {
      for (const [key, item] of callee.bound.map ?? []) { rememberReference(callee.bound, key); rememberReference(callee.bound, item); }
      callee.bound.map?.clear();
      return primitiveValue("undefined");
    }
    if (callee.caps.has("MAP_FOREACH")) {
      if (args.length < 1 || !args[0].fn) fail(SAFE.ast, "SYNTAX_POLICY");
      for (const [key, item] of callee.bound.map ?? []) {
        this.analyzeFunction(args[0].fn, [item, key, callee.bound], args[0].closure);
      }
      return primitiveValue("undefined");
    }
    if (callee.caps.has("MAP_VALUES") || callee.caps.has("MAP_KEYS") || callee.caps.has("MAP_ENTRIES")) {
      if (callee.caps.has("MAP_KEYS")) return value({ kind: "array", elements: [...(callee.bound.map?.keys?.() ?? [])] });
      if (callee.caps.has("MAP_ENTRIES")) {
        const elements = [...(callee.bound.map?.entries?.() ?? [])].map(([key, item]) => value({
          kind: "array",
          elements: [key, item],
          refs: [key, item],
        }));
        return value({ kind: "array", elements, refs: elements });
      }
      return value({ kind: "array", elements: [...(callee.bound.map?.values?.() ?? [])] });
    }
    if (callee.caps.has("WEAKMAP_HAS")) return primitiveValue("boolean");
    if (callee.caps.has("WEAKMAP_DELETE")) {
      if (args.length !== 1) fail(SAFE.authority, "AUTHORITY_SCHEMA");
      const historical = callee.bound.map?.get(args[0]);
      if (historical) rememberReference(callee.bound, historical);
      callee.bound.map?.delete(args[0]);
      return primitiveValue("boolean");
    }
    if (callee.caps.has("REGEXP_TEST")) return primitiveValue("boolean");
    if (callee.caps.has("SYMBOL_CONSTRUCTOR")) {
      return value({
        kind: "symbol",
        taint: combinedTaint(args),
        caps: combinedCaps(args),
        provenance: combinedProvenance(args),
      });
    }
    if (callee.caps.has("STRING_METHOD")) {
      if (!callee.bound) fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION");
      if (callee.bound.kind === "credential" &&
          (callee.label !== "trim" || !this.isPasswordValidationCall(node))) {
        this.pendingPasswordOperation = true;
      }
      if (callee.label === "replace" && args[1]?.fn) {
        this.analyzeFunction(args[1].fn, [
          primitiveValue("match"),
          primitiveValue("offset"),
          callee.bound,
        ], args[1].closure);
      }
      const urlNormalization = callee.bound.kind === "string" &&
        ["replace", "toLowerCase"].includes(callee.label) &&
        provenanceOf(callee.bound).size > 0;
      return value({
        kind: "string",
        taint: callee.bound.taint,
        directCredential: false,
        label: callee.bound.taint ? "transformed-credential" : "",
        provenance: provenanceOf(callee.bound),
        exact: urlNormalization,
      });
    }
    if (callee.caps.has("OBJECT_FREEZE")) {
      if (args.length !== 1) fail(SAFE.flow, "CAPABILITY_REFLECTION");
      args[0].frozen = true;
      return args[0];
    }
    if (callee.caps.has("OBJECT_KEYS")) {
      const target = args[0];
      if (!target || target.kind === "unknown") fail(SAFE.flow, "CAPABILITY_REFLECTION");
      return value({
        kind: "array",
        elements: [...(target.props?.keys?.() ?? [])].map((key) => primitiveValue(key)),
      });
    }
    if (callee.caps.has("OBJECT_HAS_OWN")) {
      if (args.length !== 2) fail(SAFE.flow, "CAPABILITY_REFLECTION");
      return primitiveValue("boolean");
    }
    if (callee.caps.has("ARRAY_IS_ARRAY")) return primitiveValue("boolean");
    if (callee.caps.has("NUMBER_CONSTRUCTOR")) {
      if (args.some((item) => hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC))) fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION");
      return value({
        kind: "primitive",
        label: "number",
        literalType: "number",
        constant: args[0]?.constant !== undefined ? Number(args[0].constant) : undefined,
        provenance: args[0] ? provenanceOf(args[0]) : [],
        exact: args[0]?.exact !== false,
      });
    }
    if (callee.caps.has("DECODE_URI")) {
      if (args.some((item) => hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC))) fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION");
      return value({
        kind: "primitive",
        label: "string",
        literalType: "string",
        provenance: args[0] ? provenanceOf(args[0]) : [],
        exact: args[0]?.exact !== false,
      });
    }
    if (callee.caps.has("STRING_CONSTRUCTOR")) {
      const target = args[0];
      const toString = target?.methods?.get("toString");
      if (toString?.fn) this.analyzeFunction(toString.fn, [], toString.closure, target);
      if (args.some((item) => hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC))) fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION");
      return value({
        kind: "string",
        taint: combinedTaint(args),
        caps: combinedCaps(args),
        provenance: combinedProvenance(args),
        exact: false,
      });
    }
    if (callee.caps.has("JSON_STRINGIFY")) {
      const target = args[0];
      const toJson = target?.methods?.get("toJSON");
      if (toJson?.fn) this.analyzeFunction(toJson.fn, [], toJson.closure, target);
      const replacer = args[1];
      if (replacer?.fn) {
        this.analyzeFunction(replacer.fn, [
          primitiveValue("key"),
          target ?? unknownValue(),
        ], replacer.closure);
      }
      return value({
        kind: "string",
        taint: combinedTaint(args),
        caps: combinedCaps(args),
        provenance: combinedProvenance(args),
        label: combinedTaint(args) ? "serialized-value" : "string",
        exact: false,
      });
    }
    if (callee.caps.has("OPAQUE_OPERATION")) {
      if (args.length !== 0) fail(SAFE.flow, "CAPABILITY_CALLBACK");
      this.operationInvocations += 1;
      this.operationInvocationNodes.push(node.pos);
      if (this.operationInvocations > 1) fail(SAFE.flow, "CAPABILITY_CALLBACK", "AP_OPERATION");
      return value({ kind: "operation-result" });
    }
    if (callee.caps.has("PROMISE_RESOLVE")) {
      fail(SAFE.unresolved, "CALL_RESOLUTION", "TV_CALLBACK_UNMODELED");
    }
    if (callee.fn && isFunctionLike(callee.fn)) return this.analyzeFunction(callee.fn, args, callee.closure, callee.bound);
    const locationAtCall = () => {
      const point = this.sourceFile.getLineAndCharacterOfPosition(node.getStart(this.sourceFile));
      return { line: point.line + 1, column: point.character + 1 };
    };
    if (callee.kind === "function" && !callee.fn) {
      fail(SAFE.unresolved, "CALL_RESOLUTION", "TV_CALLBACK_UNMODELED", locationAtCall());
    }
    if (callee.kind === "class") {
      if (!callee.fn || (!ts.isClassDeclaration(callee.fn) && !ts.isClassExpression(callee.fn))) fail(SAFE.unresolved, "CALL_RESOLUTION");
      return this.analyzeClassConstructor(callee.fn, args, callee.closure);
    }
    if (callee.caps.has("UNUSED_EXTERNAL")) {
      fail(SAFE.unresolved, "CALL_RESOLUTION", "DP_CAPABILITY", locationAtCall());
    }
    if (callee.kind === "unknown") {
      fail(SAFE.unresolved, "CALL_RESOLUTION", "TV_CALLBACK_UNMODELED", locationAtCall());
    }
    fail(SAFE.unresolved, "CALL_RESOLUTION", "TV_CALLBACK_UNMODELED", locationAtCall());
  }

  validateAuthorityRecord(token, record) {
    const keys = [...record.props.keys()];
    if (!sameTextSet(keys, AUTHORITY_KEYS)) fail(SAFE.authority, "AUTHORITY_SCHEMA");
    for (const [name, item] of record.props) {
      if (name === "pool") {
        if (item?.kind !== "pool") fail(SAFE.authority, "AUTHORITY_SCHEMA");
        continue;
      }
      if (!item || item.kind === "unknown" ||
          hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC | Taint.MAYBE_SENSITIVE)) {
        fail(SAFE.flow, "AUTHORITY_SCHEMA");
      }
      if (name !== "authority" && name !== "brand" && name !== "pool" &&
          name !== "valid" && item.kind !== "primitive" && item.kind !== "string") {
        fail(SAFE.authority, "AUTHORITY_SCHEMA");
      }
    }
    if (record.props.get("authority") !== token) {
      fail(SAFE.authority, "AUTHORITY_SCHEMA");
    }
    if (record.props.get("brand") !== this.topValue("migrationAuthorityBrand")) {
      fail(SAFE.authority, "AUTHORITY_SCHEMA");
    }
    if (record.props.get("pool")?.kind !== "pool") {
      fail(SAFE.authority, "AUTHORITY_SCHEMA");
    }
    if (!isBooleanValue(record.props.get("valid"), true)) {
      fail(SAFE.authority, "AUTHORITY_SCHEMA");
    }
    const exact = (name, expectedKeys) => {
      const item = record.props.get(name);
      const expected = new Set(expectedKeys.map((key) => this.originIdentity(key)));
      if (!item || item.exact === false || !sameIdentitySet(provenanceOf(item), expected)) {
        fail(SAFE.authority, "AUTHORITY_SCHEMA");
      }
    };
    exact("database", ["input.expectedDatabase"]);
    exact("user", ["input.expectedUser", "default.expectedUser.cloud_admin"]);
    exact("clusterFingerprint", ["query.catalog_fingerprint"]);
    exact("lifecycleFingerprint", ["query.lifecycle_fingerprint"]);
    exact("migrationsFolder", ["input.migrationsFolder"]);
    const phase = record.props.get("phase");
    const expectedPhase = new Set([
      this.originIdentity("input.phase"),
      this.originIdentity("default.phase.initialization"),
    ]);
    if (!phase || phase.exact === false || !sameIdentitySet(provenanceOf(phase), expectedPhase)) {
      fail(SAFE.authority, "AUTHORITY_SCHEMA");
    }
  }

  assignTarget(target, right, env, context) {
    this.graphNode(right, "assignment-value");
    if (ts.isIdentifier(target)) {
      const resolved = this.resolveDeclaration(target);
      if (!resolved || resolved.kind !== "local") fail(SAFE.unresolved, "CALL_RESOLUTION");
      env.set(keyForDeclaration(resolved.declaration.name ?? resolved.declaration), right);
      this.graphEdge(resolved.declaration, right, "ASSIGNS");
      this.bindingNames.set(keyForDeclaration(resolved.declaration.name ?? resolved.declaration), target.text);
      return;
    }
    if (ts.isPropertyAccessExpression(target)) {
      const receiver = this.evalExpression(target.expression, env, context);
      const name = target.name.text;
      if (receiver.caps.has("ENV")) fail(SAFE.flow, "CAPABILITY_ENV");
      if (receiver.kind === "unknown") fail(SAFE.flow, "CAPABILITY_STORAGE");
      if (receiver.frozen && receiver.kind !== "authority-token") fail(SAFE.flow, "CAPABILITY_STORAGE");
      if (receiver.kind === "pool-options") {
        if (name !== "password" || receiver.props.has("password") || !right.directCredential ||
            right.kind !== "credential" || summarizeRisk(right).taint !== Taint.CREDENTIAL ||
            summarizeRisk(right).caps.size > 0) {
          fail(SAFE.flow, "CAPABILITY_PASSWORD");
        }
        assignValueProperty(receiver, name, right);
        this.declassificationCount += 1;
        if (this.declassificationCount > 1) fail(SAFE.flow, "CAPABILITY_PASSWORD");
        this.graphEdge(right, receiver, "DECLASSIFICATION_USE");
        return;
      }
      if (receiver === this.authorityRecord && name === "valid" && isBooleanValue(right, false)) {
        assignValueProperty(receiver, name, right);
        return;
      }
      if (hasTaint(right, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC)) fail(SAFE.flow, "CAPABILITY_STORAGE");
      assignValueProperty(receiver, name, right);
      this.graphEdge(receiver, right, "ASSIGNS");
      return;
    }
    if (ts.isElementAccessExpression(target)) {
      const receiver = this.evalExpression(target.expression, env, context);
      if (receiver.caps.has("ENV")) fail(SAFE.flow, "CAPABILITY_ENV");
      const key = this.evalKey(target.argumentExpression, env, context);
      if (key === null) fail(SAFE.computed, "COMPUTED_CAPABILITY");
      if (receiver.kind === "pool-options" || receiver === this.authorityRecord) {
        fail(SAFE.computed, "COMPUTED_CAPABILITY");
      }
      if (receiver.frozen && receiver.kind !== "authority-token") fail(SAFE.flow, "CAPABILITY_STORAGE");
      if (hasTaint(right, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC)) fail(SAFE.flow, "CAPABILITY_STORAGE");
      assignValueProperty(receiver, key, right);
      this.graphEdge(receiver, right, "COMPUTED_CHILD");
      return;
    }
    fail(SAFE.ast, "SYNTAX_POLICY");
  }
}

function applyEdits(source, edits) {
  const ordered = [...edits].sort((left, right) => right.start - left.start);
  let result = source;
  for (const edit of ordered) {
    result = `${result.slice(0, edit.start)}${edit.text}${result.slice(edit.end)}`;
  }
  return result;
}

function createVirtualProgram({ helperPath, source, label }) {
  const safeLabel = String(label ?? "variant").replace(/[^A-Za-z0-9_-]/gu, "_");
  const virtualRoot = path.join(path.parse(helperPath).root, "__ssc_virtual__", safeLabel);
  const stubPaths = new Map([
    ["drizzle-orm/node-postgres", path.join(virtualRoot, "drizzle-node-postgres.d.ts")],
    ["drizzle-orm/node-postgres/migrator", path.join(virtualRoot, "drizzle-migrator.d.ts")],
    ["pg", path.join(virtualRoot, "pg.d.ts")],
    ["../../dist/db/runtime-posture.js", path.join(virtualRoot, "runtime-posture.d.ts")],
  ]);
  const stubs = new Map([
    [stubPaths.get("drizzle-orm/node-postgres"), "export declare function drizzle(pool: unknown): unknown;"],
    [stubPaths.get("drizzle-orm/node-postgres/migrator"), "export declare function migrate(db: unknown, options: unknown): Promise<void>;"],
    [stubPaths.get("pg"), "export declare class Client {} export declare class Pool { constructor(options: unknown); query(...args: unknown[]): Promise<unknown>; connect(...args: unknown[]): Promise<unknown>; end(...args: unknown[]): Promise<void>; }"],
    [stubPaths.get("../../dist/db/runtime-posture.js"), "export declare function inspectRuntimeDatabaseRoleAuthorityPosture(...args: unknown[]): Promise<unknown>;"],
  ]);
  const options = {
    allowJs: true,
    checkJs: false,
    noEmit: true,
    skipLibCheck: true,
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
    types: [],
  };
  const defaultHost = ts.createCompilerHost(options, true);
  const samePath = (left, right) => path.resolve(left).toLowerCase() === path.resolve(right).toLowerCase();
  const stubPathFor = (fileName) => [...stubs.keys()].find((candidate) => samePath(candidate, fileName));
  const host = {
    ...defaultHost,
    fileExists(fileName) {
      return samePath(fileName, helperPath) || Boolean(stubPathFor(fileName)) || defaultHost.fileExists(fileName);
    },
    readFile(fileName) {
      if (samePath(fileName, helperPath)) return source;
      const stubPath = stubPathFor(fileName);
      if (stubPath) return stubs.get(stubPath);
      return defaultHost.readFile(fileName);
    },
    getSourceFile(fileName, languageVersion, onError, shouldCreateNewSourceFile) {
      if (samePath(fileName, helperPath)) return ts.createSourceFile(fileName, source, languageVersion, true, ts.ScriptKind.JS);
      const stubPath = stubPathFor(fileName);
      if (stubPath) return ts.createSourceFile(fileName, stubs.get(stubPath), languageVersion, true, ts.ScriptKind.TS);
      return defaultHost.getSourceFile(fileName, languageVersion, onError, shouldCreateNewSourceFile);
    },
    resolveModuleNames(moduleNames) {
      return moduleNames.map((moduleName) => {
        const stub = stubPaths.get(moduleName);
        return stub
          ? { resolvedFileName: stub, extension: ts.Extension.Dts, isExternalLibraryImport: true }
          : undefined;
      });
    },
  };
  const program = ts.createProgram([helperPath], options, host);
  const sourceFile = program.getSourceFile(helperPath);
  if (!sourceFile) fail(SAFE.ast, "SOURCE_IDENTITY");
  if (program.getSyntacticDiagnostics(sourceFile).length > 0) fail(SAFE.ast, "PARSE_DIAGNOSTICS");
  return { program, sourceFile, checker: program.getTypeChecker() };
}

function findNode(sourceFile, predicate) {
  let found = null;
  const visit = (node) => {
    if (found) return;
    if (predicate(node)) {
      found = node;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return found;
}

function findRootFunction(sourceFile) {
  return sourceFile.statements.find(
    (statement) => ts.isFunctionDeclaration(statement) && statement.name?.text === ROOT_EXPORT,
  );
}

function buildMutantSources(source, sourceFile) {
  const root = findRootFunction(sourceFile);
  if (!root?.body?.statements?.[0]) fail(SAFE.internal, "MUTANT_ANCHOR");
  const insertion = root.body.statements[0].getStart(sourceFile);
  const mutants = new Map();
  const prefix = (text) => applyEdits(source, [{ start: insertion, end: insertion, text: `${text}\n` }]);
  mutants.set("NC01_REACHABLE_WRITE_HELPER", prefix(
    "function innocuousForward(value) { console.log(value); } innocuousForward(input.connectionPassword);",
  ));
  mutants.set("NC02_REACHABLE_HASH_HELPER", prefix(
    "function innocuousDigest(value) { return globalThis.crypto.subtle.digest(\"SHA-256\", value); } innocuousDigest(input.connectionPassword);",
  ));
  mutants.set("NC03_STATIC_ONLY_BRANCH", prefix(
    "if (input) { console.log(input.connectionPassword); }",
  ));
  mutants.set("NC04_ALIASED_SINK", prefix(
    "const innocuousSink = console.log; innocuousSink(input.connectionPassword);",
  ));
  mutants.set("NC05_COMPUTED_SINK", prefix(
    "const sinkName = \"log\"; console[sinkName](input.connectionPassword);",
  ));
  mutants.set("NC07_UNRESOLVED_CALL", prefix(
    "unknownExternal(input.connectionPassword);",
  ));
  mutants.set("NC08_TRANSIENT_ENV", prefix(
    "process.env.SSC_TRANSIENT = input.connectionPassword; delete process.env.SSC_TRANSIENT;",
  ));
  mutants.set("NC06_NEW_IMPORT", applyEdits(source, [{
    start: 0,
    end: 0,
    text: "import { readFile as unexpectedRead } from \"node:fs\";\n",
  }]));

  mutants.set("PROBE_ARROW_OUTPUT", prefix(
    "const innocuousArrow = (value) => console.log(value); innocuousArrow(input.connectionPassword);",
  ));
  mutants.set("PROBE_ARRAY_SOME_OUTPUT", prefix(
    "[input.connectionPassword].some((value) => console.log(value));",
  ));
  mutants.set("PROBE_MODULE_IF_OUTPUT", applyEdits(source, [{
    start: root.getStart(sourceFile),
    end: root.getStart(sourceFile),
    text: "if (true) { console.log(\"ssc-module-output\"); }\n",
  }]));

  const publicReturn = findNode(root, (node) =>
    ts.isReturnStatement(node) && node.expression &&
    node.expression.getText(sourceFile).includes("operation"),
  );
  if (!publicReturn?.expression) fail(SAFE.internal, "MUTANT_PUBLIC_RETURN_ANCHOR");
  mutants.set("PROBE_PUBLIC_CREDENTIAL_RETURN", applyEdits(source, [{
    start: publicReturn.expression.getStart(sourceFile),
    end: publicReturn.expression.getEnd(),
    text: "input.connectionPassword",
  }]));

  const authorityCall = findNode(sourceFile, (node) =>
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    node.expression.name.text === "set" &&
    node.arguments.length === 2 &&
    ts.isIdentifier(node.arguments[0]) &&
    node.arguments[0].text === "authority" &&
    ts.isObjectLiteralExpression(node.arguments[1]),
  );
  if (!authorityCall || !ts.isObjectLiteralExpression(authorityCall.arguments[1])) fail(SAFE.internal, "MUTANT_AUTHORITY_ANCHOR");
  const authorityObject = authorityCall.arguments[1];
  mutants.set("NC09_INNOCENT_AUTHORITY_FIELD", applyEdits(source, [{
    start: authorityObject.getEnd() - 1,
    end: authorityObject.getEnd() - 1,
    text: " innocentMetadata: connectionPassword",
  }]));

  const brandProperty = authorityObject.properties.find((property) =>
    ts.isPropertyAssignment(property) &&
    property.name.getText(sourceFile).replace(/^['"]|['"]$/gu, "") === "brand" &&
    ts.isIdentifier(property.initializer) && property.initializer.text === "migrationAuthorityBrand",
  );
  if (!brandProperty || !ts.isPropertyAssignment(brandProperty)) fail(SAFE.internal, "MUTANT_BRAND_ANCHOR");
  mutants.set("PROBE_AUTHORITY_BRAND", applyEdits(source, [{
    start: brandProperty.initializer.getStart(sourceFile),
    end: brandProperty.initializer.getEnd(),
    text: "Symbol(\"spoofed-authority\")",
  }]));

  const passwordAssignment = findNode(sourceFile, (node) =>
    ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
    ts.isPropertyAccessExpression(node.left) && node.left.name.text === "password" &&
    ts.isIdentifier(node.right) && node.right.text === "connectionPassword",
  );
  if (!passwordAssignment) fail(SAFE.internal, "MUTANT_PASSWORD_ANCHOR");
  mutants.set("PROBE_TRIMMED_PASSWORD", applyEdits(source, [{
    start: passwordAssignment.right.getStart(sourceFile),
    end: passwordAssignment.right.getEnd(),
    text: "connectionPassword.trim()",
  }]));

  const cleanupCall = findNode(sourceFile, (node) =>
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    node.expression.name.text === "catch" &&
    ts.isCallExpression(node.expression.expression) &&
    ts.isPropertyAccessExpression(node.expression.expression.expression) &&
    node.expression.expression.expression.name.text === "end" &&
    node.arguments.length === 1 &&
    ts.isArrowFunction(node.arguments[0]),
  );
  if (!cleanupCall || !ts.isArrowFunction(cleanupCall.arguments[0])) fail(SAFE.internal, "MUTANT_CLEANUP_ANCHOR");
  mutants.set("NC10_CLEANUP_PUBLISH", applyEdits(source, [{
    start: cleanupCall.arguments[0].getStart(sourceFile),
    end: cleanupCall.arguments[0].getEnd(),
    text: "(cleanupError) => { console.log(cleanupError); }",
  }]));
  mutants.set("PROBE_CLEANUP_CONCISE_OUTPUT", applyEdits(source, [{
    start: cleanupCall.arguments[0].getStart(sourceFile),
    end: cleanupCall.arguments[0].getEnd(),
    text: "(cleanupError) => console.log(cleanupError)",
  }]));

  mutants.set("PROBE_ARRAY_CREDENTIAL_RETURN", prefix(
    "return [input.connectionPassword];",
  ));
  mutants.set("PROBE_NESTED_ARRAY_CREDENTIAL_RETURN", prefix(
    "return { data: [input.connectionPassword] };",
  ));
  mutants.set("PROBE_JSON_ARRAY_CREDENTIAL_RETURN", prefix(
    "return JSON.stringify([input.connectionPassword]);",
  ));
  mutants.set("PROBE_SYMBOL_CREDENTIAL_RETURN", prefix(
    "return Symbol(input.connectionPassword);",
  ));
  mutants.set("PROBE_CLOSURE_ASSIGNMENT_RETURN", prefix(
    "let leak = \"safe\"; const capture = () => { leak = input.connectionPassword; }; capture(); return leak;",
  ));
  mutants.set("PROBE_CALLBACK_ASSIGNMENT_RETURN", prefix(
    "let callbackLeak = \"safe\"; function captureCallback() { callbackLeak = input.connectionPassword; } captureCallback(); return callbackLeak;",
  ));
  mutants.set("PROBE_CONDITIONAL_AGGREGATE_RETURN", prefix(
    "return input ? [input.connectionPassword] : [];",
  ));
  mutants.set("PROBE_FOR_INITIALIZER_OUTPUT", prefix(
    "for (console.log(input.connectionPassword); false;) {}",
  ));
  mutants.set("PROBE_WHILE_CONDITION_OUTPUT", prefix(
    "while (console.log(input.connectionPassword)) {}",
  ));
  mutants.set("PROBE_DO_CONDITION_OUTPUT", prefix(
    "do {} while (console.log(input.connectionPassword));",
  ));

  const withTopLevelClass = (classSource, rootSource) => applyEdits(source, [
    { start: insertion, end: insertion, text: `${rootSource}\n` },
    { start: root.getStart(sourceFile), end: root.getStart(sourceFile), text: `${classSource}\n` },
  ]);
  mutants.set("PROBE_CONSTRUCTOR_OUTPUT", withTopLevelClass(
    "class SecretSurfaceCarrier { constructor(value) { console.log(value); } }",
    "new SecretSurfaceCarrier(input.connectionPassword);",
  ));
  mutants.set("PROBE_CONSTRUCTOR_PROPERTY_RETURN", withTopLevelClass(
    "class SecretSurfaceCarrier { constructor(value) { this.value = value; } }",
    "const carrier = new SecretSurfaceCarrier(input.connectionPassword); return carrier;",
  ));

  const authorityProperty = (name) => authorityObject.properties.find((property) =>
    ts.isPropertyAssignment(property) &&
    property.name.getText(sourceFile).replace(/^['"]|['"]$/gu, "") === name,
  );
  const replaceAuthorityProperty = (id, name, text) => {
    const property = authorityProperty(name);
    if (!property || !ts.isPropertyAssignment(property)) fail(SAFE.internal, "MUTANT_AUTHORITY_FIELD_ANCHOR");
    mutants.set(id, applyEdits(source, [{
      start: property.initializer.getStart(sourceFile),
      end: property.initializer.getEnd(),
      text,
    }]));
  };
  replaceAuthorityProperty("PROBE_AUTHORITY_DATABASE_IDENTITY", "database", "\"wrong-database\"");
  replaceAuthorityProperty("PROBE_AUTHORITY_USER_IDENTITY", "user", "\"wrong-user\"");
  replaceAuthorityProperty("PROBE_AUTHORITY_CLUSTER_IDENTITY", "clusterFingerprint", "\"wrong-cluster\"");
  replaceAuthorityProperty("PROBE_AUTHORITY_LIFECYCLE_IDENTITY", "lifecycleFingerprint", "\"wrong-lifecycle\"");
  replaceAuthorityProperty("PROBE_AUTHORITY_MIGRATIONS_IDENTITY", "migrationsFolder", "\"wrong-migrations\"");
  replaceAuthorityProperty("PROBE_AUTHORITY_PHASE_IDENTITY", "phase", "\"final_start\"");

  const identityQueryCall = findNode(sourceFile, (node) =>
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    ts.isIdentifier(node.expression.expression) &&
    node.expression.expression.text === "pool" &&
    node.expression.name.text === "query" &&
    node.arguments.length === 2 &&
    ts.isIdentifier(node.arguments[0]) &&
    node.arguments[0].text === "identitySql",
  );
  if (!identityQueryCall) fail(SAFE.internal, "MUTANT_IDENTITY_QUERY_ANCHOR");
  mutants.set("PROBE_EFFECTIVE_SQL_REBIND", applyEdits(source, [{
    start: identityQueryCall.arguments[0].getStart(sourceFile),
    end: identityQueryCall.arguments[0].getEnd(),
    text: "\"select 1\"",
  }]));

  mutants.set("MATRIX_OBJECT_OUTPUT", prefix(
    "console.log({ secret: input.connectionPassword });",
  ));
  mutants.set("MATRIX_ARRAY_OUTPUT", prefix(
    "console.log([input.connectionPassword]);",
  ));
  mutants.set("MATRIX_SET_OUTPUT", prefix(
    "const matrixSet = new Set([input.connectionPassword]); console.log(matrixSet);",
  ));
  mutants.set("MATRIX_MAP_OUTPUT", prefix(
    "const matrixMap = new Map([[\"secret\", input.connectionPassword]]); console.log(matrixMap);",
  ));
  mutants.set("MATRIX_WEAKMAP_OUTPUT", prefix(
    "const matrixWeakMapKey = {}; const matrixWeakMap = new WeakMap([[matrixWeakMapKey, input.connectionPassword]]); console.log(matrixWeakMap);",
  ));
  mutants.set("MATRIX_CLASS_PROPERTY_OUTPUT", prefix(
    "class MatrixCarrier { constructor(value) { this.value = value; } } const matrixCarrier = new MatrixCarrier(input.connectionPassword); console.log(matrixCarrier);",
  ));
  mutants.set("MATRIX_CLASS_METHOD_OUTPUT", prefix(
    "class MatrixCarrier { constructor(value) { this.value = value; } reveal() { return this.value; } } const matrixCarrier = new MatrixCarrier(input.connectionPassword); console.log(matrixCarrier.reveal());",
  ));
  mutants.set("MATRIX_OBJECT_METHOD_OUTPUT", prefix(
    "const matrixCarrier = { reveal() { return input.connectionPassword; } }; console.log(matrixCarrier.reveal());",
  ));
  mutants.set("MATRIX_CALLBACK_OUTPUT", prefix(
    "[input.connectionPassword].forEach((value) => console.log(value));",
  ));
  mutants.set("MATRIX_MAP_CALLBACK_OUTPUT", prefix(
    "new Map([[\"secret\", input.connectionPassword]]).forEach((value) => console.log(value));",
  ));
  mutants.set("MATRIX_RETURN_OBJECT", prefix(
    "return { secret: input.connectionPassword };",
  ));
  mutants.set("MATRIX_RETURN_SET", prefix(
    "return new Set([input.connectionPassword]);",
  ));
  mutants.set("MATRIX_RETURN_MAP", prefix(
    "return new Map([[\"secret\", input.connectionPassword]]);",
  ));
  mutants.set("MATRIX_RETURN_WEAKMAP", prefix(
    "const matrixWeakMapKey = {}; return new WeakMap([[matrixWeakMapKey, input.connectionPassword]]);",
  ));
  mutants.set("MATRIX_RETURN_CLASS", prefix(
    "class MatrixCarrier { constructor(value) { this.value = value; } } return new MatrixCarrier(input.connectionPassword);",
  ));
  mutants.set("MATRIX_RETURN_METHOD", prefix(
    "return { reveal() { return input.connectionPassword; } };",
  ));
  mutants.set("MATRIX_RETURN_CALLBACK", prefix(
    "return () => input.connectionPassword;",
  ));
  mutants.set("MATRIX_RETURN_ALIAS", prefix(
    "const matrixSecret = input.connectionPassword; return matrixSecret;",
  ));
  mutants.set("MATRIX_LATE_MUTATION_OUTPUT", prefix(
    "const matrixHolder = {}; const matrixAlias = matrixHolder; matrixHolder.secret = input.connectionPassword; console.log(matrixAlias);",
  ));
  mutants.set("MATRIX_DELETE_HISTORY_OUTPUT", prefix(
    "const matrixHolder = { secret: input.connectionPassword }; delete matrixHolder.secret; console.log(matrixHolder);",
  ));
  mutants.set("MATRIX_CLEAR_HISTORY_OUTPUT", prefix(
    "const matrixSet = new Set([input.connectionPassword]); matrixSet.clear(); console.log(matrixSet);",
  ));
  mutants.set("MATRIX_FREEZE_OUTPUT", prefix(
    "console.log(Object.freeze({ secret: input.connectionPassword }));",
  ));
  mutants.set("MATRIX_COMPUTED_OBJECT_OUTPUT", prefix(
    "const matrixKey = \"secret\"; const matrixObject = {}; matrixObject[matrixKey] = input.connectionPassword; console.log(matrixObject);",
  ));
  mutants.set("MATRIX_COMPUTED_ARRAY_OUTPUT", prefix(
    "const matrixArray = [input.connectionPassword]; const matrixIndex = 0; console.log(matrixArray[matrixIndex]);",
  ));
  mutants.set("MATRIX_RETAINED_CLOSURE_OUTPUT", prefix(
    "let matrixLeak = \"safe\"; const matrixCapture = () => { matrixLeak = input.connectionPassword; }; matrixCapture(); console.log(matrixLeak);",
  ));
  mutants.set("MATRIX_RETAINED_FUNCTION_OUTPUT", prefix(
    "const matrixCapture = () => input.connectionPassword; console.log(matrixCapture());",
  ));
  mutants.set("MATRIX_CALLBACK_RETURN_OUTPUT", prefix(
    "const matrixMapped = [input.connectionPassword].map((value) => value); console.log(matrixMapped);",
  ));
  mutants.set("MATRIX_WEAKMAP_GET_OUTPUT", prefix(
    "const matrixWeakMapKey = {}; const matrixWeakMap = new WeakMap(); matrixWeakMap.set(matrixWeakMapKey, input.connectionPassword); console.log(matrixWeakMap.get(matrixWeakMapKey));",
  ));
  mutants.set("MATRIX_MAP_UNKNOWN_GET_OUTPUT", prefix(
    "const matrixMap = new Map([[\"secret\", input.connectionPassword]]); console.log(matrixMap.get(input.expectedUser));",
  ));
  mutants.set("MATRIX_STRING_TRANSFORM_OUTPUT", prefix(
    "console.log(input.connectionPassword.trim());",
  ));
  mutants.set("MATRIX_JSON_SECRET_OUTPUT", prefix(
    "console.log(JSON.stringify(input.connectionPassword));",
  ));
  mutants.set("MATRIX_UNKNOWN_COMPUTED_OUTPUT", prefix(
    "const matrixName = input.expectedUser; console[matrixName](input.connectionPassword);",
  ));
  return mutants;
}

async function readFrozenSource() {
  const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(moduleDirectory, "../..");
  const helperPath = path.resolve(repoRoot, HELPER_RELATIVE);
  if (path.relative(repoRoot, helperPath).replaceAll("\\", "/") !== HELPER_RELATIVE) {
    fail(SAFE.internal, "SOURCE_IDENTITY");
  }
  const bytes = await readFile(helperPath);
  const canonicalBytes = Buffer.from(
    bytes.toString("utf8").split("\r\n").join("\n"),
    "utf8",
  );
  const digest = createHash("sha1")
    .update(`blob ${canonicalBytes.byteLength}\0`)
    .update(canonicalBytes)
    .digest("hex");
  if (digest !== FROZEN_HELPER_BLOB) fail(SAFE.flow, "FROZEN_HELPER_BLOB");
  return { helperPath, source: bytes.toString("utf8") };
}

function rootBodyInsertion(source) {
  const rootStart = source.indexOf(`export async function ${ROOT_EXPORT}`);
  const brace = source.indexOf("{", rootStart);
  if (rootStart < 0 || brace < 0) fail(SAFE.internal, "MUTANT_ANCHOR");
  return brace + 1;
}

function prependRootStatements(source, statements) {
  return applyEdits(source, [{
    start: rootBodyInsertion(source),
    end: rootBodyInsertion(source),
    text: `${statements}\n`,
  }]);
}

export async function readFrozenMigrationClosureSource() {
  const frozen = await readFrozenSource();
  return Object.freeze({ ...frozen });
}

export async function analyzeMigrationClosureVariant(source, { label = "variant" } = {}) {
  const frozen = await readFrozenSource();
  return analyzeSourceVariant({ helperPath: frozen.helperPath, source, label });
}

export async function analyzeMigrationClosureVariants(variants) {
  if (!Array.isArray(variants)) fail(SAFE.internal, "VARIANT_INTERFACE");
  const frozen = await readFrozenSource();
  const results = [];
  for (const [index, variant] of variants.entries()) {
    if (!variant || typeof variant.source !== "string") fail(SAFE.internal, "VARIANT_INTERFACE");
    try {
      results.push(Object.freeze({
        id: variant.id ?? `variant-${index}`,
        ok: true,
        result: analyzeSourceVariant({
          helperPath: frozen.helperPath,
          source: variant.source,
          label: `external-${index}`,
        }),
      }));
    } catch (error) {
      const failure = failureOf(error);
      results.push(Object.freeze({
        id: variant.id ?? `variant-${index}`,
        ok: false,
        result: failure,
      }));
    }
  }
  return Object.freeze(results);
}

const POSITIVE_CONTROL_SOURCES = Object.freeze([
  Object.freeze({
    id: "POSITIVE_CLEAN_OBJECT_COMPUTED",
    source: "const cleanObject = {}; cleanObject[\"value\"] = \"safe\"; Object.freeze(cleanObject);",
  }),
  Object.freeze({
    id: "POSITIVE_CLEAN_ARRAY_CALLBACK",
    source: "const cleanArray = [\"safe\"]; cleanArray.map((value) => value);",
  }),
  Object.freeze({
    id: "POSITIVE_CLEAN_SET_COLLECTION",
    source: "const cleanSet = new Set([\"safe\"]); cleanSet.has(\"safe\");",
  }),
  Object.freeze({
    id: "POSITIVE_CLEAN_MAP_COLLECTION",
    source: "const cleanMap = new Map([[\"safe\", \"value\"]]); cleanMap.get(\"safe\");",
  }),
  Object.freeze({
    id: "POSITIVE_CLEAN_CLASS_METHOD",
    source: "class CleanCarrier { constructor(value) { this.value = value; } reveal() { return this.value; } } const cleanCarrier = new CleanCarrier(\"safe\"); cleanCarrier.reveal();",
  }),
  Object.freeze({
    id: "POSITIVE_CLEAN_CLOSURE",
    source: "const cleanClosure = () => \"safe\"; cleanClosure();",
  }),
  Object.freeze({
    id: "POSITIVE_CLEAN_FREEZE_ALIAS",
    source: "const cleanAlias = Object.freeze({ value: \"safe\" }); Object.keys(cleanAlias);",
  }),
  Object.freeze({
    id: "POSITIVE_CLEAN_WEAKMAP",
    source: "const cleanWeakKey = {}; const cleanWeakMap = new WeakMap(); cleanWeakMap.set(cleanWeakKey, \"safe\"); cleanWeakMap.get(cleanWeakKey);",
  }),
]);

async function runVariantSet(variants, { expected = "pass" } = {}) {
  const frozen = await readFrozenSource();
  const results = [];
  for (const variant of variants) {
    let observed = null;
    try {
      observed = analyzeSourceVariant({
        helperPath: frozen.helperPath,
        source: variant.source,
        label: variant.id,
      });
    } catch (error) {
      observed = failureOf(error);
    }
    const pass = expected === "pass"
      ? observed?.ok === true
      : observed?.code !== "SSC_NEGATIVE_CONTROL_INACTIVE" && Boolean(observed?.code);
    results.push(Object.freeze({ id: variant.id, pass, observed }));
  }
  return Object.freeze({
    count: results.length,
    ids: Object.freeze(results.map((result) => result.id)),
    results: Object.freeze(results),
    pass: results.every((result) => result.pass),
  });
}

export async function runMigrationClosurePositiveControls() {
  if (positiveControlResultCache) return positiveControlResultCache;
  const frozen = await readFrozenSource();
  const variants = POSITIVE_CONTROL_SOURCES.map((control) => Object.freeze({
    id: control.id,
    source: prependRootStatements(frozen.source, control.source),
  }));
  positiveControlResultCache = await runVariantSet(variants, { expected: "pass" });
  return positiveControlResultCache;
}

export async function runMigrationClosureAdversarialMatrix() {
  const result = await runMigrationClosureNegativeControls();
  const matrixIds = new Set(NEGATIVE_CONTROLS.filter((control) => control.id.startsWith("MATRIX_")).map((control) => control.id));
  const results = result.results.filter((control) => matrixIds.has(control.id));
  return Object.freeze({
    count: results.length,
    ids: Object.freeze(results.map((control) => control.id)),
    results: Object.freeze(results),
    pass: results.length === matrixIds.size && results.every((control) => control.pass),
  });
}

export async function runMigrationClosureOrthogonalRepresentationMatrix() {
  return runMigrationClosureAdversarialMatrix();
}

export async function runMigrationClosureF2() {
  const baseline = await runFrozenMigrationClosure();
  const adversarial = await runMigrationClosureAdversarialMatrix();
  return Object.freeze({
    id: "F2_STATIC_CLOSURE_ASSURANCE",
    pass: baseline.ok === true && adversarial.pass === true,
    baseline,
    adversarial,
  });
}

export async function runMigrationClosureF3() {
  const positive = await runMigrationClosurePositiveControls();
  const matrix = await runMigrationClosureOrthogonalRepresentationMatrix();
  return Object.freeze({
    id: "F3_REPRESENTATION_ASSURANCE",
    pass: positive.pass === true && matrix.pass === true,
    positive,
    matrix,
  });
}

export function analyzeSourceVariant({ helperPath, source, label }) {
  try {
    const { program, sourceFile, checker } = createVirtualProgram({ helperPath, source, label });
    return new ClosureAnalyzer({ source, sourceFile, program, checker }).analyze();
  } catch (error) {
    throw error instanceof StaticFailure ? error : new StaticFailure(SAFE.internal, "ANALYZER_BOUNDARY");
  }
}

export async function runFrozenMigrationClosure() {
  try {
    const frozen = await readFrozenSource();
    return analyzeSourceVariant({ ...frozen, label: "baseline" });
  } catch (error) {
    const failure = failureOf(error);
    throw new Error(failure.code);
  }
}

export async function runMigrationClosureNegativeControls() {
  if (negativeControlResultCache) return negativeControlResultCache;
  try {
    const frozen = await readFrozenSource();
    const baselineProgram = createVirtualProgram({ ...frozen, label: "mutant-index" });
    const mutants = buildMutantSources(frozen.source, baselineProgram.sourceFile);
    const results = [];
    for (const control of NEGATIVE_CONTROLS) {
      let observed;
      try {
        analyzeSourceVariant({
          helperPath: frozen.helperPath,
          source: mutants.get(control.id),
          label: control.id,
        });
        observed = { code: "SSC_NEGATIVE_CONTROL_INACTIVE", detector: "CONTROL_INACTIVE" };
      } catch (error) {
        observed = failureOf(error);
      }
      results.push(Object.freeze({
        id: control.id,
        code: observed.code,
        detector: observed.detector,
        obligation: observed.obligation ?? null,
        pass: observed.code === control.code && observed.detector === control.detector &&
          (control.obligation === undefined || observed.obligation === control.obligation),
      }));
    }
    negativeControlResultCache = Object.freeze({
      count: results.length,
      ids: Object.freeze(results.map((result) => result.id)),
      results: Object.freeze(results),
    });
    return negativeControlResultCache;
  } catch (error) {
    const failure = failureOf(error);
    negativeControlResultCache = Object.freeze({
      count: NEGATIVE_CONTROLS.length,
      ids: Object.freeze(NEGATIVE_CONTROLS.map((control) => control.id)),
      results: Object.freeze(NEGATIVE_CONTROLS.map((control) => Object.freeze({
        id: control.id,
        code: failure.code,
        detector: failure.detector,
        pass: false,
      }))),
    });
    return negativeControlResultCache;
  }
}

export const migrationClosureNegativeControlIds = Object.freeze(
  NEGATIVE_CONTROLS.map((control) => control.id),
);

export const migrationClosurePositiveControlIds = Object.freeze(
  POSITIVE_CONTROL_SOURCES.map((control) => control.id),
);

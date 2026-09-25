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
const FROZEN_HELPER_BLOB = "f065fe714d560e72578184e4efc02c6e2a5efe72";
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

const NON_OBJECT_VALUE_KINDS = new Set([
  "primitive", "string", "number", "boolean", "null", "undefined", "bigint", "symbol",
]);

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

function minimumOf(items, select) {
  let minimum = Number.POSITIVE_INFINITY;
  for (const item of items) minimum = Math.min(minimum, select(item));
  return minimum;
}

function maximumOf(items, select) {
  let maximum = Number.NEGATIVE_INFINITY;
  for (const item of items) maximum = Math.max(maximum, select(item));
  return maximum;
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

function containsPublicBoundaryValue(item, seen = new Set(), publicFunctionWitnesses = null) {
  if (!item || (typeof item !== "object" && typeof item !== "function") || seen.has(item)) return false;
  seen.add(item);
  if (item.kind === "input" || item.kind === "authority-token") return true;
  const callableTargets = item.callableTargets?.length
    ? item.callableTargets
    : item.fn && isFunctionLike(item.fn) ? [{ fn: item.fn }] : [];
  if (publicFunctionWitnesses && callableTargets.some((target) => target.fn &&
      publicFunctionWitnesses.has(String(target.fn.pos) + ":" + String(target.fn.end)))) return true;
  return [
    ...closureCaptureValues(item),
    ...(item.props?.values?.() ?? []),
    ...(item.historyProps?.values?.() ?? []),
    ...(item.elements ?? []),
    ...(item.map?.keys?.() ?? []),
    ...(item.map?.values?.() ?? []),
    ...(item.methods?.values?.() ?? []),
    ...(item.refs ?? []),
    item.classRef,
    item.bound,
    item.options,
    item.record,
  ].some((child) => containsPublicBoundaryValue(child, seen, publicFunctionWitnesses));
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
  target.origins ??= target.provenance;
  target.securityDependencies ??= new Set();
  for (const origin of provenanceOf(source)) {
    target.provenance.add(origin);
    target.historyProvenance.add(origin);
    target.origins.add(origin);
  }
  for (const dependency of source.securityDependencies ?? provenanceOf(source)) {
    target.securityDependencies.add(dependency);
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

function exactRelationsOf(item) {
  return item?.exactRelations instanceof Set ? item.exactRelations : new Set();
}

function mergeCaptureIdentityMaps(left, right) {
  const merged = new Map();
  for (const source of [left, right]) {
    if (!(source instanceof Map)) continue;
    for (const [key, identities] of source) {
      if (!merged.has(key)) merged.set(key, new Set());
      for (const identity of identities instanceof Set ? identities : [identities]) {
        merged.get(key).add(identity);
      }
    }
  }
  return merged;
}

function sameCaptureIdentityMaps(left, right) {
  if (!(left instanceof Map) || !(right instanceof Map) || left.size !== right.size) return false;
  for (const [key, identities] of left) {
    if (!right.has(key) || !sameIdentitySet(identities, right.get(key))) return false;
  }
  return true;
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
  exactRelations = null,
  securityDependencies = null,
  precision = null,
  derived = false,
  normalization = null,
  captureKeys = null,
  captureCells = null,
  callableTargets = null,
  authorityRecord = false,
  allocationIdentity = null,
  allocationIdentityCandidates = [],
  allocationIdentityKinds = null,
  allocationMayBeUnknown = null,
} = {}) {
  const directTaint = taint ?? Taint.NONE;
  const directCaps = new Set(caps);
  const directOrigins = new Set(provenance);
  const directExactRelations = exactRelations instanceof Set
    ? new Set(exactRelations)
    : exact && !derived ? new Set(directOrigins) : new Set();
  const directDependencies = new Set(securityDependencies ??
    (directTaint !== Taint.NONE ? directOrigins : []));
  const identityCandidates = new Set(allocationIdentityCandidates);
  if (allocationIdentity) identityCandidates.add(allocationIdentity);
  const identityKinds = new Map(allocationIdentityKinds ?? []);
  if (allocationIdentity && !identityKinds.has(allocationIdentity)) identityKinds.set(allocationIdentity, kind);
  const mayBeUnknownAllocation = allocationMayBeUnknown ??
    (!NON_OBJECT_VALUE_KINDS.has(kind) && identityCandidates.size === 0);
  const targets = Array.isArray(callableTargets) ? [...callableTargets]
    : kind === "function" && fn
      ? [{ fn, closure, captureKeys: captureKeys instanceof Set ? new Set(captureKeys) : captureKeys,
        captureCells: captureCells instanceof Map ? new Map(captureCells) : captureCells, bound }]
      : [];
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
    captureCells: captureCells instanceof Map ? new Map(captureCells) : captureCells,
    callableTargets: targets,
    authorityRecord: Boolean(authorityRecord),
    allocationIdentity,
    allocationIdentityCandidates: identityCandidates,
    allocationIdentityKinds: identityKinds,
    allocationMayBeUnknown: mayBeUnknownAllocation,
    bound,
    binding,
    label,
    directCredential,
    elements,
    map,
    constant,
    literalType,
    exact: Boolean(exact && !derived),
    normalization,
    provenance: directOrigins,
    historyProvenance: new Set(directOrigins),
    origins: directOrigins,
    securityDependencies: directDependencies,
    exactRelations: directExactRelations,
    precision: precision ?? (derived ? "derived" : exact ? "exact" : "unresolved"),
    derived: Boolean(derived),
  };
}

function unknownValue() {
  return value();
}

function abstractIdentityKey(item) {
  return item?.allocationIdentity ?? item;
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

function concreteBoolean(item) {
  if (item?.kind === "primitive") {
    if (item.literalType === "boolean" && typeof item.constant === "boolean") return item.constant;
    if (item.literalType === "null" || item.label === "undefined") return false;
    if (item.constant !== undefined && ["number", "string", "bigint"].includes(item.literalType)) {
      return Boolean(item.constant);
    }
    return null;
  }
  if (item && ["input", "object", "array", "set", "map", "weakmap", "pool-options", "pool", "authority-token", "class", "function", "instance", "error", "regexp", "url", "client", "drizzle-db"].includes(item.kind)) return true;
  return null;
}

function abstractValueSignature(item, seen = new Map()) {
  if (!item || (typeof item !== "object" && typeof item !== "function")) {
    return `${typeof item}:${String(item)}`;
  }
  if (seen.has(item)) return `@${seen.get(item)}`;
  const id = seen.size;
  seen.set(item, id);
  const children = (entries) => [...(entries ?? [])]
    .map(([key, child]) => `${String(key)}=${abstractValueSignature(child, seen)}`)
    .sort();
  const closureEntries = item.closure instanceof Map
    ? [...(item.captureKeys instanceof Set ? item.captureKeys : item.closure.keys())]
      .map((key) => [key, item.closure.get(key)])
    : [];
  return JSON.stringify({
    id,
    kind: item.kind,
    taint: summarizeRisk(item).taint,
    caps: [...summarizeRisk(item).caps].sort(),
    provenance: [...provenanceOf(item)].map((entry) => entry?.description ?? String(entry)).sort(),
    origins: [...(item.origins ?? provenanceOf(item))].map((entry) => entry?.description ?? String(entry)).sort(),
    securityDependencies: [...(item.securityDependencies ?? provenanceOf(item))]
      .map((entry) => entry?.description ?? String(entry)).sort(),
    exactRelations: [...exactRelationsOf(item)].map((entry) => entry?.description ?? String(entry)).sort(),
    exact: item.exact !== false,
    precision: item.precision ?? "unresolved",
    derived: item.derived === true,
    normalization: item.normalization ?? null,
    literalType: item.literalType,
    constant: `${typeof item.constant}:${String(item.constant)}`,
    label: item.label,
    allocationIdentity: item.allocationIdentity ?? null,
    allocationIdentityCandidates: [...(item.allocationIdentityCandidates ?? [])].sort(),
    allocationIdentityKinds: [...(item.allocationIdentityKinds ?? [])].sort(([left], [right]) => left.localeCompare(right)),
    allocationMayBeUnknown: item.allocationMayBeUnknown === true,
    fn: item.fn ? `${item.fn.pos}:${item.fn.end}` : "",
    props: children(item.props),
    history: children(item.historyProps),
    elements: (item.elements ?? []).map((child) => abstractValueSignature(child, seen)),
    map: [...(item.map?.entries?.() ?? [])].map(([key, child]) =>
      `${abstractValueSignature(key, seen)}=${abstractValueSignature(child, seen)}`).sort(),
    methods: children(item.methods),
    closure: children(closureEntries),
    captureCells: [...(item.captureCells ?? [])].map(([key, identities]) =>
      `${key}:${[...(identities instanceof Set ? identities : [identities])].sort().join(",")}`).sort(),
    callableTargets: (item.callableTargets ?? []).map((target) => JSON.stringify({
      fn: target.fn ? `${target.fn.pos}:${target.fn.end}` : "",
      bound: target.bound?.kind ?? "",
      captureCells: [...(target.captureCells ?? [])].map(([key, identities]) =>
        `${key}:${[...(identities instanceof Set ? identities : [identities])].sort().join(",")}`).sort(),
    })).sort(),
  });
}

function environmentSignature(env) {
  return [...env.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, item]) => `${key}:${abstractValueSignature(item)}`)
    .join("|");
}

function hasExactProvenance(item, expectedKeys) {
  return item?.exact !== false &&
    sameIdentitySet(
      exactRelationsOf(item),
      new Set(expectedKeys.map((key) => key)),
    );
}

function sameExactPrimitiveValue(left, right) {
  return left === right || (left?.kind === right?.kind &&
    ["primitive", "string"].includes(left?.kind) &&
    left.literalType === right.literalType && Object.is(left.constant, right.constant) &&
    left.exact !== false && right.exact !== false &&
    sameIdentitySet(exactRelationsOf(left), exactRelationsOf(right)));
}

function capabilityValue(cap, options = {}) {
  return value({ ...options, kind: "capability", caps: [cap] });
}

function mergeValues(left, right, seen = new Map(), missingAlternative = null) {
  if (!left && !right) return null;
  if (!left) return right;
  if (!right) return left;
  if (left === right) return left;
  missingAlternative ??= value({ kind: "unknown", exact: false });
  const priorPairs = seen.get(left);
  if (priorPairs?.has(right)) return priorPairs.get(right);

  const leftOrigins = provenanceOf(left);
  const rightOrigins = provenanceOf(right);
  const origins = new Set([...leftOrigins, ...rightOrigins]);
  const leftRelations = exactRelationsOf(left);
  const rightRelations = exactRelationsOf(right);
  const commonRelations = new Set([...leftRelations].filter((relation) => rightRelations.has(relation)));
  const securityDependencies = new Set([
    ...(left.securityDependencies ?? leftOrigins),
    ...(right.securityDependencies ?? rightOrigins),
  ]);
  const sameKnownConstant = left.kind !== "unknown" && right.kind !== "unknown" &&
    left.kind === right.kind && left.constant !== undefined && right.constant !== undefined &&
    left.literalType === right.literalType && Object.is(left.constant, right.constant);
  const unresolvedAlternative = left.kind === "unknown" || right.kind === "unknown" ||
    left.exact === false || right.exact === false || left.derived === true || right.derived === true;
  const relationExact = commonRelations.size > 0 && !unresolvedAlternative;
  const valueExactWithoutOrigin = origins.size === 0 && sameKnownConstant && !unresolvedAlternative;
  const mergedExact = relationExact || valueExactWithoutOrigin;
  const callableTargets = [...(left.callableTargets ?? []), ...(right.callableTargets ?? [])];
  const uniqueCallableTargets = [];
  for (const target of callableTargets) {
    if (!uniqueCallableTargets.some((item) => item.fn === target.fn && item.bound === target.bound &&
        sameCaptureIdentityMaps(item.captureCells, target.captureCells))) {
      uniqueCallableTargets.push(target);
    }
  }
  const merged = value({
    kind: left.kind === right.kind && left.kind !== "unknown" ? left.kind : "unknown",
    taint: joinTaint(summarizeRisk(left).taint, summarizeRisk(right).taint),
    caps: [...summarizeRisk(left).caps, ...summarizeRisk(right).caps],
    bound: left.bound === right.bound ? left.bound : null,
    binding: left.binding === right.binding ? left.binding : null,
    fn: left.fn === right.fn ? left.fn : null,
    closure: left.closure === right.closure ? left.closure : null,
    label: left.label === right.label ? left.label : "",
    directCredential: left.directCredential && right.directCredential,
    literalType: left.literalType === right.literalType ? left.literalType : "",
    provenance: origins,
    securityDependencies,
    exactRelations: commonRelations,
    constant: sameKnownConstant ? left.constant : undefined,
    exact: mergedExact,
    precision: relationExact ? "exact" : mergedExact ? "exact-value" :
      left.derived === true || right.derived === true ? "derived" : "unresolved",
    derived: left.derived === true || right.derived === true,
    normalization: left.normalization === right.normalization ? left.normalization : null,
    captureKeys: left.captureKeys instanceof Set && right.captureKeys instanceof Set
      ? new Set([...left.captureKeys, ...right.captureKeys])
      : null,
    captureCells: left.captureCells instanceof Map || right.captureCells instanceof Map
      ? mergeCaptureIdentityMaps(left.captureCells, right.captureCells) : null,
    callableTargets: uniqueCallableTargets,
    authorityRecord: left.authorityRecord === true && right.authorityRecord === true,
    allocationIdentity: left.allocationIdentity &&
      left.allocationIdentity === right.allocationIdentity ? left.allocationIdentity : null,
    allocationIdentityCandidates: [
      ...(left.allocationIdentityCandidates ?? []), ...(left.allocationIdentity ? [left.allocationIdentity] : []),
      ...(right.allocationIdentityCandidates ?? []), ...(right.allocationIdentity ? [right.allocationIdentity] : []),
    ],
    allocationIdentityKinds: [
      ...(left.allocationIdentityKinds ?? []),
      ...(left.allocationIdentity && !left.allocationIdentityKinds?.has(left.allocationIdentity)
        ? [[left.allocationIdentity, left.kind]] : []),
      ...(right.allocationIdentityKinds ?? []),
      ...(right.allocationIdentity && !right.allocationIdentityKinds?.has(right.allocationIdentity)
        ? [[right.allocationIdentity, right.kind]] : []),
    ],
    allocationMayBeUnknown: left.allocationMayBeUnknown === true || right.allocationMayBeUnknown === true,
  });
  const rightPairs = priorPairs ?? new Map();
  if (!priorPairs) seen.set(left, rightPairs);
  rightPairs.set(right, merged);
  const propertyKeys = new Set([...left.props.keys(), ...right.props.keys()]);
  for (const key of propertyKeys) {
    const leftValue = left.props.has(key) ? left.props.get(key) : missingAlternative;
    const rightValue = right.props.has(key) ? right.props.get(key) : missingAlternative;
    merged.props.set(key, mergeValues(leftValue, rightValue, seen, missingAlternative));
  }
  for (const [key, property] of left.historyProps ?? []) merged.historyProps.set(key, property);
  for (const [key, property] of right.historyProps ?? []) merged.historyProps.set(key, property);
  for (const child of [...(left.refs ?? []), ...(right.refs ?? [])]) rememberReference(merged, child);
  const methodKeys = new Set([...(left.methods?.keys?.() ?? []), ...(right.methods?.keys?.() ?? [])]);
  for (const key of methodKeys) {
    const leftMethod = left.methods?.get(key) ?? missingAlternative;
    const rightMethod = right.methods?.get(key) ?? missingAlternative;
    merged.methods.set(key, mergeValues(leftMethod, rightMethod, seen, missingAlternative));
  }
  if (left.kind === "array" && right.kind === "array") {
    const length = Math.max(left.elements?.length ?? 0, right.elements?.length ?? 0);
    merged.elements = Array.from({ length }, (_item, index) => mergeValues(
      left.elements?.[index] ?? missingAlternative,
      right.elements?.[index] ?? missingAlternative,
      seen,
      missingAlternative,
    ));
  }
  if (left.map instanceof Map || right.map instanceof Map) {
    merged.map = new Map();
    const leftEntries = left.map ?? new Map();
    const rightEntries = right.map ?? new Map();
    const keys = new Set([...leftEntries.keys(), ...rightEntries.keys()]);
    for (const key of keys) {
      const leftValue = leftEntries.has(key) ? leftEntries.get(key) : missingAlternative;
      const rightValue = rightEntries.has(key) ? rightEntries.get(key) : missingAlternative;
      merged.map.set(key, mergeValues(leftValue, rightValue, seen, missingAlternative));
    }
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
    this.poolAllocationValues = new Map();
    this.abstractAllocations = new Map();
    this.declassificationAssignmentEvents = new Map();
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
    this.analysisConverged = true;
    this.pendingSummaries = new Set();
    this.summaryStates = new Map();
    this.expressionCompletionOutcomes = new WeakMap();
    this.summaryWorklist = [];
    this.queuedSummaryIds = new Set();
    this.summaryExecutionStack = [];
    this.activationStack = [];
    this.activationIds = new Map();
    this.environmentCellIds = new WeakMap();
    this.cellValues = new Map();
    this.cellDependents = new Map();
    this.bindingDeclarations = new Map();
    this.summaryWorkBudget = 50000;
    this.replayingSummary = false;
    this.rootSummaryKey = null;
    this.activeExecutionObligations = new Set();
    this.executionObligations = new Map();
    this.activatedFunctionNodes = new Set();
    this.provenanceObligations = new Set([
      "pool-target",
      "identity-target",
      "authority-record",
      "migration-folder",
    ]);
    this.traversalClosed = false;
    this.authorityRevoked = false;
    this.migrationCompleted = false;
    this.poolEndAttempts = 0;
    this.poolEndNodes = new Set();
    this.poolConstructionNodes = new Set();
    this.authoritySetNodes = new Set();
    this.identityQueryNodes = new Set();
    this.fingerprintComparisons = new Set();
    this.fingerprintsEqual = false;
    this.authorityGuardPassed = false;
    this.pendingSecretStorage = false;
    this.pendingPasswordOperation = false;
    this.childInventory = [];
    this.importAliases = new Map();
    this.rootFunction = null;
    this.graphNodes = new Map();
    this.graphEdges = new Set();
    this.graphNodeCounter = 0;
    this.publicEscapeFunctionIds = new Set();
    this.dormantBodies = [];
    this.originIdentities = new Map();
    this.captureKeyCache = new WeakMap();
    this.identitySqlBinding = this.originIdentity("binding.identitySql");
    this.identitySqlText = null;
  }

  originIdentity(key) {
    let identity = this.originIdentities.get(key);
    if (!identity) {
      identity = Symbol(key);
      this.originIdentities.set(key, identity);
    }
    return identity;
  }

  executionKey(node) {
    return String(node.kind) + ":" + String(node.pos) + ":" + String(node.end);
  }

  activationContextFor(node, callsite = null) {
    const functionId = String(node.pos) + ":" + String(node.end);
    const parent = this.activationStack.at(-1)?.id ?? "module";
    const site = callsite && Number.isInteger(callsite.pos) && Number.isInteger(callsite.end)
      ? String(callsite.pos) + ":" + String(callsite.end)
      : "implicit";
    const key = parent + "/" + functionId + "@" + site;
    if (!this.activationIds.has(key)) this.activationIds.set(key, key);
    return this.activationIds.get(key);
  }

  cloneEnvironment(source) {
    const environment = new Map(source ?? []);
    if (source && this.environmentCellIds.has(source)) {
      const copied = new Map();
      for (const [key, identities] of this.environmentCellIds.get(source)) {
        copied.set(key, new Set(identities));
      }
      this.environmentCellIds.set(environment, copied);
    }
    return environment;
  }

  allocationFor(node, kind) {
    const activation = this.summaryExecutionStack.at(-1)?.id ??
      this.activationStack.map((frame) => frame.id).join("/");
    const key = (activation || "module") + "::" + kind + "::" + node.pos;
    if (!this.abstractAllocations.has(key)) this.abstractAllocations.set(key, value({ kind, allocationIdentity: key }));
    return this.abstractAllocations.get(key);
  }

  cellIdentitiesFor(environment, key) {
    let cells = this.environmentCellIds.get(environment);
    if (!cells) {
      cells = new Map();
      this.environmentCellIds.set(environment, cells);
    }
    if (!cells.has(key)) {
      const activation = this.activationStack.at(-1)?.id ?? "module";
      const identity = activation + "::" + key;
      cells.set(key, new Set([identity]));
      if (environment.has(key) && !this.cellValues.has(identity)) {
        this.cellValues.set(identity, environment.get(key));
      }
    }
    return cells.get(key);
  }

  captureCellsFor(keys, environment) {
    const captured = new Map();
    for (const key of keys ?? []) {
      captured.set(key, new Set(this.cellIdentitiesFor(environment, key)));
    }
    return captured;
  }

  mergeCaptureCellMaps(left, right) {
    const merged = new Map();
    for (const source of [left, right]) {
      if (!(source instanceof Map)) continue;
      for (const [key, identities] of source) {
        if (!merged.has(key)) merged.set(key, new Set());
        const values = identities instanceof Set ? identities : new Set([identities]);
        for (const identity of values) merged.get(key).add(identity);
      }
    }
    return merged;
  }

  cellInputSignature(summary) {
    const identities = new Set();
    for (const values of summary.captureCells.values()) {
      for (const identity of values) identities.add(identity);
    }
    return [...identities].sort().map((identity) =>
      identity + "=" + abstractValueSignature(this.cellValues.get(identity) ?? unknownValue())).join("|");
  }

  cellStateSignature() {
    return [...this.cellValues.entries()].sort(([left], [right]) => left.localeCompare(right))
      .map(([identity, item]) => identity + '=' + abstractValueSignature(item)).join('|');
  }

  enqueueSummary(summaryId) {
    const summary = this.summaryStates.get(summaryId);
    if (!summary) return;
    summary.stable = false;
    if (this.queuedSummaryIds.has(summaryId)) return;
    this.queuedSummaryIds.add(summaryId);
    summary.queued = true;
    this.summaryWorklist.push(summaryId);
  }

  recordCellRead(environment, key) {
    const summary = this.summaryExecutionStack.at(-1);
    if (!summary || !summary.captureKeys.has(key)) return;
    for (const identity of this.cellIdentitiesFor(environment, key)) {
      summary.cellReads.add(identity);
      if (!this.cellDependents.has(identity)) this.cellDependents.set(identity, new Set());
      this.cellDependents.get(identity).add(summary.id);
      if (!this.cellValues.has(identity)) {
        this.cellValues.set(identity, environment.get(key) ?? unknownValue());
      }
    }
  }

  recordCellWrite(environment, key, nextValue) {
    const summary = this.summaryExecutionStack.at(-1);
    for (const identity of this.cellIdentitiesFor(environment, key)) {
      if (summary) summary.cellWrites.add(identity);
      const dependents = this.cellDependents.get(identity);
      if (!dependents?.size) continue;
      const before = this.cellValues.get(identity);
      const after = before ? mergeValues(before, nextValue) : nextValue;
      if (before && abstractValueSignature(before) === abstractValueSignature(after)) continue;
      this.cellValues.set(identity, after);
      for (const dependent of dependents) this.enqueueSummary(dependent);
    }
  }

  setBinding(environment, key, nextValue) {
    environment.set(key, nextValue);
    this.recordCellWrite(environment, key, nextValue);
    return nextValue;
  }

  loopHasCapturedCallable(node, environment) {
    let found = false;
    const visit = (candidate) => {
      if (found) return;
      if (ts.isCallExpression(candidate) && ts.isIdentifier(candidate.expression)) {
        const resolved = this.resolveDeclaration(candidate.expression);
        if (resolved?.kind === "local") {
          const key = keyForDeclaration(resolved.declaration.name ?? resolved.declaration);
          const target = environment.get(key);
          const captures = target?.captureCells instanceof Map && target.captureCells.size > 0 ||
            (target?.callableTargets ?? []).some((item) => item.captureCells instanceof Map && item.captureCells.size > 0);
          if (captures && this.hasCallableTarget(target)) found = true;
        }
      }
      ts.forEachChild(candidate, visit);
    };
    visit(node);
    return found;
  }

  cellStateSnapshot(environment = null) {
    const identities = environment
      ? new Set([...(this.environmentCellIds.get(environment)?.values() ?? [])].flatMap((items) => [...items]))
      : new Set(this.cellValues.keys());
    return new Map([...identities]
      .filter((identity) => this.cellValues.has(identity))
      .map((identity) => [identity, abstractValueSignature(this.cellValues.get(identity))]));
  }

  changedCellIdentities(snapshot) {
    const changed = new Set();
    for (const [identity, previous] of snapshot) {
      const item = this.cellValues.get(identity);
      if (item && previous !== abstractValueSignature(item)) changed.add(identity);
    }
    return changed;
  }

  refreshCapturedCells(environment, changedIdentities) {
    const cells = this.environmentCellIds.get(environment);
    if (!(cells instanceof Map) || !(changedIdentities instanceof Set)) return environment;
    for (const [key, identities] of cells) {
      if (!environment.has(key)) continue;
      for (const identity of identities) {
        if (!changedIdentities.has(identity)) continue;
        const captured = this.cellValues.get(identity);
        if (captured) environment.set(key, mergeValues(environment.get(key), captured));
      }
    }
    return environment;
  }

  registerSummaryDependencies(summary) {
    for (const identities of summary.captureCells.values()) {
      for (const identity of identities) {
        if (!this.cellDependents.has(identity)) this.cellDependents.set(identity, new Set());
        this.cellDependents.get(identity).add(summary.id);
        if (!this.cellValues.has(identity)) {
          const key = [...summary.captureCells].find((entry) => entry[1].has(identity))?.[0];
          this.cellValues.set(identity, summary.closure?.get(key) ?? unknownValue());
        }
      }
    }
  }

  summaryFor(node, args, closure, thisValue, parentContext, callsite, captureCells) {
    const functionId = String(node.pos) + ":" + String(node.end);
    const activationId = this.activationContextFor(node, callsite);
    const capturedIds = [...captureCells.values()].flatMap((ids) => [...ids]).sort();
    const caller = this.summaryExecutionStack.at(-1) ?? null;
    const id = functionId + "@" + activationId + "#" + capturedIds.join(",");
    let summary = this.summaryStates.get(id);
    if (!summary) {
      summary = {
        id, functionId, activationId, node, closure, thisValue,
        captureKeys: this.captureKeysFor(node), captureCells: this.mergeCaptureCellMaps(captureCells),
        capturedCellIds: new Set(capturedIds), cellReads: new Set(), cellWrites: new Set(),
        calleeDependencies: new Set(), callers: new Set(), args: [...args],
        contextSeed: this.cloneAnalysisContext(parentContext ?? {}), finalContext: null,
        completionAlternatives: [], lifecycleTransfers: [], result: null,
        sideEffectSeed: this.captureSideEffectState(), sideEffectResult: null,
        revision: 0, stable: false, running: false, queued: false,
        lastCellInput: null, lastExecution: null,
      };
      this.summaryStates.set(id, summary);
      this.registerSummaryDependencies(summary);
    } else {
      summary.closure = closure;
      summary.thisValue = thisValue;
      summary.captureCells = this.mergeCaptureCellMaps(summary.captureCells, captureCells);
      summary.capturedCellIds = new Set([...summary.captureCells.values()].flatMap((ids) => [...ids]));
      summary.args = args.map((argument, index) => mergeValues(summary.args[index], argument));
      summary.contextSeed = this.cloneAnalysisContext(parentContext ?? summary.contextSeed ?? {});
      summary.sideEffectSeed = this.captureSideEffectState();
      this.registerSummaryDependencies(summary);
    }
    if (caller && caller.id !== id && !caller.calleeDependencies.has(id)) {
      caller.calleeDependencies.add(id);
      summary.callers.add(caller.id);
      if (caller.revision > 0) this.enqueueSummary(caller.id);
    }
    if (node === this.rootFunction && !caller) this.rootSummaryKey = id;
    return summary;
  }

  executeSummary(summary, args, closure, thisValue, parentContext, callsite, replay = false) {
    if (summary.running) fail(SAFE.internal, "FIXED_POINT_RECURSION", "CF_RECURSION");
    summary.running = true;
    summary.queued = false;
    summary.lastCellInput = this.cellInputSignature(summary);
    summary.contextSeed = this.cloneAnalysisContext(parentContext ?? {});
    const frame = { id: summary.activationId, node: summary.node, summary };
    this.activationStack.push(frame);
    this.summaryExecutionStack.push(summary);
    const previousReplay = this.replayingSummary;
    this.replayingSummary = previousReplay || replay;
    const beforeResult = summary.result ? abstractValueSignature(summary.result) : null;
    try {
      const result = this.executeFunctionBody(summary.node, args, closure, thisValue, parentContext);
      summary.result = summary.result ? mergeValues(summary.result, result) : result;
      const afterResult = summary.result ? abstractValueSignature(summary.result) : null;
      if (beforeResult !== afterResult) {
        summary.revision += 1;
        for (const callerId of summary.callers) this.enqueueSummary(callerId);
      }
      summary.finalContext = this.cloneAnalysisContext(parentContext ?? {});
      summary.lifecycleTransfers = [{
        input: summary.contextSeed.ap,
        output: summary.finalContext.ap,
      }];
      summary.sideEffectResult = this.captureSideEffectState();
      summary.lastExecution ??= { result, completion: "NORMAL", callsite };
      summary.stable = !summary.queued;
      return result;
    } finally {
      this.replayingSummary = previousReplay;
      this.summaryExecutionStack.pop();
      this.activationStack.pop();
      summary.running = false;
    }
  }

  drainSummaryWorklist() {
    let processed = 0;
    while (this.summaryWorklist.length > 0) {
      if (++processed > this.summaryWorkBudget) {
        this.analysisConverged = false;
        break;
      }
      const summaryId = this.summaryWorklist.shift();
      this.queuedSummaryIds.delete(summaryId);
      const summary = this.summaryStates.get(summaryId);
      if (!summary) continue;
      summary.queued = false;
      if (summary.running) continue;
      const inputSignature = this.cellInputSignature(summary);
      if (summary.stable && summary.lastCellInput === inputSignature) continue;
      const previousSideEffects = this.captureSideEffectState();
      this.restoreSideEffectState(summary.sideEffectSeed);
      const context = this.cloneAnalysisContext(summary.contextSeed);
      let replayCompleted = false;
      try {
        this.executeSummary(summary, summary.args, summary.closure, summary.thisValue,
          context, null, true);
        replayCompleted = true;
      } finally {
        const replaySideEffects = summary.sideEffectResult;
        this.restoreSideEffectState(previousSideEffects);
        if (replayCompleted && summary.node === this.rootFunction && replaySideEffects) {
          this.restoreSideEffectState(replaySideEffects);
        }
      }
      if (!summary.queued && summary.lastCellInput === this.cellInputSignature(summary)) summary.stable = true;
    }
    return this.analysisConverged && this.pendingSummaries.size === 0 &&
      this.summaryWorklist.length === 0 && [...this.summaryStates.values()].every((summary) =>
        summary.stable && !summary.queued && !summary.running);
  }

  captureSideEffectState() {
    return {
      poolConstructs: this.poolConstructs,
      poolOptions: this.poolOptions,
      authorityToken: this.authorityToken,
      authorityRecord: this.authorityRecord,
      authoritySetCount: this.authoritySetCount,
      declassificationCount: this.declassificationCount,
      identityQueryCount: this.identityQueryCount,
      identityQueryPool: this.identityQueryPool,
      identityQueryArguments: this.identityQueryArguments?.map((item) => new Set(item)) ?? null,
      authoritySecondIdentityChecked: this.authoritySecondIdentityChecked,
      operationInvocations: this.operationInvocations,
      operationInvocationNodes: [...this.operationInvocationNodes],
      authorityRevoked: this.authorityRevoked,
      migrationCompleted: this.migrationCompleted,
      poolEndAttempts: this.poolEndAttempts,
      poolEndNodes: new Set(this.poolEndNodes),
      poolConstructionNodes: new Set(this.poolConstructionNodes),
      authoritySetNodes: new Set(this.authoritySetNodes),
      identityQueryNodes: new Set(this.identityQueryNodes),
      fingerprintComparisons: new Set(this.fingerprintComparisons),
      fingerprintsEqual: this.fingerprintsEqual,
      authorityGuardPassed: this.authorityGuardPassed,
      pendingSecretStorage: this.pendingSecretStorage,
      pendingPasswordOperation: this.pendingPasswordOperation,
      provenanceObligations: new Set(this.provenanceObligations),
      declassificationAssignmentEvents: new Map(this.declassificationAssignmentEvents),
    };
  }

  restoreSideEffectState(state) {
    if (!state) return;
    for (const key of Object.keys(state)) {
      const value = state[key];
      this[key] = value instanceof Set ? new Set(value)
        : value instanceof Map ? new Map(value)
          : Array.isArray(value) ? value.map((item) => item instanceof Set ? new Set(item) : item)
            : value;
    }
  }

  mergeSideEffectStates(states) {
    if (!Array.isArray(states) || states.length === 0) return this.captureSideEffectState();
    const merged = this.captureSideEffectState();
    const unionSet = (key) => new Set(states.flatMap((state) => [...(state[key] ?? [])]));
    for (const key of ["poolEndNodes", "poolConstructionNodes", "authoritySetNodes", "identityQueryNodes", "fingerprintComparisons"]) {
      merged[key] = unionSet(key);
    }
    merged.poolConstructs = merged.poolConstructionNodes.size;
    merged.authoritySetCount = merged.authoritySetNodes.size;
    merged.identityQueryCount = maximumOf(states, (state) => state.identityQueryCount ?? 0);
    merged.poolEndAttempts = merged.poolEndNodes.size;
    merged.operationInvocationNodes = [...new Set(states.flatMap((state) => state.operationInvocationNodes ?? []))];
    merged.operationInvocations = merged.operationInvocationNodes.length;
    merged.declassificationAssignmentEvents = new Map();
    for (const state of states) {
      for (const [key, receiver] of state.declassificationAssignmentEvents ?? []) {
        const previous = merged.declassificationAssignmentEvents.get(key);
        merged.declassificationAssignmentEvents.set(key, previous && previous !== receiver ? null : receiver);
      }
    }
    merged.declassificationCount = maximumOf(states, (state) => state.declassificationCount ?? 0);
    for (const key of ["authorityRevoked", "migrationCompleted", "fingerprintsEqual", "authorityGuardPassed", "authoritySecondIdentityChecked"]) {
      merged[key] = states.every((state) => state[key] === true);
    }
    for (const key of ["pendingSecretStorage", "pendingPasswordOperation"]) {
      merged[key] = states.some((state) => state[key] === true);
    }
    merged.provenanceObligations = new Set(states.flatMap((state) => [...(state.provenanceObligations ?? [])]));
    for (const key of ["poolOptions", "authorityToken", "authorityRecord"]) {
      const values = states.map((state) => state[key]);
      if (values.every((item) => item === values[0])) merged[key] = values[0];
      else if (values.some((item) => item == null)) merged[key] = null;
      else merged[key] = values.reduce((result, item) => mergeValues(result, item), null);
    }
    return merged;
  }

  analyzeStatementWithState(node, env, context) {
    const before = this.captureSideEffectState();
    const result = this.analyzeStatement(node, env, context);
    const observed = this.captureSideEffectState();
    const outcomes = this.statementOutcomes(result, env, context).map((outcome) =>
      outcome.sideEffects ? outcome : { ...outcome, sideEffects: observed });
    this.restoreSideEffectState(before);
    return { ...result, completionAlternatives: outcomes };
  }

  dischargeExecution(node) {
    if (!node || !(ts.isStatement(node) || ts.isExpression(node))) return;
    const key = this.executionKey(node);
    this.executionObligations.set(key, "executed");
    this.activeExecutionObligations.delete(key);
  }

  markDormantSubtree(node) {
    if (!node) return;
    if (ts.isStatement(node) || ts.isExpression(node)) {
      const key = this.executionKey(node);
      if (this.executionObligations.get(key) !== "executed") this.executionObligations.set(key, "dormant");
    }
    ts.forEachChild(node, (child) => this.markDormantSubtree(child));
  }
  initialAnalysisFacts() {
    return {
      poolAllocated: false,
      poolAllocatedAny: false,
      poolAllocationCleanupAttempts: { min: 0, max: 0 },
      authorityMinted: false,
      authorityMintedAny: false,
      authorityRevokedWhenMinted: false,
      authorityGuardPassed: false,
      identity2Validated: false,
      fingerprintsEqual: false,
      migrationAttempted: false,
      migrationCompleted: false,
      authorityRevoked: false,
      cleanupAttempts: { min: 0, max: 0 },
      cleanupEntryCount: { min: 0, max: 0 },
      cleanupSites: new Set(),
      cleanupAttempted: false,
      cleanupSucceeded: false,
      originalCompletion: null,
      propagatedCompletion: null,
    };
  }

  cloneAnalysisContext(context) {
    const source = context ?? {};
    const range = source.operationRange ?? { min: 0, max: 0 };
    const facts = source.ap ?? this.initialAnalysisFacts();
    return {
      ...source,
      operationRange: { min: range.min, max: range.max },
      ap: {
        ...facts,
        cleanupAttempts: { ...facts.cleanupAttempts },
        cleanupEntryCount: { ...(facts.cleanupEntryCount ?? facts.cleanupAttempts) },
        poolAllocationCleanupAttempts: { ...(facts.poolAllocationCleanupAttempts ?? { min: 0, max: 0 }) },
        cleanupSites: new Set(facts.cleanupSites ?? []),
      },
    };
  }

  appendPathPredicate(context, predicate) {
    const previous = context.pathPredicateFormula ?? {
      kind: "path",
      predicates: [...(context.pathPredicates ?? [])],
    };
    context.pathPredicateFormula = { kind: "and", previous, predicate };
    context.pathPredicates = [...(context.pathPredicates ?? []), predicate];
  }

  mergePathPredicateState(target, contexts) {
    if (!contexts.length) return;
    const formulaAlternatives = [];
    for (const context of contexts) {
      const formula = context.pathPredicateFormula ?? {
        kind: "path",
        predicates: [...(context.pathPredicates ?? [])],
      };
      const alternatives = formula.kind === "or" ? formula.alternatives : [formula];
      for (const alternative of alternatives) {
        if (!formulaAlternatives.includes(alternative)) formulaAlternatives.push(alternative);
      }
    }
    target.pathPredicateFormula = formulaAlternatives.length === 1
      ? formulaAlternatives[0]
      : { kind: "or", alternatives: formulaAlternatives };
    const common = [...(contexts[0].pathPredicates ?? [])];
    for (const context of contexts.slice(1)) {
      const keys = new Set((context.pathPredicates ?? []).map((predicate) => JSON.stringify(predicate)));
      for (let index = common.length - 1; index >= 0; index -= 1) {
        if (!keys.has(JSON.stringify(common[index]))) common.splice(index, 1);
      }
    }
    target.pathPredicates = common;
  }

  mergeCompletionAlternatives(outcomes) {
    const groups = new Map();
    for (const outcome of outcomes) {
      const completion = outcome.completion ?? "NORMAL";
      const predicates = [...(outcome.predicates ?? outcome.context?.pathPredicates ?? [])];
      const normalized = { ...outcome, completion, predicates };
      const lifecycle = normalized.context?.ap;
      const lifecycleKey = lifecycle ? JSON.stringify({
        poolAllocated: lifecycle.poolAllocated,
        poolAllocatedAny: lifecycle.poolAllocatedAny,
        authorityMinted: lifecycle.authorityMinted,
        authorityMintedAny: lifecycle.authorityMintedAny,
        authorityGuardPassed: lifecycle.authorityGuardPassed,
        identity2Validated: lifecycle.identity2Validated,
        fingerprintsEqual: lifecycle.fingerprintsEqual,
        migrationAttempted: lifecycle.migrationAttempted,
        migrationCompleted: lifecycle.migrationCompleted,
        authorityRevoked: lifecycle.authorityRevoked,
        authorityRevokedWhenMinted: lifecycle.authorityRevokedWhenMinted,
        cleanupAttempts: lifecycle.cleanupAttempts,
        cleanupEntryCount: lifecycle.cleanupEntryCount,
        poolAllocationCleanupAttempts: lifecycle.poolAllocationCleanupAttempts,
        cleanupSites: [...(lifecycle.cleanupSites ?? [])].sort(),
        cleanupAttempted: lifecycle.cleanupAttempted,
        cleanupSucceeded: lifecycle.cleanupSucceeded,
      }) : "";
      const catchKey = normalized.context?.publicReturnFromCatch === true ? "catch" : "ordinary";
      const groupKey = completion + "::" + catchKey + "::" + lifecycleKey;
      const existing = groups.get(groupKey);
      if (!existing) {
        groups.set(groupKey, {
          ...normalized,
          env: normalized.env ? this.cloneEnvironment(normalized.env) : normalized.env,
          context: normalized.context ? this.cloneAnalysisContext(normalized.context) : null,
          pathPredicateAlternativeCount: normalized.pathPredicateAlternativeCount ?? 1,
        });
        continue;
      }
      if (existing.env && normalized.env) {
        existing.env = this.joinEnvironments(existing.env, normalized.env);
      } else {
        existing.env ??= normalized.env;
      }
      if (existing.context || normalized.context) {
        const mergedContext = this.cloneAnalysisContext(existing.context ?? normalized.context);
        this.mergeAnalysisContexts(mergedContext,
          [existing.context, normalized.context].filter(Boolean));
        existing.context = mergedContext;
      }
      if (existing.value && normalized.value) {
        existing.value = mergeValues(existing.value, normalized.value);
      } else {
        existing.value ??= normalized.value;
      }
      if (existing.error && normalized.error) {
        existing.error = mergeValues(existing.error, normalized.error);
      } else {
        existing.error ??= normalized.error;
      }
      if (existing.sideEffects && normalized.sideEffects) {
        existing.sideEffects = this.mergeSideEffectStates([existing.sideEffects, normalized.sideEffects]);
      } else if (existing.sideEffects !== normalized.sideEffects) {
        existing.sideEffects = null;
      }
      const predicateKeys = new Set(normalized.predicates.map((predicate) => JSON.stringify(predicate)));
      existing.predicates = existing.predicates.filter((predicate) => predicateKeys.has(JSON.stringify(predicate)));
      existing.pathPredicateAlternativeCount += normalized.pathPredicateAlternativeCount ?? 1;
      for (const key of ["originalCompletion", "propagatedCompletion"]) {
        if (existing[key] !== normalized[key]) existing[key] = null;
      }
    }
    return [...groups.values()];
  }

  mergeAnalysisContexts(target, contexts) {
    const ranges = contexts.map((context) => context.operationRange ?? { min: 0, max: 0 });
    target.operationRange = {
      min: minimumOf(ranges, (range) => range.min),
      max: maximumOf(ranges, (range) => range.max),
    };
    this.mergePathPredicateState(target, contexts);
    const facts = contexts.map((context) => context.ap ?? this.initialAnalysisFacts());
    const cleanupSites = new Set(facts[0].cleanupSites ?? []);
    for (const fact of facts.slice(1)) {
      for (const site of [...cleanupSites]) {
        if (!(fact.cleanupSites instanceof Set) || !fact.cleanupSites.has(site)) cleanupSites.delete(site);
      }
    }
    const allocatedPoolFacts = facts.filter((fact) => fact.poolAllocatedAny ?? fact.poolAllocated);
    const mintedAuthorityFacts = facts.filter((fact) => fact.authorityMintedAny ?? fact.authorityMinted);
    target.ap = {
      poolAllocated: facts.every((fact) => fact.poolAllocated),
      poolAllocatedAny: facts.some((fact) => fact.poolAllocatedAny ?? fact.poolAllocated),
      poolAllocationCleanupAttempts: allocatedPoolFacts.length === 0
        ? { min: 0, max: 0 }
        : {
          min: minimumOf(allocatedPoolFacts, (fact) => fact.poolAllocationCleanupAttempts?.min ?? fact.cleanupAttempts.min),
          max: maximumOf(allocatedPoolFacts, (fact) => fact.poolAllocationCleanupAttempts?.max ?? fact.cleanupAttempts.max),
        },
      authorityMinted: facts.every((fact) => fact.authorityMinted),
      authorityMintedAny: facts.some((fact) => fact.authorityMintedAny ?? fact.authorityMinted),
      authorityRevokedWhenMinted: mintedAuthorityFacts.length > 0 && mintedAuthorityFacts.every((fact) =>
        fact.authorityRevokedWhenMinted ?? fact.authorityRevoked),
      authorityGuardPassed: facts.every((fact) => fact.authorityGuardPassed),
      identity2Validated: facts.every((fact) => fact.identity2Validated),
      fingerprintsEqual: facts.every((fact) => fact.fingerprintsEqual),
      migrationAttempted: facts.every((fact) => fact.migrationAttempted),
      migrationCompleted: facts.every((fact) => fact.migrationCompleted),
      authorityRevoked: facts.every((fact) => fact.authorityRevoked),
      cleanupAttempts: {
        min: minimumOf(facts, (fact) => fact.cleanupAttempts.min),
        max: maximumOf(facts, (fact) => fact.cleanupAttempts.max),
      },
      cleanupEntryCount: {
        min: minimumOf(facts, (fact) => fact.cleanupEntryCount?.min ?? fact.cleanupAttempts.min),
        max: maximumOf(facts, (fact) => fact.cleanupEntryCount?.max ?? fact.cleanupAttempts.max),
      },
      cleanupSites,
      cleanupAttempted: facts.every((fact) => fact.cleanupAttempted === true),
      cleanupSucceeded: facts.every((fact) => fact.cleanupSucceeded === true),
      originalCompletion: facts.every((fact) => fact.originalCompletion === facts[0].originalCompletion)
        ? facts[0].originalCompletion : null,
      propagatedCompletion: facts.every((fact) => fact.propagatedCompletion === facts[0].propagatedCompletion)
        ? facts[0].propagatedCompletion : null,
    };
    target.publicReturnFromCatch = contexts.length > 0 && contexts.every((context) =>
      context.publicReturnFromCatch === true);
    return target;
  }

  markAnalysisFact(context, name) {
    if (!context?.ap) return;
    context.ap[name] = true;
    if (name === "poolAllocated") {
      context.ap.poolAllocatedAny = true;
      context.ap.poolAllocationCleanupAttempts ??= { min: 0, max: 0 };
    }
    if (name === "authorityMinted") context.ap.authorityMintedAny = true;
    if (name === "authorityRevoked") context.ap.authorityRevokedWhenMinted = true;
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
          if (key) {
            keys.add(key);
            this.bindingDeclarations.set(key, declaration);
          }
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
    if (defaultOrigin) result.exactRelations.add(defaultOrigin);
    return result;
  }

  analyze() {
    this.validateImportsAndIndex();
    this.inventoryExecutableChildren();
    this.scanModuleInitializers();
    this.rootFunction = this.findRootFunction();
    this.validateIdentityQueryDefinition();
    const input = value({ kind: "input" });
    const operation = value({ kind: "opaque-function", caps: ["OPAQUE_OPERATION"] });
    const initialRootContext = {
      pathPredicates: [],
      operationRange: { min: 0, max: 0 },
      loopDepth: 0,
      ap: {
        poolAllocated: false,
        poolAllocatedAny: false,
        poolAllocationCleanupAttempts: { min: 0, max: 0 },
        authorityMinted: false,
        authorityMintedAny: false,
        authorityRevokedWhenMinted: false,
        authorityGuardPassed: false,
        identity2Validated: false,
        fingerprintsEqual: false,
        migrationAttempted: false,
        migrationCompleted: false,
        authorityRevoked: false,
        cleanupAttempts: { min: 0, max: 0 },
        cleanupEntryCount: { min: 0, max: 0 },
        cleanupSites: new Set(),
        cleanupAttempted: false,
        cleanupSucceeded: false,
        originalCompletion: null,
        propagatedCompletion: null,
      },
    };
    const initialRootResult = this.analyzeFunction(
      this.rootFunction, [input, operation], null, null, initialRootContext, this.rootFunction,
    );
    let summariesConverged = this.drainSummaryWorklist();
    const rootSummary = this.summaryStates.get(this.rootSummaryKey);
    let rootResult = rootSummary?.result ?? initialRootResult;
    let rootContext = rootSummary?.finalContext ?? initialRootContext;
    const rootSuccessAlternatives = (rootSummary?.completionAlternatives ?? [])
      .filter((outcome) => outcome.completion === "NORMAL" || outcome.completion === "RETURN");
    const successfulSideEffects = rootSuccessAlternatives.map((outcome) => outcome.sideEffects).filter(Boolean);
    if (successfulSideEffects.length > 0) {
      this.restoreSideEffectState(this.mergeSideEffectStates(successfulSideEffects));
    }
    const terminalFailures = [];
    const completionCleanupFailure = (rootSummary?.completionAlternatives ?? []).some((outcome) => {
      const lifecycle = outcome.context?.ap;
      if (!lifecycle) return false;
      const attempts = lifecycle.poolAllocationCleanupAttempts ?? lifecycle.cleanupEntryCount;
      return (lifecycle.poolAllocatedAny ?? lifecycle.poolAllocated) &&
        (attempts?.min !== 1 || attempts?.max !== 1);
    });
    if (completionCleanupFailure) {
      terminalFailures.push(new StaticFailure(SAFE.flow, "CAPABILITY_CLEANUP", "AP_CLEANUP"));
    }
    const completionRevocationFailure = (rootSummary?.completionAlternatives ?? []).some((outcome) => {
      const lifecycle = outcome.context?.ap;
      return Boolean((lifecycle?.authorityMintedAny ?? lifecycle?.authorityMinted) &&
        !(lifecycle.authorityRevokedWhenMinted ?? lifecycle.authorityRevoked));
    });
    if (completionRevocationFailure) {
      terminalFailures.push(new StaticFailure(SAFE.authority, "AUTHORITY_SCHEMA", "AP_REVOCATION"));
    }
    const collectTerminalFailure = (action) => {
      try {
        action();
      } catch (error) {
        if (!(error instanceof StaticFailure)) throw error;
        terminalFailures.push(error);
      }
    };
    collectTerminalFailure(() => this.inspectEscapedValue(rootResult, new Set()));
    if (this.summaryWorklist.length > 0) {
      summariesConverged = this.drainSummaryWorklist() && summariesConverged;
      rootResult = rootSummary?.result ?? rootResult;
      rootContext = rootSummary?.finalContext ?? rootContext;
      collectTerminalFailure(() => this.inspectEscapedValue(rootResult, new Set()));
    }
    const totalTraversal = this.executionObligations.size > 0 &&
      [...this.executionObligations.values()].every((state) => state === "executed" || state === "dormant") &&
      this.activeExecutionObligations.size === 0;
    this.traversalClosed = totalTraversal;
    const provenanceComplete = this.provenanceObligations.size === 0;
    const rootRisk = summarizeRisk(rootResult);
    const publicThrown = (rootSummary?.completionAlternatives ?? []).some((outcome) => {
      if (outcome.completion !== "THROW") return false;
      const sensitiveCause = (item, seen = new Set()) => {
        if (!item || (typeof item !== "object" && typeof item !== "function") || seen.has(item)) return false;
        seen.add(item);
        if (item.kind === "input" ||
            (summarizeRisk(item).taint & (Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC)) !== 0) return true;
        return [
          ...(item.refs ?? []),
          ...(item.props?.values?.() ?? []),
          ...(item.elements ?? []),
          ...(item.map?.values?.() ?? []),
        ].some((child) => sensitiveCause(child, seen));
      };
      const thrown = outcome.error ?? outcome.value;
      const thrownRisk = summarizeRisk(thrown);
      return sensitiveCause(thrown) || (thrownRisk.caps.size > 0 && !thrownRisk.caps.has("CATCH_ERROR"));
    });
    if (publicThrown) terminalFailures.push(new StaticFailure("SSC_PUBLIC_SURFACE", "PUBLIC_CAUSE", "CF_PUBLIC_THROW"));
    if (rootResult.kind === "unknown" ||
        rootResult.kind === "input" ||
        rootResult.kind === "authority-token" ||
        (rootRisk.taint & (Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC | Taint.MAYBE_SENSITIVE)) ||
        rootRisk.caps.size > 0) {
      terminalFailures.push(new StaticFailure(SAFE.flow, "PUBLIC_RETURN"));
    }
    const publicBoundaryFailure = terminalFailures.some((failure) =>
      failure.violations.has("CF_PUBLIC_ESCAPE") || failure.violations.has("CF_PUBLIC_THROW"));
    const rootReturnLeaks = terminalFailures.some((failure) =>
      failure.detector === "PUBLIC_RETURN" && failure.violations.has("CF_PUBLIC_ESCAPE"));
    const publicReturnOperationFailure = (rootSummary?.completionAlternatives ?? []).some((outcome) => {
      if (!(["NORMAL", "RETURN"].includes(outcome.completion)) ||
          outcome.context?.publicReturnFromCatch === true) return false;
      const item = outcome.value ?? outcome.result;
      const risk = summarizeRisk(item);
      const leaks = item?.kind === "unknown" || item?.kind === "input" || item?.kind === "authority-token" ||
        (risk.taint & (Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC | Taint.MAYBE_SENSITIVE)) !== 0 ||
        risk.caps.size > 0 || containsPublicBoundaryValue(item, new Set(), this.publicEscapeFunctionIds);
      const range = outcome.context?.operationRange ?? { min: 0, max: 0 };
      return leaks && (range.min !== 1 || range.max !== 1);
    });
    const hasEscapingPublicReturnBeforeOperation = publicReturnOperationFailure ||
      (rootReturnLeaks && (rootSummary?.completionAlternatives ?? []).some((outcome) => {
        if (!["NORMAL", "RETURN"].includes(outcome.completion) ||
            outcome.context?.publicReturnFromCatch === true) return false;
        const range = outcome.context?.operationRange ?? { min: 0, max: 0 };
        return range.min !== 1 || range.max !== 1;
      }));
    if (terminalFailures.some((failure) => failure.violations.has("CF_PUBLIC_ESCAPE")) &&
        !terminalFailures.some((failure) => failure.violations.has("CF_PUBLIC_THROW")) &&
        hasEscapingPublicReturnBeforeOperation) {
      terminalFailures.push(new StaticFailure(SAFE.flow, "CAPABILITY_CALLBACK", "AP_OPERATION"));
    }
    if (!publicBoundaryFailure) {
      if (this.poolConstructs !== 1 || this.declassificationCount > 1) {
        terminalFailures.push(new StaticFailure(SAFE.flow, "CAPABILITY_POOL"));
      }
      if (!this.authorityRecord || this.authoritySetCount !== 1) {
        terminalFailures.push(new StaticFailure(SAFE.authority, "AUTHORITY_SCHEMA"));
      }
      if (rootContext.operationRange.min !== 1 || rootContext.operationRange.max !== 1) {
        terminalFailures.push(new StaticFailure(SAFE.flow, "CAPABILITY_CALLBACK", "AP_OPERATION"));
      }
      if (!summariesConverged) {
        terminalFailures.push(new StaticFailure(SAFE.internal, "FIXED_POINT_NONCONVERGENCE", "CF_NONCONVERGENCE"));
      }
      if (!totalTraversal) {
        terminalFailures.push(new StaticFailure(SAFE.ast, "TOP_LEVEL_SYNTAX", "TV_CHILD_UNDISPOSED"));
      }
      if (!provenanceComplete) {
        terminalFailures.push(new StaticFailure(SAFE.authority, "CAPABILITY_RECONSTRUCTION", "PV_EXACT_RELATION"));
      }
      if (!rootContext.ap.authorityGuardPassed) {
        terminalFailures.push(new StaticFailure(SAFE.authority, "AUTHORITY_SCHEMA", "AP_AUTHORITY_GUARD"));
      }
      if (!rootContext.ap.fingerprintsEqual) {
        terminalFailures.push(new StaticFailure(SAFE.authority, "AUTHORITY_SCHEMA", "AP_FINGERPRINT_COMPARE"));
      }
      if (!rootContext.ap.migrationCompleted) {
        terminalFailures.push(new StaticFailure(SAFE.flow, "CAPABILITY_MIGRATE", "AP_MIGRATION"));
      }
      if ((rootContext.ap.authorityMintedAny ?? rootContext.ap.authorityMinted) &&
          !(rootContext.ap.authorityRevokedWhenMinted ?? rootContext.ap.authorityRevoked)) {
        terminalFailures.push(new StaticFailure(SAFE.authority, "AUTHORITY_SCHEMA", "AP_REVOCATION"));
      }
      const poolCleanupAttempts = rootContext.ap.poolAllocationCleanupAttempts ?? rootContext.ap.cleanupAttempts;
      if ((rootContext.ap.poolAllocatedAny ?? rootContext.ap.poolAllocated) &&
          (poolCleanupAttempts.min !== 1 || poolCleanupAttempts.max !== 1)) {
        terminalFailures.push(new StaticFailure(SAFE.flow, "CAPABILITY_CLEANUP", "AP_CLEANUP"));
      }
      if (this.pendingSecretStorage) {
        terminalFailures.push(new StaticFailure(SAFE.flow, "CAPABILITY_STORAGE", "CF_PUBLIC_ESCAPE"));
      }
      if (this.pendingPasswordOperation) {
        terminalFailures.push(new StaticFailure(SAFE.flow, "CAPABILITY_PASSWORD", "AP_TOKEN"));
      }
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
      summariesConverged,
      totalTraversal,
      provenanceComplete,
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

  validateIdentityQueryDefinition() {
    const identitySqlDeclaration = this.sourceFile.statements
      .filter(ts.isVariableStatement)
      .flatMap((statement) => statement.declarationList.declarations)
      .find((declaration) => ts.isIdentifier(declaration.name) && declaration.name.text === "identitySql");
    const initializer = identitySqlDeclaration?.initializer;
    if (!initializer || !ts.isNoSubstitutionTemplateLiteral(initializer)) {
      fail(SAFE.flow, "CAPABILITY_QUERY", "AP_IDENTITY_SQL");
    }
    const normalizedIdentitySql = initializer.text.replace(/\s+/gu, " ").trim().toLowerCase();
    const expectedIdentitySql = "select current_database() = $1 as database_matches, " +
      "session_user = $2 as user_matches, " +
      "current_setting('server_version_num')::integer / 10000 = 17 as postgres17, " +
      "not pg_is_in_recovery() as non_recovery, " +
      "(select system_identifier::text from pg_control_system()) as catalog_fingerprint, " +
      "(select oid::text from pg_database where datname = current_database()) as lifecycle_fingerprint";
    if (normalizedIdentitySql !== expectedIdentitySql) {
      fail(SAFE.flow, "CAPABILITY_QUERY", "AP_IDENTITY_SQL");
    }
    this.identitySqlText = initializer.text;
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
    const callableTargets = item.callableTargets?.length
      ? item.callableTargets
      : item.fn && isFunctionLike(item.fn)
        ? [{ fn: item.fn, closure: item.closure, captureKeys: item.captureKeys,
          captureCells: item.captureCells, bound: item.bound }]
        : [];
    for (const target of callableTargets) {
      if (!target.fn || !isFunctionLike(target.fn)) fail(SAFE.unresolved, "CALL_RESOLUTION", "TV_CALLBACK_UNMODELED");
      const signature = String(target.fn.pos) + ":" + String(target.fn.end);
      if (this.functionActive.has(signature)) continue;
      const args = target.fn.parameters.map(() => value({ kind: "escaped-argument" }));
      const result = this.analyzeFunction(target.fn, args, target.closure, target.bound,
        {}, null, target.captureCells);
      const risk = summarizeRisk(result);
      if (result?.kind === "unknown" || risk.taint !== Taint.NONE || risk.caps.size > 0) {
        this.publicEscapeFunctionIds.add(signature);
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
        if (statement.body) this.markDormantSubtree(statement.body);
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
        const fn = value({ kind: "function", fn: statement, closure: moduleEnv, captureKeys: this.captureKeysFor(statement), captureCells: this.captureCellsFor(this.captureKeysFor(statement), moduleEnv) });
        const key = keyForDeclaration(statement.name);
        this.setBinding(moduleEnv, key, fn);
        this.topValues.set(key, fn);
        this.topValuesByName.set(statement.name.text, fn);
        this.bindingNames.set(key, statement.name.text);
      } else if (ts.isClassDeclaration(statement) && statement.name) {
        const cls = value({ kind: "class", fn: statement, closure: moduleEnv, captureKeys: this.captureKeysFor(statement) });
        const key = keyForDeclaration(statement.name);
        this.setBinding(moduleEnv, key, cls);
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
            this.setBinding(moduleEnv, key, initialized);
            this.bindingNames.set(key, declaration.name.text);
          } else {
            const empty = unknownValue();
          this.topValues.set(key, empty);
          this.topValuesByName.set(declaration.name.text, empty);
          if (declaration.name.text === "migrationAuthorityValues") empty.role = "authority-store";
            this.setBinding(moduleEnv, key, empty);
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
        this.analyzeStatements(member.body.statements, this.cloneEnvironment(env), {});
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
      if (env.has(key)) {
        this.recordCellRead(env, key);
        return env.get(key);
      }
      if (ts.isShorthandPropertyAssignment(declaration)) {
        const matches = [...env.entries()].filter(([candidate]) => this.bindingNames.get(candidate) === identifier.text);
        if (matches.length === 1) return matches[0][1];
      }
      if (this.topValues.has(key)) {
        this.recordCellRead(this.topValues, key);
        return this.topValues.get(key);
      }
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
        return value({ kind: "function", fn: declaration, closure: env, captureKeys: this.captureKeysFor(declaration), captureCells: this.captureCellsFor(this.captureKeysFor(declaration), env) });
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

  analyzeFunction(node, args, closure, thisValue = null, parentContext = null, callsite = null, captureCells = null) {
    const captureKeys = this.captureKeysFor(node);
    const captures = captureCells instanceof Map
      ? this.mergeCaptureCellMaps(captureCells, new Map())
      : this.captureCellsFor(captureKeys, closure ?? this.topValues);
    const summary = this.summaryFor(node, args, closure ?? this.topValues, thisValue,
      parentContext ?? {}, callsite, captures);
    const result = this.executeSummary(summary, summary.args, summary.closure, summary.thisValue,
      parentContext ?? {}, callsite, false);
    const outcomes = summary.completionAlternatives ?? [];
    this.expressionCompletionOutcomes.set(result, outcomes.map((outcome) => ({
      completion: outcome.completion === "THROW" ? "THROW" : "NORMAL",
      value: outcome.completion === "RETURN" ? outcome.value : result,
      error: outcome.error ?? null,
      context: outcome.context ?? summary.finalContext ?? parentContext,
      sideEffects: outcome.sideEffects ?? summary.sideEffectResult,
    })));
    return result;
  }

  expressionOutcomes(expressionValue, fallbackEnv, fallbackContext, normalCompletion = "NORMAL") {
    const outcomes = expressionValue && this.expressionCompletionOutcomes.get(expressionValue);
    if (!outcomes?.length) return null;
    return outcomes.map((outcome) => ({
      completion: outcome.completion === "THROW" ? "THROW" : normalCompletion,
      env: fallbackEnv,
      context: outcome.context ?? fallbackContext,
      value: normalCompletion === "RETURN" ? outcome.value ?? expressionValue : null,
      error: outcome.completion === "THROW" ? outcome.error : null,
      sideEffects: outcome.sideEffects,
      predicates: [...((outcome.context ?? fallbackContext)?.pathPredicates ?? [])],
    }));
  }

  executeFunctionBody(node, args, closure, thisValue = null, parentContext = null) {
    const signature = String(node.pos) + ":" + String(node.end);
    this.activatedFunctionNodes.add(signature);
    if (node.body) this.markDormantSubtree(node.body);
    if (this.functionActive.has(signature)) fail(SAFE.flow, "FIXED_POINT_RECURSION");
    this.functionActive.add(signature);
    this.pendingSummaries.add(signature);
    this.activeExecutionObligations.add("function:" + signature);
    const previousThis = this.currentThis;
    this.currentThis = thisValue ?? previousThis;
    try {
      const env = this.cloneEnvironment(closure ?? this.topValues);
      const captureNode = value({ kind: "callable" });
      const captureKeys = this.captureKeysFor(node);
      for (const key of captureKeys) {
        if (env.has(key)) this.graphEdge(captureNode, env.get(key), "CAPTURES");
      }
      for (const [index, parameter] of node.parameters.entries()) {
        this.bindParameter(parameter, args[index], env);
      }
      if (!node.body) fail(SAFE.ast, "SYNTAX_POLICY");
      this.dischargeExecution(node.body);
      const result = ts.isBlock(node.body)
        ? this.analyzeStatements(node.body.statements, env, parentContext ?? {})
        : { env, returnValue: this.evalExpression(node.body, env, parentContext ?? {}), completion: "NORMAL" };
      const continuingContexts = (result.completionAlternatives ?? [])
        .filter((outcome) => outcome.completion === "NORMAL" || outcome.completion === "RETURN")
        .map((outcome) => outcome.context)
        .filter(Boolean);
      if (continuingContexts.length > 0 && parentContext) {
        this.mergeAnalysisContexts(parentContext, continuingContexts);
      }
      this.propagateClosure(closure, result.env ?? env, captureKeys);
      this.graphNode(result.returnValue, "return");
      const summary = this.summaryExecutionStack.at(-1);
      if (summary) {
        summary.completionAlternatives = result.completionAlternatives ?? [{
          completion: result.completion ?? "NORMAL",
          value: result.returnValue ?? primitiveValue("undefined"),
          environment: result.env ?? env,
          lifecycle: this.cloneAnalysisContext(parentContext ?? {}).ap,
        }];
        summary.lastExecution = {
          result: result.returnValue ?? primitiveValue("undefined"),
          completion: result.completion ?? "NORMAL",
          environment: result.env ?? env,
        };
      }
      return result.returnValue ?? primitiveValue("undefined");
    } finally {
      this.currentThis = previousThis;
      this.functionActive.delete(signature);
      this.pendingSummaries.delete(signature);
      this.activeExecutionObligations.delete("function:" + signature);
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
      this.setBinding(env, keyForDeclaration(parameter.name), source);
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
        this.setBinding(env, keyForDeclaration(element.name), item);
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
        this.setBinding(env, keyForDeclaration(element.name), item);
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
      if (env.has(key)) {
        this.setBinding(closure, key, mergeValues(closure.get(key), env.get(key)));
      }
    }
  }

  analyzeClassConstructor(node, args, closure, knownClass = null) {
    const instance = value({ kind: "instance" });
    const classRef = knownClass ?? this.evalClass(node, closure ?? this.topValues);
    instance.classRef = classRef;
    rememberReference(instance, classRef);
    this.analyzeClassConstructorOnInstance(classRef, args, instance);
    return instance;
  }

  analyzeClassConstructorOnInstance(classRef, args, instance) {
    const node = classRef?.fn;
    if (!node || (!ts.isClassDeclaration(node) && !ts.isClassExpression(node))) {
      fail(SAFE.unresolved, "CALL_RESOLUTION", "TV_CALLBACK_UNMODELED");
    }
    const constructor = node.members.find((member) => ts.isConstructorDeclaration(member));
    const captureKeys = this.captureKeysFor(node);
    const env = this.cloneEnvironment(classRef.closure ?? this.topValues);
    for (const [index, parameter] of (constructor?.parameters ?? []).entries()) {
      this.bindParameter(parameter, args[index], env);
    }
    const frame = { classRef, instance, env, superCalled: false };
    const previousThis = this.currentThis;
    const previousClassFrame = this.currentClassConstructor;
    this.currentThis = instance;
    this.currentClassConstructor = frame;
    try {
      if (!constructor) {
        if (classRef.baseClass) this.analyzeClassConstructorOnInstance(classRef.baseClass, args, instance);
        this.initializeClassFields(classRef, env);
        return instance;
      }
      if (!classRef.baseClass) this.initializeClassFields(classRef, env);
      if (!constructor.body) fail(SAFE.ast, "SYNTAX_POLICY");
      const result = this.analyzeStatements(constructor.body.statements, env, {});
      if ((classRef.baseClass || classRef.baseError) && !frame.superCalled) {
        fail(SAFE.ast, "SYNTAX_POLICY", "TV_CHILD_UNDISPOSED");
      }
      this.propagateClosure(classRef.closure, result.env ?? env, captureKeys);
      if (result.returnValue && result.returnValue.label !== "undefined") return result.returnValue;
      return instance;
    } finally {
      this.currentThis = previousThis;
      this.currentClassConstructor = previousClassFrame;
    }
  }

  initializeClassFields(classRef, env) {
    for (const member of classRef.fn.members) {
      if (!ts.isPropertyDeclaration(member) || !member.initializer ||
          member.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.StaticKeyword)) continue;
      if (!member.name || member.name.kind === ts.SyntaxKind.ComputedPropertyName || !ts.isIdentifier(member.name)) {
        fail(SAFE.ast, "SYNTAX_POLICY");
      }
      const initialized = this.evalExpression(member.initializer, env, {});
      if (hasTaint(initialized, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC)) {
        fail(SAFE.flow, "CAPABILITY_STORAGE", "CF_PUBLIC_ESCAPE");
      }
      assignValueProperty(this.currentThis, member.name.text, initialized);
    }
  }
  classConstructorHasRelevantInput(callee, args) {
    return args.some((item) => item?.kind === "input" ||
      hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC | Taint.MAYBE_SENSITIVE) ||
      provenanceOf(item).size > 0);
  }

  statementOutcomes(result, fallbackEnv, fallbackContext) {
    if (Array.isArray(result?.completionAlternatives)) return this.mergeCompletionAlternatives(result.completionAlternatives.map((outcome) => ({
      ...outcome,
      context: outcome.context ? this.cloneAnalysisContext(outcome.context)
        : fallbackContext ? this.cloneAnalysisContext(fallbackContext) : null,
      predicates: [...(outcome.predicates ?? outcome.context?.pathPredicates ?? [])],
    })));
    return [{ completion: result?.completion ?? "NORMAL", env: result?.env ?? fallbackEnv,
      context: fallbackContext ? this.cloneAnalysisContext(fallbackContext) : null,
      value: result?.completion === "RETURN" ? result.returnValue : null,
      error: result?.error ?? null, predicates: [...(fallbackContext?.pathPredicates ?? [])] }];
  }

  summarizeStatementOutcomes(outcomes, fallbackEnv, fallbackContext) {
    const alternatives = outcomes.length > 0 ? outcomes : [{ completion: "NORMAL", env: fallbackEnv,
      context: fallbackContext, value: null, error: null,
      predicates: [...(fallbackContext?.pathPredicates ?? [])] }];
    const feasible = this.mergeCompletionAlternatives(alternatives.map((outcome) => ({
      ...outcome,
      context: outcome.context ? this.cloneAnalysisContext(outcome.context)
        : fallbackContext ? this.cloneAnalysisContext(fallbackContext) : null,
      predicates: [...(outcome.predicates ?? outcome.context?.pathPredicates ?? [])],
    })));
    const contexts = feasible.map((outcome) => outcome.context).filter(Boolean);
    if (fallbackContext && contexts.length > 0) this.mergeAnalysisContexts(fallbackContext, contexts);
    const sideEffectStates = feasible.map((outcome) => outcome.sideEffects).filter(Boolean);
    if (sideEffectStates.length > 0) this.restoreSideEffectState(this.mergeSideEffectStates(sideEffectStates));
    let joinedEnv = feasible[0].env ?? fallbackEnv;
    for (const outcome of feasible.slice(1)) joinedEnv = this.joinEnvironments(joinedEnv, outcome.env ?? fallbackEnv);
    let returnValue = null;
    let errorValue = null;
    for (const outcome of feasible) {
      if (outcome.completion === "RETURN") returnValue = mergeValues(returnValue, outcome.value);
      if (outcome.completion === "THROW") errorValue = mergeValues(errorValue, outcome.error);
    }
    const completions = new Set(feasible.map((outcome) => outcome.completion));
    return { env: joinedEnv, returnValue, error: errorValue,
      completion: completions.has("NORMAL") ? "NORMAL" : completions.size === 1 ? feasible[0].completion : "ABRUPT",
      completionAlternatives: feasible };
  }

  analyzeStatements(statements, env, context) {
    let normal = [{ completion: "NORMAL", env, context, value: null, error: null,
      sideEffects: this.captureSideEffectState(), predicates: [...(context?.pathPredicates ?? [])] }];
    const pending = [];
    for (const [index, statement] of statements.entries()) {
      const next = [];
      const pendingNext = [];
      for (const frame of normal) {
        const obligation = this.executionKey(statement);
        this.activeExecutionObligations.add(obligation);
        this.restoreSideEffectState(frame.sideEffects);
        const result = this.analyzeStatementWithState(statement, frame.env, frame.context);
        this.activeExecutionObligations.delete(obligation);
        for (const outcome of this.statementOutcomes(result, frame.env, frame.context)) {
          if (outcome.completion === "NORMAL") next.push(outcome);
          else pendingNext.push(outcome);
        }
      }
      pending.splice(0, pending.length,
        ...this.mergeCompletionAlternatives([...pending, ...pendingNext]));
      if (next.length === 0) {
        for (const unreachable of statements.slice(index + 1)) this.markDormantSubtree(unreachable);
        normal = [];
        break;
      }
      normal = this.mergeCompletionAlternatives(next);
    }
    return this.summarizeStatementOutcomes([...pending,
      ...normal.map((frame) => ({ ...frame, completion: "NORMAL" }))], env, context);
  }

  analyzeStatement(node, env, context) {
    this.dischargeExecution(node);
    if (ts.isBlock(node)) return this.analyzeStatements(node.statements, env, context);
    if (ts.isEmptyStatement(node) || ts.isDebuggerStatement(node)) {
      return { env, returnValue: null };
    }
    if (ts.isVariableStatement(node)) {
      for (const declaration of node.declarationList.declarations) {
        if (!ts.isIdentifier(declaration.name)) fail(SAFE.ast, "SYNTAX_POLICY");
        const beforeInitialization = this.cloneEnvironment(env);
        const initialized = declaration.initializer
          ? this.evalExpression(declaration.initializer, env, context)
          : primitiveValue("undefined");
        if (initialized.caps.has("OUTPUT") || initialized.caps.has("CRYPTO")) initialized.aliasProvenance = true;
        this.setBinding(env, keyForDeclaration(declaration.name), initialized);
        this.bindingNames.set(keyForDeclaration(declaration.name), declaration.name.text);
        const outcomes = this.expressionOutcomes(initialized, env, context);
        if (outcomes) return { env, returnValue: null, completionAlternatives: outcomes.map((outcome) => ({
          ...outcome,
          env: outcome.completion === "THROW" ? beforeInitialization : this.cloneEnvironment(env),
        })) };
      }
      return { env, returnValue: null };
    }
    if (ts.isExpressionStatement(node)) {
      const expressionValue = this.evalExpression(node.expression, env, context);
      const outcomes = this.expressionOutcomes(expressionValue, env, context);
      return outcomes
        ? { env, returnValue: null, completionAlternatives: outcomes }
        : { env, returnValue: null };
    }
    if (ts.isFunctionDeclaration(node)) {
      if (node.body) this.markDormantSubtree(node.body);
      if (node.name) {
        const fn = value({ kind: "function", fn: node, closure: env, captureKeys: this.captureKeysFor(node), captureCells: this.captureCellsFor(this.captureKeysFor(node), env) });
        this.setBinding(env, keyForDeclaration(node.name), fn);
        this.bindingNames.set(keyForDeclaration(node.name), node.name.text);
        this.graphNode(fn, "function");
      }
      return { env, returnValue: null };
    }
    if (ts.isReturnStatement(node)) {
      const returned = node.expression ? this.evalExpression(node.expression, env, context) : primitiveValue("undefined");
      const outcomes = this.expressionOutcomes(returned, env, context, "RETURN");
      if (outcomes) return { env, returnValue: returned, completion: "ABRUPT",
        completionAlternatives: outcomes };
      return { env, returnValue: returned, completion: "RETURN",
        completionAlternatives: [{ completion: "RETURN", env, context, value: returned, error: null,
          predicates: [...(context?.pathPredicates ?? [])] }] };
    }
    if (ts.isThrowStatement(node)) {
      const thrown = this.evalExpression(node.expression, env, context);
      const expressionOutcomes = this.expressionOutcomes(thrown, env, context, "THROW");
      if (expressionOutcomes) return { env, returnValue: null, error: thrown, completion: "ABRUPT",
        completionAlternatives: expressionOutcomes.map((outcome) => ({
          ...outcome,
          error: outcome.completion === "THROW" && outcome.error ? outcome.error : thrown,
        })) };
      return { env, returnValue: null, error: thrown, completion: "THROW",
        completionAlternatives: [{ completion: "THROW", env, context, value: null, error: thrown,
          predicates: [...(context?.pathPredicates ?? [])] }] };
    }
    if (ts.isIfStatement(node)) {
      const condition = this.evalExpression(node.expression, env, context);
      const concrete = concreteBoolean(condition);
      const baseContext = this.isAdmissionCatchGuard(node.expression, env)
        ? { ...context, allowCatchRethrow: true } : context;
      const refineTruthyIdentifier = (expression, targetEnv, targetContext) => {
        if (!ts.isIdentifier(expression)) return;
        const resolved = this.resolveDeclaration(expression);
        if (resolved?.kind !== "local") return;
        const key = keyForDeclaration(resolved.declaration.name ?? resolved.declaration);
        const current = targetEnv.get(key);
        const candidates = current?.allocationIdentityCandidates ?? new Set();
        if (candidates.size === 1 && current?.allocationMayBeUnknown !== true) {
          const identity = candidates.values().next().value;
          const kind = current.allocationIdentityKinds?.get(identity) ?? current.kind;
          this.setBinding(targetEnv, key, {
            ...current,
            allocationIdentity: identity,
            kind,
            allocationMayBeUnknown: false,
          });
          if (kind === "pool") {
            targetContext.ap.poolAllocated = true;
            targetContext.ap.poolAllocatedAny = true;
            targetContext.ap.poolAllocationCleanupAttempts ??= { min: 0, max: 0 };
          }
          if (kind === "authority-token" && identity === this.authorityToken?.allocationIdentity) {
            this.markAnalysisFact(targetContext, "authorityMinted");
          }
        }
      };
      const branch = (statement, truth, branchEnv = this.cloneEnvironment(env)) => {
        const branchContext = this.cloneAnalysisContext(baseContext);
        if (truth) refineTruthyIdentifier(node.expression, branchEnv, branchContext);
        this.appendPathPredicate(branchContext, { node: this.executionKey(node.expression), truth });
        if (!statement) return [{ completion: "NORMAL", env: branchEnv, context: branchContext,
          value: null, error: null, predicates: branchContext.pathPredicates }];
        return this.statementOutcomes(this.analyzeStatementWithState(statement, branchEnv, branchContext), branchEnv, branchContext);
      };
      if (concrete === true) {
        if (node.elseStatement) this.markDormantSubtree(node.elseStatement);
        if (this.isAuthorityGuardCondition(node.expression) && this.statementAlwaysThrows(node.thenStatement)) this.authorityGuardPassed = true;
        if (this.isFingerprintGuardCondition(node.expression) && this.statementAlwaysThrows(node.thenStatement)) this.fingerprintsEqual = true;
        return this.summarizeStatementOutcomes(branch(node.thenStatement, true), env, context);
      }
      if (concrete === false) {
        this.markDormantSubtree(node.thenStatement);
        const falseContext = this.cloneAnalysisContext(context);
        if (this.statementAlwaysThrows(node.thenStatement)) {
          if (this.isAuthorityGuardCondition(node.expression)) this.markAnalysisFact(falseContext, "authorityGuardPassed");
          if (this.isFingerprintGuardCondition(node.expression)) this.markAnalysisFact(falseContext, "fingerprintsEqual");
        }
        const outcomes = node.elseStatement
          ? this.statementOutcomes(this.analyzeStatementWithState(node.elseStatement, this.cloneEnvironment(env), falseContext), env, falseContext)
          : [{ completion: "NORMAL", env: this.cloneEnvironment(env), context: falseContext,
            value: null, error: null, predicates: [...(falseContext.pathPredicates ?? [])] }];
        return this.summarizeStatementOutcomes(outcomes, env, context);
      }
      if (this.isAuthorityGuardCondition(node.expression) && this.statementAlwaysThrows(node.thenStatement)) this.authorityGuardPassed = true;
      if (this.isFingerprintGuardCondition(node.expression) && this.statementAlwaysThrows(node.thenStatement)) this.fingerprintsEqual = true;
      const trueContext = this.cloneAnalysisContext(baseContext);
      const falseContext = this.cloneAnalysisContext(context);
      this.appendPathPredicate(trueContext, { node: this.executionKey(node.expression), truth: true });
      this.appendPathPredicate(falseContext, { node: this.executionKey(node.expression), truth: false });
      if (this.statementAlwaysThrows(node.thenStatement)) {
        if (this.isAuthorityGuardCondition(node.expression)) this.markAnalysisFact(falseContext, "authorityGuardPassed");
        if (this.isFingerprintGuardCondition(node.expression)) this.markAnalysisFact(falseContext, "fingerprintsEqual");
      }
      const trueEnv = this.cloneEnvironment(env);
      refineTruthyIdentifier(node.expression, trueEnv, trueContext);
      const thenResult = this.analyzeStatementWithState(node.thenStatement, trueEnv, trueContext);
      const elseResult = node.elseStatement
        ? this.analyzeStatementWithState(node.elseStatement, this.cloneEnvironment(env), falseContext)
        : { env: this.cloneEnvironment(env), returnValue: null };
      return this.summarizeStatementOutcomes([
        ...this.statementOutcomes(thenResult, env, trueContext),
        ...this.statementOutcomes(elseResult, env, falseContext),
      ], env, context);
    }
    if (ts.isTryStatement(node)) {
      const tryContext = this.cloneAnalysisContext(context);
      const tryResult = this.analyzeStatementWithState(node.tryBlock, this.cloneEnvironment(env), tryContext);
      const active = [];
      let caughtCount = 0;
      for (const outcome of this.statementOutcomes(tryResult, env, tryContext)) {
        if (outcome.completion !== "THROW" || !node.catchClause) { active.push(outcome); continue; }
        caughtCount += 1;
        const catchEnv = this.cloneEnvironment(outcome.env);
        if (node.catchClause.variableDeclaration) {
          const catchName = node.catchClause.variableDeclaration.name;
          if (!ts.isIdentifier(catchName)) fail(SAFE.ast, "SYNTAX_POLICY");
          const caughtValue = value({ kind: "caught-error",
            taint: Taint.MAYBE_SENSITIVE | combinedTaint([outcome.error]), caps: ["CATCH_ERROR"] });
          if (outcome.error) rememberReference(caughtValue, outcome.error);
          this.setBinding(catchEnv, keyForDeclaration(catchName), caughtValue);
        }
        const catchContext = this.cloneAnalysisContext(outcome.context ?? context);
        catchContext.allowCatchRethrow = true;
        catchContext.publicReturnFromCatch = true;
        this.appendPathPredicate(catchContext, { node: this.executionKey(node.catchClause), caught: true });
        const catchResult = this.analyzeStatementWithState(node.catchClause.block, catchEnv, catchContext);
        active.push(...this.statementOutcomes(catchResult, catchEnv, catchContext));
      }
      if (node.catchClause && caughtCount === 0) this.markDormantSubtree(node.catchClause.block);
      let completed = active;
      if (node.finallyBlock) {
        completed = [];
        for (const incoming of active) {
          const finalContext = this.cloneAnalysisContext(incoming.context ?? context);
          this.restoreSideEffectState(incoming.sideEffects ?? this.captureSideEffectState());
          const finalResult = this.analyzeStatementWithState(node.finallyBlock,
            this.cloneEnvironment(incoming.env), finalContext);
          for (const finalOutcome of this.statementOutcomes(finalResult, incoming.env, finalContext)) {
            const originalCompletion = incoming.originalCompletion ?? incoming.completion;
            const propagatedCompletion = finalOutcome.completion === "NORMAL"
              ? incoming.completion : finalOutcome.completion;
            const completionContext = this.cloneAnalysisContext(finalOutcome.context ?? finalContext);
            completionContext.ap.originalCompletion = originalCompletion;
            completionContext.ap.propagatedCompletion = propagatedCompletion;
            if (finalOutcome.completion === "NORMAL") completed.push({ ...finalOutcome,
              context: completionContext, completion: incoming.completion,
              value: incoming.value, error: incoming.error,
              originalCompletion, propagatedCompletion });
            else completed.push({ ...finalOutcome, context: completionContext,
              originalCompletion, propagatedCompletion });
          }
        }
      }
      return this.summarizeStatementOutcomes(completed, env, context);
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
      if (loopValues.length === 0) this.markDormantSubtree(node.statement);
      let current = this.cloneEnvironment(env);
      let returnValue = null;
      if (ts.isVariableDeclarationList(node.initializer) && node.initializer.declarations.length === 1) {
        const declaration = node.initializer.declarations[0];
        if (!ts.isIdentifier(declaration.name)) fail(SAFE.ast, "SYNTAX_POLICY");
        this.bindingNames.set(keyForDeclaration(declaration.name), declaration.name.text);
        for (const item of loopValues) {
          const loopEnv = this.cloneEnvironment(current);
          this.setBinding(loopEnv, keyForDeclaration(declaration.name), item);
          const trackCapturedCells = this.loopHasCapturedCallable(node.statement, env);
          const cellSnapshot = trackCapturedCells ? this.cellStateSnapshot() : null;
          const result = this.analyzeStatement(node.statement, loopEnv, context);
          if (trackCapturedCells) this.refreshCapturedCells(result.env, this.changedCellIdentities(cellSnapshot));
          current = this.joinEnvironments(current, result.env);
          returnValue = mergeValues(returnValue, result.returnValue);
        }
        return { env: current, returnValue };
      }
      for (const item of loopValues) {
        const loopEnv = this.cloneEnvironment(current);
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
            this.setBinding(env,
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
      const doLoop = ts.isDoStatement(node);
      let current = this.cloneEnvironment(env);
      let returnValue = null;
      let firstIteration = true;
      const loopContext = this.cloneAnalysisContext(context);
      const trackCapturedCells = this.loopHasCapturedCallable(node.statement, env);
      loopContext.loopDepth = (context?.loopDepth ?? 0) + 1;
      while (true) {
        const before = environmentSignature(current) + (trackCapturedCells ? "::" + this.cellStateSignature() : "");
        let conditionValue = null;
        let conditionResult = true;
        if (!doLoop || !firstIteration) {
          conditionValue = condition ? this.evalExpression(condition, current, loopContext) : booleanValue(true);
          conditionResult = concreteBoolean(conditionValue);
          if (conditionResult === false) { this.markDormantSubtree(node.statement); break; }
        }
        const cellSnapshot = trackCapturedCells ? this.cellStateSnapshot() : null;
        const body = this.analyzeStatement(node.statement, this.cloneEnvironment(current), loopContext);
        returnValue = mergeValues(returnValue, body.returnValue);
        if (body.completion === "RETURN" || body.completion === "THROW") {
          this.mergeAnalysisContexts(context, [context, loopContext]);
          return { env: body.env, returnValue, completion: body.completion };
        }
        const changedCells = trackCapturedCells ? this.changedCellIdentities(cellSnapshot) : new Set();
        const backEdge = trackCapturedCells
          ? this.refreshCapturedCells(this.cloneEnvironment(body.env), changedCells)
          : this.cloneEnvironment(body.env);
        if (body.completion !== "BREAK" && node.incrementor) this.evalExpression(node.incrementor, backEdge, loopContext);
        current = this.joinEnvironments(current, backEdge);
        firstIteration = false;
        if (body.completion === "BREAK") break;
        if (doLoop && condition) {
          const doCondition = this.evalExpression(condition, current, loopContext);
          const doResult = concreteBoolean(doCondition);
          if (doResult === false) break;
          if (doResult === null) current = this.joinEnvironments(current, backEdge);
        }
        if (environmentSignature(current) + (trackCapturedCells ? "::" + this.cellStateSignature() : "") === before) break;
      }
      this.mergeAnalysisContexts(context, [context, loopContext]);
      return { env: current, returnValue };
    }
    if (ts.isLabeledStatement(node)) return this.analyzeStatement(node.statement, env, context);
    if (ts.isClassDeclaration(node)) {
      if (!node.name) fail(SAFE.ast, "SYNTAX_POLICY");
      const cls = this.evalClass(node, env);
      this.setBinding(env, keyForDeclaration(node.name), cls);
      this.bindingNames.set(keyForDeclaration(node.name), node.name.text);
      this.graphNode(cls, "class");
      return { env, returnValue: null };
    }
    if (ts.isWithStatement(node) || ts.isSwitchStatement(node)) {
      fail(SAFE.ast, "SYNTAX_POLICY");
    }
    if (ts.isBreakStatement(node)) return { env, returnValue: null, completion: "BREAK" };
    if (ts.isContinueStatement(node)) return { env, returnValue: null, completion: "CONTINUE" };
    fail(SAFE.ast, "SYNTAX_POLICY");
  }

  expressionKey(node) {
    if (ts.isIdentifier(node)) return node.text;
    if (ts.isPropertyAccessExpression(node)) {
      return `${this.expressionKey(node.expression)}.${node.name.text}`;
    }
    if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.ExclamationToken) {
      return `!${this.expressionKey(node.operand)}`;
    }
    return "";
  }

  flattenLogical(node, operatorKind) {
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === operatorKind) {
      return [...this.flattenLogical(node.left, operatorKind), ...this.flattenLogical(node.right, operatorKind)];
    }
    return [node];
  }

  statementAlwaysThrows(statement) {
    if (ts.isThrowStatement(statement)) return true;
    if (ts.isBlock(statement)) {
      const last = statement.statements.at(-1);
      return last ? this.statementAlwaysThrows(last) : false;
    }
    return false;
  }

  isAuthorityGuardCondition(expression) {
    const required = [
      "!value",
      "value.brand!==migrationAuthorityBrand",
      "value.authority!==authority",
      "!value.valid",
      "value.pool!==pool",
      "value.migrationsFolder!==migrationsFolder",
      "value.database!==target.expectedDatabase",
      "value.user!==target.expectedUser",
    ];
    const parts = this.flattenLogical(expression, ts.SyntaxKind.BarBarToken).map((part) => {
      if (ts.isBinaryExpression(part) && part.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken) {
        return `${this.expressionKey(part.left)}!==${this.expressionKey(part.right)}`;
      }
      return this.expressionKey(part);
    });
    return parts.length === required.length && required.every((item) => parts.includes(item));
  }

  isFingerprintGuardCondition(expression) {
    const required = [
      "identity.catalogFingerprint!==value.clusterFingerprint",
      "identity.lifecycleFingerprint!==value.lifecycleFingerprint",
    ];
    const parts = this.flattenLogical(expression, ts.SyntaxKind.BarBarToken).map((part) => {
      if (ts.isBinaryExpression(part) && part.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken) {
        return `${this.expressionKey(part.left)}!==${this.expressionKey(part.right)}`;
      }
      return this.expressionKey(part);
    });
    return parts.length === required.length && required.every((item) => parts.includes(item));
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
    const joined = this.cloneEnvironment(left);
    const keys = new Set([...left.keys(), ...right.keys()]);
    const leftCells = this.environmentCellIds.get(left) ?? new Map();
    const rightCells = this.environmentCellIds.get(right) ?? new Map();
    const joinedCells = this.environmentCellIds.get(joined) ?? new Map();
    for (const key of keys) {
      const leftValue = left.has(key) ? left.get(key) : value({ kind: "unknown", exact: false });
      const rightValue = right.has(key) ? right.get(key) : value({ kind: "unknown", exact: false });
      this.setBinding(joined, key, mergeValues(leftValue, rightValue));
      const cellIds = new Set([...(leftCells.get(key) ?? []), ...(rightCells.get(key) ?? [])]);
      if (cellIds.size > 0) joinedCells.set(key, cellIds);
    }
    this.environmentCellIds.set(joined, joinedCells);
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
    this.dischargeExecution(node);
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
        if (node.body) this.markDormantSubtree(node.body);
        return value({ kind: "function", fn: node, closure: env, captureKeys: this.captureKeysFor(node), captureCells: this.captureCellsFor(this.captureKeysFor(node), env) });
      case ts.SyntaxKind.BinaryExpression:
        return this.evalBinary(node, env, context);
      case ts.SyntaxKind.PrefixUnaryExpression:
        return this.evalPrefixUnary(node, env, context);
      case ts.SyntaxKind.TypeOfExpression:
        this.evalExpression(node.expression, env, context);
        return primitiveValue("string");
      case ts.SyntaxKind.PostfixUnaryExpression:
        return this.evalPostfixUnary(node, env, context);
      case ts.SyntaxKind.ConditionalExpression: {
        const condition = concreteBoolean(this.evalExpression(node.condition, env, context));
        if (condition === true) {
          this.markDormantSubtree(node.whenFalse);
          return this.evalExpression(node.whenTrue, env, context);
        }
        if (condition === false) {
          this.markDormantSubtree(node.whenTrue);
          return this.evalExpression(node.whenFalse, env, context);
        }
        const trueEnv = this.cloneEnvironment(env);
        const falseEnv = this.cloneEnvironment(env);
        const truePathContext = this.cloneAnalysisContext(context);
        const falsePathContext = this.cloneAnalysisContext(context);
        const whenTrue = this.evalExpression(node.whenTrue, trueEnv, truePathContext);
        const whenFalse = this.evalExpression(node.whenFalse, falseEnv, falsePathContext);
        this.mergeAnalysisContexts(context, [truePathContext, falsePathContext]);
        const joined = this.joinEnvironments(trueEnv, falseEnv);
        for (const [key, item] of joined) this.setBinding(env, key, item);
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
    const result = this.allocationFor(node, "array");
    result.elements = elements;
    rememberRisk(result, value({
      kind: "array",
      taint: combinedTaint(elements),
      caps: combinedCaps(elements),
      provenance: combinedProvenance(elements),
    }));
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
    const result = this.allocationFor(node, isPoolOptions ? "pool-options" : "object");
    result.frozen = false;
    const currentPropertyNames = new Set(propertyNames.filter((name) => name !== null));
    for (const [name, previous] of result.props) {
      if (!currentPropertyNames.has(name)) result.historyProps.set(name, mergeValues(result.historyProps.get(name), previous));
    }
    result.props = new Map();
    result.methods = new Map();
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
        this.markDormantSubtree(property.body);
        const method = value({ kind: "function", fn: property, closure: env, captureKeys: this.captureKeysFor(property), captureCells: this.captureCellsFor(this.captureKeysFor(property), env) });
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
    result.baseClass = null;
    result.baseError = false;
    for (const heritage of node.heritageClauses ?? []) {
      for (const type of heritage.types) {
        const base = this.evalExpression(type.expression, env, {});
        if (result.baseClass) fail(SAFE.ast, "SYNTAX_POLICY", "TV_CHILD_UNDISPOSED");
        if (base.kind === "class") result.baseClass = base;
        if (base.caps.has("ERROR_CONSTRUCTOR")) result.baseError = true;
        if (base.kind !== "class" && !base.caps.has("ERROR_CONSTRUCTOR")) {
          fail(SAFE.ast, "SYNTAX_POLICY");
        }
      }
    }
    for (const member of node.members ?? []) {
      if ((ts.isMethodDeclaration(member) || ts.isConstructorDeclaration(member)) && member.body) {
        this.markDormantSubtree(member.body);
      }
      if (ts.isPropertyDeclaration(member) && member.initializer &&
          !member.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.StaticKeyword)) {
        this.markDormantSubtree(member.initializer);
      }
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
        this.analyzeStatements(member.body.statements, this.cloneEnvironment(env), {});
      }
      if (ts.isMethodDeclaration(member) && member.name) {
        const name = this.propertyName(member.name, env, {});
        if (name === null || !member.body) fail(SAFE.ast, "SYNTAX_POLICY");
        const method = value({ kind: "function", fn: member, closure: env, captureKeys: this.captureKeysFor(member), captureCells: this.captureCellsFor(this.captureKeysFor(member), env) });
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
      const port = options.props.get("port");
      const admittedPortNormalization = port?.normalization === "url-port" &&
        provenanceOf(port).has(this.originIdentity("url.port"));
      const host = options.props.get("host");
      const admittedHostNormalization = host?.normalization === "url-hostname" &&
        provenanceOf(host).has(this.originIdentity("url.hostname"));
      if (!(exactOrigin(host, "url.hostname") || admittedHostNormalization) ||
          !(exactOrigin(port, "url.port") || admittedPortNormalization) ||
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
      if (!this.poolConstructionNodes.has(node.pos)) {
        this.poolConstructs += 1;
        this.poolConstructionNodes.add(node.pos);
      }
      if (this.poolConstructs > 1) fail(SAFE.flow, "CAPABILITY_POOL");
      this.markAnalysisFact(context, "poolAllocated");
      this.poolConstructionNodes.add(node.pos);
      this.provenanceObligations.delete("pool-target");
      const activation = this.summaryExecutionStack.at(-1)?.id ??
        this.activationStack.map((frame) => frame.id).join("/");
      const allocationKey = (activation || "module") + "::pool::" + node.pos;
      let pool = this.poolAllocationValues.get(allocationKey);
      if (pool) {
        pool.options = mergeValues(pool.options, options);
      } else {
        pool = value({ kind: "pool", allocationIdentity: allocationKey });
        pool.options = options;
        this.poolAllocationValues.set(allocationKey, pool);
      }
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
        weakmap.map.set(abstractIdentityKey(pair.elements[0]), pair.elements[1]);
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
    if (this.hasCallableTarget(callee)) return this.invokeFunctionValue(callee, args, null, context, node, env);
    fail(SAFE.unresolved, "CALL_RESOLUTION");
  }

  evalBinary(node, env, context) {
    const operator = node.operatorToken.kind;
    if (operator === ts.SyntaxKind.EqualsToken) {
      const right = this.evalExpression(node.right, env, context);
      this.assignTarget(node.left, right, env, context, node);
      return right;
    }
    if (operator === ts.SyntaxKind.CommaToken) {
      this.evalExpression(node.left, env, context);
      return this.evalExpression(node.right, env, context);
    }
    const logical = operator === ts.SyntaxKind.AmpersandAmpersandToken ||
      operator === ts.SyntaxKind.BarBarToken || operator === ts.SyntaxKind.QuestionQuestionToken;
    const left = this.evalExpression(node.left, env, context);
    const leftBoolean = concreteBoolean(left);
    const leftConcrete = leftBoolean !== null;
    const leftTruthy = leftBoolean === true;
    const leftNullish = left.literalType === "null" || left.label === "undefined";
    if (logical) {
      const skipsRight = operator === ts.SyntaxKind.AmpersandAmpersandToken
        ? leftConcrete && !leftTruthy
        : operator === ts.SyntaxKind.BarBarToken
          ? leftConcrete && leftTruthy
          : leftConcrete && !leftNullish;
      if (skipsRight) {
        this.markDormantSubtree(node.right);
        return left;
      }
      if (leftConcrete) return this.evalExpression(node.right, env, context);
      const skippedContext = this.cloneAnalysisContext(context);
      const rightContext = this.cloneAnalysisContext(context);
      const rightEnv = this.cloneEnvironment(env);
      const right = this.evalExpression(node.right, rightEnv, rightContext);
      this.mergeAnalysisContexts(context, [skippedContext, rightContext]);
      for (const [key, item] of this.joinEnvironments(env, rightEnv)) this.setBinding(env, key, item);
      const merged = mergeValues(left, right);
      const defaultOrigin = operator === ts.SyntaxKind.QuestionQuestionToken
        ? this.canonicalDefaultOrigin(node.right)
        : null;
      const defaultKey = defaultOrigin === this.originIdentity("default.expectedUser.cloud_admin")
        ? "input.expectedUser"
        : defaultOrigin === this.originIdentity("default.phase.initialization")
          ? "input.phase"
          : null;
      const inputOrigin = defaultKey ? this.originIdentity(defaultKey) : null;
      if (defaultOrigin && inputOrigin && exactRelationsOf(left).has(inputOrigin) &&
          exactRelationsOf(right).has(defaultOrigin)) {
        merged.exactRelations = new Set([inputOrigin, defaultOrigin]);
        merged.exact = true;
        merged.derived = false;
        merged.precision = "canonical-normalization";
        merged.normalization = "canonical-default";
      }
      return merged;
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
    ].includes(operator)) {
      const current = this.evalExpression(node.left, env, context);
      const right = this.evalExpression(node.right, env, context);
      if (hasTaint(current, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC) ||
          hasTaint(right, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC)) {
        fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION", "PV_EXACT_RELATION");
      }
      if (operator !== ts.SyntaxKind.PlusEqualsToken && operator !== ts.SyntaxKind.MinusEqualsToken &&
          operator !== ts.SyntaxKind.AsteriskEqualsToken && operator !== ts.SyntaxKind.SlashEqualsToken) {
        fail(SAFE.ast, "SYNTAX_POLICY");
      }
      if (current.literalType !== "number" || right.literalType !== "number" ||
          typeof current.constant !== "number" || typeof right.constant !== "number") {
        fail(SAFE.ast, "SYNTAX_POLICY");
      }
      const next = primitiveValue("number", {
        literalType: "number",
        constant: operator === ts.SyntaxKind.PlusEqualsToken
          ? current.constant + right.constant
          : operator === ts.SyntaxKind.MinusEqualsToken
            ? current.constant - right.constant
            : operator === ts.SyntaxKind.AsteriskEqualsToken
              ? current.constant * right.constant
              : current.constant / right.constant,
      });
      next.exact = false;
      this.assignTarget(node.left, next, env, context);
      return next;
    }
    const right = this.evalExpression(node.right, env, context);
    if (operator === ts.SyntaxKind.PlusToken) {
      if (hasTaint(left, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC) ||
          hasTaint(right, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC)) {
        fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION", "PV_EXACT_RELATION");
      }
      if (typeof left.constant === "number" && typeof right.constant === "number") {
        return primitiveValue("number", { literalType: "number", constant: left.constant + right.constant });
      }
      if (typeof left.constant === "string" && typeof right.constant === "string") {
        return primitiveValue("string", { literalType: "string", constant: left.constant + right.constant });
      }
      const result = primitiveValue("string");
      result.exact = false;
      return result;
    }
    if ([
      ts.SyntaxKind.MinusToken,
      ts.SyntaxKind.AsteriskToken,
      ts.SyntaxKind.SlashToken,
      ts.SyntaxKind.PercentToken,
      ts.SyntaxKind.AsteriskAsteriskToken,
    ].includes(operator)) {
      if (hasTaint(left, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC) ||
          hasTaint(right, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC)) {
        fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION", "PV_EXACT_RELATION");
      }
      if (typeof left.constant === "number" && typeof right.constant === "number") {
        const constant = operator === ts.SyntaxKind.MinusToken
          ? left.constant - right.constant
          : operator === ts.SyntaxKind.AsteriskToken
            ? left.constant * right.constant
            : operator === ts.SyntaxKind.SlashToken
              ? left.constant / right.constant
              : operator === ts.SyntaxKind.PercentToken
                ? left.constant % right.constant
                : left.constant ** right.constant;
        return primitiveValue("number", { literalType: "number", constant });
      }
      const result = primitiveValue("number");
      result.exact = false;
      return result;
    }
    if ([
      ts.SyntaxKind.EqualsEqualsEqualsToken,
      ts.SyntaxKind.ExclamationEqualsEqualsToken,
      ts.SyntaxKind.EqualsEqualsToken,
      ts.SyntaxKind.ExclamationEqualsToken,
      ts.SyntaxKind.LessThanToken,
      ts.SyntaxKind.LessThanEqualsToken,
      ts.SyntaxKind.GreaterThanToken,
      ts.SyntaxKind.GreaterThanEqualsToken,
    ].includes(operator)) {
      const concrete = left.literalType !== "abstract" && right.literalType !== "abstract" &&
        left.constant !== undefined && right.constant !== undefined;
      if (!concrete) return primitiveValue("boolean");
      const equal = operator === ts.SyntaxKind.EqualsEqualsEqualsToken || operator === ts.SyntaxKind.EqualsEqualsToken
        ? left.constant === right.constant
        : operator === ts.SyntaxKind.ExclamationEqualsEqualsToken || operator === ts.SyntaxKind.ExclamationEqualsToken
          ? left.constant !== right.constant
          : operator === ts.SyntaxKind.LessThanToken
            ? left.constant < right.constant
            : operator === ts.SyntaxKind.LessThanEqualsToken
              ? left.constant <= right.constant
              : operator === ts.SyntaxKind.GreaterThanToken
                ? left.constant > right.constant
                : left.constant >= right.constant;
      return booleanValue(equal);
    }
    return primitiveValue("boolean");
  }
  evalPrefixUnary(node, env, context) {
    const operand = this.evalExpression(node.operand, env, context);
    if (node.operator === ts.SyntaxKind.ExclamationToken) {
      const concrete = concreteBoolean(operand);
      return concrete === null ? primitiveValue("boolean") : booleanValue(!concrete);
    }
    if (node.operator === ts.SyntaxKind.PlusPlusToken || node.operator === ts.SyntaxKind.MinusMinusToken) {
      const next = this.updatedNumericValue(operand, node.operator === ts.SyntaxKind.PlusPlusToken ? 1 : -1);
      this.assignTarget(node.operand, next, env, context);
      return next;
    }
    if ([ts.SyntaxKind.PlusToken, ts.SyntaxKind.MinusToken, ts.SyntaxKind.TildeToken].includes(node.operator)) {
      if (hasTaint(operand, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC)) {
        fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION", "PV_EXACT_RELATION");
      }
      const number = operand.literalType === "number" || typeof operand.constant === "number"
        ? Number(operand.constant)
        : operand.constant === undefined ? undefined : Number(operand.constant);
      const constant = number === undefined ? undefined
        : node.operator === ts.SyntaxKind.PlusToken ? +number
          : node.operator === ts.SyntaxKind.MinusToken ? -number : ~number;
      return value({
        kind: "primitive", label: "number", literalType: "number", constant,
        taint: summarizeRisk(operand).taint, caps: summarizeRisk(operand).caps,
        provenance: provenanceOf(operand), exact: false,
      });
    }
    fail(SAFE.ast, "SYNTAX_POLICY");
  }

  updatedNumericValue(operand, delta) {
    if (hasTaint(operand, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC)) {
      fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION", "PV_EXACT_RELATION");
    }
    const constant = typeof operand.constant === "number" ? operand.constant + delta : undefined;
    return value({
      kind: "primitive", label: "number", literalType: "number", constant,
      taint: summarizeRisk(operand).taint, caps: summarizeRisk(operand).caps,
      provenance: provenanceOf(operand), exact: false,
    });
  }

  evalPostfixUnary(node, env, context) {
    const operand = this.evalExpression(node.operand, env, context);
    if (node.operator !== ts.SyntaxKind.PlusPlusToken && node.operator !== ts.SyntaxKind.MinusMinusToken) {
      fail(SAFE.ast, "SYNTAX_POLICY");
    }
    const next = this.updatedNumericValue(operand, node.operator === ts.SyntaxKind.PlusPlusToken ? 1 : -1);
    this.assignTarget(node.operand, next, env, context);
    return operand;
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
      const bound = value({ kind: "function", fn: method.fn, closure: method.closure, captureKeys: method.captureKeys, captureCells: method.captureCells, bound: receiver });
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
        result.exactRelations.add(this.originIdentity(`input.${name}`));
        this.graphEdge(receiver, result, "READS");
        return result;
      }
    }
    if (receiver.kind === "row" && QUERY_ROW_FIELDS.has(name)) {
      const result = primitiveValue(`query.${name}`, { constant: undefined });
      result.provenance.add(this.originIdentity(`query.${name}`));
      result.exactRelations.add(this.originIdentity(`query.${name}`));
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

  hasCallableTarget(item) {
    return Boolean(item?.fn && isFunctionLike(item.fn)) || Boolean(item?.callableTargets?.length);
  }

  invokeFunctionValue(item, args, thisValue, parentContext, callsite, callerEnv = null) {
    const targets = item?.callableTargets?.length
      ? item.callableTargets
      : item?.fn && isFunctionLike(item.fn)
        ? [{ fn: item.fn, closure: item.closure, captureKeys: item.captureKeys,
          captureCells: item.captureCells, bound: item.bound }]
        : [];
    if (targets.length === 0) fail(SAFE.unresolved, "CALL_RESOLUTION", "TV_CALLBACK_UNMODELED");
    let result = null;
    const completionOutcomes = [];
    for (const target of targets) {
      if (!target.fn || !isFunctionLike(target.fn)) {
        fail(SAFE.unresolved, "CALL_RESOLUTION", "TV_CALLBACK_UNMODELED");
      }
      const cellSnapshot = callerEnv ? this.cellStateSnapshot(callerEnv) : null;
      const observed = this.analyzeFunction(target.fn, args, target.closure,
        target.bound ?? thisValue, parentContext, callsite, target.captureCells);
      if (callerEnv && target.captureCells instanceof Map) {
        this.refreshCapturedCells(callerEnv, this.changedCellIdentities(cellSnapshot));
      }
      completionOutcomes.push(...(this.expressionCompletionOutcomes.get(observed) ?? [{
        completion: "NORMAL", value: observed, context: parentContext,
      }]));
      result = mergeValues(result, observed);
    }
    const returned = result ?? primitiveValue("undefined");
    this.expressionCompletionOutcomes.set(returned, completionOutcomes);
    return returned;
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
    if (callee.caps.has("CLASS_SUPER")) {
      const frame = this.currentClassConstructor;
      if (!(frame?.classRef?.baseClass || frame?.classRef?.baseError) || frame.superCalled) {
        fail(SAFE.unresolved, "CALL_RESOLUTION", "TV_CHILD_UNDISPOSED");
      }
      frame.superCalled = true;
      if (frame.classRef.baseClass) this.analyzeClassConstructorOnInstance(frame.classRef.baseClass, args, frame.instance);
      this.initializeClassFields(frame.classRef, frame.env);
      return frame.instance;
    }
    if (callee.caps.has("POOL_QUERY")) {
      if (args.length !== 2) {
        fail(SAFE.flow, "CAPABILITY_QUERY", "AP_IDENTITY_ARGUMENTS");
      }
      if (args[0]?.binding !== this.identitySqlBinding || args[0]?.constant !== this.identitySqlText) {
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
      if ((context?.loopDepth ?? 0) > 0) fail(SAFE.flow, "CAPABILITY_QUERY", "AP_IDENTITY_SQL");
      const activationId = this.summaryExecutionStack.at(-1)?.id ??
        this.activationStack.at(-1)?.id ?? "module";
      const querySite = activationId + "::" + String(node.pos);
      const repeatedQuerySite = this.identityQueryNodes.has(querySite);
      if (!repeatedQuerySite && this.identityQueryCount >= 2) {
        fail(SAFE.flow, "CAPABILITY_QUERY", "AP_IDENTITY_SQL");
      }
      const identityArguments = args[1].elements.map((item) => new Set(provenanceOf(item)));
      if (this.identityQueryPool && this.identityQueryPool !== callee.bound) fail(SAFE.flow, "CAPABILITY_QUERY");
      if (this.identityQueryArguments && !sameIdentitySequence(identityArguments, this.identityQueryArguments)) {
        fail(SAFE.flow, "CAPABILITY_QUERY");
      }
      this.identityQueryPool = callee.bound;
      this.identityQueryArguments ??= identityArguments;
      this.identityQueryNodes.add(querySite);
      if (!repeatedQuerySite) this.identityQueryCount += 1;
      this.provenanceObligations.delete("identity-target");
      if (this.identityQueryCount >= 2 && this.authoritySetCount === 1) {
        this.authoritySecondIdentityChecked = true;
        this.markAnalysisFact(context, "identity2Validated");
      }
      return value({ kind: "query-result" });
    }
    if (callee.caps.has("POOL_END")) {
      const cleanupRange = context?.ap?.cleanupAttempts ?? { min: 0, max: 0 };
      const cleanupEntryRange = context?.ap?.cleanupEntryCount ?? cleanupRange;
      const activationId = this.summaryExecutionStack.at(-1)?.id ??
        this.activationStack.at(-1)?.id ?? "module";
      const cleanupSite = activationId + "::" + String(node.pos);
      const repeatedCleanupSite = context?.ap?.cleanupSites?.has(cleanupSite) === true;
      if (context?.ap) {
        context.ap.cleanupSites ??= new Set();
        context.ap.cleanupSites.add(cleanupSite);
        context.ap.cleanupAttempted = true;
        if (!repeatedCleanupSite) {
          context.ap.cleanupEntryCount = (context?.loopDepth ?? 0) > 0
            ? { min: cleanupEntryRange.min, max: 2 }
            : {
              min: Math.min(2, cleanupEntryRange.min + 1),
              max: Math.min(2, cleanupEntryRange.max + 1),
            };
          context.ap.cleanupAttempts = (context?.loopDepth ?? 0) > 0
            ? { min: cleanupRange.min, max: 2 }
            : {
              min: Math.min(2, cleanupRange.min + 1),
              max: Math.min(2, cleanupRange.max + 1),
            };
          if (context.ap.poolAllocated) {
            const allocatedRange = context.ap.poolAllocationCleanupAttempts ?? { min: 0, max: 0 };
            context.ap.poolAllocationCleanupAttempts = (context?.loopDepth ?? 0) > 0
              ? { min: allocatedRange.min, max: 2 }
              : {
                min: Math.min(2, allocatedRange.min + 1),
                max: Math.min(2, allocatedRange.max + 1),
              };
          }
        }
      }
      if (!this.poolEndNodes.has(node.pos)) {
        this.poolEndAttempts += 1;
        this.poolEndNodes.add(node.pos);
      }
      if (args.length !== 0) fail(SAFE.flow, "CAPABILITY_CLEANUP");
      if (callee.bound?.kind !== "pool") fail(SAFE.flow, "CAPABILITY_CLEANUP");
      if (context?.ap) context.ap.cleanupSucceeded = true;
      return capabilityValue("CLEANUP_PROMISE", { bound: callee.bound, taint: Taint.SENSITIVE_DIAGNOSTIC });
    }
    if (callee.caps.has("POOL_CONNECT")) {
      fail(SAFE.flow, "CAPABILITY_CONNECT", "AP_CLIENT_PROTOCOL");
    }
    if (callee.caps.has("CLIENT_QUERY")) {
      if (args.length !== 2 || args[0].binding !== this.identitySqlBinding || args[0].constant !== this.identitySqlText || args[1].kind !== "array" ||
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
      if ((context?.loopDepth ?? 0) > 0) fail(SAFE.flow, "CAPABILITY_QUERY", "AP_IDENTITY_SQL");
      const querySite = String(node.pos);
      if (this.identityQueryCount >= 2) fail(SAFE.flow, "CAPABILITY_QUERY", "AP_IDENTITY_SQL");
      this.identityQueryNodes.add(querySite);
      this.identityQueryCount += 1;
      this.provenanceObligations.delete("identity-target");
      if (this.identityQueryCount >= 2 && this.authoritySetCount === 1) {
        this.authoritySecondIdentityChecked = true;
        this.markAnalysisFact(context, "identity2Validated");
      }
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
      this.markAnalysisFact(context, "migrationAttempted");
      if (args.length !== 2 || args[0].kind !== "drizzle-db" || args[1].kind !== "object" ||
          !sameTextSet([...args[1].props.keys()], ["migrationsFolder"]) ||
          !sameExactPrimitiveValue(args[1].props.get("migrationsFolder"),
            this.authorityRecord?.props.get("migrationsFolder")) ||
          args[1].props.get("migrationsFolder")?.exact === false ||
          hasTaint(args[1], Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC) ||
          !this.authorityRecord || this.authoritySetCount !== 1 || !this.authoritySecondIdentityChecked ||
          args[0].bound?.kind !== "pool" || args[0].bound !== this.authorityRecord.props.get("pool")) {
        fail(SAFE.flow, "CAPABILITY_MIGRATE", "AP_MIGRATION");
      }
      this.migrationCompleted = true;
      this.markAnalysisFact(context, "migrationCompleted");
      return primitiveValue("promise");
    }
    if (callee.caps.has("WEAKMAP_SET")) {
      if (callee.bound?.role !== "authority-store") {
        if (args.length !== 2 || !args[0] || args[0].kind === "primitive") fail(SAFE.authority, "AUTHORITY_SCHEMA");
        if (hasTaint(args[1], Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC)) {
          fail(SAFE.flow, "CAPABILITY_STORAGE");
        }
        callee.bound.map ??= new Map();
        callee.bound.map.set(abstractIdentityKey(args[0]), args[1]);
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
      callee.bound.map.set(abstractIdentityKey(args[0]), args[1]);
      this.authorityRecord = args[1];
      this.authorityToken = args[0];
      if (!this.authoritySetNodes.has(node.pos)) {
        this.authoritySetNodes.add(node.pos);
        this.authoritySetCount += 1;
      }
      if (this.authoritySetCount > 1) fail(SAFE.authority, "AUTHORITY_SCHEMA");
      this.markAnalysisFact(context, "authorityMinted");
      return callee.bound;
    }
    if (callee.caps.has("WEAKMAP_GET")) {
      if (args.length !== 1) fail(SAFE.authority, "AUTHORITY_SCHEMA");
      const record = callee.bound.map.get(abstractIdentityKey(args[0]));
      if (!record && callee.bound?.role === "authority-store") fail(SAFE.authority, "AUTHORITY_SCHEMA");
      return record ?? unknownValue();
    }
    if (callee.caps.has("CLEANUP_CATCH")) {
      if (args.length !== 1 || !this.hasCallableTarget(args[0])) fail(SAFE.flow, "CLEANUP_DIAGNOSTIC");
      return this.invokeFunctionValue(args[0],
        [value({ kind: "diagnostic", taint: Taint.SENSITIVE_DIAGNOSTIC, caps: ["CLEANUP_DIAGNOSTIC"] })],
        null, context, node, env);
    }
    if (callee.caps.has("ARRAY_SOME")) {
      if (args.length < 1 || !this.hasCallableTarget(args[0])) fail(SAFE.ast, "SYNTAX_POLICY");
      for (const [index, item] of (callee.bound?.elements ?? [unknownValue()]).entries()) {
        this.invokeFunctionValue(args[0], [item, primitiveValue(String(index)), callee.bound], null, context, node, env);
      }
      return primitiveValue("boolean");
    }
    if (callee.caps.has("ARRAY_EVERY")) {
      if (args.length < 1 || !this.hasCallableTarget(args[0])) fail(SAFE.ast, "SYNTAX_POLICY");
      for (const [index, item] of (callee.bound?.elements ?? [unknownValue()]).entries()) {
        this.invokeFunctionValue(args[0], [item, primitiveValue(String(index)), callee.bound], null, context, node, env);
      }
      return primitiveValue("boolean");
    }
    if (callee.caps.has("ARRAY_MAP")) {
      if (args.length < 1 || !this.hasCallableTarget(args[0])) fail(SAFE.ast, "SYNTAX_POLICY");
      const elements = [];
      for (const [index, item] of (callee.bound?.elements ?? []).entries()) {
        elements.push(this.invokeFunctionValue(args[0], [item, primitiveValue(String(index)), callee.bound], null, context, node, env));
      }
      const result = value({ kind: "array", elements });
      for (const item of elements) rememberReference(result, item);
      return result;
    }
    if (callee.caps.has("ARRAY_FOREACH")) {
      if (args.length < 1 || !this.hasCallableTarget(args[0])) fail(SAFE.ast, "SYNTAX_POLICY");
      for (const [index, item] of (callee.bound?.elements ?? []).entries()) {
        this.invokeFunctionValue(args[0], [item, primitiveValue(String(index)), callee.bound], null, context, node, env);
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
      if (args.length < 1 || !this.hasCallableTarget(args[0])) fail(SAFE.ast, "SYNTAX_POLICY");
      for (const item of callee.bound.map?.values?.() ?? []) {
        this.invokeFunctionValue(args[0], [item, item, callee.bound], null, context, node, env);
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
      callee.bound.map.set(abstractIdentityKey(args[0]), args[1]);
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
      if (args.length < 1 || !this.hasCallableTarget(args[0])) fail(SAFE.ast, "SYNTAX_POLICY");
      for (const [key, item] of callee.bound.map ?? []) {
        this.invokeFunctionValue(args[0], [item, key, callee.bound], null, context, node, env);
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
      if (callee.label === "replace" && this.hasCallableTarget(args[1])) {
        this.invokeFunctionValue(args[1], [
          primitiveValue("match"),
          primitiveValue("offset"),
          callee.bound,
        ], null, context, node, env);
      }
      const hostNormalization = provenanceOf(callee.bound).size === 1 &&
        provenanceOf(callee.bound).has(this.originIdentity("url.hostname")) &&
        ((callee.label === "replace" && callee.bound.label === "url.hostname") ||
          (callee.label === "toLowerCase" && callee.bound.normalization === "url-hostname"));
      return value({
        kind: "string",
        taint: callee.bound.taint,
        directCredential: false,
        label: callee.bound.taint ? "transformed-credential" : "",
        provenance: provenanceOf(callee.bound),
        exact: false,
        normalization: hostNormalization ? "url-hostname" : null,
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
        exact: false,
        normalization: args[0] && sameIdentitySet(
          provenanceOf(args[0]),
          new Set([this.originIdentity("url.port")]),
        ) ? "url-port" : null,
      });
    }
    if (callee.caps.has("DECODE_URI")) {
      if (args.some((item) => hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC))) fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION");
      return value({
        kind: "primitive",
        label: "string",
        literalType: "string",
        provenance: args[0] ? provenanceOf(args[0]) : [],
        exact: false,
      });
    }
    if (callee.caps.has("STRING_CONSTRUCTOR")) {
      const target = args[0];
      const toString = target?.methods?.get("toString");
      if (toString && this.hasCallableTarget(toString)) this.invokeFunctionValue(toString, [], target, context, node, env);
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
      if (toJson && this.hasCallableTarget(toJson)) this.invokeFunctionValue(toJson, [], target, context, node, env);
      const replacer = args[1];
      if (this.hasCallableTarget(replacer)) {
        this.invokeFunctionValue(replacer, [
          primitiveValue("key"),
          target ?? unknownValue(),
        ], null, context, node, env);
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
      if (args.length !== 0) fail(SAFE.flow, "CAPABILITY_CALLBACK", "AP_OPERATION");
      if (!context?.ap?.migrationAttempted) {
        fail(SAFE.flow, "CAPABILITY_CALLBACK", "AP_OPERATION");
      }
      if (context?.ap?.poolAllocated &&
          (!context.ap.authorityGuardPassed || !this.authorityGuardPassed)) {
        fail(SAFE.authority, "AUTHORITY_SCHEMA", "AP_AUTHORITY_GUARD");
      }
      if (!context?.ap?.migrationCompleted || !this.migrationCompleted) {
        fail(SAFE.flow, "CAPABILITY_CALLBACK", "AP_OPERATION");
      }
      if (!context?.ap?.fingerprintsEqual || !this.fingerprintsEqual) {
        fail(SAFE.authority, "AUTHORITY_SCHEMA", "AP_FINGERPRINT_COMPARE");
      }
      if (!context?.ap?.migrationCompleted || !context?.ap?.authorityGuardPassed ||
          !context?.ap?.identity2Validated || !context?.ap?.fingerprintsEqual ||
          !context?.ap?.authorityMinted || context?.ap?.authorityRevoked || !context?.ap?.poolAllocated ||
          !this.migrationCompleted || !this.authorityGuardPassed ||
          !this.authoritySecondIdentityChecked || !this.fingerprintsEqual ||
          !this.authorityRecord || this.authorityRevoked || this.poolConstructs !== 1) {
        fail(SAFE.flow, "CAPABILITY_CALLBACK", "AP_OPERATION");
      }
      const callSite = node.pos;
      const range = context?.operationRange ?? { min: 0, max: 0 };
      if (this.operationInvocationNodes.includes(callSite) || (context?.loopDepth ?? 0) > 0) {
        context.operationRange = { min: range.min, max: 2 };
      } else {
        this.operationInvocationNodes.push(callSite);
        context.operationRange = {
          min: Math.min(2, range.min + 1),
          max: Math.min(2, range.max + 1),
        };
      }
      this.operationInvocations = this.operationInvocationNodes.length;
      return value({ kind: "operation-result" });
    }
    if (callee.caps.has("PROMISE_RESOLVE")) {
      fail(SAFE.unresolved, "CALL_RESOLUTION", "TV_CALLBACK_UNMODELED");
    }
    if (this.hasCallableTarget(callee)) return this.invokeFunctionValue(callee, args, callee.bound, context, node, env);
    const locationAtCall = () => {
      const point = this.sourceFile.getLineAndCharacterOfPosition(node.getStart(this.sourceFile));
      return { line: point.line + 1, column: point.character + 1 };
    };
    if (callee.kind === "function" && !this.hasCallableTarget(callee)) {
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
      if (!item || item.kind === "unknown") {
        if (["database", "user", "clusterFingerprint", "lifecycleFingerprint", "migrationsFolder", "phase"].includes(name)) {
          fail(SAFE.authority, "AUTHORITY_SCHEMA", "PV_EXACT_RELATION");
        }
        fail(SAFE.flow, "AUTHORITY_SCHEMA");
      }
      if (hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC | Taint.MAYBE_SENSITIVE)) {
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
      if (item?.exact === false && item.literalType === "number") {
        fail(SAFE.authority, "AUTHORITY_SCHEMA", "PV_EXACT_RELATION");
      }
      if (!item || item.exact === false || !sameIdentitySet(exactRelationsOf(item), expected)) {
        fail(SAFE.authority, "AUTHORITY_SCHEMA", "PV_EXACT_RELATION");
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
    if (!phase || phase.exact === false || !sameIdentitySet(exactRelationsOf(phase), expectedPhase)) {
      fail(SAFE.authority, "AUTHORITY_SCHEMA", "PV_EXACT_RELATION");
    }
    record.authorityRecord = true;
    this.provenanceObligations.delete("authority-record");
    this.provenanceObligations.delete("migration-folder");
  }

  assignTarget(target, right, env, context, assignmentNode = target) {
    this.graphNode(right, "assignment-value");
    if (ts.isIdentifier(target)) {
      const resolved = this.resolveDeclaration(target);
      if (!resolved || resolved.kind !== "local") fail(SAFE.unresolved, "CALL_RESOLUTION");
      this.setBinding(env, keyForDeclaration(resolved.declaration.name ?? resolved.declaration), right);
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
        const activation = this.summaryExecutionStack.at(-1)?.id ??
          this.activationStack.map((frame) => frame.id).join("/");
        const eventKey = (activation || "module") + "::" + assignmentNode.pos;
        const previousReceiver = this.declassificationAssignmentEvents.get(eventKey);
        const replayedAssignment = previousReceiver === receiver && receiver.props.has("password");
        const previousCredential = receiver.props.get("password");
        const sameCredential = previousCredential === right ||
          (previousCredential?.directCredential === true && right.directCredential === true &&
            sameIdentitySet(provenanceOf(previousCredential), provenanceOf(right)) &&
            summarizeRisk(previousCredential).taint === Taint.CREDENTIAL &&
            summarizeRisk(right).taint === Taint.CREDENTIAL);
        if (name !== "password" || (receiver.props.has("password") &&
            !(replayedAssignment && sameCredential)) || !right.directCredential ||
            right.kind !== "credential" || summarizeRisk(right).taint !== Taint.CREDENTIAL ||
            summarizeRisk(right).caps.size > 0) {
          fail(SAFE.flow, "CAPABILITY_PASSWORD");
        }
        this.declassificationAssignmentEvents.set(eventKey, receiver);
        if (replayedAssignment) assignValueProperty(receiver, name, mergeValues(previousCredential, right));
        else {
          assignValueProperty(receiver, name, right);
          this.declassificationCount += 1;
          if (this.declassificationCount > 1) fail(SAFE.flow, "CAPABILITY_PASSWORD");
        }
        this.graphEdge(right, receiver, "DECLASSIFICATION_USE");
        return;
      }
      if ((receiver === this.authorityRecord || receiver.authorityRecord === true) &&
          name === "valid" && isBooleanValue(right, false)) {
        assignValueProperty(receiver, name, right);
        this.authorityRevoked = true;
        this.markAnalysisFact(context, "authorityRevoked");
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
  return { helperPath, source: canonicalBytes.toString("utf8") };
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
  const receiptGate = await runFrozenReceiptStaticGate();
  if (receiptGate.ok !== true) {
    return Object.freeze({
      id: "F3_REPRESENTATION_ASSURANCE",
      pass: false,
      receiptGate,
    });
  }
  const positive = await runMigrationClosurePositiveControls();
  const matrix = await runMigrationClosureOrthogonalRepresentationMatrix();
  return Object.freeze({
    id: "F3_REPRESENTATION_ASSURANCE",
    pass: receiptGate.ok === true && positive.pass === true && matrix.pass === true,
    receiptGate,
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


const RECEIPT_STATIC_ROOTS = Object.freeze([
  "fixture.withDisposablePostgresFixtureMigration",
  "fixture.beginDisposablePostgresReceiptInvocation",
  "fixture.consumeDisposablePostgresAuthorityReceipt",
  "fixture.consumeDisposablePostgresFreshErrorReceipt",
  "fixture.finishDisposablePostgresReceiptInvocation",
]);
const RECEIPT_STATIC_API_NAMES = Object.freeze(RECEIPT_STATIC_ROOTS.slice(1).map((root) => root.slice("fixture.".length)));
const RECEIPT_STATIC_FAILURES = Object.freeze([
  "SSC_RECEIPT_STATIC_SOURCE_INVALID", "SSC_RECEIPT_ROOTS_INVALID",
  "SSC_RECEIPT_ISSUER_SITE_INVALID", "SSC_RECEIPT_REVOCATION_INVALID",
  "SSC_RECEIPT_CALLSITE_INVALID", "SSC_RECEIPT_FLOW_UNSUPPORTED",
  "SSC_RECEIPT_GATE_INTERNAL",
]);
const RECEIPT_STATIC_EXPECTED_BODY_IDENTITIES = Object.freeze({
  withDisposablePostgresFixtureMigration: "caa6e78d2821dd32015da22816ffedc975da5c2bb1527cc9df95ddbf76aaac4b",
  installDisposablePostgresAuthoritySetReceipt: "caf52ebb66e90cc3a3433e1d41310b60324aa4c9258c266a812988783376ca96",
  beginDisposablePostgresReceiptInvocation: "0d9ae4825f729e2af5378f833e7de5408bbce17281dd527f14cb99dd7fc58b0c",
  consumeDisposablePostgresAuthorityReceipt: "bdf0930723c7dce2b34ec181a9ec287a0ce4eb9770a0a51ff52ab3f0ec7a7b0f",
  consumeDisposablePostgresFreshErrorReceipt: "341aaf495f1e597db25a628e2fc913c266e47f11b7f076d20c18393f6b7b6b6e",
  finishDisposablePostgresReceiptInvocation: "c1174829f305fbe1cfde4702a7afb563dc4f28ab55ff1b5fef08483d1bf1bfb5",
  issueDisposablePostgresReceipt: "cb2afacd875091d306f471e2eb47491d5d262d9adfba4ae423f93963f08ce7f8",
  invalidateDisposablePostgresReceiptInvocation: "9cf8faa004b7514a72080b716f6aeeff428786a597e447f3fc64eb1d17992768",
  consumeDisposablePostgresReceipt: "f08593fbcd4b89a3ff2e31a82e306263a1d89c88d37cc54d68c7901ed3b2ad9a",
  "harness.installWeakMapObserver": "516d3dfc4a79f92658b0c63dff1594c4b4bbf6388782939752e53f840f67df47",
  "harness.runScenario": "ffb38b456d4f8c6e5930aadd8b1ba83b920cd3de8b3d910d6cfb41e8267383f8",
  "harness.runHarnessChild": "28102048862702cac54efdf4f313ec4bdd5adec654d3908014379561c57cf51d",
  "harness.runSecretSurfaceBehavioralHarnessInCurrentThread": "16f1aa93a5263af59873905f57f043cde4852bd7ff98e51ab275b06d8a4ecdf7",
  "harness.runSecretSurfaceBehavioralHarness": "ddb89a5a8fcf5a7cf3672423ced30ca36863f04935d8f6fa7e69109cdc74b30d",
  "harness.runSecretSurfaceF2": "6a4f9bff17d84dbeccf9177311fe00ad18cd76f91b9cade79c7ec1f9d31b646c",
  "harness.runSecretSurfaceF3": "7a0dd3e03decb8f7aac56cabeace3687e93fcf45820921042a8cc4d04a1cf566",
  "harness.runSecretSurfaceRun660RuntimeControls": "e4932498622f3a9a775037c724b44ed123765545a0eaebbc54c256c3aeefcd5d",
  "harness.runSecretSurfaceRun669PrivateStateOriginControls": "909a315e166aca40447d2c5ce7a852b2d9ffae882a86321cdac3da0149e36cdd",
  "harness.runSecretSurfaceIndependentRuntimeCorpus": "3c2ed57fb51c34bffc55f40dada1496eac84f1701f4f2b58b9ded0680db2e360",
  "harness.runSecretSurfaceRun660F3Pair": "b6b21fd63ac5bd483315ea8afb7538dcc04a4ad3fc82cf45b66df00c9391cb70",
  "harness.runHarnessChildMode": "4662e8f35e1c2398d910574af7b68ce7aa1d5d788920422309fbab873c02bfd2",
  "harness.allowedChildEnvironment": "a11170f0077c0301117e9393f9aaf9b53d949c100a366387dcdcd44cc9adcbf7",
  "harness.safeChildTree": "d8a99a2d6fd7630e9c8d14fe007f1e975abb4c728c652961dfb1d8cc5ef2fe1f",
  "harness.validChildCase": "46c676e91419827e2c7df92d1ab54245471a176a38052b5ba11058ba5eb14d24",
  "harness.repoRootFromHarness": "98ae54fa37a038c381aa8c25c36b1a6ccb905d74b9b9c9962415053ea06f58c2",
  "harness.receiptGateEvidence": "71b756a870e549764696040b4b1e1a9de1dcebe65bc6cd063603600be5f6f3bd",
});
const RECEIPT_STATIC_CALLSITE_IDENTITY = "c7292cb3435f61cc246787f2bc8208139fcb5c68c805940ec21de878aea7610b";
export const RECEIPT_STATIC_GATE_RESULT_INTERFACE = Object.freeze({
  schemaVersion: 1, id: "SSC_RECEIPT_STATIC_GATE",
  successFields: Object.freeze(["schemaVersion", "id", "ok", "rootsExpected", "rootsAnalyzed", "fixtureGitBlobId", "harnessGitBlobId", "bodyIdentities", "callsiteIdentity"]),
  failureFields: Object.freeze(["schemaVersion", "id", "ok", "failureCode", "rootsExpected", "rootsAnalyzed"]),
  receiptStore: "PRIVATE_SINGLE_ACTIVE_INVOCATION_STATE",
  rootsExpected: RECEIPT_STATIC_ROOTS,
});
export const receiptStaticPositiveControlIds = Object.freeze([
  "RECEIPT_STATIC_GREEN_BASELINE", "RECEIPT_STATIC_GREEN_ALLOCATE_CONSUME", "RECEIPT_STATIC_GREEN_FINISH_CLEANUP",
]);
export const receiptStaticNegativeControlIds = Object.freeze([
  "RECEIPT_STATIC_RED_WRONG_OPERATION", "RECEIPT_STATIC_RED_WRONG_IDENTITY",
  "RECEIPT_STATIC_RED_DUPLICATE_ISSUER", "RECEIPT_STATIC_RED_MISSING_DELETE",
  "RECEIPT_STATIC_RED_MISSING_FINISH", "RECEIPT_STATIC_RED_ISSUER_ESCAPE",
  "RECEIPT_STATIC_RED_ERROR_RETHROW_ISSUE", "RECEIPT_STATIC_RED_OBSERVER_BEFORE_CONSUME",
  "RECEIPT_STATIC_RED_WORKER_BOUNDARY", "RECEIPT_STATIC_RED_EXTRA_ROOT",
  "RECEIPT_STATIC_RED_BODY_DRIFT", "RECEIPT_STATIC_RED_PUBLIC_GATE_AFTER_CACHE",
  "RECEIPT_STATIC_RED_SHELL_ENABLED", "RECEIPT_STATIC_RED_CHILD_GATE_BYPASS",
  "RECEIPT_STATIC_RED_NONCANONICAL_CHILD_OUTPUT", "RECEIPT_STATIC_RED_CHILD_ENV_LEAK",
  "RECEIPT_STATIC_RED_OUTPUT_LIMIT_WIDENED", "RECEIPT_STATIC_RED_TIMEOUT_WIDENED",
]);
function receiptStaticBlobId(source) {
  const bytes = Buffer.from(source.replace(/\r\n/g, "\n"), "utf8");
  return createHash("sha1").update("blob " + bytes.byteLength + "\0").update(bytes).digest("hex");
}
function receiptStaticSha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}
function receiptStaticSource(source, filename) {
  if (typeof source !== "string" || !source) throw new Error("SSC_RECEIPT_STATIC_SOURCE_INVALID");
  const file = ts.createSourceFile(filename, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  if (file.parseDiagnostics.length) throw new Error("SSC_RECEIPT_STATIC_SOURCE_INVALID");
  return file;
}
function receiptStaticFunction(sourceFile, name) {
  const matches = sourceFile.statements.filter((node) => ts.isFunctionDeclaration(node) && node.name?.text === name);
  if (matches.length !== 1 || !matches[0].body) throw new Error("SSC_RECEIPT_ROOTS_INVALID");
  return matches[0];
}
function receiptStaticExported(node) {
  return node.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) === true;
}
function receiptStaticCalls(node, name) {
  const found = [];
  const visit = (candidate) => {
    if (ts.isCallExpression(candidate)) {
      const expression = candidate.expression;
      if ((ts.isIdentifier(expression) && expression.text === name) ||
          (ts.isPropertyAccessExpression(expression) && expression.name.text === name)) found.push(candidate);
    }
    ts.forEachChild(candidate, visit);
  };
  visit(node);
  return found;
}

function receiptStaticBody(source, node) {
  return source.slice(node.body.getStart(), node.body.end);
}
function analyzeReceiptStaticPair({ fixtureSource, harnessSource, id = "variant" }) {
  const rootsAnalyzed = [...RECEIPT_STATIC_ROOTS];
  const failure = (failureCode) => Object.freeze({
    schemaVersion: 1, id: String(id), ok: false, failureCode,
    rootsExpected: RECEIPT_STATIC_ROOTS, rootsAnalyzed: Object.freeze(rootsAnalyzed),
  });
  try {
    const fixture = receiptStaticSource(fixtureSource, "disposable-postgres-fixture.mjs");
    const harness = receiptStaticSource(harnessSource, "disposable-postgres-secret-surface-harness.mjs");
    const rootNames = ["withDisposablePostgresFixtureMigration", ...RECEIPT_STATIC_API_NAMES];
    const apiNodes = RECEIPT_STATIC_API_NAMES.map((name) => receiptStaticFunction(fixture, name));
    const allocationInstaller = receiptStaticFunction(fixture, "installDisposablePostgresAuthoritySetReceipt");
    if (apiNodes.some((node) => !receiptStaticExported(node)) ||
        receiptStaticExported(allocationInstaller) ||
        receiptStaticExported(receiptStaticFunction(fixture, "issueDisposablePostgresReceipt")) ||
        receiptStaticExported(receiptStaticFunction(fixture, "invalidateDisposablePostgresReceiptInvocation"))) return failure("SSC_RECEIPT_ROOTS_INVALID");
    const receiptExports = fixture.statements.filter((node) =>
      ts.isFunctionDeclaration(node) && receiptStaticExported(node) && node.name?.text?.toLowerCase().includes("receipt")).map((node) => node.name.text);
    if (receiptExports.length !== RECEIPT_STATIC_API_NAMES.length ||
        RECEIPT_STATIC_API_NAMES.some((name) => !receiptExports.includes(name))) return failure("SSC_RECEIPT_ROOTS_INVALID");

    const migration = receiptStaticFunction(fixture, "withDisposablePostgresFixtureMigration");
    const beginInvocation = receiptStaticFunction(fixture, "beginDisposablePostgresReceiptInvocation");
    const issueCalls = receiptStaticCalls(migration, "issueDisposablePostgresReceipt");
    const authorityIssueCalls = receiptStaticCalls(allocationInstaller, "issueDisposablePostgresReceipt");
    const invalidationCalls = receiptStaticCalls(migration, "invalidateDisposablePostgresReceiptInvocation");
    const beginInstallerCalls = receiptStaticCalls(beginInvocation, "installDisposablePostgresAuthoritySetReceipt");
    const authoritySetCalls = receiptStaticCalls(migration, "set").filter((call) =>
      ts.isPropertyAccessExpression(call.expression) &&
      call.expression.expression.getText(fixture) === "migrationAuthorityValues" && call.expression.name.text === "set");
    const weakMapSetCalls = receiptStaticCalls(allocationInstaller, "call").filter((call) =>
      ts.isPropertyAccessExpression(call.expression) &&
      call.expression.expression.getText(fixture) === "WeakMap.prototype.set" && call.expression.name.text === "call");
    const issueBody = receiptStaticBody(fixtureSource, receiptStaticFunction(fixture, "issueDisposablePostgresReceipt"));
    const invalidationBody = receiptStaticBody(fixtureSource, receiptStaticFunction(fixture, "invalidateDisposablePostgresReceiptInvocation"));
    const consumeBody = receiptStaticBody(fixtureSource, receiptStaticFunction(fixture, "consumeDisposablePostgresReceipt"));
    const authorityIssue = authorityIssueCalls[0];
    const delegatedSet = weakMapSetCalls[0];
    const authorityRecordArgument = authoritySetCalls[0]?.arguments?.[1];
    const beginBody = receiptStaticBody(fixtureSource, beginInvocation);
    const finishBody = receiptStaticBody(fixtureSource,
      receiptStaticFunction(fixture, "finishDisposablePostgresReceiptInvocation"));
    if (issueCalls.length !== 1 || authorityIssueCalls.length !== 1 || invalidationCalls.length !== 1 ||
        authoritySetCalls.length !== 1 || !ts.isObjectLiteralExpression(authorityRecordArgument) ||
        beginInstallerCalls.length !== 1 || weakMapSetCalls.length !== 1 || !authorityIssue || !delegatedSet ||
        authorityIssue.arguments.length !== 5 ||
        authorityIssue.arguments.map((argument) => argument.getText(fixture)).join("|") !==
          'invocation.invocationKey|authority|authorityRecord|"authority"|"migration-authority-allocation"' ||
        authorityIssue.pos >= delegatedSet.pos ||
        delegatedSet.arguments.length !== 3 || delegatedSet.arguments[0].getText(fixture) !== "this" ||
        delegatedSet.arguments[1].getText(fixture) !== "authority" ||
        delegatedSet.arguments[2].getText(fixture) !== "authorityRecord" ||
        !beginBody.includes("installDisposablePostgresAuthoritySetReceipt()") ||
        beginBody.indexOf("installDisposablePostgresAuthoritySetReceipt()") > beginBody.indexOf("activeDisposablePostgresReceiptInvocation = invocation") ||
        !finishBody.includes("delete migrationAuthorityValues.set") ||
        issueCalls[0].arguments.length !== 5 ||
        issueCalls[0].arguments[3].getText(fixture) !== '"fresh-error"' ||
        issueCalls[0].arguments[4].getText(fixture) !== '"replacement-admission-error-allocation"' ||
        !issueBody.includes("disposablePostgresReceipts.set(identity, receipt)") ||
        !issueBody.includes("invocation.identities.add(identity)") ||
        !invalidationBody.includes('receipt.kind === "authority"') ||
        !invalidationBody.includes("disposablePostgresReceipts.delete(identity)") ||
        !consumeBody.includes("invocation.operation !== operation") ||
        !consumeBody.includes("receipt.identityRecord !== identityRecord") ||
        !consumeBody.includes("disposablePostgresReceipts.delete(identity)") ||
        !fixtureSource.includes("completedDisposablePostgresReceiptOperations.set(operation, true)")) return failure("SSC_RECEIPT_ISSUER_SITE_INVALID");
    const runScenario = receiptStaticFunction(harness, "runScenario");
    const observer = receiptStaticFunction(harness, "installWeakMapObserver");
    const begin = receiptStaticCalls(runScenario, "beginDisposablePostgresReceiptInvocation");
    const finish = receiptStaticCalls(runScenario, "finishDisposablePostgresReceiptInvocation");
    const fresh = receiptStaticCalls(runScenario, "consumeDisposablePostgresFreshErrorReceipt");
    const authority = receiptStaticCalls(observer, "consumeDisposablePostgresAuthorityReceipt");
    const shape = receiptStaticCalls(observer, "isAuthorityRecord");
    const fixtureCalls = receiptStaticCalls(runScenario, "withDisposablePostgresFixtureMigration");
    const prototype = receiptStaticCalls(runScenario, "getPrototypeOf");
    if (begin.length !== 1 || finish.length !== 1 || fresh.length !== 1 ||
        authority.length !== 1 || shape.length < 1 || fixtureCalls.length !== 1 ||
        authority[0].pos >= shape[0].pos || begin[0].pos >= fixtureCalls[0].pos ||
        (prototype.length && fresh[0].pos >= prototype[0].pos) ||
        !receiptStaticBody(harnessSource, runScenario).includes("current.receiptOperation = null") ||
        !receiptStaticBody(harnessSource, runScenario).includes("current.receiptSubject = null")) return failure("SSC_RECEIPT_CALLSITE_INVALID");
    if (/worker_threads|new Worker\s*\(|workerData|parentPort/u.test(harnessSource) ||
        /JSON\.stringify\s*\(\s*(?:authorityToken|authorityRecord|error|identityRecord|invocationKey)/u.test(issueBody) ||
        /\b(?:console\.(?:log|error)|process\.(?:stdout|stderr)|postMessage|send)\s*\(/u.test(fixtureSource)) return failure("SSC_RECEIPT_FLOW_UNSUPPORTED");

    const bodies = Object.create(null);
    for (const name of Object.keys(RECEIPT_STATIC_EXPECTED_BODY_IDENTITIES)) {
      const isHarness = name.startsWith("harness.");
      const functionName = isHarness ? name.slice("harness.".length) : name;
      const sourceFile = isHarness ? harness : fixture;
      const source = isHarness ? harnessSource : fixtureSource;
      bodies[name] = receiptStaticSha256(receiptStaticBody(source,
        receiptStaticFunction(sourceFile, functionName)));
    }
    if (Object.keys(bodies).length !== Object.keys(RECEIPT_STATIC_EXPECTED_BODY_IDENTITIES).length ||
        Object.entries(RECEIPT_STATIC_EXPECTED_BODY_IDENTITIES).some(([name, expected]) => bodies[name] !== expected)) {
      return failure("SSC_RECEIPT_STATIC_SOURCE_INVALID");
    }

    const runChild = receiptStaticFunction(harness, "runHarnessChild");
    const spawnCalls = receiptStaticCalls(runChild, "spawn").filter((call) =>
      ts.isIdentifier(call.expression) && call.expression.text === "spawn");
    const spawnOptions = spawnCalls[0]?.arguments?.[2];
    const spawnProperty = (name) => ts.isObjectLiteralExpression(spawnOptions)
      ? spawnOptions.properties.find((property) => ts.isPropertyAssignment(property) &&
        (ts.isIdentifier(property.name) || ts.isStringLiteral(property.name)) && property.name.text === name)?.initializer
      : undefined;
    const stdio = spawnProperty("stdio");
    const exactStdio = ts.isArrayLiteralExpression(stdio) && stdio.elements.length === 3 &&
      stdio.elements.every((item, index) => ts.isStringLiteral(item) && item.text === ["ignore", "pipe", "pipe"][index]);
    const exactSpawn = spawnCalls.length === 1 && spawnCalls[0].arguments.length === 3 &&
      spawnCalls[0].arguments[0].getText(harness) === "process.execPath" &&
      spawnCalls[0].arguments[1].getText(harness) === "args" &&
      ts.isObjectLiteralExpression(spawnOptions) && spawnOptions.properties.length === 5 &&
      spawnProperty("shell")?.kind === ts.SyntaxKind.FalseKeyword &&
      spawnProperty("cwd")?.getText(harness) === "repoRootFromHarness()" &&
      spawnProperty("env")?.getText(harness) === "allowedChildEnvironment()" &&
      spawnProperty("windowsHide")?.kind === ts.SyntaxKind.TrueKeyword && exactStdio;
    if (!exactSpawn || !receiptStaticBody(harnessSource, runChild).includes("expectedGate?.ok !== true")) {
      return failure("SSC_RECEIPT_FLOW_UNSUPPORTED");
    }

    const childVariableInitializers = new Map();
    for (const statement of harness.statements) {
      if (!ts.isVariableStatement(statement)) continue;
      for (const declaration of statement.declarationList.declarations) {
        if (ts.isIdentifier(declaration.name)) childVariableInitializers.set(declaration.name.text, declaration.initializer);
      }
    }
    const specialCases = childVariableInitializers.get("CHILD_SPECIAL_CASES");
    const specialArgument = specialCases && ts.isNewExpression(specialCases) ? specialCases.arguments?.[0] : undefined;
    const specialCaseValues = specialArgument && ts.isArrayLiteralExpression(specialArgument)
      ? specialArgument.elements.filter((item) => ts.isStringLiteral(item)).map((item) => item.text) : [];
    if (childVariableInitializers.get("MAX_CHILD_OUTPUT_BYTES")?.getText(harness) !== "2 * 1024 * 1024" ||
        childVariableInitializers.get("CHILD_TIMEOUT_MS")?.getText(harness) !== "60_000" ||
        JSON.stringify(specialCaseValues) !== JSON.stringify([
          "RUN660_HS5_DP6_RUNTIME_CONTROLS", "RUN669_HS5_PRIVATE_STATE_ORIGIN_CONTROLS",
          "RUN657_INDEPENDENT_RUNTIME_CORPUS", "SSC_FORCE_RESTORE_MISMATCH",
        ])) return failure("SSC_RECEIPT_FLOW_UNSUPPORTED");
    const gatedEntrypoints = [
      "runSecretSurfaceBehavioralHarness", "runSecretSurfaceF2", "runSecretSurfaceF3",
      "runSecretSurfaceRun660RuntimeControls", "runSecretSurfaceRun669PrivateStateOriginControls",
      "runSecretSurfaceIndependentRuntimeCorpus", "runSecretSurfaceRun660F3Pair",
    ];
    for (const name of gatedEntrypoints) {
      const entry = receiptStaticFunction(harness, name);
      const calls = receiptStaticCalls(entry, "runFrozenReceiptStaticGate");
      if (!receiptStaticExported(entry) || calls.length !== 1) return failure("SSC_RECEIPT_CALLSITE_INVALID");
      const body = receiptStaticBody(harnessSource, entry);
      const gateAt = calls[0].getStart() - entry.body.getStart();
      for (const barrier of ["defaultHarnessResultCache", "runHarnessChild(",
        "runSecretSurfaceBehavioralHarness("]) {
        const barrierAt = body.indexOf(barrier);
        if (barrierAt >= 0 && gateAt >= barrierAt) return failure("SSC_RECEIPT_CALLSITE_INVALID");
      }
    }
    const childMode = receiptStaticFunction(harness, "runHarnessChildMode");
    const childGateCalls = receiptStaticCalls(childMode, "runFrozenReceiptStaticGate");
    const childModeBody = receiptStaticBody(harnessSource, childMode);
    const childGateAt = childGateCalls.length === 1
      ? childGateCalls[0].getStart() - childMode.body.getStart() : -1;
    if (childGateAt < 0 || [
      "runSecretSurfaceBehavioralHarnessInCurrentThread(",
      "runSecretSurfaceRun660RuntimeControlsInCurrentThread(",
      "runSecretSurfaceRun669PrivateStateOriginControlsInCurrentThread(",
      "runSecretSurfaceIndependentRuntimeCorpusInCurrentThread(",
      "runSecretSurfaceBehavioralHarness(",
    ].some((call) => {
      const at = childModeBody.indexOf(call);
      return at >= 0 && childGateAt >= at;
    })) return failure("SSC_RECEIPT_CALLSITE_INVALID");

    const callsites = [
      ...issueCalls.map((node) => "issue:" + node.getText(fixture)),
      ...authorityIssueCalls.map((node) => "authority-issue:" + node.getText(fixture)),
      ...invalidationCalls.map((node) => "invalidate:" + node.getText(fixture)),
      ...beginInstallerCalls.map((node) => "install-set-receipt:" + node.getText(fixture)),
      ...weakMapSetCalls.map((node) => "weakmap-set:" + node.getText(fixture)),
      ...authoritySetCalls.map((node) => "authority-set:" + node.getText(fixture)),
      ...begin.map((node) => "begin:" + node.getText(harness)),
      ...finish.map((node) => "finish:" + node.getText(harness)),
      ...fresh.map((node) => "fresh:" + node.getText(harness)),
      ...authority.map((node) => "authority:" + node.getText(harness)),
    ];
    if (receiptStaticSha256(callsites.join("\n")) !== RECEIPT_STATIC_CALLSITE_IDENTITY) return failure("SSC_RECEIPT_CALLSITE_INVALID");
    return Object.freeze({
      schemaVersion: 1, id: String(id), ok: true,
      rootsExpected: RECEIPT_STATIC_ROOTS, rootsAnalyzed: Object.freeze(rootsAnalyzed),
      fixtureGitBlobId: receiptStaticBlobId(fixtureSource),
      harnessGitBlobId: receiptStaticBlobId(harnessSource),
      bodyIdentities: Object.freeze(bodies),
      callsiteIdentity: receiptStaticSha256(callsites.join("\n")),
    });
  } catch (error) {
    const code = RECEIPT_STATIC_FAILURES.includes(error?.message) ? error.message : "SSC_RECEIPT_GATE_INTERNAL";
    return failure(code);
  }
}
export function analyzeReceiptStaticVariant({ fixtureSource, harnessSource, id = "variant" } = {}) {
  return analyzeReceiptStaticPair({ fixtureSource, harnessSource, id });
}
export function analyzeReceiptStaticVariants(variants) {
  if (!Array.isArray(variants)) return Object.freeze([]);
  return Object.freeze(variants.map((variant, index) => analyzeReceiptStaticVariant({
    fixtureSource: variant?.fixtureSource, harnessSource: variant?.harnessSource, id: variant?.id ?? "variant-" + index,
  })));
}
export async function runFrozenReceiptStaticGate() {
  try {
    const frozen = await readFrozenSource();
    const harnessPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "disposable-postgres-secret-surface-harness.mjs");
    const harnessSource = (await readFile(harnessPath, "utf8")).replace(/\r\n/g, "\n");
    return analyzeReceiptStaticVariant({ fixtureSource: frozen.source, harnessSource, id: "SSC_RECEIPT_STATIC_GATE" });
  } catch (error) {
    return Object.freeze({
      schemaVersion: 1, id: "SSC_RECEIPT_STATIC_GATE", ok: false,
      failureCode: error?.message === "FROZEN_HELPER_BLOB" ? "SSC_RECEIPT_STATIC_SOURCE_INVALID" : "SSC_RECEIPT_GATE_INTERNAL",
      rootsExpected: RECEIPT_STATIC_ROOTS, rootsAnalyzed: Object.freeze([]),
    });
  }
}
export async function runReceiptStaticPositiveControls() {
  const sources = await readFrozenReceiptClosureSources();
  const results = analyzeReceiptStaticVariants(receiptStaticPositiveControlIds.map((id) => ({ id, ...sources })))
    .map((item) => Object.freeze({ ...item, pass: item.ok }));
  return Object.freeze({
    count: results.length, ids: Object.freeze(results.map((item) => item.id)), results: Object.freeze(results),
    pass: results.length === receiptStaticPositiveControlIds.length && results.every((item) => item.pass),
  });
}
export async function runReceiptStaticNegativeControls() {
  const sources = await readFrozenReceiptClosureSources();
  const replaceOnce = (source, before, after) => {
    const at = source.indexOf(before);
    if (at < 0) throw new Error("SSC_RECEIPT_GATE_INTERNAL");
    return source.slice(0, at) + after + source.slice(at + before.length);
  };
  const publicGateOriginal = [
    "  const gate = await runFrozenReceiptStaticGate();",
    "  if (gate.ok !== true) return runtimeGateFailure(gate);",
    "  const defaultRun = Object.keys(options).length === 0;",
  ].join("\n");
  const childGateOriginal = [
    "  const gate = await runFrozenReceiptStaticGate();",
    "  if (gate.ok !== true) {",
    "    process.stdout.write(JSON.stringify({ ok: false, mode, caseId, code: \"SSC_RECEIPT_GATE_BLOCKED\" }) + \"\\n\");",
    "    process.exitCode = 1;",
    "    return;",
    "  }",
  ].join("\n");
  const variants = [
    { id: receiptStaticNegativeControlIds[0], fixtureSource: replaceOnce(sources.fixtureSource, "invocation.operation !== operation", "invocation.operation === operation"), harnessSource: sources.harnessSource },
    { id: receiptStaticNegativeControlIds[1], fixtureSource: replaceOnce(sources.fixtureSource, "receipt.identityRecord !== identityRecord", "receipt.identityRecord === identityRecord"), harnessSource: sources.harnessSource },
    { id: receiptStaticNegativeControlIds[2], fixtureSource: replaceOnce(sources.fixtureSource, "migrationAuthorityValues.set(authority, {", 'issueDisposablePostgresReceipt(key, authority, {}, "authority", "migration-authority-allocation");\n    const authorityRecord = {'), harnessSource: sources.harnessSource },
    { id: receiptStaticNegativeControlIds[3], fixtureSource: replaceOnce(sources.fixtureSource, "if (!receipt) return false;\n  disposablePostgresReceipts.delete(identity);\n  receipt.invocation.identities.delete(identity);", "if (!receipt) return false;\n  receipt.invocation.identities.delete(identity);"), harnessSource: sources.harnessSource },
    { id: receiptStaticNegativeControlIds[4], fixtureSource: sources.fixtureSource, harnessSource: replaceOnce(sources.harnessSource, "subject.finishDisposablePostgresReceiptInvocation(operation);", "void operation;") },
    { id: receiptStaticNegativeControlIds[5], fixtureSource: replaceOnce(sources.fixtureSource, "function issueDisposablePostgresReceipt(", "export function issueDisposablePostgresReceipt("), harnessSource: sources.harnessSource },
    { id: receiptStaticNegativeControlIds[6], fixtureSource: replaceOnce(sources.fixtureSource, 'if (error instanceof DisposablePostgresFixtureAdmissionError) throw error;', 'issueDisposablePostgresReceipt(key, error, error, "fresh-error", "replacement-admission-error-allocation");\n    if (error instanceof DisposablePostgresFixtureAdmissionError) throw error;'), harnessSource: sources.harnessSource },
    { id: receiptStaticNegativeControlIds[7], fixtureSource: sources.fixtureSource, harnessSource: replaceOnce(sources.harnessSource, "const consumed = subject && operation", "const inspectedFirst = isAuthorityRecord(key, record, ObservedPool);\n    const consumed = subject && operation") },
    { id: receiptStaticNegativeControlIds[8], fixtureSource: sources.fixtureSource, harnessSource: replaceOnce(sources.harnessSource, 'import { spawn } from "node:child_process";', 'import { Worker } from "node:worker_threads";') },
    { id: receiptStaticNegativeControlIds[9], fixtureSource: sources.fixtureSource + "\nexport function unexpectedReceiptRoot() {}", harnessSource: sources.harnessSource },
    { id: receiptStaticNegativeControlIds[10], fixtureSource: replaceOnce(sources.fixtureSource, "invocation.active = false;", "invocation.active = true;"), harnessSource: sources.harnessSource },
    { id: receiptStaticNegativeControlIds[11], fixtureSource: sources.fixtureSource, harnessSource: replaceOnce(sources.harnessSource, publicGateOriginal, [
      "  const defaultRun = Object.keys(options).length === 0;",
      "  const gate = await runFrozenReceiptStaticGate();",
      "  if (gate.ok !== true) return runtimeGateFailure(gate);",
    ].join("\n")) },
    { id: receiptStaticNegativeControlIds[12], fixtureSource: sources.fixtureSource, harnessSource: replaceOnce(sources.harnessSource, "shell: false", "shell: true") },
    { id: receiptStaticNegativeControlIds[13], fixtureSource: sources.fixtureSource, harnessSource: replaceOnce(sources.harnessSource, childGateOriginal, childGateOriginal.replace("const gate = await runFrozenReceiptStaticGate();", "const gate = { ok: true };")) },
    { id: receiptStaticNegativeControlIds[14], fixtureSource: sources.fixtureSource, harnessSource: replaceOnce(sources.harnessSource, "JSON.stringify(message) !== line", "JSON.stringify(message) === line") },
    { id: receiptStaticNegativeControlIds[15], fixtureSource: sources.fixtureSource, harnessSource: replaceOnce(sources.harnessSource, "const env = Object.create(null);", "const env = { ...process.env };") },
    { id: receiptStaticNegativeControlIds[16], fixtureSource: sources.fixtureSource, harnessSource: replaceOnce(sources.harnessSource, "2 * 1024 * 1024", "16 * 1024 * 1024") },
    { id: receiptStaticNegativeControlIds[17], fixtureSource: sources.fixtureSource, harnessSource: replaceOnce(sources.harnessSource, "const CHILD_TIMEOUT_MS = 60_000;", "const CHILD_TIMEOUT_MS = 61_000;") },
  ];
  const results = analyzeReceiptStaticVariants(variants).map((item) => Object.freeze({ ...item, pass: !item.ok }));
  return Object.freeze({
    count: results.length, ids: Object.freeze(results.map((item) => item.id)), results: Object.freeze(results),
    pass: results.length === receiptStaticNegativeControlIds.length && results.every((item) => item.pass),
  });
}
async function readFrozenReceiptClosureSources() {
  const frozen = await readFrozenSource();
  const harnessPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "disposable-postgres-secret-surface-harness.mjs");
  const harnessSource = (await readFile(harnessPath, "utf8")).replace(/\r\n/g, "\n");
  return Object.freeze({ fixtureSource: frozen.source, harnessSource });
}

export const migrationClosureNegativeControlIds = Object.freeze(
  NEGATIVE_CONTROLS.map((control) => control.id),
);

export const migrationClosurePositiveControlIds = Object.freeze(
  POSITIVE_CONTROL_SOURCES.map((control) => control.id),
);

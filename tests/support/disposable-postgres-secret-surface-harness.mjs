import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import { inspect, types } from "node:util";
import { spawn } from "node:child_process";
import ts from "typescript";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { readFrozenMigrationClosureSource, runFrozenReceiptStaticGate } from "./disposable-postgres-migration-closure.mjs";

const SUBJECT_RELATIVE = "tests/support/disposable-postgres-fixture.mjs";
const MIGRATIONS_FOLDER = "./drizzle/migrations";
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

const MAX_INSPECTION_DEPTH = 6;
const MAX_INSPECTION_ENTRIES = 256;
const BUILTIN_PROTOTYPES = new Set([
  Object.prototype,
  Array.prototype,
  Function.prototype,
  Error.prototype,
  EvalError.prototype,
  RangeError.prototype,
  ReferenceError.prototype,
  SyntaxError.prototype,
  TypeError.prototype,
  URIError.prototype,
  AggregateError.prototype,
  Map.prototype,
  Set.prototype,
  WeakMap.prototype,
  WeakSet.prototype,
  Date.prototype,
  RegExp.prototype,
  String.prototype,
  Number.prototype,
  Boolean.prototype,
  BigInt.prototype,
  Symbol.prototype,
  Promise.prototype,
]);
const BOXED_PRIMITIVE_UNBOXERS = Object.freeze([
  String.prototype.valueOf,
  Number.prototype.valueOf,
  Boolean.prototype.valueOf,
  BigInt.prototype.valueOf,
  Symbol.prototype.valueOf,
]);
const TRUSTED_SURFACE_ORIGIN_KINDS = new Set([
  "ordinary",
  "array",
  "map",
  "set",
  "boxed-primitive",
  "admission-error",
]);
const NATIVE_ERROR_STACK_DESCRIPTOR = Object.getOwnPropertyDescriptor(new Error(), "stack");

class Run669PrivateStateCarrier extends class {
  constructor(target) {
    return target;
  }
} {
  #value;

  constructor(target, value) {
    super(target);
    this.#value = value;
  }

  static has(candidate) {
    return isSurfaceObject(candidate) && #value in candidate;
  }
}

const SCENARIOS = Object.freeze([
  Object.freeze({ id: "SC01_ORDINARY_SUCCESS", rejectOperation: false, rejectCleanup: false, rejectSecondIdentity: false }),
  Object.freeze({ id: "SC02_SUCCESS_CLEANUP_REJECT", rejectOperation: false, rejectCleanup: true, rejectSecondIdentity: false }),
  Object.freeze({ id: "SC03_OPERATION_REJECT_CLEANUP_REJECT", rejectOperation: true, rejectCleanup: true, rejectSecondIdentity: false }),
  Object.freeze({ id: "SC04_SECOND_IDENTITY_REJECT_CLEANUP_REJECT", rejectOperation: false, rejectCleanup: true, rejectSecondIdentity: true }),
  Object.freeze({ id: "SC05_PASSWORD_ABSENT", rejectOperation: false, rejectCleanup: false, rejectSecondIdentity: false, omitPassword: true }),
  Object.freeze({ id: "SC06_PRE_POOL_FAILURE", rejectOperation: false, rejectCleanup: false, rejectSecondIdentity: false, prePoolFailure: true }),
  Object.freeze({ id: "SC07_MIGRATION_REJECT_CLEANUP", rejectOperation: false, rejectCleanup: false, rejectSecondIdentity: false, rejectMigration: true }),
  Object.freeze({ id: "SC08_MIGRATION_REJECT_CLEANUP_REJECT", rejectOperation: false, rejectCleanup: true, rejectSecondIdentity: false, rejectMigration: true }),
]);

const BEHAVIORAL_CONTROLS = Object.freeze([
  Object.freeze({ id: "NC11_PUBLIC_CAUSE", code: "SSC_PUBLIC_SURFACE", detector: "PUBLIC_CAUSE" }),
  Object.freeze({ id: "NC12_PUBLIC_NONENUM", code: "SSC_PUBLIC_SURFACE", detector: "PUBLIC_DESCRIPTOR" }),
  Object.freeze({ id: "NC13_BROKEN_INSTALL", code: "SSC_OBSERVER_INSTALL", detector: "INSTALL_LEDGER" }),
  Object.freeze({ id: "NC14_BROKEN_RESTORE", code: "SSC_OBSERVER_RESTORE", detector: "RESTORE_LEDGER" }),
  Object.freeze({ id: "NC15_OUTER_RESTORE_FAILURE", code: "SSC_OBSERVER_RESTORE", detector: "RESTORE_LEDGER" }),
  Object.freeze({ id: "NC16_HIDDEN_AUTHORITY_METADATA", code: "SSC_AUTHORITY_SCHEMA", detector: "AUTHORITY_DESCRIPTOR_SCHEMA" }),
  Object.freeze({ id: "NC17_DEEP_HIDDEN_SURFACE", code: "SSC_PUBLIC_SURFACE", detector: "SURFACE_DEPTH_BOUND" }),
  Object.freeze({ id: "NC18_BOUNDED_HIDDEN_SURFACE", code: "SSC_PUBLIC_SURFACE", detector: "SURFACE_ENTRY_BOUND" }),
  Object.freeze({ id: "NC19_SYMBOL_HIDDEN_SURFACE", code: "SSC_PUBLIC_SURFACE", detector: "PUBLIC_SYMBOL" }),
  Object.freeze({ id: "NC20_POOL_WRONG_PASSWORD", code: "SSC_POOL_BINDING", detector: "POOL_PASSWORD_PRESERVATION" }),
  Object.freeze({ id: "NC21_POOL_BINDING_MISMATCH", code: "SSC_POOL_BINDING", detector: "POOL_BINDING_IDENTITY" }),
  Object.freeze({ id: "NC22_RUNTIME_PRE_EFFECT_CAPABILITY", code: "SSC_RUNTIME_CAPABILITY", detector: "PRE_EFFECT_CAPABILITY_GATE" }),
  Object.freeze({ id: "NC23_INHERITED_HIDDEN_SURFACE", code: "SSC_PUBLIC_SURFACE", detector: "INHERITED_DATA_SURFACE" }),
  Object.freeze({ id: "NC24_MAP_INTERNAL_HIDDEN_SURFACE", code: "SSC_PUBLIC_SURFACE", detector: "COLLECTION_INTERNAL_SURFACE" }),
  Object.freeze({ id: "NC25_POOL_WRONG_MAX", code: "SSC_POOL_BINDING", detector: "POOL_MAX_EXACTNESS" }),
  Object.freeze({ id: "NC26_POOL_WRONG_DATABASE", code: "SSC_POOL_BINDING", detector: "POOL_DATABASE_EXACTNESS" }),
  Object.freeze({ id: "NC27_QUERY_WRONG_IDENTITY_ARGUMENTS", code: "SSC_POOL_BINDING", detector: "POOL_IDENTITY_ARGUMENTS" }),
  Object.freeze({ id: "NC28_QUERY_WRONG_RECEIVER", code: "SSC_POOL_BINDING", detector: "POOL_QUERY_RECEIVER" }),
  Object.freeze({ id: "NC29_QUERY_UNKNOWN_SQL", code: "SSC_POOL_BINDING", detector: "POOL_QUERY_ALLOWLIST" }),
]);

let defaultHarnessResultCache = null;

const SAFE = Object.freeze({
  pass: "PASS",
  internal: "SSC_HARNESS_INTERNAL",
  install: "SSC_OBSERVER_INSTALL",
  restore: "SSC_OBSERVER_RESTORE",
  surface: "SSC_PUBLIC_SURFACE",
  scenario: "SSC_SCENARIO_FAILED",
  authority: "SSC_AUTHORITY_SCHEMA",
  pool: "SSC_POOL_BINDING",
  runtime: "SSC_RUNTIME_CAPABILITY",
});

class HarnessFailure extends Error {
  constructor(code, detector = "BOUNDARY") {
    super(code);
    this.name = "HarnessFailure";
    this.code = code;
    this.detector = detector;
  }
}

function fail(code, detector) {
  throw new HarnessFailure(code, detector);
}

function descriptorOwner(target, key) {
  let owner = target;
  while (owner) {
    const descriptor = Object.getOwnPropertyDescriptor(owner, key);
    if (descriptor) return { owner, descriptor };
    owner = Object.getPrototypeOf(owner);
  }
  return null;
}

function sameDescriptor(left, right) {
  if (!left || !right) return left === right;
  return left.configurable === right.configurable &&
    left.enumerable === right.enumerable &&
    left.writable === right.writable &&
    left.value === right.value &&
    left.get === right.get &&
    left.set === right.set;
}

class PatchLedger {
  constructor() {
    this.entries = [];
  }

  install(target, key, replacement) {
    const found = descriptorOwner(target, key);
    if (!found || !Object.prototype.hasOwnProperty.call(found.descriptor, "value")) {
      fail(SAFE.install, "INSTALL_LEDGER");
    }
    if (!found.descriptor.configurable && !found.descriptor.writable) {
      fail(SAFE.install, "INSTALL_LEDGER");
    }
    const after = { ...found.descriptor, value: replacement };
    try {
      Object.defineProperty(found.owner, key, after);
    } catch {
      fail(SAFE.install, "INSTALL_LEDGER");
    }
    const installed = Object.getOwnPropertyDescriptor(found.owner, key);
    if (!installed || installed.value !== replacement) fail(SAFE.install, "INSTALL_LEDGER");
    this.entries.push(Object.freeze({
      owner: found.owner,
      key,
      before: found.descriptor,
      after: installed,
    }));
    return { owner: found.owner, descriptor: found.descriptor, replacement };
  }

  installCustom(restore, verify) {
    this.entries.push(Object.freeze({ restore, verify, custom: true }));
  }

  restore() {
    let mismatch = false;
    for (let index = this.entries.length - 1; index >= 0; index -= 1) {
      const entry = this.entries[index];
      if (entry.custom) {
        try {
          entry.restore();
          if (entry.verify && !entry.verify()) mismatch = true;
        } catch {
          mismatch = true;
        }
        continue;
      }
      const current = Object.getOwnPropertyDescriptor(entry.owner, entry.key);
      if (!sameDescriptor(current, entry.after)) mismatch = true;
      try {
        Object.defineProperty(entry.owner, entry.key, entry.before);
      } catch {
        mismatch = true;
        continue;
      }
      if (!sameDescriptor(Object.getOwnPropertyDescriptor(entry.owner, entry.key), entry.before)) mismatch = true;
    }
    this.entries = [];
    if (mismatch) fail(SAFE.restore, "RESTORE_LEDGER");
  }
}

function fixedMarkers() {
  return Object.freeze({
    connection: ["ssc", "connection", "marker", "a"].join("-"),
    cleanup: ["ssc", "cleanup", "marker", "b"].join("-"),
    operation: ["ssc", "operation", "marker", "c"].join("-"),
    canary: ["ssc", "observer", "canary", "d"].join("-"),
  });
}

function newRunState() {
  return {
    active: false,
    selfTest: false,
    canaryHits: new Set(),
    runtimeEvents: new Map(),
    current: null,
    markers: fixedMarkers(),
    originalSetImmediate: globalThis.setImmediate,
    authorityRecord: null,
    authorityPool: null,
    observedPool: null,
    require: null,
    subjectUrl: null,
    receiptOperation: null,
    receiptSubject: null,
    admissionErrorPrototype: null,
    scenarioSerial: 0,
    identitySql: null,
    migrationQueryPlan: Object.freeze([]),
    migrationHashPlan: Object.freeze([]),
    migrationManifestPlan: null,
    hashDelegationTotals: { createHash: 0, update: 0, digest: 0 },
    runSerial: 0,
    pgClient: null,
    originalPromise: globalThis.Promise,
    originalPool: null,
    allowedReadPaths: new Set(),
    migrationFsOwners: new Set(),
    migrationReadDelegations: 0,
    migrationOpenDelegations: 0,
    migrationExistenceDelegations: 0,
    surfaceOrigins: new WeakMap(),
  };
}

function recordEvent(state, id) {
  if (state.selfTest) {
    state.canaryHits.add(id);
    return;
  }
  if (!state.active) return;
  state.runtimeEvents.set(id, (state.runtimeEvents.get(id) ?? 0) + 1);
}

function blockedFunction(state, id, returnValue) {
  return function blockedObserver() {
    recordEvent(state, id);
    if (state.selfTest) return returnValue;
    if (returnValue !== undefined) return returnValue;
    throw new Error("SSC_BLOCKED");
  };
}

function installFunction(ledger, state, target, key, id, returnValue) {
  const replacement = blockedFunction(state, id, returnValue);
  ledger.install(target, key, replacement);
  state.selfTest = true;
  state.canaryHits.delete(id);
  try {
    replacement.call(target, state.markers.canary);
  } catch {
    // The synthetic canary is intentionally blocked.
  } finally {
    state.selfTest = false;
  }
  if (!state.canaryHits.has(id)) fail(SAFE.install, "INSTALL_LEDGER");
  state.canaryHits.delete(id);
}

function installEnvProxy(ledger, state) {
  const descriptor = Object.getOwnPropertyDescriptor(process, "env");
  if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")) fail(SAFE.install, "INSTALL_LEDGER");
  const original = descriptor.value;
  const proxy = new Proxy(original, {
    set(target, property, value, receiver) {
      void target;
      void property;
      void value;
      void receiver;
      recordEvent(state, "ENV_SET");
      if (!state.selfTest && state.active) throw new Error("SSC_BLOCKED");
      return true;
    },
    deleteProperty(target, property) {
      void target;
      void property;
      recordEvent(state, "ENV_DELETE");
      if (!state.selfTest && state.active) throw new Error("SSC_BLOCKED");
      return true;
    },
    defineProperty(target, property, descriptorValue) {
      void target;
      void property;
      void descriptorValue;
      recordEvent(state, "ENV_DEFINE");
      if (!state.selfTest && state.active) throw new Error("SSC_BLOCKED");
      return true;
    },
  });
  try {
    Object.defineProperty(process, "env", { ...descriptor, value: proxy });
  } catch {
    fail(SAFE.install, "INSTALL_LEDGER");
  }
  ledger.installCustom(
    () => Object.defineProperty(process, "env", descriptor),
    () => Object.getOwnPropertyDescriptor(process, "env")?.value === original,
  );
  state.selfTest = true;
  proxy.SSC_CANARY = state.markers.canary;
  delete proxy.SSC_CANARY;
  Object.defineProperty(proxy, "SSC_CANARY", {
    configurable: true,
    enumerable: false,
    value: state.markers.canary,
    writable: true,
  });
  delete proxy.SSC_CANARY;
  state.selfTest = false;
  if (!state.canaryHits.has("ENV_SET") || !state.canaryHits.has("ENV_DELETE") ||
      !state.canaryHits.has("ENV_DEFINE")) fail(SAFE.install, "INSTALL_LEDGER");
  state.canaryHits.delete("ENV_SET");
  state.canaryHits.delete("ENV_DELETE");
  state.canaryHits.delete("ENV_DEFINE");
}

function installProcessListeners(ledger, state) {
  const events = [
    ["warning", "PROCESS_WARNING"],
    ["unhandledRejection", "PROCESS_UNHANDLED_REJECTION"],
    ["uncaughtExceptionMonitor", "PROCESS_UNCAUGHT_EXCEPTION_MONITOR"],
    ["multipleResolves", "PROCESS_MULTIPLE_RESOLVES"],
  ];
  for (const [event, id] of events) {
    const listener = () => recordEvent(state, id);
    process.on(event, listener);
    ledger.installCustom(
      () => process.removeListener(event, listener),
      () => !process.listeners(event).includes(listener),
    );
    state.selfTest = true;
    listener(new Error("SSC_CANARY"));
    state.selfTest = false;
    if (!state.canaryHits.has(id)) fail(SAFE.install, "INSTALL_LEDGER");
    state.canaryHits.delete(id);
  }
}

function installDiagnosticsChannel(ledger, state, diagnosticsChannel) {
  const found = descriptorOwner(diagnosticsChannel, "channel");
  if (!found || typeof found.descriptor.value !== "function") fail(SAFE.install, "INSTALL_LEDGER");
  const originalChannel = found.descriptor.value;
  const wrappedChannels = new Set();
  const wrappedChannel = function interceptedChannel(...args) {
    recordEvent(state, "DIAGNOSTICS_CHANNEL");
    const channel = originalChannel.apply(this, args);
    if (!channel || typeof channel.publish !== "function" || wrappedChannels.has(channel)) return channel;
    const channelOwner = descriptorOwner(channel, "publish");
    if (!channelOwner || typeof channelOwner.descriptor.value !== "function") fail(SAFE.install, "INSTALL_LEDGER");
    const originalPublish = channelOwner.descriptor.value;
    const publish = function interceptedPublish() {
      recordEvent(state, "DIAGNOSTICS_PUBLISH");
      if (state.selfTest) return undefined;
      return undefined;
    };
    ledger.install(channelOwner.owner, "publish", publish);
    wrappedChannels.add(channel);
    void originalPublish;
    return channel;
  };
  ledger.install(found.owner, "channel", wrappedChannel);
  state.selfTest = true;
  const channel = wrappedChannel("ssc-canary");
  channel.publish(state.markers.canary);
  state.selfTest = false;
  if (!state.canaryHits.has("DIAGNOSTICS_CHANNEL") || !state.canaryHits.has("DIAGNOSTICS_PUBLISH")) fail(SAFE.install, "INSTALL_LEDGER");
  state.canaryHits.delete("DIAGNOSTICS_CHANNEL");
  state.canaryHits.delete("DIAGNOSTICS_PUBLISH");
}

function installWeakMapObserver(ledger, state, ObservedPool) {
  const owner = WeakMap.prototype;
  const descriptor = Object.getOwnPropertyDescriptor(owner, "set");
  if (!descriptor || typeof descriptor.value !== "function") fail(SAFE.install, "INSTALL_LEDGER");
  const original = descriptor.value;
  const wrapper = function observedWeakMapSet(key, record) {
    if (state.selfTest && key === state.weakMapCanaryKey) {
      const result = original.call(this, key, record);
      recordEvent(state, "WEAKMAP_CANARY");
      return result;
    }
    const current = state.current;
    const subject = state.active ? current?.receiptSubject : null;
    const operation = state.active ? current?.receiptOperation : null;
    const consumed = subject && operation
      ? subject.consumeDisposablePostgresAuthorityReceipt(operation, key, record)
      : false;
    const result = original.call(this, key, record);
    if (state.active && isAuthorityRecord(key, record, ObservedPool)) {
      if (consumed !== true || !Object.isFrozen(key) || record.valid !== true) {
        if (current) current.protocolRejected = true;
        return result;
      }
      rememberSurfaceOrigin(state, key, "ordinary", "trusted-authority-token-allocation");
      state.authorityRecord = record;
      state.authorityPool = record.pool;
      current.authorityCaptureCount += 1;
      current.authorityReceiptAccepted = true;
      current.authorityValidAtCapture = record.valid === true;
      current.authorityTokenFrozen = Object.isFrozen(key);
      current.events.push("AUTHORITY_SET");
    }
    return result;
  };
  ledger.install(owner, "set", wrapper);
  const canaryMap = new WeakMap();
  state.weakMapCanaryKey = {};
  state.selfTest = true;
  canaryMap.set(state.weakMapCanaryKey, {});
  state.selfTest = false;
  if (!state.canaryHits.has("WEAKMAP_CANARY")) fail(SAFE.install, "INSTALL_LEDGER");
  state.canaryHits.delete("WEAKMAP_CANARY");
  state.weakMapCanaryKey = null;
}

function installObserverSet(state, ledger, owner, keys, prefix, returns = undefined) {
  for (const key of keys) {
    if (!descriptorOwner(owner, key)) fail(SAFE.install, "INSTALL_LEDGER");
    installFunction(ledger, state, owner, key, `${prefix}_${key.toUpperCase()}`, returns);
  }
}

function installPoolDependencyObserver(state, ledger, owner, key, id) {
  const found = descriptorOwner(owner, key);
  if (!found || typeof found.descriptor.value !== "function") fail(SAFE.install, "INSTALL_LEDGER");
  const original = found.descriptor.value;
  const wrapper = function observedPoolDependency(...args) {
    recordEvent(state, id);
    if (state.selfTest) return undefined;
    if (state.active) throw new Error("SSC_BLOCKED");
    return original.apply(this, args);
  };
  ledger.install(found.owner, key, wrapper);
  state.selfTest = true;
  try {
    wrapper.call(found.owner, state.markers.canary);
  } catch {
    // The synthetic canary is intentionally blocked.
  } finally {
    state.selfTest = false;
  }
  if (!state.canaryHits.has(id)) fail(SAFE.install, "INSTALL_LEDGER");
  state.canaryHits.delete(id);
}

function installPassthroughObserver(state, ledger, target, key, id) {
  const found = descriptorOwner(target, key);
  if (!found || typeof found.descriptor.value !== "function") fail(SAFE.install, "INSTALL_LEDGER");
  const original = found.descriptor.value;
  const wrapper = function observedPassthrough(...args) {
    if (state.selfTest || state.active) {
      recordEvent(state, id);
      if (state.selfTest) return undefined;
      throw new Error("SSC_BLOCKED");
    }
    return original.apply(this, args);
  };
  ledger.install(found.owner, key, wrapper);
  state.selfTest = true;
  try {
    wrapper.call(found.owner, state.markers.canary);
  } catch {
    // The synthetic secret is intentionally blocked.
  } finally {
    state.selfTest = false;
  }
  if (!state.canaryHits.has(id)) fail(SAFE.install, "INSTALL_LEDGER");
  state.canaryHits.delete(id);
}

function migrationIdentityAdmission(state, current) {
  const pool = current?.pools?.[0];
  const record = state.authorityRecord;
  return Boolean(
    state.active && current && state.current === current && !current.protocolRejected &&
    current.lifecyclePhase === "MIGRATION" && current.operationEntered !== true &&
    current.authorityRevocationStarted !== true && current.cleanupAttempted !== true &&
    current.publicCompleted !== true && current.cleanupEntryCount === 0 &&
    current.poolCount === 1 && current.poolInputValidated === true && current.poolEffectiveValidated === true &&
    pool && pool === state.authorityPool && current.identityCalls === 2 &&
    current.identity1Validated === true && current.identity2Validated === true && current.fingerprintsEqual === true &&
    current.authorityGuardPassed === true && current.authorityCaptureCount === 1 &&
    current.authorityValidAtCapture === true && current.authorityTokenFrozen === true &&
    record && record.valid === true && record.pool === pool && record.authority && Object.isFrozen(record.authority) &&
    record.database === "runtime_posture_test" && record.user === "cloud_admin" &&
    record.phase === "initialization" && record.migrationsFolder === MIGRATIONS_FOLDER &&
    current.identityFingerprints?.[0]?.catalog === record.clusterFingerprint &&
    current.identityFingerprints?.[0]?.lifecycle === record.lifecycleFingerprint &&
    isAuthorityRecord(record.authority, record, state.observedPool) &&
    poolBindingContract(current, state)
  );
}

function migrationHashAdmission(state, current, index, stage) {
  if (!migrationIdentityAdmission(state, current) || current.migrationEntered !== true ||
      current.manifestExistsCount !== 1 || current.manifestReadCount !== 1 ||
      current.migrationReadCursor !== index + 1 || current.lastReadMigrationIndex !== index ||
      current.lastReadMigrationPath !== state.migrationHashPlan[index]?.path ||
      current.lastReadMigrationSource !== state.migrationHashPlan[index]?.source ||
      current.hashCompleted !== index) return false;
  if (stage === "NEW") {
    return current.hashIndex === index && current.pendingHash === null;
  }
  const pending = current.pendingHash;
  return Boolean(
    pending && pending.index === index && pending.runId === current.runId &&
    pending.lifecycleGeneration === current.lifecycleGeneration &&
    pending.path === state.migrationHashPlan[index]?.path &&
    current.hashIndex === index + 1 &&
    (stage === "HASH_ALLOCATED" ? pending.stage === "HASH_ALLOCATED" && !pending.updated
      : stage === "HASH_UPDATED" ? pending.stage === "HASH_UPDATED" && pending.updated
        : false)
  );
}

function rejectMigrationDependency(state, detector, eventId) {
  if (state.current) state.current.protocolRejected = true;
  recordEvent(state, eventId);
  fail(SAFE.runtime, detector);
}

function installMigrationHashObserver(state, ledger, crypto) {
  const createHashDescriptor = descriptorOwner(crypto, "createHash");
  if (!createHashDescriptor || typeof createHashDescriptor.descriptor.value !== "function") {
    fail(SAFE.install, "INSTALL_LEDGER");
  }
  const originalCreateHash = createHashDescriptor.descriptor.value;
  const probeHash = originalCreateHash.call(crypto, "sha256");
  const hashPrototype = Object.getPrototypeOf(probeHash);
  const updateDescriptor = descriptorOwner(hashPrototype, "update");
  const digestDescriptor = descriptorOwner(hashPrototype, "digest");
  if (!updateDescriptor || !digestDescriptor ||
      typeof updateDescriptor.descriptor.value !== "function" ||
      typeof digestDescriptor.descriptor.value !== "function") {
    fail(SAFE.install, "INSTALL_LEDGER");
  }
  const originalUpdate = updateDescriptor.descriptor.value;
  const originalDigest = digestDescriptor.descriptor.value;
  try { originalDigest.call(probeHash); } catch { fail(SAFE.install, "INSTALL_LEDGER"); }

  const createHash = function observedMigrationCreateHash(...args) {
    if (state.selfTest) {
      recordEvent(state, "CRYPTO_CREATEHASH");
      return undefined;
    }
    if (!state.active) return originalCreateHash.apply(this, args);
    if (this !== crypto) rejectMigrationDependency(state, "DP_RECEIVER", "CRYPTO_CREATEHASH");
    if (args.length !== 1 || args[0] !== "sha256") {
      rejectMigrationDependency(state, "DP_ARGUMENTS", "CRYPTO_CREATEHASH");
    }
    const current = state.current;
    const index = current?.hashIndex ?? -1;
    const expected = state.migrationHashPlan[index];
    if (!expected || !migrationHashAdmission(state, current, index, "NEW")) {
      rejectMigrationDependency(state, "DP_STATE", "CRYPTO_CREATEHASH");
    }
    current.hashDelegations.createHash += 1;
    state.hashDelegationTotals.createHash += 1;
    const hash = originalCreateHash.apply(this, args);
    current.hashIndex = index + 1;
    current.pendingHash = {
      hash,
      index,
      runId: current.runId,
      lifecycleGeneration: current.lifecycleGeneration,
      path: expected.path,
      updated: false,
      stage: "HASH_ALLOCATED",
    };
    return hash;
  };
  const update = function observedMigrationHashUpdate(...args) {
    if (state.selfTest) {
      recordEvent(state, "CRYPTO_HASH_UPDATE");
      return this;
    }
    if (!state.active) return originalUpdate.apply(this, args);
    const current = state.current;
    const pending = current?.pendingHash;
    if (!pending || pending.hash !== this) {
      rejectMigrationDependency(state, "DP_RECEIVER", "CRYPTO_HASH_UPDATE");
    }
    if (args.length !== 1 || typeof args[0] !== "string" ||
        args[0] !== state.migrationHashPlan[pending.index]?.input) {
      rejectMigrationDependency(state, "DP_ARGUMENTS", "CRYPTO_HASH_UPDATE");
    }
    if (!migrationHashAdmission(state, current, pending.index, "HASH_ALLOCATED")) {
      rejectMigrationDependency(state, "DP_STATE", "CRYPTO_HASH_UPDATE");
    }
    current.hashDelegations.update += 1;
    state.hashDelegationTotals.update += 1;
    const result = originalUpdate.apply(this, args);
    pending.updated = true;
    pending.stage = "HASH_UPDATED";
    return result;
  };
  const digest = function observedMigrationHashDigest(...args) {
    if (state.selfTest) {
      recordEvent(state, "CRYPTO_HASH_DIGEST");
      return "ssc-canary";
    }
    if (!state.active) return originalDigest.apply(this, args);
    const current = state.current;
    const pending = current?.pendingHash;
    if (!pending || pending.hash !== this) {
      rejectMigrationDependency(state, "DP_RECEIVER", "CRYPTO_HASH_DIGEST");
    }
    if (args.length !== 1 || args[0] !== "hex") {
      rejectMigrationDependency(state, "DP_ARGUMENTS", "CRYPTO_HASH_DIGEST");
    }
    if (!migrationHashAdmission(state, current, pending.index, "HASH_UPDATED")) {
      rejectMigrationDependency(state, "DP_STATE", "CRYPTO_HASH_DIGEST");
    }
    const expected = state.migrationHashPlan[pending.index];
    current.hashDelegations.digest += 1;
    state.hashDelegationTotals.digest += 1;
    const result = originalDigest.apply(this, args);
    if (result !== expected.hash) rejectMigrationDependency(state, "DP_STATE", "CRYPTO_HASH_DIGEST");
    current.pendingHash = null;
    current.hashCompleted += 1;
    return result;
  };

  ledger.install(createHashDescriptor.owner, "createHash", createHash);
  ledger.install(updateDescriptor.owner, "update", update);
  ledger.install(digestDescriptor.owner, "digest", digest);
  for (const [wrapper, receiver, args, id] of [
    [createHash, crypto, ["canary"], "CRYPTO_CREATEHASH"],
    [update, {}, ["canary"], "CRYPTO_HASH_UPDATE"],
    [digest, {}, ["hex"], "CRYPTO_HASH_DIGEST"],
  ]) {
    state.selfTest = true;
    try { wrapper.apply(receiver, args); } catch { /* observer canary */ }
    state.selfTest = false;
    if (!state.canaryHits.has(id)) fail(SAFE.install, "INSTALL_LEDGER");
    state.canaryHits.delete(id);
  }
}

function installMigrationExistenceObserver(state, ledger, fs) {
  const found = descriptorOwner(fs, "existsSync");
  if (!found || typeof found.descriptor.value !== "function") fail(SAFE.install, "INSTALL_LEDGER");
  const original = found.descriptor.value;
  const wrapper = function observedMigrationExistsSync(...args) {
    if (state.selfTest) { recordEvent(state, "FS_MIGRATION_EXISTS"); return true; }
    if (!state.active) return original.apply(this, args);
    const current = state.current;
    if (this !== fs) rejectMigrationDependency(state, "DP_RECEIVER", "FS_MIGRATION_EXISTS");
    if (args.length !== 1 || typeof args[0] !== "string") rejectMigrationDependency(state, "DP_ARGUMENTS", "FS_MIGRATION_EXISTS");
    if (!migrationIdentityAdmission(state, current) || current.migrationEntered || current.manifestExistsCount !== 0 ||
        current.manifestReadCount !== 0 || current.hashIndex !== 0) {
      rejectMigrationDependency(state, "DP_STATE", "FS_MIGRATION_EXISTS");
    }
    if (args[0] !== state.migrationManifestPlan?.path) rejectMigrationDependency(state, "DP_MANIFEST", "FS_MIGRATION_EXISTS");
    current.migrationExistenceDelegations += 1;
    state.migrationExistenceDelegations += 1;
    const result = original.apply(this, args);
    if (result !== true) rejectMigrationDependency(state, "DP_MANIFEST", "FS_MIGRATION_EXISTS");
    current.manifestExistsCount += 1;
    current.events.push("MIGRATION_MANIFEST_EXISTS");
    return result;
  };
  ledger.install(found.owner, "existsSync", wrapper);
  state.selfTest = true;
  try { wrapper.call(fs, "ssc-canary"); } catch { /* observer canary */ }
  state.selfTest = false;
  if (!state.canaryHits.has("FS_MIGRATION_EXISTS")) fail(SAFE.install, "INSTALL_LEDGER");
  state.canaryHits.delete("FS_MIGRATION_EXISTS");
}

function installMigrationReadObserver(state, ledger, fs) {
  const found = descriptorOwner(fs, "readFileSync");
  if (!found || typeof found.descriptor.value !== "function") fail(SAFE.install, "INSTALL_LEDGER");
  const original = found.descriptor.value;
  const wrapper = function observedMigrationReadFileSync(...args) {
    if (state.selfTest) { recordEvent(state, "FS_MIGRATION_READ"); return Buffer.from("ssc-canary"); }
    if (!state.active) return original.apply(this, args);
    const current = state.current;
    if (this !== fs) rejectMigrationDependency(state, "DP_RECEIVER", "FS_MIGRATION_READ");
    if (args.length !== 1 || typeof args[0] !== "string") rejectMigrationDependency(state, "DP_ARGUMENTS", "FS_MIGRATION_READ");
    if (!migrationIdentityAdmission(state, current)) rejectMigrationDependency(state, "DP_STATE", "FS_MIGRATION_READ");
    let expected;
    let kind;
    let index = -1;
    if (current.manifestExistsCount === 1 && current.manifestReadCount === 0 && !current.migrationEntered &&
        current.migrationReadCursor === 0 && current.hashIndex === 0) {
      expected = state.migrationManifestPlan;
      kind = "manifest";
    } else {
      index = current.migrationReadCursor;
      expected = state.migrationHashPlan[index];
      kind = "migration";
      if (!current.migrationEntered || current.manifestReadCount !== 1 || current.hashIndex !== index ||
          current.hashCompleted !== index || current.pendingHash !== null || !expected) {
        rejectMigrationDependency(state, "DP_STATE", "FS_MIGRATION_READ");
      }
    }
    if (!expected || args[0] !== expected.path) rejectMigrationDependency(state, "DP_MANIFEST", "FS_MIGRATION_READ");
    if (current.fileReadTicket !== null || current.fileOpenTicket !== null) {
      rejectMigrationDependency(state, "DP_STATE", "FS_MIGRATION_READ");
    }
    const ticket = {
      runId: current.runId,
      lifecycleGeneration: current.lifecycleGeneration,
      kind,
      index: kind === "manifest" ? 0 : index,
      path: expected.path,
      cursor: current.migrationReadCursor,
      event: kind === "manifest" ? "MIGRATION_MANIFEST_READ" : "MIGRATION_SQL_READ",
      consumed: false,
    };
    current.fileReadTicket = ticket;
    current.fileOpenTicket = {
      capability: "FS_MIGRATION_READ_OPEN",
      receiver: fs,
      args: Object.freeze([expected.path, "r", 438]),
      readTicket: ticket,
      runId: ticket.runId,
      lifecycleGeneration: ticket.lifecycleGeneration,
      path: ticket.path,
      cursor: ticket.cursor,
      consumed: false,
    };
    if (!migrationIdentityAdmission(state, current) || state.current !== current ||
        ticket.runId !== current.runId || ticket.lifecycleGeneration !== current.lifecycleGeneration ||
        ticket.cursor !== current.migrationReadCursor || ticket.path !== args[0] ||
        ticket.event !== (kind === "manifest" ? "MIGRATION_MANIFEST_READ" : "MIGRATION_SQL_READ")) {
      current.fileReadTicket = null;
      current.fileOpenTicket = null;
      rejectMigrationDependency(state, "DP_STATE", "FS_MIGRATION_READ");
    }
    ticket.consumed = true;
    current.migrationReadDelegations += 1;
    state.migrationReadDelegations += 1;
    let content;
    try {
      content = original.apply(this, args);
    } finally {
      current.fileReadTicket = null;
      current.fileOpenTicket = null;
    }
    if (!ticket.consumed || ticket.runId !== current.runId ||
        ticket.lifecycleGeneration !== current.lifecycleGeneration || ticket.path !== expected.path) {
      rejectMigrationDependency(state, "DP_STATE", "FS_MIGRATION_READ");
    }
    if (content.toString("utf8") !== expected.source) rejectMigrationDependency(state, "DP_MANIFEST", "FS_MIGRATION_READ");
    if (kind === "manifest") {
      current.manifestReadCount += 1;
      current.migrationEntered = true;
      current.events.push("MIGRATION_MANIFEST_READ");
    } else {
      current.lastReadMigrationIndex = index;
      current.lastReadMigrationPath = expected.path;
      current.lastReadMigrationSource = expected.source;
      current.migrationReadCursor += 1;
      current.events.push("MIGRATION_SQL_READ");
    }
    return content;
  };
  ledger.install(found.owner, "readFileSync", wrapper);
  state.selfTest = true;
  try { wrapper.call(fs, "ssc-canary"); } catch { /* observer canary */ }
  state.selfTest = false;
  if (!state.canaryHits.has("FS_MIGRATION_READ")) fail(SAFE.install, "INSTALL_LEDGER");
  state.canaryHits.delete("FS_MIGRATION_READ");
}

function hasWriteOpenIntent(flags, writeMask) {
  if (typeof flags === "number") return (flags & writeMask) !== 0;
  if (typeof flags === "string") return /[wax+]/u.test(flags);
  return true;
}

function installOpenObserver(state, ledger, owner, key, id, writeMask) {
  const found = descriptorOwner(owner, key);
  if (!found || typeof found.descriptor.value !== "function") fail(SAFE.install, "INSTALL_LEDGER");
  const original = found.descriptor.value;
  const wrapper = function observedOpen(...args) {
    const flags = args[1];
    const writeIntent = hasWriteOpenIntent(flags, writeMask);
    const allowedRead = state.allowedReadPaths instanceof Set && state.allowedReadPaths.has(args[0]);
    if (state.active && state.migrationFsOwners?.has(owner)) {
      const current = state.current;
      if (this !== owner) rejectMigrationDependency(state, "DP_RECEIVER", id);
      if (args.length !== 3 || typeof args[0] !== "string" || args[1] !== "r" ||
          args[2] !== 438 || writeIntent) {
        rejectMigrationDependency(state, "DP_ARGUMENTS", id);
      }
      const ticket = current?.fileOpenTicket;
      const readTicket = ticket?.readTicket;
      const expectedReadEvent = readTicket?.kind === "manifest"
        ? "MIGRATION_MANIFEST_READ" : "MIGRATION_SQL_READ";
      const expectedReadIndex = readTicket?.kind === "manifest" ? 0 : ticket?.cursor;
      const exactTicketArgs = Array.isArray(ticket?.args) && ticket.args.length === args.length &&
        ticket.args.every((argument, index) => Object.is(argument, args[index]));
      if (!migrationIdentityAdmission(state, current) || !allowedRead || !ticket ||
          ticket.capability !== "FS_MIGRATION_READ_OPEN" || ticket.receiver !== owner ||
          !exactTicketArgs || ticket.readTicket !== current.fileReadTicket || !readTicket?.consumed ||
          ticket.consumed || ticket.cursor !== current.migrationReadCursor ||
          ticket.runId !== current.runId || ticket.lifecycleGeneration !== current.lifecycleGeneration ||
          ticket.path !== args[0] || readTicket.runId !== current.runId ||
          readTicket.lifecycleGeneration !== current.lifecycleGeneration ||
          readTicket.cursor !== current.migrationReadCursor || readTicket.path !== args[0] ||
          readTicket.kind !== "manifest" && readTicket.kind !== "migration" ||
          readTicket.index !== expectedReadIndex || readTicket.event !== expectedReadEvent) {
        rejectMigrationDependency(state, "DP_STATE", id);
      }
      ticket.consumed = true;
      current.migrationOpenDelegations += 1;
      state.migrationOpenDelegations += 1;
      return original.apply(this, args);
    }
    if (writeIntent || (state.active && !allowedRead)) {
      recordEvent(state, id);
      if (!state.selfTest) throw new Error("SSC_BLOCKED");
      return undefined;
    }
    return original.apply(this, args);
  };
  ledger.install(found.owner, key, wrapper);
  state.selfTest = true;
  try {
    wrapper.call(found.owner, "ssc-canary", "w");
    wrapper.call(found.owner, "ssc-canary", writeMask);
  } catch {
    // The synthetic write is intentionally blocked.
  } finally {
    state.selfTest = false;
  }
  if (!state.canaryHits.has(id)) fail(SAFE.install, "INSTALL_LEDGER");
  state.canaryHits.delete(id);
}

function installJsonObserver(state, ledger) {
  const found = descriptorOwner(JSON, "stringify");
  if (!found || typeof found.descriptor.value !== "function") fail(SAFE.install, "INSTALL_LEDGER");
  const original = found.descriptor.value;
  const wrapper = function observedJsonStringify(...args) {
    if (state.active && !state.selfTest) {
      recordEvent(state, "JSON_SECRET_SERIALIZATION");
      throw new Error("SSC_BLOCKED");
    }
    const output = original.apply(this, args);
    if (typeof output === "string" && containsMarker(output, state.markers)) recordEvent(state, "JSON_SECRET_SERIALIZATION");
    return output;
  };
  ledger.install(found.owner, "stringify", wrapper);
  state.selfTest = true;
  wrapper.call(JSON, { marker: state.markers.canary });
  state.selfTest = false;
  if (!state.canaryHits.has("JSON_SECRET_SERIALIZATION")) fail(SAFE.install, "INSTALL_LEDGER");
  state.canaryHits.delete("JSON_SECRET_SERIALIZATION");
}

function installObservers(state) {
  const require = createRequire(import.meta.url);
  state.require = require;
  const ledger = new PatchLedger();
  const net = require("node:net");
  const tls = require("node:tls");
  const http = require("node:http");
  const https = require("node:https");
  const dgram = require("node:dgram");
  const childProcess = require("node:child_process");
  const fs = require("node:fs");
  const fsPromises = require("node:fs/promises");
  const os = require("node:os");
  const crypto = require("node:crypto");
  state.migrationFsOwners = new Set([fs, fsPromises]);
  const v8 = require("node:v8");
  const diagnosticsChannel = require("node:diagnostics_channel");

  try {
    const originalOpenSync = descriptorOwner(fs, "openSync");
    if (!originalOpenSync || typeof originalOpenSync.descriptor.value !== "function") {
      fail(SAFE.install, "INSTALL_LEDGER");
    }
    state.capabilityFd = originalOpenSync.descriptor.value.call(fs, os.devNull, fs.constants.O_WRONLY);
    installObserverSet(state, ledger, net, ["connect", "createConnection"], "NET");
    installObserverSet(state, ledger, net.Socket.prototype, ["connect"], "NET_SOCKET");
    installObserverSet(state, ledger, tls, ["connect"], "TLS");
    installObserverSet(state, ledger, http, ["request", "get"], "HTTP");
    installObserverSet(state, ledger, https, ["request", "get"], "HTTPS");
    installObserverSet(state, ledger, dgram.Socket.prototype, ["send", "connect"], "DGRAM");
    installObserverSet(state, ledger, childProcess, ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"], "CHILD_PROCESS");
    installObserverSet(state, ledger, globalThis, ["fetch"], "GLOBAL_FETCH");
    installObserverSet(state, ledger, console, [
      "log", "error", "warn", "info", "debug", "dir", "table", "trace", "assert",
      "group", "groupEnd", "groupCollapsed", "count", "countReset", "time", "timeEnd",
      "timeLog", "clear", "dirxml", "profile", "profileEnd",
    ], "CONSOLE");
    installObserverSet(state, ledger, process, ["emitWarning"], "PROCESS_WARNING");
    installObserverSet(state, ledger, process.stdout, ["write"], "STDOUT", true);
    installObserverSet(state, ledger, process.stderr, ["write"], "STDERR", true);
    installObserverSet(state, ledger, globalThis, ["setTimeout", "setInterval", "setImmediate", "queueMicrotask"], "TIMER");
    installObserverSet(state, ledger, process, ["nextTick"], "TIMER_PROCESS");

    const writeMethods = [
      "write", "writeSync", "writev", "writevSync", "writeFile", "writeFileSync", "appendFile", "appendFileSync",
      "createWriteStream", "truncate", "truncateSync", "ftruncate", "ftruncateSync",
      "copyFile", "copyFileSync", "cp", "cpSync", "rename", "renameSync", "link",
      "linkSync", "symlink", "symlinkSync", "mkdir", "mkdirSync", "mkdtemp", "mkdtempSync",
      "rm", "rmSync", "rmdir", "rmdirSync", "unlink", "unlinkSync", "writeFileHandle",
    ];
    for (const key of writeMethods) {
      if (descriptorOwner(fs, key)) installFunction(ledger, state, fs, key, `FS_${key.toUpperCase()}`);
    }
    for (const key of ["writeFile", "appendFile", "truncate", "rm", "rmdir", "unlink", "mkdir", "mkdtemp", "rename", "copyFile", "cp", "link", "symlink"]) {
      if (descriptorOwner(fsPromises, key)) installFunction(ledger, state, fsPromises, key, `FS_PROMISES_${key.toUpperCase()}`);
    }
    const writeOpenMask = (fs.constants?.O_WRONLY ?? 1) |
      (fs.constants?.O_RDWR ?? 2) |
      (fs.constants?.O_CREAT ?? 64) |
      (fs.constants?.O_TRUNC ?? 512) |
      (fs.constants?.O_APPEND ?? 1024) |
      (fs.constants?.O_EXCL ?? 128) |
      (fs.constants?.O_TMPFILE ?? 0);
    if (descriptorOwner(fs, "open")) installOpenObserver(state, ledger, fs, "open", "FS_OPEN", writeOpenMask);
    if (descriptorOwner(fs, "openSync")) installOpenObserver(state, ledger, fs, "openSync", "FS_OPENSYNC", writeOpenMask);
    installMigrationExistenceObserver(state, ledger, fs);
    installMigrationReadObserver(state, ledger, fs);
    if (descriptorOwner(fsPromises, "open")) installOpenObserver(state, ledger, fsPromises, "open", "FS_PROMISES_OPEN", writeOpenMask);
    if (descriptorOwner(v8, "writeHeapSnapshot")) installFunction(ledger, state, v8, "writeHeapSnapshot", "V8_WRITE_HEAP_SNAPSHOT");
    if (process.report && descriptorOwner(process.report, "writeReport")) installFunction(ledger, state, process.report, "writeReport", "PROCESS_REPORT");

    for (const key of [
      "createHmac", "createCipheriv", "createDecipheriv", "createSign", "createVerify",
      "generateKey", "generateKeyPair", "generateKeyPairSync", "randomBytes", "randomFill", "randomFillSync",
      "pbkdf2", "pbkdf2Sync", "scrypt", "scryptSync", "hkdf", "hkdfSync",
      "createSecretKey", "createPublicKey", "createPrivateKey", "hash", "randomUUID", "randomInt",
      "generatePrime", "generatePrimeSync", "checkPrime", "checkPrimeSync",
    ]) {
      if (descriptorOwner(crypto, key)) installPassthroughObserver(state, ledger, crypto, key, `CRYPTO_${key.toUpperCase()}`);
    }
    installMigrationHashObserver(state, ledger, crypto);
    const webcryptoTargets = new Set([crypto.webcrypto, globalThis.crypto].filter(Boolean));
    const subtlePrototypes = new Set();
    for (const webcrypto of webcryptoTargets) {
      const subtle = webcrypto.subtle;
      const subtlePrototype = subtle && Object.getPrototypeOf(subtle);
      if (subtlePrototype && !subtlePrototypes.has(subtlePrototype)) {
        subtlePrototypes.add(subtlePrototype);
        for (const key of ["digest", "deriveKey", "deriveBits", "encrypt", "decrypt", "sign", "generateKey"]) {
          if (descriptorOwner(subtlePrototype, key)) {
            installPassthroughObserver(state, ledger, subtlePrototype, key, `WEBCRYPTO_${key.toUpperCase()}`);
          }
        }
      }
      for (const key of ["getRandomValues", "randomUUID"]) {
        if (descriptorOwner(webcrypto, key)) {
          installPassthroughObserver(state, ledger, webcrypto, key, `WEBCRYPTO_${key.toUpperCase()}`);
        }
      }
    }
    installEnvProxy(ledger, state);
    installProcessListeners(ledger, state);
    installDiagnosticsChannel(ledger, state, diagnosticsChannel);
    installPrototypeMutationObservers(state, ledger);
    installJsonObserver(state, ledger);
    installWeakMapObserver(ledger, state, function ObservedPool() {});
  } catch (error) {
    try {
      if (typeof state.capabilityFd === "number") fs.closeSync(state.capabilityFd);
      state.capabilityFd = null;
      ledger.restore();
    } catch {
      // The boundary below reports only the fixed install code.
    }
    if (error instanceof HarnessFailure) throw error;
    fail(SAFE.install, "INSTALL_LEDGER");
  }
  return { ledger, require };
}

function isAuthorityRecord(key, record, ObservedPool, { allowRevoked = false } = {}) {
  if (!record || typeof record !== "object" || typeof key !== "object") return false;
  const ownNames = Object.getOwnPropertyNames(record);
  const ownKeys = Reflect.ownKeys(record);
  if (ownKeys.length !== AUTHORITY_KEYS.length ||
      ownNames.length !== AUTHORITY_KEYS.length ||
      ownKeys.some((item) => typeof item !== "string") ||
      !AUTHORITY_KEYS.every((name) => ownNames.includes(name))) return false;
  if (record.authority !== key || !(record.pool instanceof ObservedPool)) return false;
  if ((record.valid !== true && !(allowRevoked && record.valid === false)) ||
      record.phase !== "initialization" || typeof record.brand !== "symbol") return false;
  for (const name of AUTHORITY_KEYS) {
    const descriptor = Object.getOwnPropertyDescriptor(record, name);
    if (!descriptor || descriptor.get || descriptor.set ||
        descriptor.enumerable !== true || descriptor.configurable !== true || descriptor.writable !== true) return false;
  }
  return true;
}

function installPoolSeam(state, ledger, pg) {
  const originalPool = pg.Pool;
  if (typeof originalPool !== "function") fail(SAFE.install, "INSTALL_LEDGER");
  state.originalPool = originalPool;
  class ObservedPool extends originalPool {
    constructor(options) {
      if (state.active && state.current && !state.selfTest) {
        if (!poolOptionsMatch(options, state, state.current, false)) {
          state.current.poolOptionRejectCount += 1;
          state.current.protocolRejected = true;
          recordEvent(state, "POOL_OPTIONS_REJECT");
          throw new Error("SSC_BLOCKED");
        }
        state.current.poolInputValidated = true;
      }
      super(options);
      this.__sscInputOptions = options;
      if (state.active && state.current) {
        if (!poolOptionsMatch(this.options, state, state.current, true)) {
          state.current.poolOptionRejectCount += 1;
          state.current.protocolRejected = true;
          recordEvent(state, "POOL_EFFECTIVE_OPTIONS_REJECT");
          throw new Error("SSC_BLOCKED");
        }
        state.current.poolEffectiveValidated = true;
        state.current.poolCount += 1;
        state.current.pools.push(this);
        state.current.events.push("POOL_CONSTRUCTOR");
      }
    }

    async query(...args) {
      return executeQuery(state, this, args, "pool");
    }

    async connect(...args) {
      if (!state.active || !state.current) throw new Error("SSC_BLOCKED");
      const current = state.current;
      const expected = state.migrationQueryPlan[current.migrationPlanIndex];
      if (this !== current.pools[0] || args.length !== 0 || current.connectCount !== 0 ||
          current.identityCalls !== 2 || expected?.channel !== "client" ||
          expected.text.toLowerCase() !== "begin" || expected.values.length !== 0) {
        rejectPoolOperation(state, "POOL_CONNECT_REJECT");
      }
      current.connectCount += 1;
      const client = {
        async query(...queryArgs) {
          if (this !== client) rejectPoolOperation(state, "POOL_CLIENT_RECEIVER_REJECT");
          return executeQuery(state, this, queryArgs, "client");
        },
        release(...releaseArgs) {
          if (this !== client || releaseArgs.length !== 0 ||
              current.connectedClient !== client || current.connectCount !== 1 ||
              current.releaseCount !== 0 ||
              current.migrationPlanIndex !== state.migrationQueryPlan.length) {
            rejectPoolOperation(state, "POOL_RELEASE_REJECT");
          }
          current.releaseCount += 1;
        },
      };
      current.connectedClient = client;
      return client;
    }

    async end(...args) {
      const current = state.current;
      if (current) {
        if (state.authorityRecord && state.authorityRecord.valid === false &&
            current.authorityRevocationStarted !== true) {
          current.authorityRevocationStarted = true;
          current.lifecyclePhase = "REVOCATION";
          current.lifecycleGeneration += 1;
          current.events.push("AUTHORITY_REVOKED");
        }
        current.cleanupEntryCount += 1;
        current.cleanupAttempted = true;
        current.lifecyclePhase = "CLEANUP";
        current.lifecycleGeneration += 1;
        current.events.push("POOL_END_ENTRY");
        if (current.originalCompletion === null) {
          current.originalCompletion = current.scenario.prePoolFailure ? "THROW"
            : current.scenario.rejectOperation || current.scenario.rejectSecondIdentity ||
              current.scenario.rejectMigration ? "THROW" : "RETURN";
        }
      }
      if (!state.active || !current) return undefined;
      const complete = current.identityCalls === 2 &&
        current.migrationPlanIndex === state.migrationQueryPlan.length &&
        current.releaseCount === 1 && current.operationCalls === 1;
      const expectedEarlyReject = current.scenario.rejectSecondIdentity &&
        current.identityCalls === 2 && current.migrationPlanIndex === 0 &&
        current.connectCount === 0 && current.operationCalls === 0;
      if (this !== current.pools[0] || args.length !== 0 || current.endCount !== 0 ||
          (!complete && !expectedEarlyReject && !current.queryRejected)) {
        rejectPoolOperation(state, "POOL_END_REJECT");
      }
      current.endCount += 1;
      current.events.push("POOL_END");
      if (current.scenario.rejectCleanup) {
        current.cleanupWasAsyncPromise = true;
        throw current.cleanupError;
      }
      current.cleanupSucceeded = true;
      return undefined;
    }
  }
  state.observedPool = ObservedPool;
  const poolDescriptor = Object.getOwnPropertyDescriptor(pg, "Pool");
  if (!poolDescriptor) fail(SAFE.install, "INSTALL_LEDGER");
  ledger.install(pg, "Pool", ObservedPool);
  for (const key of ["query", "connect", "end"]) {
    const found = descriptorOwner(originalPool.prototype, key);
    if (!found) fail(SAFE.install, "INSTALL_LEDGER");
    installPoolDependencyObserver(state, ledger, found.owner, key, `POOL_FALLBACK_${key.toUpperCase()}`);
  }
  state.selfTest = true;
  const canary = new ObservedPool({ host: "127.0.0.1", port: 1, user: "canary", database: "canary", max: 1 });
  void canary.end();
  state.selfTest = false;
  if (pg.Pool !== ObservedPool) fail(SAFE.install, "INSTALL_LEDGER");
  return ObservedPool;
}

function extractIdentitySql(source) {
  const sourceFile = ts.createSourceFile(
    "disposable-postgres-fixture.mjs",
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.JS,
  );
  let count = 0;
  let value;
  const visit = (node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) &&
        node.name.text === "identitySql") {
      count += 1;
      if (!node.initializer || !ts.isNoSubstitutionTemplateLiteral(node.initializer)) {
        fail(SAFE.internal, "IDENTITY_SQL_SOURCE");
      }
      value = node.initializer.text;
    }
    ts.forEachChild(node, visit);
  };
  if (sourceFile.parseDiagnostics.length !== 0) fail(SAFE.internal, "IDENTITY_SQL_SOURCE");
  visit(sourceFile);
  if (count !== 1 || typeof value !== "string" || value.length === 0) {
    fail(SAFE.internal, "IDENTITY_SQL_SOURCE");
  }
  return value;
}

async function buildMigrationContract(require, migrationsFolder) {
  const { PgDialect } = require("drizzle-orm/pg-core");
  const { sql } = require("drizzle-orm");
  const { readMigrationFiles } = require("drizzle-orm/migrator");
  if (typeof PgDialect !== "function" || typeof readMigrationFiles !== "function" ||
      !sql || typeof sql.raw !== "function") {
    fail(SAFE.internal, "DRIZZLE_CONTRACT");
  }
  const migrations = readMigrationFiles({ migrationsFolder });
  const fs = require("node:fs");
  const migrationRoot = path.resolve(migrationsFolder);
  const journalPath = path.join(migrationRoot, "meta", "_journal.json");
  let journal;
  let manifestSource;
  try {
    manifestSource = await readFile(journalPath, "utf8");
    journal = JSON.parse(manifestSource);
  } catch {
    fail(SAFE.internal, "DRIZZLE_MANIFEST");
  }
  if (!Array.isArray(journal?.entries) || journal.entries.length !== migrations.length) {
    fail(SAFE.internal, "DRIZZLE_MANIFEST");
  }
  const readPaths = new Set([`${migrationsFolder}/meta/_journal.json`]);
  const verifiedReadPaths = new Set([journalPath]);
  const migrationTags = new Set();
  for (const entry of journal.entries) {
    const tag = entry?.tag;
    if (typeof tag !== "string" || !/^\d{4}_[a-z0-9_]+$/u.test(tag) || migrationTags.has(tag)) {
      fail(SAFE.internal, "DRIZZLE_MANIFEST");
    }
    migrationTags.add(tag);
    const sqlPath = path.resolve(migrationRoot, `${tag}.sql`);
    if (path.dirname(sqlPath) !== migrationRoot) fail(SAFE.internal, "DRIZZLE_MANIFEST");
    readPaths.add(`${migrationsFolder}/${tag}.sql`);
    verifiedReadPaths.add(sqlPath);
  }
  for (const readPath of verifiedReadPaths) {
    try {
      const realPath = fs.realpathSync.native(readPath);
      if (path.resolve(realPath).toLowerCase() !== readPath.toLowerCase() ||
          !fs.statSync(readPath).isFile()) {
        fail(SAFE.internal, "DRIZZLE_MANIFEST");
      }
    } catch {
      fail(SAFE.internal, "DRIZZLE_MANIFEST");
    }
  }
  const dialect = new PgDialect();
  const queries = [];
  const capture = (channel, statement) => {
    const query = dialect.sqlToQuery(statement);
    if (!query || typeof query.sql !== "string" || !Array.isArray(query.params)) {
      fail(SAFE.internal, "DRIZZLE_CONTRACT");
    }
    queries.push(Object.freeze({
      channel,
      text: query.sql,
      values: Object.freeze([...query.params]),
    }));
  };
  const session = {
    async execute(statement) {
      capture("pool", statement);
      return { rows: [] };
    },
    async all(statement) {
      capture("pool", statement);
      return [];
    },
    async transaction(callback) {
      capture("client", sql`begin`);
      const transaction = {
        async execute(statement) {
          capture("client", statement);
          return { rows: [] };
        },
      };
      try {
        const result = await callback(transaction);
        capture("client", sql`commit`);
        return result;
      } catch (error) {
        capture("client", sql`rollback`);
        throw error;
      }
    },
  };
  await dialect.migrate(migrations, session, {});
  const hashes = migrations.map((migration, index) => {
    const tag = journal.entries[index].tag;
    const relativePath = migrationsFolder + "/" + tag + ".sql";
    const absolutePath = path.resolve(migrationRoot, tag + ".sql");
    return Object.freeze({
      input: migration.sql.join("--> statement-breakpoint"),
      hash: migration.hash,
      path: relativePath,
      absolutePath,
      source: fs.readFileSync(absolutePath, "utf8"),
    });
  });
  return Object.freeze({
    queries: Object.freeze(queries),
    hashes: Object.freeze(hashes),
    readPaths: Object.freeze([...readPaths]),
    manifest: Object.freeze({
      path: migrationsFolder + "/meta/_journal.json",
      absolutePath: journalPath,
      source: manifestSource,
    }),
  });
}

function ownDataValue(target, key, enumerable = true) {
  const descriptor = Object.getOwnPropertyDescriptor(target, key);
  if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value") ||
      descriptor.enumerable !== enumerable || descriptor.configurable !== true ||
      descriptor.writable !== true) return { ok: false };
  return { ok: true, value: descriptor.value };
}

function queryText(input) {
  if (typeof input === "string") return { text: input, configured: false };
  if (!input || typeof input !== "object" || types.isProxy(input) ||
      Object.getPrototypeOf(input) !== Object.prototype) return null;
  const keys = Reflect.ownKeys(input);
  if (keys.length !== 3 || keys.some((key) =>
    typeof key !== "string" || !["name", "text", "types"].includes(key))) return null;
  const name = ownDataValue(input, "name");
  const text = ownDataValue(input, "text");
  const typeMap = ownDataValue(input, "types");
  if (!name.ok || name.value !== undefined || !text.ok || typeof text.value !== "string" ||
      !typeMap.ok || !typeMap.value || typeof typeMap.value !== "object" ||
      types.isProxy(typeMap.value) || Object.getPrototypeOf(typeMap.value) !== Object.prototype) return null;
  const typeKeys = Reflect.ownKeys(typeMap.value);
  const parser = ownDataValue(typeMap.value, "getTypeParser");
  if (typeKeys.length !== 1 || typeKeys[0] !== "getTypeParser" ||
      !parser.ok || typeof parser.value !== "function") return null;
  return { text: text.value, configured: true };
}

function arrayValues(value) {
  if (!Array.isArray(value) || types.isProxy(value) ||
      Object.getPrototypeOf(value) !== Array.prototype) return null;
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  if (!lengthDescriptor || lengthDescriptor.enumerable || lengthDescriptor.configurable ||
      !lengthDescriptor.writable || !Number.isSafeInteger(lengthDescriptor.value) ||
      lengthDescriptor.value < 0) return null;
  const length = lengthDescriptor.value;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== length + 1 || keys.some((key) =>
    key !== "length" && (typeof key !== "string" || !/^(?:0|[1-9]\d*)$/u.test(key) ||
      Number(key) >= length))) return null;
  const values = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = ownDataValue(value, String(index));
    if (!descriptor.ok) return null;
    values.push(descriptor.value);
  }
  return values;
}

function sameValues(actual, expected) {
  const values = arrayValues(actual);
  return values !== null && values.length === expected.length &&
    values.every((value, index) => Object.is(value, expected[index]));
}

function rejectPoolOperation(state, id = "POOL_QUERY_REJECT") {
  if (state.current) { state.current.queryRejected = true; state.current.protocolRejected = true; }
  recordEvent(state, id);
  throw new Error("SSC_BLOCKED");
}

function executeQuery(state, receiver, args, channel) {
  if (!state.active || !state.current) throw new Error("SSC_BLOCKED");
  const current = state.current;
  const expectedPool = current.pools[0];
  const query = args.length > 0 ? queryText(args[0]) : null;
  const values = args.length === 2 ? args[1] : null;
  if ((channel === "pool" && receiver !== expectedPool) ||
      (channel === "client" && receiver !== current.connectedClient) ||
      args.length !== 2 || !query || !Array.isArray(values) || types.isProxy(values)) {
    rejectPoolOperation(state);
  }
  const parameters = arrayValues(values);
  if (parameters === null) rejectPoolOperation(state);

  if (query.text === state.identitySql) {
    const expectedAuthorityOrder = current.identityCalls === 0
      ? current.authorityCaptureCount === 0 && state.authorityRecord === null
      : current.identityCalls === 1 && current.authorityCaptureCount === 1 &&
        state.authorityRecord?.valid === true && state.authorityPool === expectedPool;
    if (channel !== "pool" || query.configured || current.identityCalls >= 2 ||
        !expectedAuthorityOrder ||
        !sameValues(values, ["runtime_posture_test", "cloud_admin"])) {
      rejectPoolOperation(state, "POOL_IDENTITY_REJECT");
    }
    current.identityCalls += 1;
    current.events.push(current.identityCalls === 1 ? "IDENTITY_1" : "IDENTITY_2");
    const rejected = current.scenario.rejectSecondIdentity && current.identityCalls === 2;
    if (rejected) current.originalCompletion = "THROW";
    const row = {
      database_matches: !rejected,
      user_matches: true,
      postgres17: true,
      non_recovery: true,
      catalog_fingerprint: "100",
      lifecycle_fingerprint: rejected ? "201" : "200",
    };
    current.identityFingerprints.push({ catalog: row.catalog_fingerprint, lifecycle: row.lifecycle_fingerprint });
    const rowValidated = row.database_matches && row.user_matches && row.postgres17 && row.non_recovery;
    if (current.identityCalls === 1) {
      current.identity1Validated = rowValidated && current.poolInputValidated && current.poolEffectiveValidated;
    } else {
      const first = current.identityFingerprints[0];
      current.fingerprintsEqual = Boolean(first && first.catalog === row.catalog_fingerprint &&
        first.lifecycle === row.lifecycle_fingerprint);
      const record = state.authorityRecord;
      current.authorityGuardPassed = Boolean(record && record.valid === true && record.pool === expectedPool &&
        record.database === "runtime_posture_test" && record.user === "cloud_admin" &&
        record.migrationsFolder === MIGRATIONS_FOLDER && record.phase === "initialization" &&
        current.authorityTokenFrozen && Object.isFrozen(record.authority));
      current.identity2Validated = rowValidated && current.authorityGuardPassed;
      if (current.identity2Validated && current.fingerprintsEqual && !rejected) {
        current.lifecyclePhase = "MIGRATION";
        current.events.push("MIGRATION_PERMISSION_GRANTED");
      }
      if (rejected || !current.identity2Validated || !current.fingerprintsEqual) current.protocolRejected = true;
    }
    return Promise.resolve({ rows: [row] });
  }

  const expected = state.migrationQueryPlan[current.migrationPlanIndex];
  if (current.identityCalls !== 2 || state.authorityRecord?.valid !== true ||
      state.authorityPool !== expectedPool || !expected || expected.channel !== channel ||
      !query.configured || query.text !== expected.text ||
      !sameValues(values, expected.values)) {
    rejectPoolOperation(state);
  }
  if (current.scenario.rejectMigration && current.migrationPlanIndex === 0) {
    current.queryRejected = true;
    current.migrationRejected = true;
    current.originalCompletion = "THROW";
    current.events.push("MIGRATION_REJECT");
    throw new Error("SSC_BLOCKED");
  }
  current.migrationPlanIndex += 1;
  current.migrationQueries += 1;
  if (!current.events.includes("MIGRATION")) current.events.push("MIGRATION");
  return Promise.resolve({ rows: [] });
}

function makeDiagnosticError(markers, kind) {
  const marker = kind === "cleanup" ? markers.cleanup : markers.operation;
  const message = `${markers.connection}:${marker}`;
  const error = new Error(message);
  error.stack = `Error: ${message}\n    at synthetic-${kind}-diagnostic`;
  error.cause = new Error(`${markers.connection}:${marker}:cause`);
  Object.defineProperty(error, "diagnostic", {
    configurable: true,
    enumerable: false,
    value: { connection: markers.connection, marker },
    writable: true,
  });
  return error;
}

function createScenarioState(scenario, markers) {
  return {
    scenario,
    cleanupError: makeDiagnosticError(markers, "cleanup"),
    authorityCaptureCount: 0,
    authorityReceiptAccepted: false,
    freshErrorReceiptAccepted: false,
    receiptInvocationBegan: false,
    authorityValidAtCapture: false,
    poolCount: 0,
    pools: [],
    identityCalls: 0,
    migrationQueries: 0,
    migrationPlanIndex: 0,
    hashIndex: 0,
    hashCompleted: 0,
    pendingHash: null,
    operationCalls: 0,
    endCount: 0,
    cleanupEntryCount: 0,
    cleanupAttempted: false,
    cleanupSucceeded: false,
    originalCompletion: null,
    propagatedCompletion: null,
    lifecyclePhase: "PRE_ADMISSION",
    lifecycleGeneration: 0,
    operationEntered: false,
    authorityRevocationStarted: false,
    publicCompleted: false,
    fileReadTicket: null,
    fileOpenTicket: null,
    migrationReadDelegations: 0,
    migrationOpenDelegations: 0,
    migrationExistenceDelegations: 0,
    connectCount: 0,
    releaseCount: 0,
    bindingMismatch: false,
    connectedClient: null,
    queryRejected: false,
    poolOptionRejectCount: 0,
    protocolRejected: false,
    poolInputValidated: false,
    poolEffectiveValidated: false,
    identity1Validated: false,
    identity2Validated: false,
    identityFingerprints: [],
    fingerprintsEqual: false,
    authorityGuardPassed: false,
    authorityTokenFrozen: false,
    migrationEntered: false,
    manifestExistsCount: 0,
    manifestReadCount: 0,
    migrationReadCursor: 0,
    lastReadMigrationIndex: -1,
    lastReadMigrationPath: null,
    lastReadMigrationSource: null,
    hashDelegations: { createHash: 0, update: 0, digest: 0 },
    operationOrderViolation: false,
    cleanupWasAsyncPromise: false,
    events: [],
  };
}

function containsMarker(value, markers) {
  if (typeof value === "symbol") value = value.description ?? "";
  if (typeof value !== "string") return false;
  return value.includes(markers.connection) || value.includes(markers.cleanup) ||
    value.includes(markers.operation) || value.includes(markers.canary);
}

function inspectSurface(valueToInspect, state, { trustedClassPrototype = null } = {}) {
  let leak = false;
  let invalid = false;
  let unsupported = false;
  let accessorUnsupported = false;
  let boundDetector = null;
  let halted = false;
  const visited = new Set();
  let entryCount = 0;
  const markUnsupported = () => {
    invalid = true;
    unsupported = true;
  };
  const markBound = (detector) => {
    invalid = true;
    boundDetector ??= detector;
    halted = true;
  };
  const walk = (current, depth) => {
    if (halted || leak) return;
    if (containsMarker(current, state.markers)) {
      leak = true;
      return;
    }
    if (entryCount >= MAX_INSPECTION_ENTRIES) {
      markBound("HS_ENTRY_BOUND");
      return;
    }
    entryCount += 1;
    if (!current || (typeof current !== "object" && typeof current !== "function")) return;
    if (types.isProxy(current)) {
      markUnsupported();
      halted = true;
      return;
    }
    if (typeof current === "function" || types.isWeakMap(current) || types.isWeakSet(current) || types.isPromise(current)) {
      markUnsupported();
      return;
    }
    if (visited.has(current)) return;
    if (depth >= MAX_INSPECTION_DEPTH) {
      markBound("HS_DEPTH_BOUND");
      return;
    }
    visited.add(current);
    const origin = surfaceOrigin(state, current);
    if (!origin || origin.kind === "unsupported") {
      markUnsupported();
      return;
    }

    let prototype;
    try { prototype = Object.getPrototypeOf(current); }
    catch {
      markUnsupported();
      halted = true;
      return;
    }

    const inspectDescriptors = (owner, childDepth) => {
      let keys;
      try { keys = Reflect.ownKeys(owner); }
      catch { markUnsupported(); halted = true; return; }
      for (const key of keys) {
        if (halted || leak) return;
        if (containsMarker(typeof key === "symbol" ? key.description ?? "" : key, state.markers)) {
          leak = true;
          return;
        }
        let descriptor;
        try { descriptor = Object.getOwnPropertyDescriptor(owner, key); }
        catch { markUnsupported(); halted = true; return; }
        if (!descriptor) {
          markUnsupported();
          halted = true;
          return;
        }
        if (descriptor.get || descriptor.set) {
          if (key === "stack" && descriptor.get === NATIVE_ERROR_STACK_DESCRIPTOR?.get &&
              descriptor.set === NATIVE_ERROR_STACK_DESCRIPTOR?.set) continue;
          invalid = true;
          accessorUnsupported = true;
          continue;
        }
        if (key === "then" && typeof descriptor.value === "function") markUnsupported();
        walk(descriptor.value, childDepth);
      }
    };

    inspectDescriptors(current, depth + 1);
    if (halted || leak) return;

    try {
      Reflect.apply(Map.prototype.forEach, current, [
        (item, key) => { walk(key, depth + 1); walk(item, depth + 1); },
      ]);
    } catch { /* The intrinsic rejects non-Map values without consulting user iterators. */ }
    if (halted || leak) return;
    try {
      Reflect.apply(Set.prototype.forEach, current, [(item) => walk(item, depth + 1)]);
    } catch { /* The intrinsic rejects non-Set values without consulting user iterators. */ }
    if (halted || leak) return;

    for (const unbox of BOXED_PRIMITIVE_UNBOXERS) {
      try { walk(Reflect.apply(unbox, current, []), depth + 1); break; }
      catch { /* Only boxed primitives pass these intrinsic internal-slot checks. */ }
    }
    if (halted || leak) return;

    while (prototype && !BUILTIN_PROTOTYPES.has(prototype)) {
      if (prototype === trustedClassPrototype) {
        try { prototype = Object.getPrototypeOf(prototype); }
        catch { markUnsupported(); halted = true; return; }
        continue;
      }
      if (types.isProxy(prototype)) {
        markUnsupported();
        halted = true;
        return;
      }
      if (visited.has(prototype)) break;
      if (depth + 1 >= MAX_INSPECTION_DEPTH) {
        markBound("HS_DEPTH_BOUND");
        return;
      }
      if (entryCount >= MAX_INSPECTION_ENTRIES) {
        markBound("HS_ENTRY_BOUND");
        return;
      }
      visited.add(prototype);
      entryCount += 1;
      inspectDescriptors(prototype, depth + 2);
      if (halted || leak) return;
      try { prototype = Object.getPrototypeOf(prototype); }
      catch {
        markUnsupported();
        halted = true;
        return;
      }
    }
  };
  walk(valueToInspect, 0);
  const detector = leak ? "HS_SECRET_REACHABLE"
    : unsupported ? "HS_INTERNAL_SLOT_UNSUPPORTED"
      : accessorUnsupported ? "HS_ACCESSOR_UNSUPPORTED"
        : boundDetector;
  return Object.freeze({ safe: !leak && !invalid, leak, invalid, ...(detector ? { detector } : {}) });
}
function authorityMetadataSafe(record, state) {
  if (!record || !isAuthorityRecord(record.authority, record, state.observedPool, { allowRevoked: true })) return false;
  for (const key of AUTHORITY_KEYS) {
    if (key === "pool") continue;
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (!descriptor || descriptor.get || descriptor.set ||
        !inspectSurface(descriptor.value, state).safe) return false;
  }
  return true;
}

function publicSuccess(result) {
  return Boolean(result && typeof result === "object" && Object.keys(result).length === 1 && result.ok === true);
}

function publicFailure(error, state) {
  if (!error || typeof error !== "object" || types.isProxy(error) || !types.isNativeError(error) ||
      !state.admissionErrorPrototype || Object.getPrototypeOf(error) !== state.admissionErrorPrototype) return false;
  const origin = state.surfaceOrigins.get(error);
  if (!origin || origin.identity !== error || origin.runId !== currentSurfaceRunId(state) ||
      origin.kind !== "admission-error" || origin.producer !== "frozen-helper-allocation") return false;
  const own = (key) => {
    const descriptor = Object.getOwnPropertyDescriptor(error, key);
    return descriptor && !descriptor.get && !descriptor.set ? descriptor.value : undefined;
  };
  if (own("name") !== "DisposablePostgresFixtureAdmissionError" ||
      own("message") !== "Disposable fixture admission failed." ||
      own("code") !== "disposable_fixture_admission_failed" ||
      Object.prototype.hasOwnProperty.call(error, "cause")) return false;
  const surface = inspectSurface(error, state, { trustedClassPrototype: state.admissionErrorPrototype });
  return surface.safe && Object.keys(error).every((key) => key === "name" || key === "code");
}

function eventIndex(events, name) {
  return events.indexOf(name);
}

function poolOptionsMatch(options, state, current, effective) {
  if (!options || typeof options !== "object" || types.isProxy(options) ||
      Object.getPrototypeOf(options) !== Object.prototype) return false;
  const omitPassword = current?.scenario?.omitPassword === true;
  const expected = new Map([
    ["host", "127.0.0.1"],
    ["port", 1],
    ["user", "cloud_admin"],
    ["database", "runtime_posture_test"],
    ["max", 1],
  ]);
  if (!omitPassword) expected.set("password", state.markers.connection);
  if (effective) {
    expected.set("min", 0);
    expected.set("maxUses", Infinity);
    expected.set("allowExitOnIdle", false);
    expected.set("maxLifetimeSeconds", 0);
    expected.set("idleTimeoutMillis", 10000);
  }
  const keys = Reflect.ownKeys(options);
  if (keys.length !== expected.size ||
      keys.some((key) => typeof key !== "string" || !expected.has(key))) return false;
  for (const [key, expectedValue] of expected) {
    const descriptor = Object.getOwnPropertyDescriptor(options, key);
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value") ||
        descriptor.configurable !== true || descriptor.writable !== true ||
        descriptor.enumerable !== !(effective && key === "password") ||
        !Object.is(descriptor.value, expectedValue)) return false;
  }
  return true;
}

function poolBindingContract(current, state) {
  const pool = current.pools[0];
  const capturedOptions = pool?.__sscInputOptions;
  const observedOptions = pool?.options;
  return Boolean(
    pool &&
    current.poolCount === 1 &&
    current.authorityCaptureCount === 1 &&
    state.authorityPool === pool &&
    state.authorityRecord?.pool === pool &&
    !current.bindingMismatch &&
    poolOptionsMatch(capturedOptions, state, current, false) &&
    poolOptionsMatch(observedOptions, state, current, true),
  );
}

function scenarioChecks(current, result, error, state) {
  const scenario = current.scenario;
  const prePoolFailure = scenario.prePoolFailure === true;
  const expectedFailure = Boolean(prePoolFailure || scenario.rejectOperation ||
    scenario.rejectSecondIdentity || scenario.rejectMigration);
  const poolBinding = poolBindingContract(current, state);
  const firstIdentity = eventIndex(current.events, "IDENTITY_1");
  const authoritySet = eventIndex(current.events, "AUTHORITY_SET");
  const secondIdentity = eventIndex(current.events, "IDENTITY_2");
  const migration = eventIndex(current.events, "MIGRATION");
  const migrationReject = eventIndex(current.events, "MIGRATION_REJECT");
  const operation = eventIndex(current.events, "OPERATION");
  const ordering = prePoolFailure
    ? current.identityCalls === 0 && migration < 0 && operation < 0
    : firstIdentity >= 0 && authoritySet > firstIdentity && secondIdentity > authoritySet &&
      (scenario.rejectSecondIdentity ? migration < 0 && operation < 0
        : scenario.rejectMigration ? migrationReject > secondIdentity && operation < 0
          : migration > secondIdentity && operation > migration);
  const expectedPublic = expectedFailure
    ? publicFailure(error, state)
    : publicSuccess(result);
  const cleanupSuppressed = scenario.rejectCleanup
    ? (expectedFailure ? expectedPublic : publicSuccess(result))
    : true;
  const cleanupWasAsyncPromise = scenario.rejectCleanup ? current.cleanupWasAsyncPromise : true;
  const metadataSafe = state.authorityRecord
    ? authorityMetadataSafe(state.authorityRecord, state) : prePoolFailure;
  const publicError = expectedFailure ? error : null;
  const surface = publicError && publicFailure(publicError, state)
    ? inspectSurface(publicError, state, { trustedClassPrototype: state.admissionErrorPrototype })
    : inspectSurface(publicError ?? result, state);
  const noRuntimeEffects = [...state.runtimeEvents.values()].every((count) => count === 0);
  const authorityRevoked = !state.authorityRecord || state.authorityRecord.valid === false;
  const operationCount = prePoolFailure || scenario.rejectSecondIdentity || scenario.rejectMigration
    ? current.operationCalls === 0 : current.operationCalls === 1;
  const migrationCount = prePoolFailure || scenario.rejectSecondIdentity || scenario.rejectMigration
    ? current.migrationQueries === 0 && current.migrationPlanIndex === 0
      : current.migrationQueries === state.migrationQueryPlan.length &&
        current.migrationPlanIndex === state.migrationQueryPlan.length;
  const hashCount = prePoolFailure || scenario.rejectSecondIdentity
    ? current.hashCompleted === 0 && current.hashIndex === 0 && current.pendingHash === null &&
      current.manifestExistsCount === 0 && current.manifestReadCount === 0 && current.migrationReadCursor === 0 &&
      current.hashDelegations.createHash === 0 && current.hashDelegations.update === 0 && current.hashDelegations.digest === 0
    : current.hashCompleted === state.migrationHashPlan.length &&
      current.hashIndex === state.migrationHashPlan.length && current.pendingHash === null &&
      current.manifestExistsCount === 1 && current.manifestReadCount === 1 &&
      current.migrationReadCursor === state.migrationHashPlan.length &&
      current.hashDelegations.createHash === state.migrationHashPlan.length &&
      current.hashDelegations.update === state.migrationHashPlan.length &&
      current.hashDelegations.digest === state.migrationHashPlan.length;
  const cleanupCount = prePoolFailure
    ? current.cleanupEntryCount === 0 && !current.cleanupAttempted && current.endCount === 0
    : current.cleanupEntryCount === 1 && current.cleanupAttempted && current.endCount === 1;
  const cleanupLifecycle = current.originalCompletion === current.propagatedCompletion &&
    (prePoolFailure ? !current.cleanupSucceeded
      : scenario.rejectCleanup ? !current.cleanupSucceeded : current.cleanupSucceeded);
  const successOrFailure = expectedFailure
    ? error && !result
    : result && !error;
  const pass = (prePoolFailure ? current.poolCount === 0 && current.pools.length === 0 : poolBinding) &&
    ordering && expectedPublic && cleanupSuppressed && surface.safe && noRuntimeEffects &&
    authorityRevoked && metadataSafe && cleanupWasAsyncPromise &&
    current.receiptInvocationBegan &&
    current.authorityReceiptAccepted === !prePoolFailure &&
    current.freshErrorReceiptAccepted === expectedFailure &&
    current.protocolRejected === (scenario.rejectSecondIdentity === true) &&
    (prePoolFailure || current.authorityValidAtCapture) && operationCount && hashCount &&
    !current.operationOrderViolation &&
    migrationCount && cleanupCount && successOrFailure;
  return Object.freeze({
    id: scenario.id,
    pass,
    code: pass ? SAFE.pass : SAFE.scenario,
    poolCount: current.poolCount,
    identityCalls: current.identityCalls,
    migrationQueries: current.migrationQueries,
    migrationPlanQueries: current.migrationPlanIndex,
    migrationHashes: current.hashCompleted,
    migrationManifestExists: current.manifestExistsCount,
    migrationManifestReads: current.manifestReadCount,
    migrationSqlReads: current.migrationReadCursor,
    hashDelegations: Object.freeze({ ...current.hashDelegations }),
    poolOptionRejects: current.poolOptionRejectCount,
    queryRejected: current.queryRejected,
    runtimeEventIds: Object.freeze([...state.runtimeEvents.keys()]),
    operationCalls: current.operationCalls,
    cleanupCalls: current.endCount,
    cleanupEntryCount: current.cleanupEntryCount,
    cleanupAttempted: current.cleanupAttempted,
    cleanupSucceeded: current.cleanupSucceeded,
    originalCompletion: current.originalCompletion,
    propagatedCompletion: current.propagatedCompletion,
    authorityMinted: Boolean(state.authorityRecord),
    authorityCaptureCount: current.authorityCaptureCount,
    authorityValidAtCapture: current.authorityValidAtCapture,
    authorityRevoked,
    ordering,
    publicSurfaceSafe: surface.safe,
    noRuntimeEffects,
    resourcesStable: current.resourcesStable ?? false,
    metadataSafe,
    cleanupWasAsyncPromise,
  });
}

function currentSurfaceRunId(state) {
  return state.current?.runId ?? null;
}

function rememberSurfaceOrigin(state, candidate, kind, producer) {
  if (!candidate || (typeof candidate !== "object" && typeof candidate !== "function")) return null;
  const runId = currentSurfaceRunId(state);
  const existing = state.surfaceOrigins.get(candidate);
  const proxy = types.isProxy(candidate);
  let privateState = false;
  if (!proxy) {
    try {
      privateState = Run669PrivateStateCarrier.has(candidate);
    } catch {
      privateState = true;
    }
  }
  const supported = TRUSTED_SURFACE_ORIGIN_KINDS.has(kind) && !proxy && !privateState;
  if (existing && existing.identity === candidate && existing.runId === runId) {
    if (existing.kind === "unsupported" || supported) return existing;
  }
  const entry = Object.freeze({
    identity: candidate,
    kind: supported ? kind : "unsupported",
    producer: supported ? producer : privateState ? "private-state-origin" : proxy ? "proxy-identity" : "unresolved-construction-origin",
    runId,
  });
  state.surfaceOrigins.set(candidate, entry);
  return entry;
}

function trustedSurfaceAllocation(state, candidate, kind, producer) {
  rememberSurfaceOrigin(state, candidate, kind, producer);
  return candidate;
}

function isSurfaceObject(candidate) {
  return candidate !== null && (typeof candidate === "object" || typeof candidate === "function");
}

function surfaceOrigin(state, candidate) {
  if (!isSurfaceObject(candidate)) return null;
  if (types.isProxy(candidate)) return rememberSurfaceOrigin(state, candidate, "unsupported", "proxy-identity");
  try {
    if (Run669PrivateStateCarrier.has(candidate)) {
      return rememberSurfaceOrigin(state, candidate, "unsupported", "private-state-origin");
    }
  } catch {
    return rememberSurfaceOrigin(state, candidate, "unsupported", "unresolved-private-state");
  }
  const existing = state.surfaceOrigins.get(candidate);
  const runId = currentSurfaceRunId(state);
  if (existing) {
    if (existing.identity === candidate && existing.runId === runId) return existing;
    return rememberSurfaceOrigin(state, candidate, "unsupported", "stale-run-identity");
  }
  return rememberSurfaceOrigin(state, candidate, "unsupported", "unregistered-construction-origin");
}

function capturePrototypeMutation(state, target, nextPrototype) {
  if (!isSurfaceObject(target) ||
      (nextPrototype !== null && !isSurfaceObject(nextPrototype))) return;
  if (types.isProxy(target)) {
    rememberSurfaceOrigin(state, target, "unsupported", "proxy-prototype-mutation");
    throw new Error("SSC_BLOCKED");
  }
  const origin = surfaceOrigin(state, target);
  if (nextPrototype !== null && types.isProxy(nextPrototype)) {
    rememberSurfaceOrigin(state, target, "unsupported", "proxy-prototype-exposure");
    return;
  }
  if (nextPrototype !== null && nextPrototype !== Object.prototype &&
      surfaceOrigin(state, nextPrototype).kind !== "ordinary") {
    rememberSurfaceOrigin(state, target, "unsupported", "unresolved-prototype-transition");
    return;
  }
  if (origin.kind === "unsupported") return;
  rememberSurfaceOrigin(state, target, origin.kind, `${origin.producer}:prototype-transition`);
}

function installPrototypeMutationObservers(state, ledger) {
  const originalObjectSetPrototypeOf = Object.setPrototypeOf;
  const originalReflectSetPrototypeOf = Reflect.setPrototypeOf;
  const originalReflectConstruct = Reflect.construct;
  ledger.install(Reflect, "construct", function observedReflectConstruct(target, args, newTarget) {
    const result = arguments.length >= 3
      ? Reflect.apply(originalReflectConstruct, this, [target, args, newTarget])
      : Reflect.apply(originalReflectConstruct, this, [target, args]);
    if (state.active && !state.selfTest && isSurfaceObject(result)) {
      const existing = state.surfaceOrigins.get(result);
      if (existing && existing.identity === result && existing.runId === currentSurfaceRunId(state) &&
          existing.kind !== "unsupported") {
        rememberSurfaceOrigin(state, result, "unsupported", "reflect-construct-exposure");
      }
    }
    return result;
  });
  ledger.install(Object, "setPrototypeOf", function observedObjectSetPrototypeOf(target, prototype) {
    if (state.active && !state.selfTest) capturePrototypeMutation(state, target, prototype);
    return Reflect.apply(originalObjectSetPrototypeOf, this, [target, prototype]);
  });
  ledger.install(Reflect, "setPrototypeOf", function observedReflectSetPrototypeOf(target, prototype) {
    if (state.active && !state.selfTest) capturePrototypeMutation(state, target, prototype);
    return Reflect.apply(originalReflectSetPrototypeOf, this, [target, prototype]);
  });
  const protoDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "__proto__");
  if (!protoDescriptor || typeof protoDescriptor.set !== "function") fail(SAFE.install, "INSTALL_LEDGER");
  const originalProtoSetter = protoDescriptor.set;
  const observedProtoSetter = function observedLegacyPrototypeSetter(prototype) {
    if (state.active && !state.selfTest) capturePrototypeMutation(state, this, prototype);
    return Reflect.apply(originalProtoSetter, this, [prototype]);
  };
  const installedProtoDescriptor = { ...protoDescriptor, set: observedProtoSetter };
  try {
    Object.defineProperty(Object.prototype, "__proto__", installedProtoDescriptor);
  } catch {
    fail(SAFE.install, "INSTALL_LEDGER");
  }
  if (!sameDescriptor(Object.getOwnPropertyDescriptor(Object.prototype, "__proto__"), installedProtoDescriptor)) {
    fail(SAFE.install, "INSTALL_LEDGER");
  }
  ledger.installCustom(
    () => {
      if (!sameDescriptor(Object.getOwnPropertyDescriptor(Object.prototype, "__proto__"), installedProtoDescriptor)) {
        throw new Error("SSC_BLOCKED");
      }
      Object.defineProperty(Object.prototype, "__proto__", protoDescriptor);
    },
    () => sameDescriptor(Object.getOwnPropertyDescriptor(Object.prototype, "__proto__"), protoDescriptor),
  );
}

async function settle(state) {
  const immediate = state.originalSetImmediate;
  await new Promise((resolve) => immediate(resolve));
  await new Promise((resolve) => immediate(resolve));
}

function activeResources() {
  if (typeof process.getActiveResourcesInfo !== "function") return [];
  return process.getActiveResourcesInfo().sort();
}

async function runScenario(state, scenario) {
  await settle(state);
  const current = createScenarioState(scenario, state.markers);
  current.runId = state.runSerial++;
  current.resourceBefore = activeResources();
  state.current = current;
  state.authorityRecord = null;
  state.authorityPool = null;
  state.runtimeEvents.clear();
  state.active = false;
  const input = {
    connectionString: "postgres://cloud_admin@127.0.0.1:1/runtime_posture_test",
    expectedDatabase: "runtime_posture_test",
    expectedUser: "cloud_admin",
    migrationsFolder: MIGRATIONS_FOLDER,
    phase: "initialization",
  };
  if (scenario.prePoolFailure) input.expectedDatabase = "production";
  if (!scenario.omitPassword) input.connectionPassword = state.markers.connection;
  let result;
  let error;
  let subject;
  try {
    subject = await import(state.subjectUrl + "?ssc=" + scenario.id + "-" + state.scenarioSerial++);
    state.admissionErrorPrototype = subject.DisposablePostgresFixtureAdmissionError?.prototype ?? null;
  } catch (importError) {
    error = importError;
  }
  state.active = true;
  if (!error) {
    const operation = async () => {
      if (current.identityCalls !== 2 ||
          current.migrationPlanIndex !== state.migrationQueryPlan.length ||
          current.releaseCount !== 1) {
        current.operationOrderViolation = true;
        throw new Error("SSC_BLOCKED");
      }
      current.operationCalls += 1;
      current.events.push("OPERATION");
      current.operationEntered = true;
      current.lifecyclePhase = "OPERATION";
      current.lifecycleGeneration += 1;
      if (scenario.rejectOperation) {
        current.originalCompletion = "THROW";
        throw makeDiagnosticError(state.markers, "operation");
      }
      current.originalCompletion = "RETURN";
      const operationResult = { ok: true };
      rememberSurfaceOrigin(state, operationResult, "ordinary", "operation-output-boundary");
      return operationResult;
    };
    current.receiptOperation = operation;
    current.receiptSubject = subject;
    current.receiptInvocationBegan =
      subject.beginDisposablePostgresReceiptInvocation(operation) === true;
    try {
      if (!current.receiptInvocationBegan) fail(SAFE.authority, "RECEIPT_BEGIN");
      result = await subject.withDisposablePostgresFixtureMigration(input, operation);
    } catch (caught) {
      error = caught;
      current.freshErrorReceiptAccepted =
        subject.consumeDisposablePostgresFreshErrorReceipt(operation, caught) === true;
      if (current.freshErrorReceiptAccepted) {
        rememberSurfaceOrigin(state, caught, "admission-error", "frozen-helper-allocation");
      }
    } finally {
      try {
        subject.finishDisposablePostgresReceiptInvocation(operation);
      } catch {
        current.protocolRejected = true;
      }
      current.receiptOperation = null;
      current.receiptSubject = null;
    }
  }
  if (error && current.freshErrorReceiptAccepted &&
      subject?.DisposablePostgresFixtureAdmissionError &&
      Object.getPrototypeOf(error) === subject.DisposablePostgresFixtureAdmissionError.prototype) {
    state.admissionErrorPrototype = subject.DisposablePostgresFixtureAdmissionError.prototype;
  }
  current.originalCompletion ??= error ? "THROW" : "RETURN";
  current.propagatedCompletion = error ? "THROW" : "RETURN";
  current.publicCompleted = true;
  current.lifecyclePhase = "PUBLIC_COMPLETE";
  current.lifecycleGeneration += 1;
  await settle(state);
  const resources = activeResources();
  current.resourceAfter = resources;
  current.resourcesStable = resources.length === current.resourceBefore.length &&
    resources.every((resource, index) => resource === current.resourceBefore[index]);
  state.active = false;
  const scenarioResult = scenarioChecks(current, result, error, state);
  state.current = null;
  state.authorityRecord = null;
  state.authorityPool = null;
  for (const pool of current.pools) {
    try {
      delete pool.__sscInputOptions;
    } catch {
      // The object is private and discarded at the boundary.
    }
  }
  return scenarioResult;
}

function fixedRestoreFailure() {
  return Object.freeze({
    ok: false,
    code: SAFE.restore,
    detector: "RESTORE_LEDGER",
  });
}

function finalizeBoundary(result, ledger) {
  if (!ledger) return result;
  try {
    ledger.restore();
    return result;
  } catch {
    return fixedRestoreFailure();
  }
}

function runRestoreBoundaryControl() {
  const target = { slot() {} };
  const ledger = new PatchLedger();
  ledger.install(target, "slot", function replacement() {});
  target.slot = function mismatched() {};
  const result = finalizeBoundary(Object.freeze({ ok: true }), ledger);
  return Object.freeze({
    id: "NC15_OUTER_RESTORE_FAILURE",
    code: result.code ?? "SSC_NEGATIVE_CONTROL_INACTIVE",
    detector: result.detector ?? "CONTROL_INACTIVE",
    pass: result.ok === false && result.code === SAFE.restore && result.detector === "RESTORE_LEDGER",
  });
}

function createSyntheticPool(state) {
  const pool = Object.create(state.observedPool.prototype);
  const inputOptions = {
    host: "127.0.0.1",
    port: 1,
    user: "cloud_admin",
    database: "runtime_posture_test",
    max: 1,
  };
  inputOptions.password = state.markers.connection;
  const effectiveOptions = {
    ...inputOptions,
    min: 0,
    maxUses: Infinity,
    allowExitOnIdle: false,
    maxLifetimeSeconds: 0,
    idleTimeoutMillis: 10000,
  };
  Object.defineProperty(effectiveOptions, "password", {
    configurable: true,
    enumerable: false,
    writable: true,
    value: state.markers.connection,
  });
  pool.options = effectiveOptions;
  pool.__sscInputOptions = inputOptions;
  return pool;
}

function runPoolBindingControls(state) {
  const pool = createSyntheticPool(state);
  const contractState = {
    ...state,
    authorityPool: pool,
    authorityRecord: { pool },
  };
  const current = {
    scenario: { omitPassword: false },
    pools: [pool],
    poolCount: 1,
    authorityCaptureCount: 1,
    bindingMismatch: false,
  };
  const originalOptions = pool.__sscInputOptions;
  pool.__sscInputOptions = { ...originalOptions, password: "wrong-password" };
  const wrongPasswordRejected = !poolBindingContract(current, contractState);
  pool.__sscInputOptions = originalOptions;
  const bindingMismatchRejected = !poolBindingContract(
    { ...current, bindingMismatch: true },
    contractState,
  );
  return Object.freeze([
    Object.freeze({
      id: "NC20_POOL_WRONG_PASSWORD",
      code: wrongPasswordRejected ? SAFE.pool : "SSC_NEGATIVE_CONTROL_INACTIVE",
      detector: wrongPasswordRejected ? "POOL_PASSWORD_PRESERVATION" : "CONTROL_INACTIVE",
      pass: wrongPasswordRejected,
    }),
    Object.freeze({
      id: "NC21_POOL_BINDING_MISMATCH",
      code: bindingMismatchRejected ? SAFE.pool : "SSC_NEGATIVE_CONTROL_INACTIVE",
      detector: bindingMismatchRejected ? "POOL_BINDING_IDENTITY" : "CONTROL_INACTIVE",
      pass: bindingMismatchRejected,
    }),
  ]);
}

async function runExactPoolBoundaryControls(state) {
  const current = createScenarioState({
    id: "NC_POOL_EXACTNESS",
    rejectOperation: false,
    rejectCleanup: false,
    rejectSecondIdentity: false,
    omitPassword: false,
  }, state.markers);
  const previousCurrent = state.current;
  const previousActive = state.active;
  state.current = current;
  state.active = true;
  state.runtimeEvents.clear();
  const baseOptions = {
    host: "127.0.0.1",
    port: 1,
    user: "cloud_admin",
    database: "runtime_posture_test",
    max: 1,
    password: state.markers.connection,
  };
  const rejects = async (operation) => {
    try {
      await operation();
      return false;
    } catch (error) {
      return error?.message === "SSC_BLOCKED";
    }
  };
  let wrongMaxRejected = false;
  let wrongDatabaseRejected = false;
  let wrongArgumentsRejected = false;
  let wrongReceiverRejected = false;
  let unknownSqlRejected = false;
  let pool = null;
  try {
    wrongMaxRejected = await rejects(() => new state.observedPool({ ...baseOptions, max: 2 }));
    wrongDatabaseRejected = await rejects(() =>
      new state.observedPool({ ...baseOptions, database: "production" }));
    pool = new state.observedPool(baseOptions);
    wrongArgumentsRejected = await rejects(() =>
      pool.query(state.identitySql, ["wrong_database", "cloud_admin"]));
    wrongReceiverRejected = await rejects(() =>
      state.observedPool.prototype.query.call(
        {},
        state.identitySql,
        ["runtime_posture_test", "cloud_admin"],
      ));
    unknownSqlRejected = await rejects(() => pool.query("select 1", []));
  } catch {
    // A control setup failure makes each unmet boundary assertion fail below.
  } finally {
    state.active = false;
    state.current = previousCurrent;
    if (pool) await pool.end();
    state.runtimeEvents.clear();
  }
  const noQueryEffects = current.identityCalls === 0 && current.migrationQueries === 0 &&
    current.migrationPlanIndex === 0;
  const checks = [
    ["NC25_POOL_WRONG_MAX", wrongMaxRejected && current.poolOptionRejectCount >= 1, "POOL_MAX_EXACTNESS"],
    ["NC26_POOL_WRONG_DATABASE", wrongDatabaseRejected && current.poolOptionRejectCount >= 2, "POOL_DATABASE_EXACTNESS"],
    ["NC27_QUERY_WRONG_IDENTITY_ARGUMENTS", wrongArgumentsRejected && noQueryEffects, "POOL_IDENTITY_ARGUMENTS"],
    ["NC28_QUERY_WRONG_RECEIVER", wrongReceiverRejected && noQueryEffects, "POOL_QUERY_RECEIVER"],
    ["NC29_QUERY_UNKNOWN_SQL", unknownSqlRejected && noQueryEffects, "POOL_QUERY_ALLOWLIST"],
  ];
  return Object.freeze(checks.map(([id, pass, detector]) => Object.freeze({
    id,
    code: pass ? SAFE.pool : "SSC_NEGATIVE_CONTROL_INACTIVE",
    detector: pass ? detector : "CONTROL_INACTIVE",
    pass,
  })));
}

function runSurfaceControls(state) {
  const deepRoot = trustedSurfaceAllocation(state, {}, "ordinary", "surface-depth-root");
  let deepCursor = deepRoot;
  for (let index = 0; index < MAX_INSPECTION_DEPTH + 3; index += 1) {
    deepCursor.next = trustedSurfaceAllocation(state, {}, "ordinary", "surface-depth-child");
    deepCursor = deepCursor.next;
  }
  Object.defineProperty(deepCursor, "hidden", {
    configurable: true,
    enumerable: false,
    value: state.markers.connection,
    writable: true,
  });
  const deepSurface = inspectSurface(deepRoot, state);

  const boundedRoot = trustedSurfaceAllocation(state, {}, "ordinary", "surface-entry-root");
  for (let index = 0; index < MAX_INSPECTION_ENTRIES + 2; index += 1) {
    boundedRoot[`entry${index}`] = trustedSurfaceAllocation(state, {}, "ordinary", "surface-entry-child");
  }
  const boundedSurface = inspectSurface(boundedRoot, state);

  const hiddenSymbol = Symbol("hidden-authority-field");
  const symbolSurfaceValue = trustedSurfaceAllocation(state, {}, "ordinary", "surface-symbol-root");
  Object.defineProperty(symbolSurfaceValue, hiddenSymbol, {
    configurable: true,
    enumerable: false,
    value: state.markers.cleanup,
    writable: true,
  });
  const symbolSurface = inspectSurface(symbolSurfaceValue, state);
  const directSymbolSurface = inspectSurface(Symbol(state.markers.connection), state);

  const hiddenAuthority = Object.assign(Object.create(Object.getPrototypeOf({})), {
    authority: Object.freeze({}),
    brand: Symbol("migration-authority"),
    database: "runtime_posture_test",
    user: "cloud_admin",
    clusterFingerprint: "100",
    lifecycleFingerprint: "200",
    migrationsFolder: MIGRATIONS_FOLDER,
    phase: "initialization",
    pool: createSyntheticPool(state),
    valid: true,
  });
  Object.defineProperty(hiddenAuthority, "hidden", {
    configurable: true,
    enumerable: false,
    value: state.markers.connection,
    writable: true,
  });
  const hiddenAuthorityRejected = !isAuthorityRecord(
    hiddenAuthority.authority,
    hiddenAuthority,
    state.observedPool,
  );

  return Object.freeze([
    Object.freeze({
      id: "NC16_HIDDEN_AUTHORITY_METADATA",
      code: hiddenAuthorityRejected ? SAFE.authority : "SSC_NEGATIVE_CONTROL_INACTIVE",
      detector: hiddenAuthorityRejected ? "AUTHORITY_DESCRIPTOR_SCHEMA" : "CONTROL_INACTIVE",
      pass: hiddenAuthorityRejected,
    }),
    Object.freeze({
      id: "NC17_DEEP_HIDDEN_SURFACE",
      code: !deepSurface.safe && deepSurface.invalid ? SAFE.surface : "SSC_NEGATIVE_CONTROL_INACTIVE",
      detector: !deepSurface.safe && deepSurface.invalid ? "SURFACE_DEPTH_BOUND" : "CONTROL_INACTIVE",
      pass: !deepSurface.safe && deepSurface.invalid,
    }),
    Object.freeze({
      id: "NC18_BOUNDED_HIDDEN_SURFACE",
      code: !boundedSurface.safe && boundedSurface.invalid ? SAFE.surface : "SSC_NEGATIVE_CONTROL_INACTIVE",
      detector: !boundedSurface.safe && boundedSurface.invalid ? "SURFACE_ENTRY_BOUND" : "CONTROL_INACTIVE",
      pass: !boundedSurface.safe && boundedSurface.invalid,
    }),
    Object.freeze({
      id: "NC19_SYMBOL_HIDDEN_SURFACE",
      code: !symbolSurface.safe && (symbolSurface.leak || directSymbolSurface.leak)
        ? SAFE.surface
        : "SSC_NEGATIVE_CONTROL_INACTIVE",
      detector: !symbolSurface.safe && (symbolSurface.leak || directSymbolSurface.leak)
        ? "PUBLIC_SYMBOL"
        : "CONTROL_INACTIVE",
      pass: !symbolSurface.safe && (symbolSurface.leak || directSymbolSurface.leak),
    }),
  ]);
}

function runInheritedAndMapSurfaceControls(state) {
  const inheritedPrototype = { inheritedDiagnostic: state.markers.connection };
  rememberSurfaceOrigin(state, inheritedPrototype, "ordinary", "control-prototype-literal");
  const inheritedRoot = Object.create(inheritedPrototype);
  rememberSurfaceOrigin(state, inheritedRoot, "ordinary", "Object.create-control");
  const inheritedSurface = inspectSurface(inheritedRoot, state);
  const mapValue = trustedSurfaceAllocation(
    state,
    new Map([["diagnostic", state.markers.cleanup]]),
    "map",
    "surface-map-allocation",
  );
  let customRendererCalled = false;
  Object.defineProperty(mapValue, inspect.custom, {
    configurable: true,
    value() {
      customRendererCalled = true;
      return "safe";
    },
  });
  const mapSurface = inspectSurface(mapValue, state);
  return Object.freeze([
    Object.freeze({
      id: "NC23_INHERITED_HIDDEN_SURFACE",
      code: inheritedSurface.leak ? SAFE.surface : "SSC_NEGATIVE_CONTROL_INACTIVE",
      detector: inheritedSurface.leak ? "INHERITED_DATA_SURFACE" : "CONTROL_INACTIVE",
      pass: inheritedSurface.leak && !inheritedSurface.invalid,
    }),
    Object.freeze({
      id: "NC24_MAP_INTERNAL_HIDDEN_SURFACE",
      code: mapSurface.leak && !customRendererCalled ? SAFE.surface : "SSC_NEGATIVE_CONTROL_INACTIVE",
      detector: mapSurface.leak && !customRendererCalled ? "COLLECTION_INTERNAL_SURFACE" : "CONTROL_INACTIVE",
      pass: mapSurface.leak && !customRendererCalled,
    }),
  ]);
}

async function runRuntimeCapabilityControl(state) {
  const require = state.require;
  if (!require) {
    return Object.freeze({
      id: "NC22_RUNTIME_PRE_EFFECT_CAPABILITY",
      code: SAFE.internal,
      detector: "BOUNDARY",
      pass: false,
    });
  }
  const crypto = require("node:crypto");
  const fs = require("node:fs");
  const fsPromises = require("node:fs/promises");
  const os = require("node:os");
  const run660Fs = fs;
  const run660Crypto = crypto;
  const run660Pg = require("pg");
  const beforeRun660 = Object.freeze({
    fsReadFileSync: run660Fs.readFileSync,
    fsExistsSync: run660Fs.existsSync,
    fsOpenSync: run660Fs.openSync,
    cryptoCreateHash: run660Crypto.createHash,
    pgPool: run660Pg.Pool,
  });
  const previousCurrent = state.current;
  const previousActive = state.active;
  const effects = new Set();
  const devNullFd = state.capabilityFd;
  if (typeof devNullFd !== "number") fail(SAFE.internal, "CAPABILITY_DESCRIPTOR");
  state.current = {};
  state.runtimeEvents.clear();
  state.active = true;
  const invoke = async (callback, onResult) => {
    try {
      const result = callback();
      if (result && typeof result.then === "function") {
        onResult?.(await result);
      } else if (result !== undefined) {
        onResult?.(result);
      }
    } catch {
      // Every synthetic capability call is intentionally blocked before effect.
    }
  };
  const markEffect = (id) => effects.add(id);
  const cryptoHash = crypto.hash;
  const cryptoRandomUUID = crypto.randomUUID;
  const subtle = crypto.webcrypto?.subtle ?? globalThis.crypto?.subtle;
  const subtleDigest = subtle?.digest;
  const webcryptoRandomUUID = crypto.webcrypto?.randomUUID ?? globalThis.crypto?.randomUUID;
  const webcryptoGetRandomValues = crypto.webcrypto?.getRandomValues ?? globalThis.crypto?.getRandomValues;
  const randomValues = new Uint8Array(8);
  const outputBefore = state.runtimeEvents.get("STDOUT_WRITE") ?? 0;
  try {
    await invoke(() => crypto.createHash("sha256"), () => markEffect("CRYPTO_CREATEHASH_EFFECT"));
    if (typeof cryptoHash === "function") {
      await invoke(() => cryptoHash("sha256", "synthetic"), () => markEffect("CRYPTO_HASH_EFFECT"));
    }
    if (typeof cryptoRandomUUID === "function") {
      await invoke(() => cryptoRandomUUID(), () => markEffect("CRYPTO_RANDOMUUID_EFFECT"));
    }
    if (typeof subtleDigest === "function") {
      await invoke(() => subtleDigest.call(subtle, "SHA-256", new Uint8Array()), () => markEffect("WEBCRYPTO_DIGEST_EFFECT"));
    }
    if (typeof webcryptoRandomUUID === "function") {
      await invoke(() => webcryptoRandomUUID.call(crypto.webcrypto ?? globalThis.crypto), () => markEffect("WEBCRYPTO_RANDOMUUID_EFFECT"));
    }
    if (typeof webcryptoGetRandomValues === "function") {
      await invoke(() => webcryptoGetRandomValues.call(crypto.webcrypto ?? globalThis.crypto, randomValues), () => markEffect("WEBCRYPTO_GETRANDOMVALUES_EFFECT"));
    }
    await invoke(() => fs.write(devNullFd, Buffer.from("synthetic"), () => markEffect("FS_WRITE_EFFECT")));
    await invoke(() => fs.writeSync(devNullFd, "synthetic"), () => markEffect("FS_WRITESYNC_EFFECT"));
    await invoke(() => fs.writevSync(devNullFd, []), () => markEffect("FS_WRITEVSYNC_EFFECT"));
    await invoke(() => fs.openSync(os.devNull, fs.constants.O_WRONLY), (fd) => {
      markEffect("FS_OPENSYNC_EFFECT");
      if (typeof fd === "number") fs.closeSync(fd);
    });
    await invoke(() => fs.open(os.devNull, fs.constants.O_WRONLY, (error, fd) => {
      if (fd !== undefined) {
        markEffect("FS_OPEN_EFFECT");
        try { fs.closeSync(fd); } catch { /* synthetic descriptor cleanup */ }
      }
      void error;
    }));
    await invoke(() => fsPromises.open(os.devNull, fs.constants.O_WRONLY), async (handle) => {
      markEffect("FS_PROMISES_OPEN_EFFECT");
      await handle?.close?.();
    });
    await invoke(() => fsPromises.writeFile(os.devNull, "synthetic"), () => markEffect("FS_PROMISES_WRITEFILE_EFFECT"));
    await invoke(() => console.log("ssc-runtime-gate"));
    await invoke(() => { process.env.SSC_RUNTIME_GATE = "safe"; });
    await invoke(() => { delete process.env.SSC_RUNTIME_GATE; });
    await invoke(() => Object.defineProperty(process.env, "SSC_RUNTIME_GATE", { value: "safe" }));
    await settle(state);
  } finally {
    state.active = previousActive;
    state.current = previousCurrent;
    try { fs.closeSync(devNullFd); } catch { /* synthetic descriptor cleanup */ }
    state.capabilityFd = null;
  }
  const requiredIds = [
    "CRYPTO_CREATEHASH",
    "CRYPTO_HASH",
    "CRYPTO_RANDOMUUID",
    "WEBCRYPTO_DIGEST",
    "WEBCRYPTO_RANDOMUUID",
    "WEBCRYPTO_GETRANDOMVALUES",
    "FS_WRITE",
    "FS_WRITESYNC",
    "FS_WRITEVSYNC",
    "FS_OPEN",
    "FS_OPENSYNC",
    "FS_PROMISES_WRITEFILE",
    "FS_PROMISES_OPEN",
    "CONSOLE_LOG",
    "ENV_SET",
    "ENV_DELETE",
    "ENV_DEFINE",
  ];
  const outputEffect = (state.runtimeEvents.get("STDOUT_WRITE") ?? 0) > outputBefore;
  const pass = requiredIds.every((id) => (state.runtimeEvents.get(id) ?? 0) > 0) &&
    effects.size === 0 && !outputEffect && process.env.SSC_RUNTIME_GATE === undefined && run660Fs.readFileSync === beforeRun660.fsReadFileSync && run660Fs.existsSync === beforeRun660.fsExistsSync && run660Fs.openSync === beforeRun660.fsOpenSync && run660Crypto.createHash === beforeRun660.cryptoCreateHash && run660Pg.Pool === beforeRun660.pgPool;
  state.runtimeEvents.clear();
  return Object.freeze({
    id: "NC22_RUNTIME_PRE_EFFECT_CAPABILITY",
    code: pass ? SAFE.runtime : "SSC_NEGATIVE_CONTROL_INACTIVE",
    detector: pass ? "PRE_EFFECT_CAPABILITY_GATE" : "CONTROL_INACTIVE",
    pass,
  });
}

async function runBehavioralControls(state) {
  const markers = state.markers;
  const previousCurrent = state.current;
  state.current = { runId: state.runSerial++, lifecyclePhase: "SURFACE_CONTROL" };
  let causeSurface;
  let descriptorSurface;
  try {
    const causeError = new Error("safe");
    causeError.cause = new Error(markers.connection);
    const descriptorError = new Error("safe");
    Object.defineProperty(descriptorError, "diagnostic", {
      configurable: true,
      enumerable: false,
      value: markers.cleanup,
      writable: true,
    });
    rememberSurfaceOrigin(state, causeError, "ordinary", "control-error-allocation");
    rememberSurfaceOrigin(state, causeError.cause, "ordinary", "control-error-cause-allocation");
    rememberSurfaceOrigin(state, descriptorError, "ordinary", "control-error-allocation");
    causeSurface = inspectSurface(causeError, state);
    descriptorSurface = inspectSurface(descriptorError, state);
  } finally {
    state.current = previousCurrent;
  }
  const controls = [];
  controls.push(Object.freeze({
    id: "NC11_PUBLIC_CAUSE",
    code: causeSurface.safe ? "SSC_NEGATIVE_CONTROL_INACTIVE" : SAFE.surface,
    detector: causeSurface.safe ? "CONTROL_INACTIVE" : "PUBLIC_CAUSE",
    pass: !causeSurface.safe && causeSurface.leak,
  }));
  controls.push(Object.freeze({
    id: "NC12_PUBLIC_NONENUM",
    code: descriptorSurface.safe ? "SSC_NEGATIVE_CONTROL_INACTIVE" : SAFE.surface,
    detector: descriptorSurface.safe ? "CONTROL_INACTIVE" : "PUBLIC_DESCRIPTOR",
    pass: !descriptorSurface.safe && descriptorSurface.leak,
  }));
  const lockedTarget = {};
  Object.defineProperty(lockedTarget, "locked", {
    configurable: false,
    enumerable: false,
    value() {},
    writable: false,
  });
  const installLedger = new PatchLedger();
  let installFailed = false;
  try {
    installLedger.install(lockedTarget, "locked", function replacement() {});
  } catch (error) {
    installFailed = error instanceof HarnessFailure && error.code === SAFE.install;
  }
  controls.push(Object.freeze({
    id: "NC13_BROKEN_INSTALL",
    code: installFailed ? SAFE.install : "SSC_NEGATIVE_CONTROL_INACTIVE",
    detector: installFailed ? "INSTALL_LEDGER" : "CONTROL_INACTIVE",
    pass: installFailed,
  }));
  const restoreTarget = { slot() {} };
  const restoreLedger = new PatchLedger();
  const original = restoreTarget.slot;
  const replacement = function replacement() {};
  restoreLedger.install(restoreTarget, "slot", replacement);
  restoreTarget.slot = function mismatched() {};
  let restoreFailed = false;
  try {
    restoreLedger.restore();
  } catch (error) {
    restoreFailed = error instanceof HarnessFailure && error.code === SAFE.restore;
  }
  Object.defineProperty(restoreTarget, "slot", {
    configurable: true,
    enumerable: true,
    value: original,
    writable: true,
  });
  controls.push(Object.freeze({
    id: "NC14_BROKEN_RESTORE",
    code: restoreFailed ? SAFE.restore : "SSC_NEGATIVE_CONTROL_INACTIVE",
    detector: restoreFailed ? "RESTORE_LEDGER" : "CONTROL_INACTIVE",
    pass: restoreFailed,
  }));
  controls.push(runRestoreBoundaryControl());
  controls.push(...runSurfaceControls(state));
  controls.push(...runPoolBindingControls(state));
  controls.push(await runRuntimeCapabilityControl(state));
  controls.push(...runInheritedAndMapSurfaceControls(state));
  controls.push(...await runExactPoolBoundaryControls(state));
  return Object.freeze({
    count: controls.length,
    ids: Object.freeze(controls.map((control) => control.id)),
    results: Object.freeze(controls),
  });
}

function failureResult(error) {
  const code = error instanceof HarnessFailure ? error.code : SAFE.internal;
  const detector = error instanceof HarnessFailure ? error.detector : "BOUNDARY";
  return Object.freeze({
    scenarioCount: SCENARIOS.length,
    scenarioIds: Object.freeze(SCENARIOS.map((scenario) => scenario.id)),
    scenarios: Object.freeze(SCENARIOS.map((scenario) => Object.freeze({
      id: scenario.id,
      pass: false,
      code,
      poolCount: 0,
      identityCalls: 0,
      migrationQueries: 0,
      operationCalls: 0,
      cleanupCalls: 0,
      authorityCaptureCount: 0,
      authorityValidAtCapture: false,
      authorityRevoked: false,
      ordering: false,
      publicSurfaceSafe: false,
      noRuntimeEffects: false,
      resourcesStable: false,
    }))),
    controls: Object.freeze({
      count: BEHAVIORAL_CONTROLS.length,
      ids: Object.freeze(BEHAVIORAL_CONTROLS.map((control) => control.id)),
      results: Object.freeze(BEHAVIORAL_CONTROLS.map((control) => Object.freeze({
        id: control.id,
        code,
        detector,
        pass: false,
      }))),
    }),
    allScenariosPass: false,
    allControlsPass: false,
  });
}

async function runSecretSurfaceBehavioralHarnessInCurrentThread(options = {}) {
  const defaultRun = Object.keys(options).length === 0;
  if (defaultRun && defaultHarnessResultCache) return defaultHarnessResultCache;
  const state = newRunState();
  let ledger = null;
  const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(moduleDirectory, "../..");
  const subjectPath = path.resolve(repoRoot, SUBJECT_RELATIVE);
  let result;
  try {
    const source = await readFile(subjectPath, "utf8");
    if (!source.includes("withDisposablePostgresFixtureMigration")) fail(SAFE.internal, "SUBJECT_IDENTITY");
    const require = createRequire(import.meta.url);
    state.require = require;
    const pgBeforeObservers = require("pg");
    state.pgClient = pgBeforeObservers.Client;
    if (path.resolve(process.cwd(), MIGRATIONS_FOLDER) !==
        path.resolve(repoRoot, MIGRATIONS_FOLDER)) fail(SAFE.internal, "MIGRATION_FOLDER_CWD");
    state.identitySql = extractIdentitySql(source);
    const migrationContract = await buildMigrationContract(
      require,
      MIGRATIONS_FOLDER,
    );
    state.migrationQueryPlan = migrationContract.queries;
    state.migrationHashPlan = migrationContract.hashes;
    state.migrationManifestPlan = migrationContract.manifest;
    state.allowedReadPaths = new Set(migrationContract.readPaths);
    const installed = installObservers(state);
    ledger = installed.ledger;
    const pg = installed.require("pg");
    state.pgClient = pg.Client;
    const ObservedPool = installPoolSeam(state, installed.ledger, pg);
    state.observedPool = ObservedPool;
    installWeakMapObserver(installed.ledger, state, ObservedPool);
    state.subjectUrl = pathToFileURL(subjectPath).href;
    const selectedScenarioIds = Array.isArray(options.scenarioIds)
      ? new Set(options.scenarioIds)
      : options.scenarioId ? new Set([options.scenarioId]) : null;
    const runScenarios = selectedScenarioIds
      ? SCENARIOS.filter((scenario) => selectedScenarioIds.has(scenario.id))
      : (options.controlId || options.controlOnly) ? [] : SCENARIOS;
    const allObserverControls = runScenarios.length > 0
      ? Object.freeze({ count: 0, ids: Object.freeze([]), results: Object.freeze([]) })
      : await runBehavioralControls(state);
    const filteredControls = options.controlId
      ? allObserverControls.results.filter((control) => control.id === options.controlId)
      : allObserverControls.results;
    const observerControls = options.controlId
      ? Object.freeze({
        count: filteredControls.length,
        ids: Object.freeze(filteredControls.map((control) => control.id)),
        results: Object.freeze(filteredControls),
      })
      : allObserverControls;
    const scenarioResults = [];
    for (const scenario of runScenarios) {
      const result = await runScenario(state, scenario);
      scenarioResults.push(Object.freeze(result));
    }
    result = Object.freeze({
      scenarioCount: scenarioResults.length,
      scenarioIds: Object.freeze(scenarioResults.map((result) => result.id)),
      scenarios: Object.freeze(scenarioResults),
      controls: observerControls,
      allScenariosPass: scenarioResults.every((result) => result.pass && result.resourcesStable),
      allControlsPass: observerControls.results.every((result) => result.pass),
    });
  } catch (error) {
    result = failureResult(error);
  }
  state.active = false;
  if (options.forceRestoreMismatch && ledger?.entries?.length) {
    const entry = ledger.entries[0];
    try {
      Object.defineProperty(entry.owner, entry.key, {
        ...entry.after,
        value: function forcedRestoreMismatch() {},
      });
    } catch {
      result = fixedRestoreFailure();
    }
  }
  const finalized = finalizeBoundary(result, ledger);
  if (defaultRun && finalized.allScenariosPass === true && finalized.allControlsPass === true) {
    defaultHarnessResultCache = finalized;
  }
  return finalized;
}

export const behavioralSecretSurfaceScenarioIds = Object.freeze(SCENARIOS.map((scenario) => scenario.id));
export const behavioralSecretSurfaceControlIds = Object.freeze(BEHAVIORAL_CONTROLS.map((control) => control.id));

const MAX_CHILD_OUTPUT_BYTES = 2 * 1024 * 1024;
const CHILD_TIMEOUT_MS = 60_000;
const CHILD_SPECIAL_CASES = new Set([
  "RUN660_HS5_DP6_RUNTIME_CONTROLS",
  "RUN669_HS5_PRIVATE_STATE_ORIGIN_CONTROLS",
  "RUN657_INDEPENDENT_RUNTIME_CORPUS",
  "SSC_FORCE_RESTORE_MISMATCH",
]);

function repoRootFromHarness() {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
}

function receiptGateEvidence(result) {
  return Object.freeze({
    id: result.id,
    ok: result.ok === true,
    fixtureGitBlobId: result.fixtureGitBlobId ?? "",
    harnessGitBlobId: result.harnessGitBlobId ?? "",
  });
}

function allowedChildEnvironment() {
  const permitted = process.platform === "win32"
    ? new Set(["systemroot", "windir", "temp", "tmp"])
    : new Set(["tmpdir"]);
  const env = Object.create(null);
  for (const [key, value] of Object.entries(process.env)) {
    if (permitted.has(key.toLowerCase()) && typeof value === "string") env[key] = value;
  }
  return env;
}

function safeChildTree(value, depth = 0) {
  if (depth > 24) return false;
  if (value === null || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value === "string") return value.length <= 512 && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/u.test(value);
  if (Array.isArray(value)) return value.length <= 512 && value.every((item) => safeChildTree(item, depth + 1));
  if (typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) return false;
  const entries = Object.entries(value);
  return entries.length <= 128 && entries.every(([key, item]) =>
    /^[A-Za-z][A-Za-z0-9_]{0,63}$/u.test(key) && safeChildTree(item, depth + 1));
}

function validChildCase(mode, caseId) {
  if (mode === "scenario") return SCENARIOS.some((scenario) => scenario.id === caseId);
  if (mode !== "control") return false;
  return BEHAVIORAL_CONTROLS.some((control) => control.id === caseId) || CHILD_SPECIAL_CASES.has(caseId);
}

function runHarnessChild(mode, caseId, expectedGate) {
  if (expectedGate?.ok !== true || !["scenario", "control", "run660-f3-pair"].includes(mode) ||
      (mode === "run660-f3-pair" ? caseId !== undefined : !validChildCase(mode, caseId))) {
    return Promise.reject(new Error("SSC_CHILD_REQUEST_REJECTED"));
  }
  const harnessPath = path.resolve(fileURLToPath(import.meta.url));
  const args = caseId === undefined
    ? [harnessPath, "--ssc-child", mode]
    : [harnessPath, "--ssc-child", mode, caseId];
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, {
      shell: false,
      cwd: repoRootFromHarness(),
      env: allowedChildEnvironment(),
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let overflow = false;
    let settled = false;
    const finishFailure = (code) => {
      if (settled) return;
      settled = true;
      reject(new Error(code));
    };
    const timer = setTimeout(() => {
      overflow = true;
      child.kill();
    }, CHILD_TIMEOUT_MS);
    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_CHILD_OUTPUT_BYTES) {
        overflow = true;
        child.kill();
      } else {
        stdout.push(chunk);
      }
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > 64 * 1024) {
        overflow = true;
        child.kill();
      } else {
        stderr.push(chunk);
      }
    });
    child.once("error", () => finishFailure("SSC_CHILD_SPAWN_FAILURE"));
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      if (settled) return;
      if (overflow) return finishFailure("SSC_CHILD_TIMEOUT_OR_OUTPUT_LIMIT");
      if (signal !== null || code !== 0 || stderrBytes !== 0) return finishFailure("SSC_CHILD_ABNORMAL_EXIT");
      const output = Buffer.concat(stdout).toString("utf8");
      if (!output.endsWith("\n") || output.includes("\r") ||
          output.indexOf("\n") !== output.length - 1) return finishFailure("SSC_CHILD_OUTPUT_INVALID");
      const line = output.slice(0, -1);
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        return finishFailure("SSC_CHILD_OUTPUT_INVALID");
      }
      if (JSON.stringify(message) !== line || !safeChildTree(message) ||
          message.ok !== true || message.mode !== mode ||
          (caseId === undefined ? Object.hasOwn(message, "caseId") : message.caseId !== caseId) ||
          !Number.isSafeInteger(message.childPid) || message.childPid < 1 ||
          message.gateEvidence?.id !== expectedGate.id ||
          message.gateEvidence?.fixtureGitBlobId !== expectedGate.fixtureGitBlobId ||
          message.gateEvidence?.harnessGitBlobId !== expectedGate.harnessGitBlobId) {
        return finishFailure("SSC_CHILD_RESULT_INVALID");
      }
      settled = true;
      resolve(message);
    });
  });
}

async function collectScenarioChildren(ids, gate) {
  const results = [];
  const evidence = [];
  for (const id of ids) {
    try {
      const child = await runHarnessChild("scenario", id, gate);
      results.push(child.value);
      evidence.push(Object.freeze({
        id,
        childPid: child.childPid,
        fixtureGitBlobId: child.gateEvidence.fixtureGitBlobId,
        harnessGitBlobId: child.gateEvidence.harnessGitBlobId,
      }));
    } catch {
      results.push(Object.freeze({
        id, pass: false, code: "SSC_CHILD_BOUNDARY_FAILURE",
        resourcesStable: false,
      }));
    }
  }
  return Object.freeze({
    count: results.length,
    ids: Object.freeze(results.map((item) => item.id)),
    results: Object.freeze(results),
    evidence: Object.freeze(evidence),
  });
}

async function collectControlChildren(ids, gate) {
  const results = [];
  const evidence = [];
  for (const id of ids) {
    try {
      const child = await runHarnessChild("control", id, gate);
      results.push(child.value);
      evidence.push(Object.freeze({
        id,
        childPid: child.childPid,
        fixtureGitBlobId: child.gateEvidence.fixtureGitBlobId,
        harnessGitBlobId: child.gateEvidence.harnessGitBlobId,
      }));
    } catch {
      const definition = BEHAVIORAL_CONTROLS.find((control) => control.id === id);
      results.push(Object.freeze({
        id,
        code: definition?.code ?? "SSC_CHILD_BOUNDARY_FAILURE",
        detector: "CHILD_BOUNDARY",
        pass: false,
      }));
    }
  }
  return Object.freeze({
    count: results.length,
    ids: Object.freeze(results.map((item) => item.id)),
    results: Object.freeze(results),
    evidence: Object.freeze(evidence),
  });
}

function runtimeGateFailure(gate) {
  const result = failureResult(new HarnessFailure(SAFE.internal, gate.failureCode ?? "SSC_RECEIPT_STATIC_SOURCE_INVALID"));
  return Object.freeze({
    ...result,
    receiptGate: receiptGateEvidence(gate),
    childEvidence: Object.freeze([]),
  });
}

export async function runSecretSurfaceBehavioralHarness(options = {}) {
  const gate = await runFrozenReceiptStaticGate();
  if (gate.ok !== true) return runtimeGateFailure(gate);
  const defaultRun = Object.keys(options).length === 0;
  if (defaultRun && defaultHarnessResultCache) return defaultHarnessResultCache;
  if (options.forceRestoreMismatch === true) {
    try {
      const child = await runHarnessChild("control", "SSC_FORCE_RESTORE_MISMATCH", gate);
      return child.value;
    } catch {
      return fixedRestoreFailure();
    }
  }
  const scenarioIds = options.scenarioId
    ? [options.scenarioId]
    : Array.isArray(options.scenarioIds)
      ? options.scenarioIds
      : options.controlOnly ? [] : SCENARIOS.map((scenario) => scenario.id);
  const controlIds = options.controlId
    ? [options.controlId]
    : (options.scenarioId || Array.isArray(options.scenarioIds) || options.scenarioOnly)
      ? []
      : BEHAVIORAL_CONTROLS.map((control) => control.id);
  if (scenarioIds.some((id) => !SCENARIOS.some((scenario) => scenario.id === id)) ||
      controlIds.some((id) => !BEHAVIORAL_CONTROLS.some((control) => control.id === id))) {
    return failureResult(new HarnessFailure(SAFE.internal, "CHILD_CASE_ID"));
  }
  const scenarios = await collectScenarioChildren(scenarioIds, gate);
  const controls = await collectControlChildren(controlIds, gate);
  const result = Object.freeze({
    scenarioCount: scenarios.count,
    scenarioIds: scenarios.ids,
    scenarios: scenarios.results,
    controls: Object.freeze({
      count: controls.count,
      ids: controls.ids,
      results: controls.results,
    }),
    allScenariosPass: scenarios.results.every((item) => item.pass === true && item.resourcesStable === true),
    allControlsPass: controls.results.every((item) => item.pass === true),
    receiptGate: receiptGateEvidence(gate),
    childEvidence: Object.freeze([...scenarios.evidence, ...controls.evidence]),
  });
  if (defaultRun && result.allScenariosPass && result.allControlsPass) defaultHarnessResultCache = result;
  return result;
}

export async function runSecretSurfaceF2(options = {}) {
  const gate = await runFrozenReceiptStaticGate();
  if (gate.ok !== true) return Object.freeze({ id: "F2_RUNTIME_BEHAVIOURAL_CONTROLS", pass: false, controls: runtimeGateFailure(gate).controls, receiptGate: receiptGateEvidence(gate) });
  const result = await runSecretSurfaceBehavioralHarness({ ...options, controlOnly: true });
  return Object.freeze({
    id: "F2_RUNTIME_BEHAVIOURAL_CONTROLS",
    pass: result.allControlsPass === true,
    controls: result.controls,
    receiptGate: result.receiptGate,
    childEvidence: result.childEvidence,
  });
}

export async function runSecretSurfaceF3(options = {}) {
  const gate = await runFrozenReceiptStaticGate();
  if (gate.ok !== true) return Object.freeze({ id: "F3_RUNTIME_LIFECYCLE_SCENARIOS", pass: false, scenarios: [], receiptGate: receiptGateEvidence(gate) });
  const result = await runSecretSurfaceBehavioralHarness({ ...options, scenarioOnly: true });
  return Object.freeze({
    id: "F3_RUNTIME_LIFECYCLE_SCENARIOS",
    pass: result.allScenariosPass === true,
    scenarios: result.scenarios,
    receiptGate: result.receiptGate,
    childEvidence: result.childEvidence,
  });
}

function makeRun660AuthorityRecord(state, pool) {
  const authority = Object.freeze({});
  if (state.current) rememberSurfaceOrigin(state, authority, "ordinary", "trusted-authority-token-allocation");
  return {
    authority,
    brand: Symbol("migration-authority"),
    database: "runtime_posture_test",
    user: "cloud_admin",
    clusterFingerprint: "100",
    lifecycleFingerprint: "200",
    migrationsFolder: MIGRATIONS_FOLDER,
    phase: "initialization",
    pool,
    valid: true,
  };
}

function prepareRun660HashAdmission(state, { authorized = true } = {}) {
  state.observedPool = function ObservedPool() {};
  const current = createScenarioState({
    id: "RUN660_DP6_SYNTHETIC_BOUNDARY",
    rejectOperation: false,
    rejectCleanup: false,
    rejectSecondIdentity: false,
    omitPassword: false,
  }, state.markers);
  current.runId = state.runSerial++;
  const pool = createSyntheticPool(state);
  current.pools = [pool];
  current.poolCount = 1;
  current.poolInputValidated = true;
  current.poolEffectiveValidated = true;
  current.identityCalls = authorized ? 2 : 0;
  current.identity1Validated = authorized;
  current.identity2Validated = authorized;
  current.identityFingerprints = authorized
    ? [{ catalog: "100", lifecycle: "200" }, { catalog: "100", lifecycle: "200" }]
    : [];
  current.fingerprintsEqual = authorized;
  current.authorityGuardPassed = authorized;
  current.migrationEntered = true;
  current.manifestExistsCount = 1;
  current.manifestReadCount = 1;
  current.migrationReadCursor = 1;
  current.lastReadMigrationIndex = 0;
  current.lastReadMigrationPath = state.migrationHashPlan[0]?.path ?? null;
  current.lastReadMigrationSource = state.migrationHashPlan[0]?.source ?? null;
  if (authorized) {
    const record = makeRun660AuthorityRecord(state, pool);
    state.authorityRecord = record;
    state.authorityPool = pool;
    current.authorityCaptureCount = 1;
    current.authorityValidAtCapture = true;
    current.authorityTokenFrozen = Object.isFrozen(record.authority);
  } else {
    state.authorityRecord = null;
    state.authorityPool = null;
  }
  state.current = current;
  if (authorized) rememberSurfaceOrigin(state, state.authorityRecord.authority, "ordinary", "trusted-authority-token-allocation");
  return current;
}

function prepareRun660MigrationReadAdmission(state) {
  state.observedPool = function ObservedPool() {};
  const current = createScenarioState({
    id: "RUN660_DP6_ADMITTED_RUNTIME_SEQUENCE",
    rejectOperation: false,
    rejectCleanup: false,
    rejectSecondIdentity: false,
    omitPassword: false,
  }, state.markers);
  current.runId = state.runSerial++;
  const pool = createSyntheticPool(state);
  current.pools = [pool];
  current.poolCount = 1;
  current.poolInputValidated = true;
  current.poolEffectiveValidated = true;
  current.identityCalls = 2;
  current.identity1Validated = true;
  current.identity2Validated = true;
  current.identityFingerprints = [
    { catalog: "100", lifecycle: "200" },
    { catalog: "100", lifecycle: "200" },
  ];
  current.fingerprintsEqual = true;
  current.authorityGuardPassed = true;
  current.authorityCaptureCount = 1;
  current.authorityValidAtCapture = true;
  current.lifecyclePhase = "MIGRATION";
  const record = makeRun660AuthorityRecord(state, pool);
  state.authorityRecord = record;
  state.authorityPool = pool;
  current.authorityTokenFrozen = Object.isFrozen(record.authority);
  state.current = current;
  rememberSurfaceOrigin(state, record.authority, "ordinary", "trusted-authority-token-allocation");
  return current;
}

function installRun660MigrationObservers(state, ledger, fs, crypto) {
  state.migrationFsOwners = new Set([fs]);
  installMigrationExistenceObserver(state, ledger, fs);
  installMigrationReadObserver(state, ledger, fs);
  const writeMask = (fs.constants?.O_WRONLY ?? 1) | (fs.constants?.O_RDWR ?? 2) |
    (fs.constants?.O_CREAT ?? 64) | (fs.constants?.O_TRUNC ?? 512) |
    (fs.constants?.O_APPEND ?? 1024) | (fs.constants?.O_EXCL ?? 128) |
    (fs.constants?.O_TMPFILE ?? 0);
  if (descriptorOwner(fs, "openSync")) {
    installOpenObserver(state, ledger, fs, "openSync", "FS_OPENSYNC", writeMask);
  }
  installMigrationHashObserver(state, ledger, crypto);
}

function readRun660MigrationManifestAndSql(state, fs) {
  fs.existsSync(state.migrationManifestPlan.path);
  fs.readFileSync(state.migrationManifestPlan.path);
  fs.readFileSync(state.migrationHashPlan[0].path);
}

function readRun660MigrationPrefix(state, fs, count, crypto) {
  fs.existsSync(state.migrationManifestPlan.path);
  fs.readFileSync(state.migrationManifestPlan.path);
  const hashes = [];
  for (let index = 0; index < count; index += 1) {
    const plan = state.migrationHashPlan[index];
    fs.readFileSync(plan.path);
    hashes.push(crypto.createHash("sha256").update(plan.input).digest("hex"));
  }
  return hashes;
}

function hashDelegationCount(state) {
  const totals = state.hashDelegationTotals;
  return totals.createHash + totals.update + totals.digest;
}

async function runSecretSurfaceRun660RuntimeControlsInCurrentThread() {
  const require = createRequire(import.meta.url);
  const crypto = require("node:crypto");
  const fs = require("node:fs");
  const migrationContract = await buildMigrationContract(require, MIGRATIONS_FOLDER);
  const configure = (state) => {
    state.migrationManifestPlan = migrationContract.manifest;
    state.migrationHashPlan = migrationContract.hashes;
    state.allowedReadPaths = new Set(migrationContract.readPaths);
  };
  const hashCases = [];
  const rejectedCases = [
    ["RUN660_DP6_WRONG_RECEIVER", (state) => crypto.createHash.call({}, "sha256"), "DP_RECEIVER"],
    ["RUN660_DP6_NO_CURRENT_STATE", (state) => { state.current = null; return crypto.createHash("sha256"); }, "DP_STATE"],
    ["RUN660_DP6_EXTRA_ARGUMENT", (_state) => crypto.createHash("sha256", "utf8"), "DP_ARGUMENTS"],
    ["RUN660_DP6_NO_IDENTITY_AUTHORITY", (_state) => crypto.createHash("sha256"), "DP_STATE"],
    ["RUN660_DP6_WRONG_ALGORITHM", (_state) => crypto.createHash("md5"), "DP_ARGUMENTS"],
  ];
  for (const [id, invoke, expectedDetector] of rejectedCases) {
    const state = newRunState();
    configure(state);
    const current = prepareRun660MigrationReadAdmission(state);
    const ledger = new PatchLedger();
    installRun660MigrationObservers(state, ledger, fs, crypto);
    state.active = true;
    let code = "SSC_NEGATIVE_CONTROL_INACTIVE";
    let detector = "CONTROL_INACTIVE";
    let threw = false;
    try {
      readRun660MigrationManifestAndSql(state, fs);
      if (id === "RUN660_DP6_NO_CURRENT_STATE") state.current = null;
      if (id === "RUN660_DP6_NO_IDENTITY_AUTHORITY") {
        current.identity1Validated = false;
        current.identity2Validated = false;
        current.authorityGuardPassed = false;
        current.authorityCaptureCount = 0;
        current.authorityValidAtCapture = false;
        current.authorityTokenFrozen = false;
        state.authorityRecord = null;
        state.authorityPool = null;
      }
      invoke(state);
    } catch (error) {
      threw = true;
      code = error?.code ?? "SSC_HARNESS_INTERNAL";
      detector = error?.detector ?? "BOUNDARY";
    } finally {
      state.active = false;
      ledger.restore();
    }
    const delegated = hashDelegationCount(state);
    hashCases.push(Object.freeze({
      id,
      code,
      detector,
      threw,
      delegatedHashCalls: delegated,
      pass: threw && code === SAFE.runtime && detector === expectedDetector && delegated === 0,
    }));
  }

  const runLifecycleCase = async (id, expectedDetector, prepareAndInvoke) => {
    const state = newRunState();
    configure(state);
    const current = prepareRun660MigrationReadAdmission(state);
    const ledger = new PatchLedger();
    installRun660MigrationObservers(state, ledger, fs, crypto);
    state.active = true;
    let measurement = null;
    let error = null;
    const mark = (counter) => { measurement = { before: counter(), counter }; };
    try {
      readRun660MigrationManifestAndSql(state, fs);
      await prepareAndInvoke({ state, current, fs, crypto, mark });
    } catch (caught) {
      error = caught;
    } finally {
      state.active = false;
      ledger.restore();
    }
    const delegatedDelta = measurement
      ? measurement.counter() - measurement.before
      : Number.POSITIVE_INFINITY;
    const code = error?.code ?? "SSC_NEGATIVE_CONTROL_INACTIVE";
    const detector = error?.detector ?? "CONTROL_INACTIVE";
    hashCases.push(Object.freeze({
      id,
      code,
      detector,
      delegatedHashCalls: hashDelegationCount(state),
      underlyingDelegateDelta: delegatedDelta,
      pass: code === SAFE.runtime && detector === expectedDetector && delegatedDelta === 0,
    }));
  };
  const revokeMigration = (state, current) => {
    state.authorityRecord.valid = false;
    current.authorityRevocationStarted = true;
    current.lifecyclePhase = "REVOCATION";
    current.lifecycleGeneration += 1;
  };
  const beginCleanup = (current) => {
    current.cleanupEntryCount = 1;
    current.cleanupAttempted = true;
    current.lifecyclePhase = "CLEANUP";
    current.lifecycleGeneration += 1;
  };
  const completePublicly = (current) => {
    current.publicCompleted = true;
    current.lifecyclePhase = "PUBLIC_COMPLETE";
    current.lifecycleGeneration += 1;
  };
  await runLifecycleCase("RUN663_DP6_WRONG_HASH_RECEIVER", "DP_RECEIVER",
    async ({ crypto: actualCrypto, current, mark: markDelegate }) => {
      markDelegate(() => current.hashDelegations.createHash);
      actualCrypto.createHash.call({}, "sha256");
    });
  await runLifecycleCase("RUN663_DP6_WRONG_OPEN_RECEIVER", "DP_RECEIVER",
    async ({ fs: actualFs, state, current, mark: markDelegate }) => {
      markDelegate(() => current.migrationOpenDelegations);
      actualFs.openSync.call({}, state.migrationHashPlan[0].path, "r", 438);
    });
  await runLifecycleCase("RUN663_DP6_WRONG_OPEN_ARGUMENTS", "DP_ARGUMENTS",
    async ({ fs: actualFs, state, current, mark: markDelegate }) => {
      const path = state.migrationHashPlan[0].path;
      markDelegate(() => current.migrationOpenDelegations);
      actualFs.openSync(path, "r");
    });
  for (const [id, transition] of [
    ["RUN663_DP6_POST_REVOCATION_FILE_OPEN", revokeMigration],
    ["RUN663_DP6_POST_CLEANUP_FILE_OPEN", (_state, current) => beginCleanup(current)],
    ["RUN663_DP6_POST_PUBLIC_COMPLETION_FILE_OPEN", (_state, current) => completePublicly(current)],
  ]) {
    await runLifecycleCase(id, "DP_STATE", async ({ state, current, fs: actualFs, mark: markDelegate }) => {
      transition(state, current);
      markDelegate(() => current.migrationOpenDelegations);
      const fd = actualFs.openSync(state.migrationHashPlan[0].path, "r", 438);
      if (typeof fd === "number") actualFs.closeSync(fd);
    });
  }
  await runLifecycleCase("RUN663_DP6_CREATE_HASH_AFTER_TERMINAL", "DP_STATE",
    async ({ current, crypto: actualCrypto, mark: markDelegate }) => {
      completePublicly(current);
      markDelegate(() => current.hashDelegations.createHash);
      actualCrypto.createHash("sha256");
    });
  await runLifecycleCase("RUN663_DP6_UPDATE_AFTER_REVOCATION", "DP_STATE",
    async ({ state, current, crypto: actualCrypto, mark: markDelegate }) => {
      const hash = actualCrypto.createHash("sha256");
      revokeMigration(state, current);
      markDelegate(() => current.hashDelegations.update);
      hash.update(state.migrationHashPlan[0].input);
    });
  await runLifecycleCase("RUN663_DP6_DIGEST_AFTER_CLEANUP", "DP_STATE",
    async ({ state, current, crypto: actualCrypto, mark: markDelegate }) => {
      const hash = actualCrypto.createHash("sha256");
      hash.update(state.migrationHashPlan[0].input);
      beginCleanup(current);
      markDelegate(() => current.hashDelegations.digest);
      hash.digest("hex");
    });
  await runLifecycleCase("RUN663_DP6_CROSS_RUN_HASH_REUSE", "DP_RECEIVER",
    async ({ state, current, crypto: actualCrypto, mark: markDelegate }) => {
      const hash = actualCrypto.createHash("sha256");
      const next = prepareRun660MigrationReadAdmission(state);
      markDelegate(() => next.hashDelegations.update);
      hash.update(state.migrationHashPlan[0].input);
      void current;
    });
  await runLifecycleCase("RUN663_DP6_CONSUMED_HASH_REPLAY", "DP_RECEIVER",
    async ({ state, current, crypto: actualCrypto, mark: markDelegate }) => {
      const hash = actualCrypto.createHash("sha256");
      hash.update(state.migrationHashPlan[0].input);
      hash.digest("hex");
      markDelegate(() => current.hashDelegations.digest);
      hash.digest("hex");
    });

  const positiveState = newRunState();
  configure(positiveState);
  const positiveCurrent = prepareRun660MigrationReadAdmission(positiveState);
  const positiveLedger = new PatchLedger();
  installRun660MigrationObservers(positiveState, positiveLedger, fs, crypto);
  positiveState.active = true;
  let positiveHashes = [];
  try {
    positiveHashes = readRun660MigrationPrefix(positiveState, fs, migrationContract.hashes.length, crypto);
  } finally {
    positiveState.active = false;
    positiveLedger.restore();
  }
  const expectedHashes = migrationContract.hashes.map((item) => item.hash);
  const positivePass = positiveHashes.length === expectedHashes.length &&
    positiveHashes.every((hash, index) => hash === expectedHashes[index]) &&
    positiveCurrent.manifestExistsCount === 1 && positiveCurrent.manifestReadCount === 1 &&
    positiveCurrent.migrationReadCursor === migrationContract.hashes.length &&
    positiveCurrent.hashCompleted === migrationContract.hashes.length &&
    positiveCurrent.hashIndex === migrationContract.hashes.length &&
    hashDelegationCount(positiveState) === migrationContract.hashes.length * 3;
  hashCases.push(Object.freeze({
    id: "RUN660_DP6_ADMITTED_REAL_MIGRATION_FILES",
    pass: positivePass,
    migrationFiles: migrationContract.hashes.length,
    manifestExists: positiveCurrent.manifestExistsCount,
    manifestReads: positiveCurrent.manifestReadCount,
    migrationReads: positiveCurrent.migrationReadCursor,
    delegatedHashCalls: hashDelegationCount(positiveState),
    hashDelegations: Object.freeze({ ...positiveCurrent.hashDelegations }),
    hashOutputsMatch: positiveHashes.length === expectedHashes.length &&
      positiveHashes.every((hash, index) => hash === expectedHashes[index]),
  }));

  const surfaceState = newRunState();
  surfaceState.current = { runId: surfaceState.runSerial++ };
  surfaceState.observedPool = function ObservedPool() {};
  const surfaceMutationLedger = new PatchLedger();
  installPrototypeMutationObservers(surfaceState, surfaceMutationLedger);
  surfaceState.active = true;
  let hsResult;
  try {
    const marker = surfaceState.markers.connection;
    const effects = { getter: 0, callable: 0, thenable: 0, renderer: 0, iterator: 0, toJSON: 0 };
    class Run660PrivateCarrier { #value; constructor(value) { this.#value = value; } }
    const makeWeakMap = (value) => new WeakMap([[{}, value]]);
    const makeThenable = (value) => ({ then(resolve) { effects.thenable += 1; resolve(value); } });
    const makeCallable = (value) => function run660Callable() { effects.callable += 1; return value; };
    const fixturePath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..", SUBJECT_RELATIVE);
    const frozenSubject = await import(`${pathToFileURL(fixturePath).href}?run663-hs5-${surfaceState.current.runId}`);
    surfaceState.admissionErrorPrototype = frozenSubject.DisposablePostgresFixtureAdmissionError.prototype;
    const values = [
      ["weakmap_marker", makeWeakMap(marker)],
      ["promise_marker", Promise.resolve(marker)],
      ["callable_marker", makeCallable(marker)],
      ["private_marker", new Run660PrivateCarrier(marker)],
      ["thenable_marker", makeThenable(marker)],
      ["weakmap_clean", makeWeakMap("clean")],
      ["promise_clean", Promise.resolve("clean")],
      ["callable_clean", makeCallable("clean")],
      ["private_clean", new Run660PrivateCarrier("clean")],
      ["thenable_clean", makeThenable("clean")],
    ];
    const surfaceCases = [];
    const pool = createSyntheticPool(surfaceState);
    const baseRecord = makeRun660AuthorityRecord(surfaceState, pool);
    const appendSurfaceCase = (id, candidate) => {
      const observed = inspectSurface(candidate, surfaceState);
      const record = { ...baseRecord, database: candidate };
      const authorityRejected = !authorityMetadataSafe(record, surfaceState);
      const publicError = new frozenSubject.DisposablePostgresFixtureAdmissionError();
      rememberSurfaceOrigin(surfaceState, publicError, "admission-error", "frozen-helper-allocation");
      Object.defineProperty(publicError, "opaquePayload", {
        configurable: true, enumerable: false, value: candidate, writable: true,
      });
      const publicFailureRejected = !publicFailure(publicError, surfaceState);
      surfaceCases.push(Object.freeze({
        id,
        safe: observed.safe,
        invalid: observed.invalid,
        detector: observed.detector ?? null,
        authorityRejected,
        publicFailureRejected,
      }));
    };
    for (const [id, candidate] of values) appendSurfaceCase(id, candidate);

    const secretNullPrototype = new Run660PrivateCarrier(marker);
    Object.setPrototypeOf(secretNullPrototype, null);
    appendSurfaceCase("RUN663_HS_PRIVATE_SECRET_NULL_PROTO", secretNullPrototype);
    const cleanNullPrototype = new Run660PrivateCarrier("clean");
    cleanNullPrototype.__proto__ = null;
    appendSurfaceCase("RUN663_HS_PRIVATE_CLEAN_NULL_PROTO", cleanNullPrototype);
    const secretObjectPrototype = new Run660PrivateCarrier(marker);
    Object.setPrototypeOf(secretObjectPrototype, Object.prototype);
    appendSurfaceCase("RUN663_HS_PRIVATE_OBJECT_PROTO_REPLACEMENT", secretObjectPrototype);
    const ordinaryLookingPrototype = { label: "ordinary-looking" };
    rememberSurfaceOrigin(surfaceState, ordinaryLookingPrototype, "ordinary", "control-prototype-literal");
    const secretCustomPrototype = new Run660PrivateCarrier(marker);
    Reflect.setPrototypeOf(secretCustomPrototype, ordinaryLookingPrototype);
    appendSurfaceCase("RUN663_HS_PRIVATE_ORDINARY_CUSTOM_PROTO", secretCustomPrototype);

    let getterCalls = 0;
    const getterValue = trustedSurfaceAllocation(
      surfaceState,
      Object.defineProperty({}, "secret", { get() { getterCalls += 1; return marker; } }),
      "ordinary",
      "run660-getter-control",
    );
    const getterSurface = inspectSurface(getterValue, surfaceState);
    const customMap = trustedSurfaceAllocation(
      surfaceState,
      new Map([["marker", marker]]),
      "map",
      "run660-map-control",
    );
    Object.defineProperty(customMap, inspect.custom, { configurable: true, value() { effects.renderer += 1; return "safe"; } });
    const customMapSurface = inspectSurface(customMap, surfaceState);
    const customIterator = trustedSurfaceAllocation(
      surfaceState,
      { [Symbol.iterator]() { effects.iterator += 1; return [marker][Symbol.iterator](); } },
      "ordinary",
      "run660-iterator-control",
    );
    const iteratorSurface = inspectSurface(customIterator, surfaceState);
    const customJson = trustedSurfaceAllocation(
      surfaceState,
      { toJSON() { effects.toJSON += 1; return marker; } },
      "ordinary",
      "run660-json-control",
    );
    const jsonSurface = inspectSurface(customJson, surfaceState);

    const inheritedPrototype = { inherited: "clean" };
    rememberSurfaceOrigin(surfaceState, inheritedPrototype, "ordinary", "control-prototype-literal");
    const inheritedRoot = Object.create(inheritedPrototype);
    rememberSurfaceOrigin(surfaceState, inheritedRoot, "ordinary", "Object.create-control");
    const ordinaryNull = Object.create(null);
    rememberSurfaceOrigin(surfaceState, ordinaryNull, "ordinary", "Object.create-null-control");
    const ordinaryTransition = { value: "clean" };
    rememberSurfaceOrigin(surfaceState, ordinaryTransition, "ordinary", "control-literal");
    const safeTransitionPrototype = Object.create(null);
    rememberSurfaceOrigin(surfaceState, safeTransitionPrototype, "ordinary", "Object.create-null-prototype");
    Object.setPrototypeOf(ordinaryTransition, safeTransitionPrototype);
    const ordinaryObject = { value: "clean" };
    rememberSurfaceOrigin(surfaceState, ordinaryObject, "ordinary", "control-literal");
    const structural = [
      inheritedRoot,
      ordinaryNull,
      ordinaryTransition,
      ordinaryObject,
      trustedSurfaceAllocation(surfaceState, ["clean"], "array", "run660-array-control"),
      trustedSurfaceAllocation(surfaceState, new Map([["clean", "value"]]), "map", "run660-map-positive-control"),
      trustedSurfaceAllocation(surfaceState, new Set(["clean"]), "set", "run660-set-positive-control"),
      trustedSurfaceAllocation(surfaceState, new String("clean"), "boxed-primitive", "run660-boxed-positive-control"),
    ];
    const cyclic = trustedSurfaceAllocation(surfaceState, {}, "ordinary", "run660-cycle-control");
    cyclic.self = cyclic;
    structural.push(cyclic);
    const structuralPass = structural.every((value) => inspectSurface(value, surfaceState).safe);
    const hsPass = surfaceCases.length === 14 && surfaceCases.every((item) =>
      !item.safe && item.invalid && item.detector === "HS_INTERNAL_SLOT_UNSUPPORTED" &&
      item.authorityRejected && item.publicFailureRejected) &&
      !getterSurface.safe && getterSurface.invalid && getterSurface.detector === "HS_ACCESSOR_UNSUPPORTED" &&
      getterCalls === 0 && customMapSurface.leak && customMapSurface.invalid &&
      customMapSurface.detector === "HS_SECRET_REACHABLE" && iteratorSurface.invalid && jsonSurface.invalid &&
      structuralPass && Object.values(effects).every((count) => count === 0);
    hsResult = Object.freeze({
      id: "RUN660_HS5_DP6_RUNTIME_CONTROLS",
      hs: Object.freeze({
        count: surfaceCases.length,
        cases: Object.freeze(surfaceCases),
        getter: Object.freeze({ safe: getterSurface.safe, invalid: getterSurface.invalid, detector: getterSurface.detector, calls: getterCalls }),
        map: Object.freeze({ leak: customMapSurface.leak, invalid: customMapSurface.invalid, detector: customMapSurface.detector }),
        customIteratorInvalid: iteratorSurface.invalid,
        customJsonInvalid: jsonSurface.invalid,
        structuralPass,
        effects: Object.freeze({ ...effects }),
        pass: hsPass,
      }),
    });
  } finally {
    surfaceState.active = false;
    surfaceMutationLedger.restore();
  }
  return Object.freeze({
    ...hsResult,
    dp6: Object.freeze({
      count: hashCases.length,
      cases: Object.freeze(hashCases),
      pass: hashCases.every((item) => item.pass),
    }),
    pass: hsResult.hs.pass && hashCases.every((item) => item.pass),
  });
}

async function runSecretSurfaceRun669PrivateStateOriginControlsInCurrentThread() {
  const surfaceState = newRunState();
  surfaceState.current = { runId: surfaceState.runSerial++ };
  surfaceState.observedPool = function ObservedPool() {};
  const fixturePath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..", SUBJECT_RELATIVE);
  const frozenSubject = await import(`${pathToFileURL(fixturePath).href}?run669-hs5-${surfaceState.current.runId}`);
  surfaceState.admissionErrorPrototype = frozenSubject.DisposablePostgresFixtureAdmissionError.prototype;
  const surfaceMutationLedger = new PatchLedger();
  installPrototypeMutationObservers(surfaceState, surfaceMutationLedger);
  surfaceState.active = true;
  const marker = surfaceState.markers.connection;
  const pool = createSyntheticPool(surfaceState);
  const baseRecord = makeRun660AuthorityRecord(surfaceState, pool);
  const negativeCases = [];
  const appendNegative = (id, candidate, cachedSafe = null) => {
    const observed = inspectSurface(candidate, surfaceState);
    const record = { ...baseRecord, database: candidate };
    const authorityRejected = !authorityMetadataSafe(record, surfaceState);
    const publicError = new frozenSubject.DisposablePostgresFixtureAdmissionError();
    rememberSurfaceOrigin(surfaceState, publicError, "admission-error", "frozen-helper-allocation");
    Object.defineProperty(publicError, "opaquePayload", {
      configurable: true,
      enumerable: false,
      value: candidate,
      writable: true,
    });
    const publicFailureRejected = !publicFailure(publicError, surfaceState);
    negativeCases.push(Object.freeze({
      id,
      safe: observed.safe,
      invalid: observed.invalid,
      detector: observed.detector ?? null,
      authorityRejected,
      publicFailureRejected,
      ...(cachedSafe === null ? {} : { cachedSafe }),
    }));
  };
  try {
    const unregisteredOrdinary = Object.create(Object.prototype);
    appendNegative("unregistered_ordinary", unregisteredOrdinary);

    const shapeFactories = [
      ["reflect_object_prototype", () => Object.create(Object.prototype)],
      ["ordinary", () => ({})],
      ["null_prototype", () => Object.create(null)],
      ["array", () => []],
      ["map", () => new Map([["clean", "value"]])],
      ["set", () => new Set(["clean"])],
      ["boxed_string", () => new String("clean")],
    ];
    for (const [shape, create] of shapeFactories) {
      for (const [stateId, privateValue] of [["secret", marker], ["clean", "clean"]]) {
        const candidate = create();
        Reflect.construct(Run669PrivateStateCarrier, [candidate, privateValue]);
        appendNegative(`${shape}_${stateId}`, candidate);
      }
    }

    for (const [stateId, privateValue] of [["secret", marker], ["clean", "clean"]]) {
      const candidate = trustedSurfaceAllocation(
        surfaceState,
        {},
        "ordinary",
        "run669-cached-ordinary-allocation",
      );
      const cachedSafe = inspectSurface(candidate, surfaceState).safe;
      Reflect.construct(Run669PrivateStateCarrier, [candidate, privateValue]);
      appendNegative(`cached_ordinary_${stateId}`, candidate, cachedSafe);
    }

    const cleanOrdinary = trustedSurfaceAllocation(
      surfaceState,
      { value: "clean" },
      "ordinary",
      "run669-positive-ordinary-allocation",
    );
    const cleanNullPrototype = trustedSurfaceAllocation(
      surfaceState,
      Object.create(null),
      "ordinary",
      "run669-positive-null-prototype-allocation",
    );
    const cleanArray = trustedSurfaceAllocation(
      surfaceState,
      ["clean"],
      "array",
      "run669-positive-array-allocation",
    );
    const cleanMap = trustedSurfaceAllocation(
      surfaceState,
      new Map([["clean", "value"]]),
      "map",
      "run669-positive-map-allocation",
    );
    const cleanSet = trustedSurfaceAllocation(
      surfaceState,
      new Set(["clean"]),
      "set",
      "run669-positive-set-allocation",
    );
    const cleanBoxedString = trustedSurfaceAllocation(
      surfaceState,
      new String("clean"),
      "boxed-primitive",
      "run669-positive-boxed-allocation",
    );
    const safeTransitionPrototype = trustedSurfaceAllocation(
      surfaceState,
      Object.create(null),
      "ordinary",
      "run669-positive-transition-prototype",
    );
    const safeTransition = trustedSurfaceAllocation(
      surfaceState,
      { value: "clean" },
      "ordinary",
      "run669-positive-transition-allocation",
    );
    Object.setPrototypeOf(safeTransition, safeTransitionPrototype);
    const positiveCases = [
      ["ordinary", cleanOrdinary, "ordinary"],
      ["null_prototype", cleanNullPrototype, "ordinary"],
      ["array", cleanArray, "array"],
      ["map", cleanMap, "map"],
      ["set", cleanSet, "set"],
      ["boxed_string", cleanBoxedString, "boxed-primitive"],
      ["safe_transition", safeTransition, "ordinary"],
    ].map(([id, candidate, kind]) => {
      const observed = inspectSurface(candidate, surfaceState);
      const record = { ...baseRecord, database: candidate };
      return Object.freeze({
        id,
        kind,
        safe: observed.safe,
        authorityAccepted: authorityMetadataSafe(record, surfaceState),
      });
    });
    const cleanAdmissionError = new frozenSubject.DisposablePostgresFixtureAdmissionError();
    rememberSurfaceOrigin(surfaceState, cleanAdmissionError, "admission-error", "frozen-helper-allocation");
    const frozenAdmissionErrorAccepted = publicFailure(cleanAdmissionError, surfaceState);
    const positives = Object.freeze([
      ...positiveCases,
      Object.freeze({ id: "frozen_admission_error", publicAccepted: frozenAdmissionErrorAccepted }),
    ]);
    const negatives = Object.freeze(negativeCases);
    const pass = negatives.length === 17 && negatives.every((item) =>
      item.safe === false && item.invalid === true && item.detector === "HS_INTERNAL_SLOT_UNSUPPORTED" &&
      item.authorityRejected === true && item.publicFailureRejected === true &&
      (item.cachedSafe === undefined || item.cachedSafe === true)) &&
      positives.slice(0, 7).every((item) => item.safe === true && item.authorityAccepted === true) &&
      positives[7]?.publicAccepted === true;
    return Object.freeze({
      id: "RUN669_HS5_PRIVATE_STATE_ORIGIN_PROVENANCE",
      negatives,
      positives,
      pass,
    });
  } finally {
    surfaceState.active = false;
    surfaceMutationLedger.restore();
  }
}

async function runSecretSurfaceIndependentRuntimeCorpusInCurrentThread() {
  const require = createRequire(import.meta.url);
  const crypto = require("node:crypto");
  const fs = require("node:fs");
  const migrationContract = await buildMigrationContract(require, MIGRATIONS_FOLDER);
  const surfaceState = newRunState();
  const marker = surfaceState.markers.connection;
  const inheritedLongPrototype = { x: "x".repeat(12000) + marker };
  rememberSurfaceOrigin(surfaceState, inheritedLongPrototype, "ordinary", "corpus-prototype-literal");
  const inheritedLongRoot = Object.create(inheritedLongPrototype);
  rememberSurfaceOrigin(surfaceState, inheritedLongRoot, "ordinary", "Object.create-corpus");
  const inheritedPrototype = { x: marker };
  rememberSurfaceOrigin(surfaceState, inheritedPrototype, "ordinary", "corpus-prototype-literal");
  const inheritedRoot = Object.create(inheritedPrototype);
  rememberSurfaceOrigin(surfaceState, inheritedRoot, "ordinary", "Object.create-corpus");
  const inheritedNonenumPrototype = Object.defineProperty({}, "x", { value: marker });
  rememberSurfaceOrigin(surfaceState, inheritedNonenumPrototype, "ordinary", "corpus-prototype-literal");
  const inheritedNonenumRoot = Object.create(inheritedNonenumPrototype);
  rememberSurfaceOrigin(surfaceState, inheritedNonenumRoot, "ordinary", "Object.create-corpus");
  const symbolArray = trustedSurfaceAllocation(
    surfaceState,
    [...Array(100).fill(0), Symbol(marker)],
    "array",
    "corpus-array-allocation",
  );
  const symbolArrayRoot = trustedSurfaceAllocation(
    surfaceState,
    { items: symbolArray },
    "ordinary",
    "corpus-object-allocation",
  );
  const nestedSymbolChild = trustedSurfaceAllocation(
    surfaceState,
    { y: Symbol(marker) },
    "ordinary",
    "corpus-object-allocation",
  );
  const nestedSymbolRoot = trustedSurfaceAllocation(
    surfaceState,
    { x: nestedSymbolChild },
    "ordinary",
    "corpus-object-allocation",
  );
  const nonenum = trustedSurfaceAllocation(
    surfaceState,
    Object.defineProperty({}, "x", { value: marker }),
    "ordinary",
    "corpus-object-allocation",
  );
  const getter = trustedSurfaceAllocation(
    surfaceState,
    Object.defineProperty({}, "x", { get() { return marker; } }),
    "ordinary",
    "corpus-object-allocation",
  );
  const throwGetter = trustedSurfaceAllocation(
    surfaceState,
    Object.defineProperty({}, "x", { get() { throw new Error("synthetic"); } }),
    "ordinary",
    "corpus-object-allocation",
  );
  const wide = trustedSurfaceAllocation(
    surfaceState,
    Object.fromEntries(Array.from({ length: 258 }, (_, index) => ["x" + index, 0])),
    "ordinary",
    "corpus-wide-object-allocation",
  );
  const wideLateMarker = trustedSurfaceAllocation(
    surfaceState,
    Object.fromEntries(Array.from(
      { length: 258 },
      (_, index) => ["x" + index, index === 257 ? marker : 0],
    )),
    "ordinary",
    "corpus-wide-object-allocation",
  );
  const mapInternal = trustedSurfaceAllocation(
    surfaceState,
    new Map([["x", marker]]),
    "map",
    "corpus-map-allocation",
  );
  const setInternal = trustedSurfaceAllocation(
    surfaceState,
    new Set([marker]),
    "set",
    "corpus-set-allocation",
  );
  const boxedSymbol = trustedSurfaceAllocation(
    surfaceState,
    Object(Symbol(marker)),
    "boxed-primitive",
    "corpus-boxed-allocation",
  );
  const surfaceCases = [
    ["symbol", Symbol(marker)],
    ["symbol_key", trustedSurfaceAllocation(surfaceState, { [Symbol(marker)]: 0 }, "ordinary", "corpus-object-allocation")],
    ["symbol_array", symbolArrayRoot],
    ["nested_symbol", nestedSymbolRoot],
    ["nonenum", nonenum],
    ["getter", getter],
    ["throw_getter", throwGetter],
    ["throw_descriptor", new Proxy({}, {
      getOwnPropertyDescriptor() { throw new Error("synthetic"); },
      ownKeys() { return ["x"]; },
    })],
    ["inherited_long", inheritedLongRoot],
    ["inherited", inheritedRoot],
    ["inherited_nonenum", inheritedNonenumRoot],
    ["wide_258", wide],
    ["wide_late_marker", wideLateMarker],
    ["map_internal", mapInternal],
    ["set_internal", setInternal],
    ["boxed_symbol", boxedSymbol],
  ];
  let customRendererCalled = false;
  const customInspectedMap = trustedSurfaceAllocation(
    surfaceState,
    new Map([["x", marker]]),
    "map",
    "corpus-map-allocation",
  );
  Object.defineProperty(customInspectedMap, inspect.custom, {
    configurable: true,
    value() {
      customRendererCalled = true;
      return "safe";
    },
  });
  surfaceCases.push(["map_custom_inspect", customInspectedMap]);
  const deepRoot = trustedSurfaceAllocation(surfaceState, {}, "ordinary", "corpus-depth-root");
  let deepCursor = deepRoot;
  for (let index = 0; index < 7; index += 1) {
    deepCursor.next = trustedSurfaceAllocation(surfaceState, {}, "ordinary", "corpus-depth-child");
    deepCursor = deepCursor.next;
  }
  surfaceCases.push(["depth_7", deepRoot]);
  const surfaces = surfaceCases.map(([id, valueToInspect]) => {
    const surface = inspectSurface(valueToInspect, surfaceState);
    return Object.freeze({
      id,
      safe: surface.safe,
      leak: surface.leak,
      invalid: surface.invalid,
      ...(id === "map_custom_inspect" ? { customRendererCalled } : {}),
    });
  });

  const restoration = [];
  const successLedger = new PatchLedger();
  const successTarget = { x: 1 };
  successLedger.install(successTarget, "x", 2);
  const successResult = finalizeBoundary({ ok: true }, successLedger);
  restoration.push(Object.freeze({
    id: "success",
    ok: successResult.ok === true,
    restored: successTarget.x === 1,
  }));
  for (const mode of ["mismatch", "throw", "verify_false", "verify_throw"]) {
    const ledger = new PatchLedger();
    const target = { x: 1 };
    if (mode === "mismatch") {
      ledger.install(target, "x", 2);
      target.x = 3;
    } else {
      ledger.installCustom(
        () => {
          if (mode === "throw") throw new Error("synthetic");
        },
        () => {
          if (mode === "verify_throw") throw new Error("synthetic");
          return false;
        },
      );
    }
    const result = finalizeBoundary({ ok: true }, ledger);
    restoration.push(Object.freeze({
      id: mode,
      code: result.code,
      detector: result.detector,
    }));
  }
  const order = [];
  const reverseLedger = new PatchLedger();
  reverseLedger.installCustom(() => order.push(1), () => true);
  reverseLedger.installCustom(() => order.push(2), () => true);
  const reverseResult = finalizeBoundary({ ok: true }, reverseLedger);
  restoration.push(Object.freeze({
    id: "reverse_order",
    pass: reverseResult.ok && order.join(",") === "2,1",
  }));
  const partialLedger = new PatchLedger();
  const partialTarget = { a: 1 };
  let partialRejected = false;
  partialLedger.install(partialTarget, "a", 2);
  try {
    partialLedger.install(Object.freeze({ b: 1 }), "b", 2);
  } catch {
    partialRejected = true;
  }
  const partialResult = finalizeBoundary({ ok: false }, partialLedger);
  restoration.push(Object.freeze({
    id: "partial_install",
    pass: partialRejected && partialTarget.a === 1 && partialResult.ok === false,
  }));
  const failedLedger = new PatchLedger();
  const failedTarget = { x: 1 };
  failedLedger.install(failedTarget, "x", 2);
  finalizeBoundary({ ok: false }, failedLedger);
  restoration.push(Object.freeze({
    id: "scenario_failure_restore",
    pass: failedTarget.x === 1,
  }));

  const poolState = newRunState();
  poolState.observedPool = function ObservedPool() {};
  const pool = createSyntheticPool(poolState);
  poolState.authorityPool = pool;
  poolState.authorityRecord = { pool };
  const current = {
    pools: [pool],
    poolCount: 1,
    authorityCaptureCount: 1,
    bindingMismatch: false,
  };
  const poolBindings = [
    Object.freeze({ id: "good", pass: poolBindingContract(current, poolState) }),
  ];
  for (const id of [
    "captured_password", "observed_password", "binding", "authority_pool",
    "authority_record_pool", "two_pools", "two_captures", "connectionString",
    "wrong_max", "wrong_database",
  ]) {
    const candidateState = { ...poolState };
    const candidateCurrent = { ...current };
    const originalCaptured = pool.__sscInputOptions;
    const originalObserved = pool.options;
    if (id === "captured_password") {
      pool.__sscInputOptions = { ...originalCaptured, password: "synthetic-wrong" };
    } else if (id === "observed_password") {
      pool.options = { ...originalObserved, password: "synthetic-wrong" };
    } else if (id === "binding") {
      candidateCurrent.bindingMismatch = true;
    } else if (id === "authority_pool") {
      candidateState.authorityPool = {};
    } else if (id === "authority_record_pool") {
      candidateState.authorityRecord = { pool: {} };
    } else if (id === "two_pools") {
      candidateCurrent.poolCount = 2;
    } else if (id === "two_captures") {
      candidateCurrent.authorityCaptureCount = 2;
    } else if (id === "connectionString") {
      pool.options = { ...originalObserved, connectionString: "synthetic" };
    } else if (id === "wrong_max") {
      pool.options = { ...originalObserved, max: 2 };
    } else if (id === "wrong_database") {
      pool.options = { ...originalObserved, database: "wrong" };
    }
    poolBindings.push(Object.freeze({
      id,
      rejected: !poolBindingContract(candidateCurrent, candidateState),
    }));
    pool.__sscInputOptions = originalCaptured;
    pool.options = originalObserved;
  }

  const dependencies = [];
  for (const id of [
    "WRONG_HASH_ALGORITHM", "WRONG_HASH_RECEIVER", "POOL_FALLBACK_WRONG_RECEIVER",
    "UNLISTED_READ_PATH", "WRITE_OPEN_DENIED",
  ]) {
    const state = newRunState();
    const ledger = new PatchLedger();
    let effects = 0;
    const owner = {
      call() {
        effects += 1;
        return {
          update() { return this; },
          digest() { return "synthetic"; },
        };
      },
    };
    if (id.startsWith("WRONG_HASH")) {
      state.migrationManifestPlan = migrationContract.manifest;
      state.migrationHashPlan = migrationContract.hashes;
      state.allowedReadPaths = new Set(migrationContract.readPaths);
      prepareRun660MigrationReadAdmission(state);
      installRun660MigrationObservers(state, ledger, fs, crypto);
    } else if (id.startsWith("POOL_")) {
      installPoolDependencyObserver(state, ledger, owner, "call", "POOL_FALLBACK_QUERY");
    } else {
      installOpenObserver(state, ledger, owner, "call", "FS_OPEN", 1);
    }
    effects = 0;
    state.active = true;
    state.poolDependencyAllowed = true;
    state.allowedDependencyEffects = new Set(["CRYPTO_CREATEHASH"]);
    let threw = false;
    try {
      if (id.startsWith("WRONG_HASH")) readRun660MigrationManifestAndSql(state, fs);
      if (id === "WRONG_HASH_ALGORITHM") {
        crypto.createHash("md5");
      } else if (id === "WRONG_HASH_RECEIVER") {
        crypto.createHash.call({}, "sha256");
      } else if (id === "POOL_FALLBACK_WRONG_RECEIVER") {
        owner.call.call({}, "unexpected SQL");
      } else {
        owner.call("unlisted-synthetic-path", id === "WRITE_OPEN_DENIED" ? "w" : "r");
      }
    } catch {
      threw = true;
    } finally {
      state.active = false;
      ledger.restore();
    }
    dependencies.push(Object.freeze({
      id,
      effects: id.startsWith("WRONG_HASH") ? hashDelegationCount(state) : effects,
      threw,
      eventCount: state.runtimeEvents.size,
    }));
  }
  const queryProbes = [];
  for (const [id, text, values] of [
    ["UNEXPECTED_SQL", "select unexpected_synthetic_statement", [1]],
    ["WRONG_IDENTITY_PARAMETERS", "select current_database() = $1", ["wrong", "wrong"]],
  ]) {
    const state = newRunState();
    const pool = {};
    state.identitySql = "select current_database() = $1";
    state.active = true;
    state.current = {
      pools: [pool],
      identityCalls: 0,
      migrationQueries: 0,
      migrationPlanIndex: 0,
      authorityCaptureCount: 0,
      events: [],
      scenario: {},
    };
    let threw = false;
    try {
      await executeQuery(state, pool, [text, values], "pool");
    } catch {
      threw = true;
    }
    queryProbes.push(Object.freeze({
      id,
      threw,
      migrationQueries: state.current.migrationQueries,
      identityCalls: state.current.identityCalls,
      queryRejected: state.current.queryRejected,
    }));
  }
  const cases = Object.freeze([
    ...surfaces.map((result) => Object.freeze({ family: "F4A", ...result })),
    ...restoration.map((result) => Object.freeze({ family: "F2", ...result })),
    ...poolBindings.map((result) => Object.freeze({ family: "F3", ...result })),
    ...dependencies.map((result) => Object.freeze({ family: "DEPENDENCY", ...result })),
    ...queryProbes.map((result) => Object.freeze({ family: "DEPENDENCY", ...result })),
  ]);
  return Object.freeze({
    id: "RUN657_INDEPENDENT_RUNTIME_CORPUS",
    count: cases.length,
    cases,
  });
}


export async function runSecretSurfaceRun660RuntimeControls() {
  const gate = await runFrozenReceiptStaticGate();
  if (gate.ok !== true) return Object.freeze({
    id: "RUN660_HS5_DP6_RUNTIME_CONTROLS", pass: false,
    hs: Object.freeze({ pass: false }), dp6: Object.freeze({ pass: false }),
    receiptGate: receiptGateEvidence(gate),
  });
  try {
    const child = await runHarnessChild("control", "RUN660_HS5_DP6_RUNTIME_CONTROLS", gate);
    return Object.freeze({ ...child.value, childPid: child.childPid, receiptGate: receiptGateEvidence(gate) });
  } catch {
    return Object.freeze({
      id: "RUN660_HS5_DP6_RUNTIME_CONTROLS", pass: false,
      hs: Object.freeze({ pass: false }), dp6: Object.freeze({ pass: false }),
      receiptGate: receiptGateEvidence(gate),
    });
  }
}

export async function runSecretSurfaceRun669PrivateStateOriginControls() {
  const gate = await runFrozenReceiptStaticGate();
  if (gate.ok !== true) return Object.freeze({
    id: "RUN669_HS5_PRIVATE_STATE_ORIGIN_PROVENANCE", pass: false,
    negatives: Object.freeze([]), positives: Object.freeze([]),
    receiptGate: receiptGateEvidence(gate),
  });
  try {
    const child = await runHarnessChild("control", "RUN669_HS5_PRIVATE_STATE_ORIGIN_CONTROLS", gate);
    return Object.freeze({ ...child.value, childPid: child.childPid, receiptGate: receiptGateEvidence(gate) });
  } catch {
    return Object.freeze({
      id: "RUN669_HS5_PRIVATE_STATE_ORIGIN_PROVENANCE", pass: false,
      negatives: Object.freeze([]), positives: Object.freeze([]),
      receiptGate: receiptGateEvidence(gate),
    });
  }
}

export async function runSecretSurfaceIndependentRuntimeCorpus() {
  const gate = await runFrozenReceiptStaticGate();
  if (gate.ok !== true) return Object.freeze({
    id: "RUN657_INDEPENDENT_RUNTIME_CORPUS", count: 0,
    cases: Object.freeze([]), receiptGate: receiptGateEvidence(gate),
  });
  try {
    const child = await runHarnessChild("control", "RUN657_INDEPENDENT_RUNTIME_CORPUS", gate);
    return Object.freeze({ ...child.value, childPid: child.childPid, receiptGate: receiptGateEvidence(gate) });
  } catch {
    return Object.freeze({
      id: "RUN657_INDEPENDENT_RUNTIME_CORPUS", count: 0,
      cases: Object.freeze([]), receiptGate: receiptGateEvidence(gate),
    });
  }
}

export async function runSecretSurfaceRun660F3Pair() {
  const gate = await runFrozenReceiptStaticGate();
  if (gate.ok !== true) return Object.freeze({
    id: "RUN660_F3_SAME_CHILD_PROCESS", pass: false,
    childPid: 0, parentPid: process.pid, run660Pid: 0, f3Pid: 0,
    sameChildPid: false, scenarioCount: 0, resourcesStable: false,
    receiptGate: receiptGateEvidence(gate),
  });
  try {
    const child = await runHarnessChild("run660-f3-pair", undefined, gate);
    const value = child.value;
    const sameChildPid = value.sameChildPid === true &&
      value.run660Pid === value.f3Pid && value.run660Pid === child.childPid;
    const separateFromParent = child.childPid !== process.pid;
    return Object.freeze({
      id: "RUN660_F3_SAME_CHILD_PROCESS",
      pass: value.pass === true && sameChildPid && separateFromParent,
      childPid: child.childPid,
      parentPid: process.pid,
      run660Pid: value.run660Pid,
      f3Pid: value.f3Pid,
      sameChildPid,
      separateFromParent,
      scenarioCount: value.scenarioCount,
      resourcesStable: value.resourcesStable === true,
      receiptGate: receiptGateEvidence(gate),
    });
  } catch {
    return Object.freeze({
      id: "RUN660_F3_SAME_CHILD_PROCESS", pass: false,
      childPid: 0, parentPid: process.pid, run660Pid: 0, f3Pid: 0,
      sameChildPid: false, separateFromParent: false,
      scenarioCount: 0, resourcesStable: false,
      receiptGate: receiptGateEvidence(gate),
    });
  }
}

async function runHarnessChildMode() {
  const args = process.argv.slice(2);
  const mode = args[1];
  const caseId = args[2];
  const expectedCount = mode === "run660-f3-pair" ? 2 : 3;
  const environmentAllowlist = process.platform === "win32"
    ? new Set(["systemroot", "windir", "temp", "tmp"])
    : new Set(["tmpdir"]);
  const validEnvironment = Object.keys(process.env).every((key) => environmentAllowlist.has(key.toLowerCase()));
  const validRequest = args[0] === "--ssc-child" &&
    args.length === expectedCount &&
    process.execArgv.length === 0 &&
    process.versions.node.split(".")[0] === "22" &&
    path.isAbsolute(process.execPath) &&
    path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url)) &&
    path.resolve(process.cwd()) === repoRootFromHarness() &&
    validEnvironment &&
    (mode === "run660-f3-pair"
      ? caseId === undefined
      : validChildCase(mode, caseId));
  if (!validRequest) {
    process.stdout.write(JSON.stringify({ ok: false, mode: mode ?? "", code: "SSC_CHILD_REQUEST_REJECTED" }) + "\n");
    process.exitCode = 1;
    return;
  }
  const gate = await runFrozenReceiptStaticGate();
  if (gate.ok !== true) {
    process.stdout.write(JSON.stringify({ ok: false, mode, caseId, code: "SSC_RECEIPT_GATE_BLOCKED" }) + "\n");
    process.exitCode = 1;
    return;
  }
  try {
    let value;
    if (mode === "scenario") {
      const result = await runSecretSurfaceBehavioralHarnessInCurrentThread({ scenarioId: caseId });
      value = result.scenarios.find((item) => item.id === caseId) ??
        Object.freeze({ id: caseId, pass: false, code: "SSC_CHILD_CASE_MISSING", resourcesStable: false });
    } else if (mode === "control" && caseId === "RUN660_HS5_DP6_RUNTIME_CONTROLS") {
      value = await runSecretSurfaceRun660RuntimeControlsInCurrentThread();
    } else if (mode === "control" && caseId === "RUN669_HS5_PRIVATE_STATE_ORIGIN_CONTROLS") {
      value = await runSecretSurfaceRun669PrivateStateOriginControlsInCurrentThread();
    } else if (mode === "control" && caseId === "RUN657_INDEPENDENT_RUNTIME_CORPUS") {
      value = await runSecretSurfaceIndependentRuntimeCorpusInCurrentThread();
    } else if (mode === "control" && caseId === "SSC_FORCE_RESTORE_MISMATCH") {
      const restoration = runRestoreBoundaryControl();
      value = restoration.pass === true ? fixedRestoreFailure() : restoration;
    } else if (mode === "control") {
      const result = await runSecretSurfaceBehavioralHarnessInCurrentThread({ controlId: caseId });
      value = result.controls.results.find((item) => item.id === caseId) ??
        Object.freeze({ id: caseId, pass: false, code: "SSC_CHILD_CASE_MISSING", detector: "CHILD_BOUNDARY" });
    } else {
      const run660 = await runSecretSurfaceRun660RuntimeControlsInCurrentThread();
      const run660Pid = process.pid;
      const f3 = await runSecretSurfaceBehavioralHarness({
        scenarioIds: SCENARIOS.map((scenario) => scenario.id),
      });
      const f3Pid = process.pid;
      value = Object.freeze({
        id: "RUN660_F3_SAME_CHILD_PROCESS",
        pass: run660.pass === true && f3.allScenariosPass === true,
        run660Pid,
        f3Pid,
        sameChildPid: run660Pid === f3Pid,
        scenarioCount: f3.scenarioCount,
        resourcesStable: f3.scenarios.length === SCENARIOS.length &&
          f3.scenarios.every((scenario) => scenario.resourcesStable === true),
      });
    }
    const payload = {
      ok: true,
      mode,
      ...(caseId === undefined ? {} : { caseId }),
      childPid: process.pid,
      gateEvidence: receiptGateEvidence(gate),
      value,
    };
    if (!safeChildTree(payload)) throw new Error("SSC_CHILD_RESULT_UNSAFE");
    process.stdout.write(JSON.stringify(payload) + "\n");
  } catch {
    process.stdout.write(JSON.stringify({ ok: false, mode, caseId, code: "SSC_CHILD_FAILURE" }) + "\n");
    process.exitCode = 1;
  }
}

if (process.argv[2] === "--ssc-child") {
  await runHarnessChildMode();
}

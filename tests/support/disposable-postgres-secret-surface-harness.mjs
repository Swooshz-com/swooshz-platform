import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import { inspect } from "node:util";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

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

const SCENARIOS = Object.freeze([
  Object.freeze({ id: "SC01_ORDINARY_SUCCESS", rejectOperation: false, rejectCleanup: false, rejectSecondIdentity: false }),
  Object.freeze({ id: "SC02_SUCCESS_CLEANUP_REJECT", rejectOperation: false, rejectCleanup: true, rejectSecondIdentity: false }),
  Object.freeze({ id: "SC03_OPERATION_REJECT_CLEANUP_REJECT", rejectOperation: true, rejectCleanup: true, rejectSecondIdentity: false }),
  Object.freeze({ id: "SC04_SECOND_IDENTITY_REJECT_CLEANUP_REJECT", rejectOperation: false, rejectCleanup: true, rejectSecondIdentity: true }),
]);

const BEHAVIORAL_CONTROLS = Object.freeze([
  Object.freeze({ id: "NC11_PUBLIC_CAUSE", code: "SSC_PUBLIC_SURFACE", detector: "PUBLIC_CAUSE" }),
  Object.freeze({ id: "NC12_PUBLIC_NONENUM", code: "SSC_PUBLIC_SURFACE", detector: "PUBLIC_DESCRIPTOR" }),
  Object.freeze({ id: "NC13_BROKEN_INSTALL", code: "SSC_OBSERVER_INSTALL", detector: "INSTALL_LEDGER" }),
  Object.freeze({ id: "NC14_BROKEN_RESTORE", code: "SSC_OBSERVER_RESTORE", detector: "RESTORE_LEDGER" }),
]);

const SAFE = Object.freeze({
  pass: "PASS",
  internal: "SSC_HARNESS_INTERNAL",
  install: "SSC_OBSERVER_INSTALL",
  restore: "SSC_OBSERVER_RESTORE",
  surface: "SSC_PUBLIC_SURFACE",
  scenario: "SSC_SCENARIO_FAILED",
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
      if (!sameDescriptor(current, entry.after)) {
        mismatch = true;
        continue;
      }
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
    originalStringify: JSON.stringify,
    originalInspect: inspect,
    originalSetImmediate: globalThis.setImmediate,
    authorityRecord: null,
    authorityPool: null,
    observedPool: null,
    subjectUrl: null,
    scenarioSerial: 0,
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
      return true;
    },
    deleteProperty(target, property) {
      void target;
      void property;
      recordEvent(state, "ENV_DELETE");
      return true;
    },
    defineProperty(target, property, descriptorValue) {
      void target;
      void property;
      void descriptorValue;
      recordEvent(state, "ENV_DEFINE");
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
  state.selfTest = false;
  if (!state.canaryHits.has("ENV_SET") || !state.canaryHits.has("ENV_DELETE")) fail(SAFE.install, "INSTALL_LEDGER");
  state.canaryHits.delete("ENV_SET");
  state.canaryHits.delete("ENV_DELETE");
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
    const result = original.call(this, key, record);
    if (state.selfTest && key === state.weakMapCanaryKey) recordEvent(state, "WEAKMAP_CANARY");
    if (state.active && isAuthorityRecord(key, record, ObservedPool)) {
      state.authorityRecord = record;
      state.authorityPool = record.pool;
      state.current.authorityCaptureCount += 1;
      state.current.authorityValidAtCapture = record.valid === true;
      state.current.events.push("AUTHORITY_SET");
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

function argumentHasMarker(argument, markers) {
  if (typeof argument === "string") return containsMarker(argument, markers);
  if (argument instanceof Uint8Array) {
    return containsMarker(Buffer.from(argument).toString("utf8"), markers);
  }
  return false;
}

function installPassthroughObserver(state, ledger, target, key, id) {
  const found = descriptorOwner(target, key);
  if (!found || typeof found.descriptor.value !== "function") fail(SAFE.install, "INSTALL_LEDGER");
  const original = found.descriptor.value;
  const wrapper = function observedPassthrough(...args) {
    if (args.some((argument) => argumentHasMarker(argument, state.markers))) {
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

function installOpenObserver(state, ledger, owner, key, id) {
  const found = descriptorOwner(owner, key);
  if (!found || typeof found.descriptor.value !== "function") fail(SAFE.install, "INSTALL_LEDGER");
  const original = found.descriptor.value;
  const wrapper = function observedOpen(...args) {
    const flags = args[1];
    const writeIntent = typeof flags === "number"
      ? (flags & 3) !== 0
      : /[wa+]/u.test(String(flags ?? ""));
    if (writeIntent) {
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
  const ledger = new PatchLedger();
  const net = require("node:net");
  const tls = require("node:tls");
  const http = require("node:http");
  const https = require("node:https");
  const dgram = require("node:dgram");
  const childProcess = require("node:child_process");
  const fs = require("node:fs");
  const fsPromises = require("node:fs/promises");
  const crypto = require("node:crypto");
  const v8 = require("node:v8");
  const diagnosticsChannel = require("node:diagnostics_channel");

  try {
    installObserverSet(state, ledger, net, ["connect", "createConnection"], "NET");
    installObserverSet(state, ledger, net.Socket.prototype, ["connect"], "NET_SOCKET");
    installObserverSet(state, ledger, tls, ["connect"], "TLS");
    installObserverSet(state, ledger, http, ["request", "get"], "HTTP");
    installObserverSet(state, ledger, https, ["request", "get"], "HTTPS");
    installObserverSet(state, ledger, dgram.Socket.prototype, ["send", "connect"], "DGRAM");
    installObserverSet(state, ledger, childProcess, ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"], "CHILD_PROCESS");
    installObserverSet(state, ledger, globalThis, ["fetch"], "GLOBAL_FETCH");
    installObserverSet(state, ledger, console, ["log", "error", "warn", "info", "debug"], "CONSOLE");
    installObserverSet(state, ledger, process, ["emitWarning"], "PROCESS_WARNING");
    installObserverSet(state, ledger, process.stdout, ["write"], "STDOUT", true);
    installObserverSet(state, ledger, process.stderr, ["write"], "STDERR", true);
    installObserverSet(state, ledger, globalThis, ["setTimeout", "setInterval", "setImmediate", "queueMicrotask"], "TIMER");
    installObserverSet(state, ledger, process, ["nextTick"], "TIMER_PROCESS");

    const writeMethods = [
      "write", "writev", "writeFile", "writeFileSync", "appendFile", "appendFileSync",
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
    if (descriptorOwner(fs, "open")) installOpenObserver(state, ledger, fs, "open", "FS_OPEN");
    if (descriptorOwner(fs, "openSync")) installOpenObserver(state, ledger, fs, "openSync", "FS_OPENSYNC");
    if (descriptorOwner(fsPromises, "open")) installOpenObserver(state, ledger, fsPromises, "open", "FS_PROMISES_OPEN");
    if (descriptorOwner(v8, "writeHeapSnapshot")) installFunction(ledger, state, v8, "writeHeapSnapshot", "V8_WRITE_HEAP_SNAPSHOT");
    if (process.report && descriptorOwner(process.report, "writeReport")) installFunction(ledger, state, process.report, "writeReport", "PROCESS_REPORT");

    for (const key of [
      "createHash", "createHmac", "createCipheriv", "createDecipheriv", "createSign", "createVerify",
      "generateKey", "generateKeyPair", "generateKeyPairSync", "randomBytes", "randomFill", "randomFillSync",
      "pbkdf2", "pbkdf2Sync", "scrypt", "scryptSync", "hkdf", "hkdfSync",
    ]) {
      if (descriptorOwner(crypto, key)) installPassthroughObserver(state, ledger, crypto, key, `CRYPTO_${key.toUpperCase()}`);
    }
    const subtle = crypto.webcrypto?.subtle;
    if (subtle) {
      for (const key of ["digest", "deriveKey", "deriveBits", "encrypt", "decrypt", "sign", "generateKey"]) {
        if (descriptorOwner(Object.getPrototypeOf(subtle), key)) installPassthroughObserver(state, ledger, Object.getPrototypeOf(subtle), key, `WEBCRYPTO_${key.toUpperCase()}`);
      }
    }
    installEnvProxy(ledger, state);
    installProcessListeners(ledger, state);
    installDiagnosticsChannel(ledger, state, diagnosticsChannel);
    installJsonObserver(state, ledger);
    installWeakMapObserver(ledger, state, function ObservedPool() {});
  } catch (error) {
    try {
      ledger.restore();
    } catch {
      // The boundary below reports only the fixed install code.
    }
    if (error instanceof HarnessFailure) throw error;
    fail(SAFE.install, "INSTALL_LEDGER");
  }
  return { ledger, require };
}

function isAuthorityRecord(key, record, ObservedPool) {
  if (!record || typeof record !== "object" || typeof key !== "object") return false;
  const names = Object.keys(record);
  if (names.length !== AUTHORITY_KEYS.length || !AUTHORITY_KEYS.every((name) => names.includes(name))) return false;
  if (Object.getOwnPropertySymbols(record).length !== 0 || record.authority !== key || !(record.pool instanceof ObservedPool)) return false;
  if (record.valid !== true || record.phase !== "initialization" || typeof record.brand !== "symbol") return false;
  for (const name of AUTHORITY_KEYS) {
    const descriptor = Object.getOwnPropertyDescriptor(record, name);
    if (!descriptor || descriptor.get || descriptor.set) return false;
  }
  return true;
}

function installPoolSeam(state, ledger, pg) {
  const originalPool = pg.Pool;
  if (typeof originalPool !== "function") fail(SAFE.install, "INSTALL_LEDGER");
  class ObservedPool extends originalPool {
    constructor(options) {
      super(options);
      this.__sscInputOptions = options;
      if (state.active && state.current) {
        state.current.poolCount += 1;
        state.current.pools.push(this);
        state.current.events.push("POOL_CONSTRUCTOR");
      }
    }

    async query(text, values) {
      return executeQuery(state, this, text, values);
    }

    async connect() {
      if (!state.active || !state.current) throw new Error("SSC_BLOCKED");
      if (state.current.pools[0] && state.current.pools[0] !== this) state.current.bindingMismatch = true;
      state.current.connectCount += 1;
      const pool = this;
      return {
        async query(text, values) {
          return executeQuery(state, pool, text, values);
        },
        release() {
          state.current.releaseCount += 1;
        },
      };
    }

    async end() {
      if (!state.active || !state.current) return undefined;
      state.current.endCount += 1;
      state.current.events.push("POOL_END");
      if (state.current.scenario.rejectCleanup) {
        state.current.cleanupWasAsyncPromise = true;
        throw state.current.cleanupError;
      }
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
    installFunction(ledger, state, found.owner, key, `POOL_FALLBACK_${key.toUpperCase()}`);
  }
  state.selfTest = true;
  const canary = new ObservedPool({ host: "127.0.0.1", port: 1, user: "canary", database: "canary", max: 1 });
  void canary.end();
  state.selfTest = false;
  if (pg.Pool !== ObservedPool) fail(SAFE.install, "INSTALL_LEDGER");
  return ObservedPool;
}

function queryText(text) {
  if (typeof text === "string") return text;
  if (text && typeof text === "object" && typeof text.text === "string") return text.text;
  return "";
}

function executeQuery(state, pool, text, values) {
  if (!state.active || !state.current) throw new Error("SSC_BLOCKED");
  const current = state.current;
  if (current.pools[0] && current.pools[0] !== pool) current.bindingMismatch = true;
  const query = queryText(text);
  void values;
  if (query.includes("current_database()")) {
    current.identityCalls += 1;
    current.events.push(current.identityCalls === 1 ? "IDENTITY_1" : "IDENTITY_2");
    const rejected = current.scenario.rejectSecondIdentity && current.identityCalls === 2;
    return Promise.resolve({
      rows: [{
        database_matches: !rejected,
        user_matches: true,
        postgres17: true,
        non_recovery: true,
        catalog_fingerprint: "100",
        lifecycle_fingerprint: rejected ? "201" : "200",
      }],
    });
  }
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
    authorityValidAtCapture: false,
    poolCount: 0,
    pools: [],
    identityCalls: 0,
    migrationQueries: 0,
    operationCalls: 0,
    endCount: 0,
    connectCount: 0,
    releaseCount: 0,
    bindingMismatch: false,
    cleanupWasAsyncPromise: false,
    events: [],
  };
}

function containsMarker(value, markers) {
  if (typeof value !== "string") return false;
  return value.includes(markers.connection) || value.includes(markers.cleanup) ||
    value.includes(markers.operation) || value.includes(markers.canary);
}

function inspectSurface(valueToInspect, state) {
  let leak = false;
  let invalid = false;
  let visited = new Set();
  const walk = (current, depth) => {
    if (leak || invalid) return;
    if (containsMarker(current, state.markers)) {
      leak = true;
      return;
    }
    if (!current || typeof current !== "object" || depth > 6) return;
    if (visited.has(current)) return;
    visited.add(current);
    if (visited.size > 256) {
      invalid = true;
      return;
    }
    if (current instanceof Error) {
      for (const field of ["name", "message", "stack"]) {
        if (containsMarker(current[field], state.markers)) {
          leak = true;
          return;
        }
      }
    }
    for (const key of Reflect.ownKeys(current)) {
      if (containsMarker(typeof key === "symbol" ? key.description ?? "" : key, state.markers)) {
        leak = true;
        return;
      }
      const descriptor = Object.getOwnPropertyDescriptor(current, key);
      if (current instanceof Error && key === "stack" && descriptor?.get && descriptor?.set) continue;
      if (!descriptor || descriptor.get || descriptor.set) {
        invalid = true;
        return;
      }
      walk(descriptor.value, depth + 1);
    }
  };
  walk(valueToInspect, 0);
  let jsonLeak = false;
  let inspectLeak = false;
  if (!invalid && valueToInspect !== undefined) {
    try {
      jsonLeak = containsMarker(state.originalStringify(valueToInspect), state.markers);
    } catch {
      invalid = true;
    }
    try {
      inspectLeak = containsMarker(state.originalInspect(valueToInspect, { showHidden: true, showProxy: true, depth: 6 }), state.markers);
    } catch {
      invalid = true;
    }
  }
  return Object.freeze({ safe: !leak && !jsonLeak && !inspectLeak && !invalid, leak, jsonLeak, inspectLeak, invalid });
}

function authorityMetadataSafe(record, state) {
  if (!record) return false;
  const metadata = {};
  for (const key of AUTHORITY_KEYS) {
    if (key !== "pool") metadata[key] = record[key];
  }
  return inspectSurface(metadata, state).safe;
}

function publicSuccess(result) {
  return Boolean(result && typeof result === "object" && Object.keys(result).length === 1 && result.ok === true);
}

function publicFailure(error, state) {
  if (!error || typeof error !== "object") return false;
  if (error.name !== "DisposablePostgresFixtureAdmissionError" ||
      error.message !== "Disposable fixture admission failed." ||
      error.code !== "disposable_fixture_admission_failed" ||
      Object.prototype.hasOwnProperty.call(error, "cause")) return false;
  const surface = inspectSurface(error, state);
  return surface.safe && Object.keys(error).every((key) => key === "name" || key === "code");
}

function eventIndex(events, name) {
  return events.indexOf(name);
}

function scenarioChecks(current, result, error, state) {
  const scenario = current.scenario;
  const pool = current.pools[0];
  const options = pool?.options ?? {};
  const optionKeys = Object.keys(options);
  const poolBinding = Boolean(
    pool &&
    current.poolCount === 1 &&
    current.authorityCaptureCount === 1 &&
    state.authorityPool === pool &&
    optionKeys.includes("host") &&
    optionKeys.includes("port") &&
    optionKeys.includes("user") &&
    optionKeys.includes("database") &&
    optionKeys.includes("max") &&
    Object.prototype.hasOwnProperty.call(options, "password") &&
    !Object.prototype.hasOwnProperty.call(options, "connectionString"),
    options.password === state.markers.connection,
    !current.bindingMismatch,
  );
  const firstIdentity = eventIndex(current.events, "IDENTITY_1");
  const authoritySet = eventIndex(current.events, "AUTHORITY_SET");
  const secondIdentity = eventIndex(current.events, "IDENTITY_2");
  const migration = eventIndex(current.events, "MIGRATION");
  const operation = eventIndex(current.events, "OPERATION");
  const ordering = firstIdentity >= 0 && authoritySet > firstIdentity && secondIdentity > authoritySet &&
    (scenario.rejectSecondIdentity ? migration < 0 && operation < 0 : migration > secondIdentity && operation > migration);
  const expectedPublic = scenario.rejectOperation || scenario.rejectSecondIdentity
    ? publicFailure(error, state)
    : publicSuccess(result);
  const cleanupSuppressed = scenario.rejectCleanup
    ? (scenario.rejectOperation || scenario.rejectSecondIdentity ? expectedPublic : publicSuccess(result))
    : true;
  const cleanupWasAsyncPromise = scenario.rejectCleanup ? current.cleanupWasAsyncPromise : true;
  const metadataSafe = authorityMetadataSafe(state.authorityRecord, state);
  const surface = inspectSurface(scenario.rejectOperation || scenario.rejectSecondIdentity ? error : result, state);
  const noRuntimeEffects = [...state.runtimeEvents.values()].every((count) => count === 0);
  const authorityRevoked = Boolean(state.authorityRecord && state.authorityRecord.valid === false);
  const operationCount = scenario.rejectSecondIdentity ? current.operationCalls === 0 : current.operationCalls === 1;
  const migrationCount = scenario.rejectSecondIdentity ? current.migrationQueries === 0 : current.migrationQueries > 0;
  const cleanupCount = current.endCount === 1;
  const successOrFailure = scenario.rejectOperation || scenario.rejectSecondIdentity
    ? error && !result
    : result && !error;
  const pass = poolBinding && ordering && expectedPublic && cleanupSuppressed && surface.safe &&
    noRuntimeEffects && authorityRevoked && metadataSafe && cleanupWasAsyncPromise && current.authorityValidAtCapture && operationCount &&
    migrationCount && cleanupCount && successOrFailure;
  return Object.freeze({
    id: scenario.id,
    pass,
    code: pass ? SAFE.pass : SAFE.scenario,
    poolCount: current.poolCount,
    identityCalls: current.identityCalls,
    migrationQueries: current.migrationQueries,
    operationCalls: current.operationCalls,
    cleanupCalls: current.endCount,
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
  current.resourceBefore = activeResources();
  state.current = current;
  state.authorityRecord = null;
  state.authorityPool = null;
  state.runtimeEvents.clear();
  state.active = true;
  const input = {
    connectionString: "postgres://cloud_admin@127.0.0.1:1/runtime_posture_test",
    connectionPassword: state.markers.connection,
    expectedDatabase: "runtime_posture_test",
    expectedUser: "cloud_admin",
    migrationsFolder: MIGRATIONS_FOLDER,
    phase: "initialization",
  };
  let result;
  let error;
  try {
    const subject = await import(`${state.subjectUrl}?ssc=${scenario.id}-${state.scenarioSerial++}`);
    const operation = async () => {
      current.operationCalls += 1;
      current.events.push("OPERATION");
      if (scenario.rejectOperation) throw makeDiagnosticError(state.markers, "operation");
      return { ok: true };
    };
    try {
      result = await subject.withDisposablePostgresFixtureMigration(input, operation);
    } catch (caught) {
      error = caught;
    }
  } catch {
    error = new Error("SSC_SUBJECT_IMPORT");
  }
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

function runBehavioralControls(state) {
  const markers = state.markers;
  const causeError = new Error("safe");
  causeError.cause = new Error(markers.connection);
  const descriptorError = new Error("safe");
  Object.defineProperty(descriptorError, "diagnostic", {
    configurable: true,
    enumerable: false,
    value: markers.cleanup,
    writable: true,
  });
  const controls = [];
  const causeSurface = inspectSurface(causeError, state);
  controls.push(Object.freeze({
    id: "NC11_PUBLIC_CAUSE",
    code: causeSurface.safe ? "SSC_NEGATIVE_CONTROL_INACTIVE" : SAFE.surface,
    detector: causeSurface.safe ? "CONTROL_INACTIVE" : "PUBLIC_CAUSE",
    pass: !causeSurface.safe && (causeSurface.leak || causeSurface.jsonLeak || causeSurface.inspectLeak),
  }));
  const descriptorSurface = inspectSurface(descriptorError, state);
  controls.push(Object.freeze({
    id: "NC12_PUBLIC_NONENUM",
    code: descriptorSurface.safe ? "SSC_NEGATIVE_CONTROL_INACTIVE" : SAFE.surface,
    detector: descriptorSurface.safe ? "CONTROL_INACTIVE" : "PUBLIC_DESCRIPTOR",
    pass: !descriptorSurface.safe && (descriptorSurface.leak || descriptorSurface.jsonLeak || descriptorSurface.inspectLeak),
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
  return Object.freeze({
    count: controls.length,
    ids: Object.freeze(controls.map((control) => control.id)),
    results: Object.freeze(controls),
  });
}

export async function runSecretSurfaceBehavioralHarness() {
  const state = newRunState();
  let ledger = null;
  const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(moduleDirectory, "../..");
  const subjectPath = path.resolve(repoRoot, SUBJECT_RELATIVE);
  try {
    const source = await readFile(subjectPath, "utf8");
    if (!source.includes("withDisposablePostgresFixtureMigration")) fail(SAFE.internal, "SUBJECT_IDENTITY");
    const installed = installObservers(state);
    ledger = installed.ledger;
    const pg = installed.require("pg");
    const ObservedPool = installPoolSeam(state, installed.ledger, pg);
    state.observedPool = ObservedPool;
    installWeakMapObserver(installed.ledger, state, ObservedPool);
    state.subjectUrl = pathToFileURL(subjectPath).href;
    const observerControls = runBehavioralControls(state);
    const scenarioResults = [];
    for (const scenario of SCENARIOS) {
      const result = await runScenario(state, scenario);
      scenarioResults.push(Object.freeze(result));
    }
    return Object.freeze({
      scenarioCount: scenarioResults.length,
      scenarioIds: Object.freeze(scenarioResults.map((result) => result.id)),
      scenarios: Object.freeze(scenarioResults),
      controls: observerControls,
      allScenariosPass: scenarioResults.every((result) => result.pass && result.resourcesStable),
      allControlsPass: observerControls.results.every((result) => result.pass),
    });
  } catch (error) {
    try {
      state.active = false;
    } catch {
      // Fixed boundary result only.
    }
    return Object.freeze({
      scenarioCount: SCENARIOS.length,
      scenarioIds: Object.freeze(SCENARIOS.map((scenario) => scenario.id)),
      scenarios: Object.freeze(SCENARIOS.map((scenario) => Object.freeze({
        id: scenario.id,
        pass: false,
        code: error instanceof HarnessFailure ? error.code : SAFE.internal,
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
          code: error instanceof HarnessFailure ? error.code : SAFE.internal,
          detector: error instanceof HarnessFailure ? error.detector : "BOUNDARY",
          pass: false,
        }))),
      }),
      allScenariosPass: false,
      allControlsPass: false,
    });
  } finally {
    state.active = false;
    if (ledger) {
      try {
        ledger.restore();
      } catch {
        // The fixed failure result is selected before any raw restore error can escape.
      }
    }
  }
}

export const behavioralSecretSurfaceScenarioIds = Object.freeze(SCENARIOS.map((scenario) => scenario.id));
export const behavioralSecretSurfaceControlIds = Object.freeze(BEHAVIORAL_CONTROLS.map((control) => control.id));

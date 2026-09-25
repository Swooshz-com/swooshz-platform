import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { Client, Pool } from "pg";

import {
  inspectRuntimeDatabaseRoleAuthorityPosture,
} from "../../dist/db/runtime-posture.js";

const phases = new Set(["initialization", "final_start"]);
const safeIdentifier = /^[a-z_][a-z0-9_$]{0,62}$/u;
const loopbackHosts = new Set(["127.0.0.1", "::1"]);
const validPort = (value) =>
  /^\d{1,5}$/u.test(value) && Number(value) >= 1 && Number(value) <= 65535;

// These brands never leave this module. Tokens are empty frozen objects and
// their authority data is available only through these WeakMaps.
const constructionAggregateBrand = Symbol("construction-aggregate");
const provisioningTargetBrand = Symbol("provisioning-target");
const databaseCreationTargetBrand = Symbol("database-creation-target");
const configuredAggregateBrand = Symbol("configured-aggregate");
const configuredTargetBrand = Symbol("configured-target");
const mutationTargetBrand = Symbol("mutation-target");
const migrationAuthorityBrand = Symbol("migration-authority");
const managedTransportValues = new WeakMap();
const parsedUrlValues = new WeakMap();
const constructionAggregateValues = new WeakMap();
const provisioningTargetValues = new WeakMap();
const databaseCreationTargetValues = new WeakMap();
const configuredAggregateValues = new WeakMap();
const configuredTargetValues = new WeakMap();
const mutationTargetValues = new WeakMap();
const migrationAuthorityValues = new WeakMap();
const disposablePostgresReceiptOperationKeys = new WeakMap();
const disposablePostgresReceipts = new WeakMap();
const completedDisposablePostgresReceiptOperations = new WeakMap();
let activeDisposablePostgresReceiptInvocation = null;

function installDisposablePostgresAuthoritySetReceipt() {
  Object.defineProperty(migrationAuthorityValues, "set", {
    configurable: true,
    value(authority, authorityRecord) {
      const invocation = activeDisposablePostgresReceiptInvocation;
      if (this === migrationAuthorityValues && invocation?.active && !invocation.authorityRevoked &&
          authorityRecord?.authority === authority && authorityRecord?.brand === migrationAuthorityBrand) {
        issueDisposablePostgresReceipt(
          invocation.invocationKey,
          authority,
          authorityRecord,
          "authority",
          "migration-authority-allocation",
        );
      }
      return WeakMap.prototype.set.call(this, authority, authorityRecord);
    },
  });
}
export function beginDisposablePostgresReceiptInvocation(operation) {
  if (typeof operation !== "function" ||
      completedDisposablePostgresReceiptOperations.get(operation) === true ||
      activeDisposablePostgresReceiptInvocation !== null) return false;
  const invocationKey = Object.freeze(Object.create(null));
  const invocation = {
    operation,
    invocationKey,
    active: true,
    authorityRevoked: false,
    identities: new Set(),
  };
  disposablePostgresReceiptOperationKeys.set(operation, invocationKey);
  try {
    installDisposablePostgresAuthoritySetReceipt();
  } catch {
    disposablePostgresReceiptOperationKeys.delete(operation);
    return false;
  }
  activeDisposablePostgresReceiptInvocation = invocation;
  return true;
}

function issueDisposablePostgresReceipt(
  invocationKey,
  identity,
  identityRecord,
  kind,
  allocationSite,
) {
  const invocation = activeDisposablePostgresReceiptInvocation;
  if (!invocation || !invocation.active ||
      invocation.authorityRevoked ||
      invocation.invocationKey !== invocationKey ||
      !["authority", "fresh-error"].includes(kind) ||
      (kind === "authority" && allocationSite !== "migration-authority-allocation") ||
      (kind === "fresh-error" && allocationSite !== "replacement-admission-error-allocation") ||
      (typeof identity !== "object" && typeof identity !== "function") ||
      identity === null ||
      disposablePostgresReceipts.has(identity)) return undefined;
  const receipt = {
    invocation,
    invocationKey,
    identityRecord,
    kind,
    allocationSite,
  };
  disposablePostgresReceipts.set(identity, receipt);
  invocation.identities.add(identity);
  return undefined;
}

function invalidateDisposablePostgresReceiptInvocation(invocationKey) {
  const invocation = activeDisposablePostgresReceiptInvocation;
  if (!invocation || !invocation.active ||
      invocation.invocationKey !== invocationKey) return undefined;
  invocation.authorityRevoked = true;
  for (const identity of invocation.identities) {
    const receipt = disposablePostgresReceipts.get(identity);
    if (receipt?.invocation === invocation && receipt.kind === "authority") {
      disposablePostgresReceipts.delete(identity);
      invocation.identities.delete(identity);
    }
  }
  return undefined;
}

export function consumeDisposablePostgresAuthorityReceipt(
  operation,
  authorityToken,
  authorityRecord,
) {
  return consumeDisposablePostgresReceipt(
    "authority",
    operation,
    authorityToken,
    authorityRecord,
  );
}

export function consumeDisposablePostgresFreshErrorReceipt(operation, error) {
  return consumeDisposablePostgresReceipt("fresh-error", operation, error, error);
}

function consumeDisposablePostgresReceipt(kind, operation, identity, identityRecord) {
  if ((typeof identity !== "object" && typeof identity !== "function") || identity === null) {
    return false;
  }
  const receipt = disposablePostgresReceipts.get(identity);
  if (!receipt) return false;
  disposablePostgresReceipts.delete(identity);
  receipt.invocation.identities.delete(identity);
  const invocation = activeDisposablePostgresReceiptInvocation;
  if (!invocation || !invocation.active ||
      receipt.invocation !== invocation ||
      invocation.operation !== operation ||
      invocation.invocationKey !== receipt.invocationKey ||
      disposablePostgresReceiptOperationKeys.get(operation) !== receipt.invocationKey ||
      receipt.kind !== kind ||
      receipt.identityRecord !== identityRecord) return false;
  if (kind === "authority" && invocation.authorityRevoked) return false;
  return true;
}

export function finishDisposablePostgresReceiptInvocation(operation) {
  const invocationKey = disposablePostgresReceiptOperationKeys.get(operation);
  const invocation = activeDisposablePostgresReceiptInvocation;
  if (!invocationKey) return;
  if (invocation?.operation === operation &&
      invocation.invocationKey === invocationKey) {
    invocation.active = false;
    for (const identity of invocation.identities) {
      disposablePostgresReceipts.delete(identity);
    }
    invocation.identities.clear();
    if (activeDisposablePostgresReceiptInvocation === invocation) {
      activeDisposablePostgresReceiptInvocation = null;
      delete migrationAuthorityValues.set;
    }
  }
  disposablePostgresReceiptOperationKeys.delete(operation);
  completedDisposablePostgresReceiptOperations.set(operation, true);
}

const mutationKeyword =
  /\b(?:grant|revoke|alter|create|drop|truncate|insert|update|delete|merge|copy|vacuum|refresh)\b/iu;
const sessionMutationKeyword =
  /\bset\s+(?:role|session\s+authorization|session_replication_role)\b/iu;

const identitySql = `
  select
    current_database() = $1 as database_matches,
    session_user = $2 as user_matches,
    current_setting('server_version_num')::integer / 10000 = 17
      as postgres17,
    not pg_is_in_recovery() as non_recovery,
    (select system_identifier::text from pg_control_system())
      as catalog_fingerprint,
    (select oid::text from pg_database where datname = current_database())
      as lifecycle_fingerprint
`;

const creationIdentitySql = `
  select
    current_database() = $1 as database_matches,
    session_user = $2 as user_matches,
    current_setting('server_version_num')::integer / 10000 = 17
      as postgres17,
    not pg_is_in_recovery() as non_recovery,
    (select system_identifier::text from pg_control_system())
      as catalog_fingerprint,
    coalesce(
      (select oid::text from pg_database where datname = $3),
      'absent:' || $3
    ) as lifecycle_fingerprint,
    not exists (
      select 1 from pg_database where datname = $3
    ) as target_database_absent
`;

const transactionControlKeyword =
  /\b(?:begin|start\s+transaction|commit|rollback|savepoint|release\s+savepoint|rollback\s+to(?:\s+savepoint)?|prepare\s+transaction|discard)\b/iu;
const sessionAuthorityKeyword =
  /\b(?:set|reset|load)\b|set_config\s*\(/iu;
const admissionTargets = new Set(["PRIMARY", "SECONDARY"]);
const admissionStages = new Set([
  "CONNECT",
  "BINDING",
  "READONLY",
  "IDENTITY",
  "POSTURE",
  "OWNERSHIP",
  "EXPECTED_OBJECTS",
]);

class DisposablePostgresFixtureAdmissionStageError extends Error {
  constructor(stage) {
    super();
    this.stage = stage;
  }
}

export class DisposablePostgresFixtureAdmissionError extends Error {
  constructor({ target, stage } = {}) {
    super("Disposable fixture admission failed.");
    this.name = "DisposablePostgresFixtureAdmissionError";
    this.code = "disposable_fixture_admission_failed";
    if (admissionTargets.has(target) && admissionStages.has(stage)) {
      this.target = target;
      this.stage = stage;
    }
  }
}

export async function withDisposablePostgresFixtureMigration(
  input,
  operation,
) {
  if (typeof operation !== "function") {
    throw new DisposablePostgresFixtureAdmissionError();
  }
  let authority;
  let pool;
  try {
    const connectionPassword = readMigrationConnectionPassword(input);
    const target = normalizeMigrationTarget(input);
    const poolOptions = {
      host: target.hostname,
      port: Number(target.port),
      user: target.expectedUser,
      database: target.expectedDatabase,
      max: 1,
    };
    if (connectionPassword !== undefined) {
      poolOptions.password = connectionPassword;
    }
    pool = new Pool(poolOptions);
    const identity = await readMigrationAuthorityIdentity(pool, target);
    authority = Object.freeze({});
    migrationAuthorityValues.set(authority, {
      authority,
      brand: migrationAuthorityBrand,
      database: target.expectedDatabase,
      user: target.expectedUser,
      clusterFingerprint: identity.catalogFingerprint,
      lifecycleFingerprint: identity.lifecycleFingerprint,
      migrationsFolder: target.migrationsFolder,
      phase: target.phase,
      pool,
      valid: true,
    });
    await runScopedFixtureMigration(authority, pool, target.migrationsFolder, target);
    return await operation();
  } catch (error) {
    if (error instanceof DisposablePostgresFixtureAdmissionError) throw error;
    const freshError = new DisposablePostgresFixtureAdmissionError();
    issueDisposablePostgresReceipt(
      disposablePostgresReceiptOperationKeys.get(operation),
      freshError,
      freshError,
      "fresh-error",
      "replacement-admission-error-allocation",
    );
    throw freshError;
  } finally {
    if (authority) {
      const value = migrationAuthorityValues.get(authority);
      if (value) {
        value.valid = false;
        const invocationKey = disposablePostgresReceiptOperationKeys.get(operation);
        if (invocationKey) invalidateDisposablePostgresReceiptInvocation(invocationKey);
      }
    }
    if (pool) await pool.end().catch(() => {});
  }
}

function normalizeMigrationTarget(input) {
  if (!input || typeof input !== "object") throw new Error();
  const allowedKeys = new Set([
    "connectionString",
    "connectionPassword",
    "expectedDatabase",
    "expectedUser",
    "migrationsFolder",
    "phase",
  ]);
  if (Object.keys(input).some((key) => !allowedKeys.has(key))) throw new Error();
  const expectedDatabase = input.expectedDatabase;
  const expectedUser = input.expectedUser ?? "cloud_admin";
  const phase = input.phase ?? "initialization";
  if (
    typeof input.connectionString !== "string" ||
    typeof input.migrationsFolder !== "string" ||
    input.migrationsFolder.length === 0 ||
    phase !== "initialization" ||
    !safeIdentifier.test(expectedDatabase) ||
    !safeIdentifier.test(expectedUser)
  ) throw new Error();

  let parsed;
  try {
    parsed = new URL(input.connectionString);
  } catch {
    throw new Error();
  }
  const hostname = parsed.hostname.replace(/^\[|\]$/gu, "").toLowerCase();
  const port = parsed.port;
  const username = decodeURIComponent(parsed.username);
  const database = decodeURIComponent(parsed.pathname.slice(1));
  if (
    !["postgres:", "postgresql:"].includes(parsed.protocol) ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    !loopbackHosts.has(hostname) ||
    !port ||
    !validPort(port) ||
    username !== expectedUser ||
    database !== expectedDatabase ||
    parsed.pathname !== `/${database}` ||
    !safeIdentifier.test(database)
  ) throw new Error();
  return Object.freeze({
    connectionString: input.connectionString,
    expectedDatabase,
    expectedUser,
    migrationsFolder: input.migrationsFolder,
    phase,
    hostname,
    port,
  });
}

function readMigrationConnectionPassword(input) {
  if (!input || typeof input !== "object") throw new Error();
  const password = input.connectionPassword;
  if (
    password !== undefined &&
    (typeof password !== "string" || password.trim().length === 0)
  ) {
    throw new Error();
  }
  return password;
}

async function readMigrationAuthorityIdentity(pool, target) {
  const result = await pool.query(identitySql, [target.expectedDatabase, target.expectedUser]);
  const row = result?.rows?.[0];
  if (
    result?.rows?.length !== 1 ||
    row?.database_matches !== true ||
    row?.user_matches !== true ||
    row?.postgres17 !== true ||
    row?.non_recovery !== true ||
    typeof row.catalog_fingerprint !== "string" ||
    !/^\d+$/u.test(row.catalog_fingerprint) ||
    typeof row.lifecycle_fingerprint !== "string" ||
    !/^\d+$/u.test(row.lifecycle_fingerprint)
  ) throw new Error();
  return Object.freeze({
    catalogFingerprint: row.catalog_fingerprint,
    lifecycleFingerprint: row.lifecycle_fingerprint,
  });
}

async function runScopedFixtureMigration(authority, pool, migrationsFolder, target) {
  const value = migrationAuthorityValues.get(authority);
  if (
    !value ||
    value.brand !== migrationAuthorityBrand ||
    value.authority !== authority ||
    !value.valid ||
    value.pool !== pool ||
    value.migrationsFolder !== migrationsFolder ||
    value.database !== target.expectedDatabase ||
    value.user !== target.expectedUser
  ) throw new Error();
  const identity = await readMigrationAuthorityIdentity(pool, target);
  if (
    identity.catalogFingerprint !== value.clusterFingerprint ||
    identity.lifecycleFingerprint !== value.lifecycleFingerprint
  ) throw new Error();
  await migrate(drizzle(pool), { migrationsFolder });
}

export function parseDisposablePostgresUrl(
  connectionString,
  {
    expectedDatabase,
    expectedUser,
    phase,
    transport,
  } = {},
) {
  try {
    if (
      typeof connectionString !== "string" ||
      !safeIdentifier.test(expectedDatabase) ||
      !safeIdentifier.test(expectedUser) ||
      !phases.has(phase) ||
      !transport ||
      typeof transport !== "object"
    ) {
      throw new Error();
    }

    const parsed = new URL(connectionString);
    if (
      !["postgres:", "postgresql:"].includes(parsed.protocol) ||
      parsed.password ||
      parsed.hash ||
      parsed.search
    ) {
      throw new Error();
    }

    const username = decodeURIComponent(parsed.username);
    const database = decodeURIComponent(parsed.pathname.slice(1));
    const hostname = parsed.hostname.replace(/^\[|\]$/gu, "").toLowerCase();
    const port = parsed.port || "5432";
    if (
      username !== expectedUser ||
      database !== expectedDatabase ||
      !validPort(port) ||
      !hostname ||
      hostname === "localhost" ||
      !safeIdentifier.test(database) ||
      parsed.pathname !== `/${database}`
    ) {
      throw new Error();
    }

    const transportKind = transport.kind;
    if (transport.phase !== phase) {
      throw new Error();
    }

    let transportIdentity;
    if (transportKind === "loopback") {
      if (!loopbackHosts.has(hostname)) {
        throw new Error();
      }
      transportIdentity = `loopback:${hostname}:${port}`;
    } else if (transportKind === "managed-container") {
      const value = managedTransportValues.get(transport.attestation);
      if (
        !value ||
        value.phase !== phase ||
        value.image !== "postgres:17" ||
        value.alias !== hostname
      ) {
        throw new Error();
      }
      transportIdentity = `managed-container:${value.alias}:${port}:${value.image}`;
    } else {
      throw new Error();
    }

    const token = Object.freeze({});
    parsedUrlValues.set(
      token,
      Object.freeze({
        database,
        hostname,
        phase,
        port,
        transportIdentity,
        transportKind,
        username,
      }),
    );
    return token;
  } catch {
    throw new DisposablePostgresFixtureAdmissionError();
  }
}

export async function admitDisposablePostgresConstructionTargets(
  targets,
  { readOnlyProbe, clientFactory } = {},
) {
  try {
    if (!Array.isArray(targets) || targets.length < 2) {
      throw new Error();
    }
    const names = new Set();
    const locatorIdentities = new Set();
    const normalizedTargets = [];
    for (const target of targets) {
      let normalized;
      try {
        normalized = normalizeConstructionTarget(target);
      } catch (error) {
        throw admissionErrorFor(
          error instanceof DisposablePostgresFixtureAdmissionStageError
            ? error
            : new DisposablePostgresFixtureAdmissionStageError("BINDING"),
          target?.name,
        );
      }
      if (names.has(normalized.name)) {
        throw new Error();
      }
      names.add(normalized.name);
      try {
        assertDistinctCanonicalTargetLocator(locatorIdentities, normalized);
      } catch {
        throw admissionErrorFor(
          new DisposablePostgresFixtureAdmissionStageError("BINDING"),
          normalized.name,
        );
      }
      normalizedTargets.push(normalized);
    }

    const admittedTargets = new Map();
    const physicalIdentities = new Set();
    for (const target of normalizedTargets) {
      const evidence = await probeTarget({
        target,
        readOnlyProbe: readOnlyProbe ?? defaultConstructionProbe,
        builtInProbe: !readOnlyProbe,
        clientFactory,
      });
      try {
        assertDistinctObservedPhysicalIdentity(physicalIdentities, evidence);
      } catch {
        throw admissionErrorFor(
          new DisposablePostgresFixtureAdmissionStageError("IDENTITY"),
          target.name,
        );
      }
      admittedTargets.set(
        target.name,
        Object.freeze({
          evidence,
          target,
        }),
      );
    }

    const aggregate = Object.freeze({});
    constructionAggregateValues.set(aggregate, {
      admittedTargets,
      brand: constructionAggregateBrand,
      phase: "initialization",
      creationAuthorities: new Set(),
      creationTargets: new Set(),
      createdTargets: new Map(),
      provisioningTargets: new Set(),
      provisioningAuthorities: new Set(),
      valid: true,
    });
    return aggregate;
  } catch (error) {
    if (error instanceof DisposablePostgresFixtureAdmissionError) {
      throw error;
    }
    throw new DisposablePostgresFixtureAdmissionError();
  }
}

export function deriveDisposablePostgresProvisioningAuthority(
  aggregate,
  targetName,
) {
  try {
    const value = requireConstructionAggregate(aggregate);
    if (
      typeof targetName !== "string" ||
      value.provisioningTargets.has(targetName)
    ) {
      throw new Error();
    }
    const target = value.admittedTargets.get(targetName);
    if (!target) {
      throw new Error();
    }
    value.provisioningTargets.add(targetName);
    const authority = Object.freeze({});
    provisioningTargetValues.set(authority, {
      authority,
      aggregate,
      boundConnections: new WeakSet(),
      brand: provisioningTargetBrand,
      consumed: false,
      catalogFingerprint: requireFingerprint(target.evidence.catalogFingerprint),
      lifecycleFingerprint: target.target.databaseMayBeAbsent
        ? null
        : requireFingerprint(target.evidence.lifecycleFingerprint),
      phase: "initialization",
      targetName,
      target,
      valid: true,
    });
    value.provisioningAuthorities.add(authority);
    return authority;
  } catch (error) {
    if (error instanceof DisposablePostgresFixtureAdmissionError) {
      throw error;
    }
    throw new DisposablePostgresFixtureAdmissionError();
  }
}

export function deriveDisposablePostgresDatabaseCreationAuthority(
  aggregate,
  targetName,
) {
  try {
    const value = requireConstructionAggregate(aggregate);
    if (
      typeof targetName !== "string" ||
      value.creationTargets.has(targetName)
    ) {
      throw new Error();
    }
    const target = value.admittedTargets.get(targetName);
    if (!target || !target.target.allowDatabaseCreation ||
        !target.target.creationBinding) {
      throw new Error();
    }
    value.creationTargets.add(targetName);
    const authority = Object.freeze({});
    databaseCreationTargetValues.set(authority, {
      aggregate,
      authority,
      boundConnections: new WeakSet(),
      boundPool: null,
      brand: databaseCreationTargetBrand,
      consumed: false,
      phase: "initialization",
      targetName,
      target,
      valid: true,
    });
    value.creationAuthorities.add(authority);
    return authority;
  } catch (error) {
    if (error instanceof DisposablePostgresFixtureAdmissionError) {
      throw error;
    }
    throw new DisposablePostgresFixtureAdmissionError();
  }
}

export function createAuthorizedDatabaseCreationPool(pool, authority) {
  try {
    const value = requireDatabaseCreationTarget(authority);
    if (
      value.consumed ||
      value.boundPool ||
      !pool ||
      typeof pool.connect !== "function"
    ) {
      throw new Error();
    }
    const bindingMatches = poolConnectionMatchesTarget(
      pool,
      value.target,
      "creation",
    );
    if (bindingMatches !== true) {
      if (bindingMatches === false) {
        throw admissionErrorFor(
          new DisposablePostgresFixtureAdmissionStageError("BINDING"),
          value.targetName,
        );
      }
      throw new Error();
    }
    value.consumed = true;
    value.boundPool = pool;
    const base = createAuthorizedPoolWrapper(
      pool,
      value.target,
      value,
      defaultCreationConnectionRevalidator,
      "creation",
    );
    return Object.freeze({
      async query(text, values = []) {
        assertDatabaseCreationQuery(text, values, value.target);
        const result = await base.query(text, values);
        if (/^\s*create\s+database\b/iu.test(text)) {
          const createdIdentity = await readCreatedDatabaseIdentity(
            pool,
            value.target,
          );
          const aggregate = constructionAggregateValues.get(value.aggregate);
          if (!aggregate?.valid) throw new Error();
          aggregate.createdTargets.set(
            value.targetName,
            Object.freeze(createdIdentity),
          );
          value.valid = false;
        }
        return result;
      },
      end(...args) {
        return pool.end(...args);
      },
    });
  } catch (error) {
    if (error instanceof DisposablePostgresFixtureAdmissionError) {
      throw error;
    }
    throw new DisposablePostgresFixtureAdmissionError();
  }
}

export function createAuthorizedProvisioningPool(pool, authority, options = {}) {
  try {
    const value = requireProvisioningTarget(authority);
    if (
      value.consumed ||
      value.boundPool ||
      !pool ||
      typeof pool.connect !== "function"
    ) {
      throw new Error();
    }
    const bindingMatches = poolConnectionMatchesTarget(pool, value.target);
    if (bindingMatches !== true) {
      if (bindingMatches === false) {
        throw admissionErrorFor(
          new DisposablePostgresFixtureAdmissionStageError("BINDING"),
          value.targetName,
        );
      }
      throw new Error();
    }
    value.consumed = true;
    value.boundPool = pool;
    value.valid = true;
    const revalidate = createMutationRevalidator(options, value);
    return createAuthorizedPoolWrapper(pool, value.target, value, revalidate);
  } catch (error) {
    if (error instanceof DisposablePostgresFixtureAdmissionError) {
      throw error;
    }
    throw new DisposablePostgresFixtureAdmissionError();
  }
}

export async function admitDisposablePostgresFixture(
  fixture,
  {
    readOnlyProbe,
    postureInspector = inspectRuntimeDatabaseRoleAuthorityPosture,
    clientFactory,
  } = {},
) {
  try {
    let normalized;
    try {
      normalized = normalizeFixture(fixture);
    } catch (error) {
      throw admissionErrorFor(
        error instanceof DisposablePostgresFixtureAdmissionStageError
          ? error
          : new DisposablePostgresFixtureAdmissionStageError("BINDING"),
        fixture?.name,
      );
    }
    const evidence = await probeTarget({
      target: normalized,
      readOnlyProbe: readOnlyProbe ?? ((args) =>
        defaultConfiguredProbe({ ...args, postureInspector })),
      builtInProbe: !readOnlyProbe,
      clientFactory,
    });
    const token = Object.freeze({});
    configuredTargetValues.set(token, {
      brand: configuredTargetBrand,
      evidence,
      phase: normalized.phase,
      target: normalized,
    });
    return token;
  } catch (error) {
    if (error instanceof DisposablePostgresFixtureAdmissionError) {
      throw error;
    }
    throw new DisposablePostgresFixtureAdmissionError();
  }
}

export async function admitDisposablePostgresFixtures(
  fixtures,
  options = {},
) {
  try {
    if (!Array.isArray(fixtures) || fixtures.length < 2) {
      throw new Error();
    }
    const names = new Set();
    const locatorIdentities = new Set();
    const physicalIdentities = new Set();
    const targets = new Map();
    const normalizedFixtures = [];
    let phase;
    for (const fixture of fixtures) {
      let normalized;
      try {
        normalized = normalizeFixture(fixture);
      } catch (error) {
        throw admissionErrorFor(
          error instanceof DisposablePostgresFixtureAdmissionStageError
            ? error
            : new DisposablePostgresFixtureAdmissionStageError("BINDING"),
          fixture?.name,
        );
      }
      if (names.has(normalized.name)) {
        throw new Error();
      }
      names.add(normalized.name);
      try {
        assertDistinctCanonicalTargetLocator(locatorIdentities, normalized);
        if (phase && normalized.phase !== phase) {
          throw new Error();
        }
      } catch {
        throw admissionErrorFor(
          new DisposablePostgresFixtureAdmissionStageError("BINDING"),
          normalized.name,
        );
      }
      phase ??= normalized.phase;
      normalizedFixtures.push(normalized);
    }
    for (const normalized of normalizedFixtures) {
      const evidence = await probeTarget({
        target: normalized,
        readOnlyProbe: options.readOnlyProbe ?? ((args) =>
          defaultConfiguredProbe({
            ...args,
            postureInspector: options.postureInspector ??
              inspectRuntimeDatabaseRoleAuthorityPosture,
          })),
        builtInProbe: !options.readOnlyProbe,
        clientFactory: options.clientFactory,
      });
      try {
        assertDistinctObservedPhysicalIdentity(physicalIdentities, evidence);
      } catch {
        throw new DisposablePostgresFixtureAdmissionError({
          target: normalized.name.toUpperCase(),
          stage: "IDENTITY",
        });
      }
      targets.set(
        normalized.name,
        Object.freeze({ evidence, target: normalized }),
      );
    }

    const aggregate = Object.freeze({});
    configuredAggregateValues.set(aggregate, {
      brand: configuredAggregateBrand,
      phase,
      targetNames: Object.freeze([...names]),
      targets,
      valid: true,
      mutationPools: new Map(),
    });
    return aggregate;
  } catch (error) {
    if (error instanceof DisposablePostgresFixtureAdmissionError) {
      throw error;
    }
    throw new DisposablePostgresFixtureAdmissionError();
  }
}

export async function withDisposablePostgresFixturesAdmitted(
  fixtures,
  mutation,
  options = {},
) {
  try {
    if (typeof mutation !== "function") {
      throw new Error();
    }
    const admission = await admitDisposablePostgresFixtures(fixtures, options);
    try {
      return await mutation(admission);
    } finally {
      invalidateDisposablePostgresAdmission(admission);
    }
  } catch (error) {
    if (error instanceof DisposablePostgresFixtureAdmissionError) {
      throw error;
    }
    throw error;
  }
}

export function requireDisposablePostgresAdmission(token) {
  requireConfiguredAggregate(token);
}

export function deriveDisposablePostgresTargetAuthority(
  admission,
  targetName,
  pool,
  options = {},
) {
  try {
    const value = requireConfiguredAggregate(admission);
    if (
      typeof targetName !== "string" ||
      !pool ||
      typeof pool.connect !== "function" ||
      value.mutationPools.has(pool)
    ) {
      throw new Error();
    }
    const target = value.targets.get(targetName);
    if (!target) {
      throw new Error();
    }
    const bindingMatches = poolConnectionMatchesTarget(pool, target);
    if (bindingMatches !== true) {
      if (bindingMatches === false) {
        throw admissionErrorFor(
          new DisposablePostgresFixtureAdmissionStageError("BINDING"),
          targetName,
        );
      }
      throw new Error();
    }
    const authority = Object.freeze({});
    mutationTargetValues.set(authority, {
      authority,
      boundConnections: new WeakSet(),
      brand: mutationTargetBrand,
      boundClient: null,
      boundPool: pool,
      phase: value.phase,
      revalidate: createMutationRevalidator(options),
      targetName,
      target,
      valid: true,
    });
    value.mutationPools.set(pool, authority);
    return authority;
  } catch (error) {
    if (error instanceof DisposablePostgresFixtureAdmissionError) {
      throw error;
    }
    throw new DisposablePostgresFixtureAdmissionError();
  }
}

export function createAdmittedMutationClient(client, authority) {
  try {
    const value = requireMutationTarget(authority);
    if (
      value.boundClient ||
      !client ||
      typeof client.query !== "function"
    ) {
      throw new Error();
    }
    const bindingMatches = clientConnectionMatchesTarget(client, value.target);
    if (bindingMatches !== true) {
      if (bindingMatches === false) {
        throw admissionErrorFor(
          new DisposablePostgresFixtureAdmissionStageError("BINDING"),
          value.targetName,
        );
      }
      throw new Error();
    }
    value.boundClient = client;
    return createMutationClientWrapper(client, value, value.revalidate);
  } catch (error) {
    if (error instanceof DisposablePostgresFixtureAdmissionError) {
      throw error;
    }
    throw new DisposablePostgresFixtureAdmissionError();
  }
}

export function createAdmittedMutationPool(
  pool,
  admission,
  targetName,
  options = {},
) {
  try {
    const authority = deriveDisposablePostgresTargetAuthority(
      admission,
      targetName,
      pool,
      options,
    );
    const value = requireMutationTarget(authority);
    return createAuthorizedPoolWrapper(pool, value.target, value, value.revalidate);
  } catch (error) {
    if (error instanceof DisposablePostgresFixtureAdmissionError) {
      throw error;
    }
    throw new DisposablePostgresFixtureAdmissionError();
  }
}

export function invalidateDisposablePostgresAdmission(admission) {
  const value = requireConfiguredAggregate(admission);
  value.valid = false;
  for (const authority of value.mutationPools.values()) {
    const target = mutationTargetValues.get(authority);
    if (target) target.valid = false;
  }
}

export function invalidateDisposablePostgresConstructionAdmission(admission) {
  const value = requireConstructionAggregate(admission);
  value.valid = false;
  for (const authority of value.provisioningAuthorities) {
    const target = provisioningTargetValues.get(authority);
    if (target) target.valid = false;
  }
  for (const authority of value.creationAuthorities) {
    const target = databaseCreationTargetValues.get(authority);
    if (target) target.valid = false;
  }
}

function createAuthorizedPoolWrapper(
  pool,
  target,
  authority,
  revalidate,
  bindingMode = "target",
) {
  return Object.freeze({
    async query(text, values = []) {
      if (typeof text !== "string" || !Array.isArray(values)) {
        throw new DisposablePostgresFixtureAdmissionError();
      }
      const client = await connectAndRevalidate(
        pool,
        target,
        authority,
        revalidate,
        bindingMode,
      );
      try {
        if (
          !authority.valid ||
          !authority.boundConnections.has(client) ||
          !clientConnectionMatchesTarget(
            client,
            target,
            bindingMode,
            Object.hasOwn(pool.options, "password")
              ? pool.options.password
              : undefined,
          )
        ) {
          throw new DisposablePostgresFixtureAdmissionError();
        }
        return await client.query(text, values);
      } finally {
        client.release();
      }
    },
    async connect() {
      const client = await connectAndRevalidate(
        pool,
        target,
        authority,
        revalidate,
        bindingMode,
      );
      return Object.freeze({
        async query(text, values = []) {
          try {
            if (
              typeof text !== "string" ||
              !Array.isArray(values) ||
              !authority.valid ||
              !authority.boundConnections.has(client) ||
              !clientConnectionMatchesTarget(
                client,
                target,
                bindingMode,
                Object.hasOwn(pool.options, "password")
                  ? pool.options.password
                  : undefined,
              )
            ) {
              throw new Error();
            }
            return await client.query(text, values);
          } catch {
            throw new DisposablePostgresFixtureAdmissionError();
          }
        },
        release: (...args) => client.release(...args),
      });
    },
    end(...args) {
      return pool.end(...args);
    },
  });
}

async function connectAndRevalidate(
  pool,
  target,
  authority,
  revalidate,
  bindingMode = "target",
) {
  try {
    if (
      !authority.valid ||
      !pool ||
      authority.boundPool !== pool
    ) {
      throw new Error();
    }
    const poolBindingMatches = poolConnectionMatchesTarget(
      pool,
      target,
      bindingMode,
    );
    if (poolBindingMatches !== true) {
      if (poolBindingMatches === false) {
        throw admissionErrorFor(
          new DisposablePostgresFixtureAdmissionStageError("BINDING"),
          authority.targetName,
        );
      }
      throw new Error();
    }
    const client = await pool.connect();
    try {
      const clientBindingMatches = clientConnectionMatchesTarget(
        client,
        target,
        bindingMode,
        Object.hasOwn(pool.options, "password")
          ? pool.options.password
          : undefined,
      );
      if (clientBindingMatches !== true) {
        if (clientBindingMatches === false) {
          throw admissionErrorFor(
            new DisposablePostgresFixtureAdmissionStageError("BINDING"),
            authority.targetName,
          );
        }
        throw new Error();
      }
      await revalidate({ client, target });
      authority.boundConnections.add(client);
      return client;
    } catch (error) {
      client.release(true);
      if (error instanceof DisposablePostgresFixtureAdmissionError) throw error;
      throw new Error();
    }
  } catch (error) {
    if (error instanceof DisposablePostgresFixtureAdmissionError) throw error;
    throw new DisposablePostgresFixtureAdmissionError();
  }
}

function createMutationClientWrapper(client, authority, revalidate) {
  return Object.freeze({
    async query(text, values = []) {
      if (typeof text !== "string" || !Array.isArray(values)) {
        throw new DisposablePostgresFixtureAdmissionError();
      }
      try {
        if (
          !authority.valid ||
          authority.boundClient !== client ||
          !clientConnectionMatchesTarget(client, authority.target)
        ) {
          throw new Error();
        }
        await revalidate({ client, target: authority.target });
        return await client.query(text, values);
      } catch {
        throw new DisposablePostgresFixtureAdmissionError();
      }
    },
    release: (...args) => client.release(...args),
  });
}

function createMutationRevalidator(options, authorityValue = null) {
  const additionalRevalidate = options?.revalidateMutationConnection;
  return async ({ client, target }) => {
    await defaultMutationConnectionRevalidator({
      authorityValue,
      client,
      target,
    });
    if (additionalRevalidate) {
      await additionalRevalidate({ client, target });
    }
  };
}

function clientConnectionMatchesTarget(
  client,
  targetRecord,
  bindingMode = "target",
  expectedPassword,
) {
  try {
    const binding = targetConnectionBinding(targetRecord, bindingMode);
    const parameters = client?.connectionParameters;
    if (!parameters || typeof parameters !== "object") return null;
    const hasPassword = Object.hasOwn(parameters, "password");
    if (hasPassword || expectedPassword !== undefined) {
      const passwordDescriptor = Object.getOwnPropertyDescriptor(
        parameters,
        "password",
      );
      const passwordlessRealClient =
        expectedPassword === undefined &&
        hasPassword &&
        client instanceof Client &&
        passwordDescriptor?.enumerable === false &&
        passwordDescriptor.value === null;
      if (
        !(client instanceof Client) ||
        (hasPassword &&
          !passwordlessRealClient &&
          (!passwordDescriptor ||
            passwordDescriptor.enumerable ||
            typeof passwordDescriptor.value !== "string"))
      ) {
        return null;
      }
      if (
        !passwordlessRealClient &&
        (!hasPassword || passwordDescriptor.value !== expectedPassword)
      ) {
        return false;
      }
    }
    const hostname = String(parameters.host ?? "").toLowerCase();
    const port = String(parameters.port ?? "5432");
    return (
      String(parameters.user ?? "") === binding.expectedUser &&
      String(parameters.database ?? "") === binding.expectedDatabase &&
      hostname === binding.hostname &&
      port === binding.port &&
      binding.transportIdentity === transportIdentityFor(
        targetRecord,
        hostname,
        port,
        bindingMode,
      )
    );
  } catch {
    return false;
  }
}

function poolConnectionMatchesTarget(pool, targetRecord, bindingMode = "target") {
  try {
    const binding = targetConnectionBinding(targetRecord, bindingMode);
    const configured = pool?.options?.connectionString;
    if (typeof configured === "string") {
      const parsed = new URL(configured);
      if (
        !["postgres:", "postgresql:"].includes(parsed.protocol) ||
        parsed.password ||
        parsed.search ||
        parsed.hash
      ) {
        return null;
      }
      const username = decodeURIComponent(parsed.username);
      const database = decodeURIComponent(parsed.pathname.slice(1));
      const hostname = parsed.hostname.replace(/^\[|\]$/gu, "").toLowerCase();
      const port = parsed.port || "5432";
      return (
        username === binding.expectedUser &&
        database === binding.expectedDatabase &&
        hostname === binding.hostname &&
        port === binding.port &&
        binding.transportIdentity === transportIdentityFor(
          targetRecord,
          hostname,
          port,
          bindingMode,
        )
      );
    }

    const parameters = pool?.options?.connectionParameters;
    if (parameters && typeof parameters === "object") {
      if (parameters.password) return null;
      const hostname = String(parameters.host ?? "").toLowerCase();
      const port = String(parameters.port ?? "5432");
      return (
        String(parameters.user ?? "") === binding.expectedUser &&
        String(parameters.database ?? "") === binding.expectedDatabase &&
        hostname === binding.hostname &&
        port === binding.port &&
        binding.transportIdentity === transportIdentityFor(
          targetRecord,
          hostname,
          port,
          bindingMode,
        )
      );
    }

    const flatOptions = pool?.options;
    const passwordDescriptor = Object.getOwnPropertyDescriptor(
      flatOptions ?? {},
      "password",
    );
    if (
      !(pool instanceof Pool) ||
      !flatOptions ||
      typeof flatOptions !== "object" ||
      !Object.hasOwn(flatOptions, "user") ||
      !Object.hasOwn(flatOptions, "host") ||
      !Object.hasOwn(flatOptions, "port") ||
      !Object.hasOwn(flatOptions, "database") ||
      !passwordDescriptor ||
      passwordDescriptor.enumerable ||
      typeof passwordDescriptor.value !== "string" ||
      passwordDescriptor.value.length === 0
    ) {
      return null;
    }
    const hostname = String(flatOptions.host).toLowerCase();
    const port = String(flatOptions.port);
    return (
      String(flatOptions.user) === binding.expectedUser &&
      String(flatOptions.database) === binding.expectedDatabase &&
      hostname === binding.hostname &&
      port === binding.port &&
      binding.transportIdentity === transportIdentityFor(
        targetRecord,
        hostname,
        port,
        bindingMode,
      )
    );
  } catch {
    return false;
  }
}

function targetConnectionBinding(targetRecord, bindingMode = "target") {
  const target = targetRecord?.target;
  if (!target || !target.parsedUrl) throw new Error();
  const selectedBinding =
    bindingMode === "creation"
      ? target.creationBinding
      : bindingMode === "probe"
        ? null
        : target.mutationBinding;
  const parsed = parsedUrlValues.get(
    bindingMode === "probe"
      ? target.parsedUrl
      : selectedBinding?.parsedUrl ?? target.parsedUrl,
  );
  if (!parsed) throw new Error();
  return {
    expectedDatabase:
      selectedBinding?.expectedDatabase ?? target.expectedDatabase,
    expectedUser: selectedBinding?.expectedUser ?? target.expectedUser,
    hostname: parsed.hostname,
    port: parsed.port,
    transportIdentity:
      selectedBinding?.transportIdentity ?? parsed.transportIdentity,
  };
}

function transportIdentityFor(
  targetRecord,
  hostname,
  port,
  bindingMode = "target",
) {
  const target = targetRecord?.target;
  const parsed = parsedUrlValues.get(
    (bindingMode === "creation"
      ? target?.creationBinding?.parsedUrl
      : bindingMode === "probe"
        ? target?.parsedUrl
        : target?.mutationBinding?.parsedUrl) ?? target?.parsedUrl,
  );
  if (!parsed) throw new Error();
  if (parsed.transportKind === "loopback") {
    return `loopback:${hostname}:${port}`;
  }
  const transport = bindingMode === "creation"
    ? target.creationTransport ?? target.operatorTransport ?? target.transport
    : bindingMode === "probe"
      ? target.transport
      : target.mutationBinding
        ? target.mutationTransport ?? target.operatorTransport ?? target.transport
        : target.transport;
  const transportValue = managedTransportValues.get(transport?.attestation);
  if (!transportValue) throw new Error();
  return `managed-container:${transportValue.alias}:${port}:${transportValue.image}`;
}

async function probeTarget({
  target,
  readOnlyProbe,
  builtInProbe = false,
  clientFactory,
}) {
  let client = target.client;
  let ownedPool = null;
  let ownedClient = false;
  let evidence;
  let admissionFailure;
  try {
    try {
      const parsedUrl = parsedUrlValues.get(target.parsedUrl);
      if (!parsedUrl) {
        throw new DisposablePostgresFixtureAdmissionStageError("BINDING");
      }
      const customProbe = readOnlyProbe ?? target.readOnlyProbe;
      if (!client) {
        await withAdmissionStage("CONNECT", async () => {
          if (clientFactory) {
            client = await clientFactory(target);
            ownedClient = true;
          } else {
            ownedPool = new Pool({
              connectionString:
                target.probeConnectionString ?? target.connectionString,
              max: 1,
            });
            client = await ownedPool.connect();
            ownedClient = true;
          }
        });
      }
      if (!client || typeof client.query !== "function") {
        throw new DisposablePostgresFixtureAdmissionStageError("BINDING");
      }
      const bindingMode =
        target.mode === "construction" && target.databaseMayBeAbsent
          ? "creation"
          : "probe";
      if (
        client.connectionParameters &&
        !clientConnectionMatchesTarget(client, { target }, bindingMode)
      ) {
        throw new DisposablePostgresFixtureAdmissionStageError("BINDING");
      }
      const probeFixture = createReadOnlyProbeFixture(target);
      const result = await withReadOnlyProbeTransaction(
        client,
        probeFixture,
        async (probeClient) => {
          const probeResult = await customProbe({
            client: probeClient,
            fixture: probeFixture,
            parsedUrl,
            postureInspector: target.postureInspector,
          });
          assertProbeResult(probeResult, target.mode === "construction", target);
          return probeResult;
        },
      );
      evidence = Object.freeze({
        catalogFingerprint: result.catalogFingerprint,
        databaseMatches: true,
        lifecycleFingerprint: result.lifecycleFingerprint,
        nonRecovery: true,
        postgres17: true,
        userMatches: true,
      });
    } catch (error) {
      admissionFailure = error;
    }

    let cleanupFailure;
    if (ownedPool) {
      if (ownedClient) {
        try {
          await releaseProbeClient(client);
        } catch {
          cleanupFailure ??=
            new DisposablePostgresFixtureAdmissionStageError("CONNECT");
        }
      }
      try {
        await ownedPool.end();
      } catch {
        cleanupFailure ??=
          new DisposablePostgresFixtureAdmissionStageError("CONNECT");
      }
    } else if (ownedClient) {
      try {
        await releaseProbeClient(client);
      } catch {
        cleanupFailure =
          new DisposablePostgresFixtureAdmissionStageError("CONNECT");
      }
    }

    if (admissionFailure) throw admissionFailure;
    if (cleanupFailure) throw cleanupFailure;
    return evidence;
  } catch (error) {
    if (error instanceof DisposablePostgresFixtureAdmissionError) {
      throw error;
    }
    throw admissionErrorFor(error, target?.name);
  }
}

async function withReadOnlyProbeTransaction(client, fixture, callback) {
  let transactionStarted = false;
  let result;
  let admissionFailure;
  try {
    await withAdmissionStage("READONLY", () => client.query("begin"));
    transactionStarted = true;
    await withAdmissionStage("READONLY", async () => {
      await client.query("set transaction read only");
      const verification = await client.query("show transaction_read_only");
      if (
        !verification ||
        !Array.isArray(verification.rows) ||
        verification.rows.length !== 1 ||
        String(verification.rows[0]?.transaction_read_only ?? "").toLowerCase() !==
          "on"
      ) {
        throw new Error();
      }
    });
    result = await callback(readOnlyClient(client, fixture));
  } catch (error) {
    admissionFailure = error;
  }
  if (transactionStarted) {
    try {
      await withAdmissionStage("READONLY", () => client.query("rollback"));
    } catch (error) {
      admissionFailure ??= error;
    }
  }
  if (admissionFailure) throw admissionFailure;
  return result;
}

async function releaseProbeClient(client) {
  if (typeof client?.release === "function") {
    await client.release();
    return;
  }
  if (typeof client?.end === "function") {
    await client.end();
    return;
  }
  throw new Error();
}

function createReadOnlyProbeFixture(target) {
  const fixture = { ...target };
  for (const key of [
    "client",
    "pool",
    "clientFactory",
    "readOnlyProbe",
    "postureInspector",
  ]) {
    delete fixture[key];
  }
  return Object.freeze(fixture);
}

async function defaultConstructionProbe({ client, fixture }) {
  const identity = fixture.databaseMayBeAbsent
    ? await readCreationIdentity(client, fixture)
    : await readIdentity(client, fixture);
  return {
    ...identity,
    catalogIdentityPresent: true,
    databaseMatches: true,
    expectedObjectsPresent: true,
    lifecycleIdentityPresent: true,
    nonRecovery: true,
    ownershipAbsent: true,
    postgres17: true,
    runtimePosturePassed: true,
    targetDatabasePresent: identity.targetDatabasePresent ?? true,
    userMatches: true,
  };
}

async function defaultConfiguredProbe({ client, fixture, postureInspector }) {
  if (!postureInspector) {
    throw new DisposablePostgresFixtureAdmissionStageError("POSTURE");
  }
  const identity = await readIdentity(client, fixture);
  await withAdmissionStage("POSTURE", async () => {
    const posture = await postureInspector(client, fixture.expectedRuntimeRole);
    if (posture?.runtimeRoleAuthorityPosture !== "passed") throw new Error();
  });

  await withAdmissionStage("OWNERSHIP", async () => {
    const ownershipResult = await client.query(
      `
      select not exists (
        select 1
        from pg_roles runtime_role
        where runtime_role.rolname = $1
          and (
            exists (select 1 from pg_database where datdba = runtime_role.oid)
            or exists (select 1 from pg_namespace where nspowner = runtime_role.oid)
            or exists (select 1 from pg_class where relowner = runtime_role.oid)
            or exists (select 1 from pg_proc where proowner = runtime_role.oid)
            or exists (select 1 from pg_type where typowner = runtime_role.oid)
          )
      ) as ownership_absent
      `,
      [fixture.expectedRuntimeRole],
    );
    requireTrue(oneRow(ownershipResult), ["ownership_absent"]);
  });

  const objects = normalizeExpectedObjects(fixture.expectedObjects);
  await withAdmissionStage("EXPECTED_OBJECTS", async () => {
    const objectResult = await client.query(
      `
      with expected_schemas as (
        select value as schema_name
        from jsonb_array_elements_text($1::jsonb)
      ), expected_relations as (
        select *
        from jsonb_to_recordset($2::jsonb) as expected(
          schema_name text,
          object_name text,
          object_kind text
        )
      ), expected_sequences as (
        select *
        from jsonb_to_recordset($3::jsonb) as expected(
          schema_name text,
          object_name text
        )
      ), expected_routines as (
        select *
        from jsonb_to_recordset($4::jsonb) as expected(
          schema_name text,
          object_name text,
          object_kind text
        )
      )
      select
        (select count(*) from expected_schemas) =
          (select count(*) from expected_schemas expected
            join pg_namespace schema_record
              on schema_record.nspname = expected.schema_name) as schemas_present,
        (select count(*) from expected_relations) =
          (select count(*)
            from expected_relations expected
            join pg_namespace schema_record
              on schema_record.nspname = expected.schema_name
            join pg_class relation_record
              on relation_record.relnamespace = schema_record.oid
             and relation_record.relname = expected.object_name
             and (expected.object_kind = '*' or
               relation_record.relkind::text = expected.object_kind)) as relations_present,
        (select count(*) from expected_sequences) =
          (select count(*)
            from expected_sequences expected
            join pg_namespace schema_record
              on schema_record.nspname = expected.schema_name
            join pg_class sequence_record
              on sequence_record.relnamespace = schema_record.oid
             and sequence_record.relname = expected.object_name
             and sequence_record.relkind = 'S') as sequences_present,
        (select count(*) from expected_routines) =
          (select count(*)
            from expected_routines expected
            join pg_namespace schema_record
              on schema_record.nspname = expected.schema_name
            join pg_proc routine_record
              on routine_record.pronamespace = schema_record.oid
             and routine_record.proname = expected.object_name
             and (expected.object_kind = '*' or
               routine_record.prokind::text = expected.object_kind)) as routines_present
      `,
      [
        JSON.stringify(objects.schemas),
        JSON.stringify(objects.relations),
        JSON.stringify(objects.sequences),
        JSON.stringify(objects.routines),
      ],
    );
    requireTrue(oneRow(objectResult), [
      "schemas_present",
      "relations_present",
      "sequences_present",
      "routines_present",
    ]);
  });

  return {
    ...identity,
    catalogIdentityPresent: true,
    databaseMatches: true,
    expectedObjectsPresent: true,
    lifecycleIdentityPresent: true,
    nonRecovery: true,
    ownershipAbsent: true,
    postgres17: true,
    runtimePosturePassed: true,
    userMatches: true,
  };
}

async function readIdentity(client, fixture) {
  return await withAdmissionStage("IDENTITY", async () => {
    const result = await client.query(identitySql, [
      fixture.expectedDatabase,
      fixture.expectedUser,
    ]);
    const row = oneRow(result);
    requireTrue(row, ["database_matches", "user_matches"]);
    try {
      requireTrue(row, ["postgres17", "non_recovery"]);
    } catch {
      throw new DisposablePostgresFixtureAdmissionStageError("POSTURE");
    }
    const catalogFingerprint = requireFingerprint(row.catalog_fingerprint);
    const lifecycleFingerprint = requireFingerprint(row.lifecycle_fingerprint);
    return { catalogFingerprint, lifecycleFingerprint };
  });
}

async function readCreationIdentity(client, fixture) {
  const binding = targetConnectionBinding({ target: fixture }, "creation");
  const result = await client.query(creationIdentitySql, [
    binding.expectedDatabase,
    binding.expectedUser,
    fixture.expectedDatabase,
  ]);
  const row = oneRow(result);
  requireTrue(row, [
    "database_matches",
    "user_matches",
    "postgres17",
    "non_recovery",
    "target_database_absent",
  ]);
  const catalogFingerprint = requireFingerprint(row.catalog_fingerprint);
  const lifecycleFingerprint = requireFingerprint(row.lifecycle_fingerprint);
  return {
    catalogFingerprint,
    lifecycleFingerprint,
    targetDatabasePresent: false,
  };
}

async function defaultCreationConnectionRevalidator({ client, target }) {
  const binding = targetConnectionBinding(target, "creation");
  const result = await client.query(creationIdentitySql, [
    binding.expectedDatabase,
    binding.expectedUser,
    target.target.expectedDatabase,
  ]);
  const row = oneRow(result);
  requireTrue(row, [
    "database_matches",
    "user_matches",
    "postgres17",
    "non_recovery",
    "target_database_absent",
  ]);
  if (
    requireFingerprint(row.catalog_fingerprint) !==
      requireFingerprint(target.evidence.catalogFingerprint) ||
    requireFingerprint(row.lifecycle_fingerprint) !==
      requireFingerprint(target.evidence.lifecycleFingerprint)
  ) {
    throw new Error();
  }
}

async function readCreatedDatabaseIdentity(pool, target) {
  const client = await pool.connect();
  try {
    if (!clientConnectionMatchesTarget(client, target, "creation")) {
      throw new Error();
    }
    const binding = targetConnectionBinding(target, "creation");
    const result = await client.query(creationIdentitySql, [
      binding.expectedDatabase,
      binding.expectedUser,
      target.target.expectedDatabase,
    ]);
    const row = oneRow(result);
    requireTrue(row, [
      "database_matches",
      "user_matches",
      "postgres17",
      "non_recovery",
    ]);
    if (row.target_database_absent !== false) throw new Error();
    const catalogFingerprint = requireFingerprint(row.catalog_fingerprint);
    const lifecycleFingerprint = requireFingerprint(row.lifecycle_fingerprint);
    if (
      catalogFingerprint !== requireFingerprint(target.evidence.catalogFingerprint) ||
      lifecycleFingerprint.startsWith("absent:")
    ) {
      throw new Error();
    }
    return { catalogFingerprint, lifecycleFingerprint };
  } finally {
    client.release();
  }
}

async function defaultMutationConnectionRevalidator({
  authorityValue = null,
  client,
  target,
}) {
  const binding = targetConnectionBinding(target);
  const result = await client.query(identitySql, [
    binding.expectedDatabase,
    binding.expectedUser,
  ]);
  const row = oneRow(result);
  requireTrue(row, [
    "database_matches",
    "user_matches",
    "postgres17",
    "non_recovery",
  ]);
  const catalogFingerprint = requireFingerprint(row.catalog_fingerprint);
  const lifecycleFingerprint = requireFingerprint(row.lifecycle_fingerprint);
  if (
    catalogFingerprint !==
      requireFingerprint(target.evidence.catalogFingerprint)
  ) {
    throw new Error();
  }
  if (authorityValue?.target?.target?.databaseMayBeAbsent) {
    const aggregate = constructionAggregateValues.get(authorityValue.aggregate);
    const created = aggregate?.createdTargets.get(authorityValue.targetName);
    if (
      !aggregate?.valid ||
      !created ||
      created.catalogFingerprint !== catalogFingerprint ||
      created.lifecycleFingerprint !== lifecycleFingerprint
    ) {
      throw new Error();
    }
    if (authorityValue.lifecycleFingerprint === null) {
      authorityValue.lifecycleFingerprint = lifecycleFingerprint;
    }
  }
  if (
    lifecycleFingerprint !==
      requireFingerprint(authorityValue?.lifecycleFingerprint ??
        target.evidence.lifecycleFingerprint)
  ) {
    throw new Error();
  }
}

function normalizeConstructionTarget(target) {
  if (!target || typeof target !== "object") throw new Error();
  const normalized = {
    ...target,
    connectionString: target.connectionString ?? target.operatorUrl,
    creationConnectionString: target.creationConnectionString,
    expectedDatabase: target.expectedDatabase,
    expectedUser: target.expectedUser ?? "postgres",
    allowDatabaseCreation: target.allowDatabaseCreation === true,
    mode: "construction",
    name: target.name,
    phase: target.phase ?? "initialization",
    transport: target.transport,
  };
  if (
    typeof normalized.name !== "string" ||
    !safeIdentifier.test(normalized.name) ||
    !safeIdentifier.test(normalized.expectedDatabase) ||
    !safeIdentifier.test(normalized.expectedUser) ||
    normalized.phase !== "initialization" ||
    !normalized.transport ||
    normalized.transport.phase !== normalized.phase
  ) {
    throw new Error();
  }
  normalized.parsedUrl = parseDisposablePostgresUrl(
    normalized.connectionString,
    normalized,
  );
  if (normalized.allowDatabaseCreation) {
    if (typeof normalized.creationConnectionString !== "string") {
      throw new Error();
    }
    const creationExpectedDatabase = normalized.creationExpectedDatabase ?? "postgres";
    const creationExpectedUser = normalized.creationExpectedUser ?? normalized.expectedUser;
    const creationTransport = normalized.creationTransport ?? normalized.transport;
    const creationParsedUrl = parseDisposablePostgresUrl(
      normalized.creationConnectionString,
      {
        expectedDatabase: creationExpectedDatabase,
        expectedUser: creationExpectedUser,
        phase: normalized.phase,
        transport: creationTransport,
      },
    );
    normalized.creationBinding = Object.freeze({
      expectedDatabase: creationExpectedDatabase,
      expectedUser: creationExpectedUser,
      parsedUrl: creationParsedUrl,
      transportIdentity: parsedUrlValues.get(creationParsedUrl).transportIdentity,
    });
    normalized.creationTransport = creationTransport;
    normalized.probeConnectionString = normalized.creationConnectionString;
    normalized.databaseMayBeAbsent = normalized.databaseMayBeAbsent === true;
    if (!normalized.databaseMayBeAbsent) {
      throw new Error();
    }
  }
  return normalized;
}

function normalizeFixture(fixture) {
  if (!fixture || typeof fixture !== "object") {
    throw new Error();
  }
  const normalized = {
    ...fixture,
    connectionString: fixture.connectionString ?? fixture.operatorUrl,
    expectedDatabase: fixture.expectedDatabase,
    expectedUser: fixture.expectedUser,
    expectedRuntimeRole: fixture.expectedRuntimeRole,
    mode: "configured",
    name: fixture.name,
    phase: fixture.phase ?? fixture.transport?.phase,
    transport: fixture.transport,
  };
  if (
    typeof normalized.name !== "string" ||
    !safeIdentifier.test(normalized.name) ||
    !safeIdentifier.test(normalized.expectedDatabase) ||
    !safeIdentifier.test(normalized.expectedUser) ||
    !safeIdentifier.test(normalized.expectedRuntimeRole) ||
    !normalized.transport ||
    normalized.transport.phase !== normalized.phase ||
    !phases.has(normalized.phase)
  ) {
    throw new Error();
  }
  normalizeExpectedObjects(normalized.expectedObjects);
  normalized.parsedUrl = parseDisposablePostgresUrl(
    normalized.connectionString,
    normalized,
  );

  const mutationConnectionString =
    fixture.mutationConnectionString ??
    fixture.operatorConnectionString ??
    fixture.operatorUrl ??
    normalized.connectionString;
  const mutationUser =
    fixture.expectedMutationUser ??
    fixture.expectedOperatorUser ??
    fixture.expectedUser;
  const mutationTransport =
    fixture.mutationTransport ??
    fixture.operatorTransport ??
    normalized.transport;
  const mutationParsedUrl = parseDisposablePostgresUrl(
    mutationConnectionString,
    {
      expectedDatabase: normalized.expectedDatabase,
      expectedUser: mutationUser,
      phase: normalized.phase,
      transport: mutationTransport,
    },
  );
  normalized.mutationBinding = Object.freeze({
    expectedDatabase: normalized.expectedDatabase,
    expectedUser: mutationUser,
    parsedUrl: mutationParsedUrl,
    transportIdentity: parsedUrlValues.get(mutationParsedUrl).transportIdentity,
  });
  return normalized;
}

function assertDistinctCanonicalTargetLocator(identities, target) {
  const parsed = parsedUrlValues.get(target.parsedUrl);
  if (!parsed) throw new Error();
  const identity = JSON.stringify([parsed.transportIdentity, parsed.database]);
  if (identities.has(identity)) throw new Error();
  identities.add(identity);
}

function assertDistinctObservedPhysicalIdentity(identities, evidence) {
  const identity = JSON.stringify([
    requireFingerprint(evidence?.catalogFingerprint),
    requireFingerprint(evidence?.lifecycleFingerprint),
  ]);
  if (identities.has(identity)) throw new Error();
  identities.add(identity);
}

function normalizeExpectedObjects(objects) {
  if (!objects || typeof objects !== "object") {
    throw new Error();
  }
  const schemas = normalizeStringList(objects.schemas);
  const relations = normalizeObjectList(objects.relations, ["schema", "name"])
    .map((object) => ({
      object_kind: normalizeKind(object.kind, "*"),
      object_name: object.name,
      schema_name: object.schema,
    }));
  const sequences = normalizeObjectList(objects.sequences, ["schema", "name"])
    .map((object) => ({
      object_name: object.name,
      schema_name: object.schema,
    }));
  const routines = normalizeObjectList(objects.routines, ["schema", "name"])
    .map((object) => ({
      object_kind: normalizeKind(object.kind, "*"),
      object_name: object.name,
      schema_name: object.schema,
    }));
  return { relations, routines, schemas, sequences };
}

function normalizeStringList(value) {
  if (!Array.isArray(value)) throw new Error();
  return value.map((item) => {
    if (typeof item !== "string" || !safeIdentifier.test(item)) throw new Error();
    return item;
  });
}

function normalizeObjectList(value, requiredKeys) {
  if (!Array.isArray(value)) throw new Error();
  return value.map((item) => {
    if (!item || typeof item !== "object") throw new Error();
    for (const key of requiredKeys) {
      if (typeof item[key] !== "string" || !safeIdentifier.test(item[key])) {
        throw new Error();
      }
    }
    return item;
  });
}

function normalizeKind(value, fallback) {
  const kind = value ?? fallback;
  if (typeof kind !== "string" || !/^[a-z*]$/u.test(kind)) throw new Error();
  return kind;
}

function readOnlyClient(client, fixture) {
  if (!client || typeof client.query !== "function") {
    throw new Error();
  }
  return Object.freeze({
    async query(text, values = []) {
      assertReadOnlySql(text);
      if (!Array.isArray(values)) throw new Error();
      return await client.query(text, values);
    },
    fixtureName: fixture.name,
  });
}

function assertReadOnlySql(text) {
  if (typeof text !== "string") throw new Error();
  const withoutLiterals = text
    .replace(/'(?:''|[^'])*'/gu, "''")
    .replace(/--[^\r\n]*/gu, "");
  if (
    mutationKeyword.test(withoutLiterals) ||
    sessionMutationKeyword.test(withoutLiterals) ||
    transactionControlKeyword.test(withoutLiterals) ||
    sessionAuthorityKeyword.test(withoutLiterals)
  ) {
    throw new Error();
  }
}

function assertProbeResult(result, construction, target) {
  if (!result || typeof result !== "object") {
    throw new DisposablePostgresFixtureAdmissionStageError("IDENTITY");
  }
  requireProbeFields(result, [
    "databaseMatches",
    "userMatches",
    "catalogIdentityPresent",
    "lifecycleIdentityPresent",
  ], "IDENTITY");
  requireProbeFields(result, [
    "postgres17",
    "nonRecovery",
    "runtimePosturePassed",
  ], "POSTURE");
  requireProbeFields(result, ["ownershipAbsent"], "OWNERSHIP");
  requireProbeFields(result, ["expectedObjectsPresent"], "EXPECTED_OBJECTS");
  if (construction) {
    if (typeof result.targetDatabasePresent !== "boolean") {
      throw new DisposablePostgresFixtureAdmissionStageError("IDENTITY");
    }
    if (!result.targetDatabasePresent && !target?.allowDatabaseCreation) {
      throw new DisposablePostgresFixtureAdmissionStageError("IDENTITY");
    }
  }
  try {
    requireFingerprint(result.catalogFingerprint);
    requireFingerprint(result.lifecycleFingerprint);
  } catch {
    throw new DisposablePostgresFixtureAdmissionStageError("IDENTITY");
  }
}

function requireProbeFields(result, fields, stage) {
  try {
    requireTrue(result, fields);
  } catch {
    throw new DisposablePostgresFixtureAdmissionStageError(stage);
  }
}

async function withAdmissionStage(stage, operation) {
  try {
    return await operation();
  } catch (error) {
    if (
      error instanceof DisposablePostgresFixtureAdmissionStageError ||
      error instanceof DisposablePostgresFixtureAdmissionError
    ) {
      throw error;
    }
    throw new DisposablePostgresFixtureAdmissionStageError(stage);
  }
}

function admissionErrorFor(error, targetName) {
  const target = String(targetName ?? "").toUpperCase();
  if (
    error instanceof DisposablePostgresFixtureAdmissionStageError &&
    admissionTargets.has(target) &&
    admissionStages.has(error.stage)
  ) {
    return new DisposablePostgresFixtureAdmissionError({
      target,
      stage: error.stage,
    });
  }
  return new DisposablePostgresFixtureAdmissionError();
}

function requireConstructionAggregate(token) {
  const value = constructionAggregateValues.get(token);
  if (!value || value.brand !== constructionAggregateBrand || !value.valid) {
    throw new DisposablePostgresFixtureAdmissionError();
  }
  return value;
}

function requireProvisioningTarget(token) {
  const value = provisioningTargetValues.get(token);
  if (
    !value ||
    value.brand !== provisioningTargetBrand ||
    !value.valid ||
    !value.target ||
    !value.target.target
  ) {
    throw new DisposablePostgresFixtureAdmissionError();
  }
  return value;
}

function requireDatabaseCreationTarget(token) {
  const value = databaseCreationTargetValues.get(token);
  const aggregate = value?.aggregate && constructionAggregateValues.get(value.aggregate);
  if (
    !value ||
    value.brand !== databaseCreationTargetBrand ||
    !value.valid ||
    !aggregate ||
    !aggregate.valid ||
    !value.target ||
    !value.target.target
  ) {
    throw new DisposablePostgresFixtureAdmissionError();
  }
  return value;
}

function requireConfiguredAggregate(token) {
  const value = configuredAggregateValues.get(token);
  if (!value || value.brand !== configuredAggregateBrand || !value.valid) {
    throw new DisposablePostgresFixtureAdmissionError();
  }
  return value;
}

function requireMutationTarget(token) {
  const value = mutationTargetValues.get(token);
  if (!value || value.brand !== mutationTargetBrand || !value.valid) {
    throw new DisposablePostgresFixtureAdmissionError();
  }
  return value;
}

function requireFingerprint(value) {
  if (
    (typeof value !== "string" && typeof value !== "number") ||
    String(value).trim().length === 0 ||
    String(value) === "0"
  ) {
    throw new Error();
  }
  return String(value);
}

function assertDatabaseCreationQuery(text, values, targetRecord) {
  if (typeof text !== "string" || !Array.isArray(values)) throw new Error();
  const normalized = text.replace(/\s+/gu, " ").trim();
  if (/^select 1 from pg_database where datname = \$1$/iu.test(normalized)) {
    if (values.length !== 1 || values[0] !== targetRecord.target.expectedDatabase) {
      throw new Error();
    }
    return;
  }
  const createMatch = normalized.match(/^create database\s+"([a-z_][a-z0-9_$]{0,62})"$/iu);
  if (
    !createMatch ||
    createMatch[1] !== targetRecord.target.expectedDatabase ||
    values.length !== 0
  ) {
    throw new Error();
  }
}

function oneRow(result) {
  if (!result || !Array.isArray(result.rows) || result.rows.length !== 1) {
    throw new Error();
  }
  return result.rows[0];
}

function requireTrue(row, fields) {
  for (const field of fields) {
    if (row?.[field] !== true) throw new Error();
  }
}

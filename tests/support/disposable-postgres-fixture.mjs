import { Pool } from "pg";

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
const managedTransportValues = new WeakMap();
const parsedUrlValues = new WeakMap();
const constructionAggregateValues = new WeakMap();
const provisioningTargetValues = new WeakMap();
const databaseCreationTargetValues = new WeakMap();
const configuredAggregateValues = new WeakMap();
const configuredTargetValues = new WeakMap();
const mutationTargetValues = new WeakMap();

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

export class DisposablePostgresFixtureAdmissionError extends Error {
  constructor() {
    super("Disposable fixture admission failed.");
    this.name = "DisposablePostgresFixtureAdmissionError";
    this.code = "disposable_fixture_admission_failed";
  }
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
    const normalizedTargets = [];
    for (const target of targets) {
      const normalized = normalizeConstructionTarget(target);
      if (names.has(normalized.name)) {
        throw new Error();
      }
      names.add(normalized.name);
      normalizedTargets.push(normalized);
    }

    const admittedTargets = new Map();
    for (const target of normalizedTargets) {
      const evidence = await probeTarget({
        target,
        readOnlyProbe: readOnlyProbe ?? defaultConstructionProbe,
        builtInProbe: !readOnlyProbe,
        clientFactory,
      });
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
      typeof pool.connect !== "function" ||
      !poolConnectionMatchesTarget(pool, value.target, "creation")
    ) {
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
      typeof pool.connect !== "function" ||
      !poolConnectionMatchesTarget(pool, value.target)
    ) {
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
  { readOnlyProbe, postureInspector = inspectRuntimeDatabaseRoleAuthorityPosture } = {},
) {
  try {
    const normalized = normalizeFixture(fixture);
    const evidence = await probeTarget({
      target: normalized,
      readOnlyProbe: readOnlyProbe ?? ((args) =>
        defaultConfiguredProbe({ ...args, postureInspector })),
      builtInProbe: !readOnlyProbe,
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
    const targets = new Map();
    let phase;
    for (const fixture of fixtures) {
      const normalized = normalizeFixture(fixture);
      if (names.has(normalized.name)) {
        throw new Error();
      }
      names.add(normalized.name);
      if (phase && normalized.phase !== phase) {
        throw new Error();
      }
      phase ??= normalized.phase;
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
    if (!poolConnectionMatchesTarget(pool, target)) {
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
      typeof client.query !== "function" ||
      !clientConnectionMatchesTarget(client, value.target)
    ) {
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
          !clientConnectionMatchesTarget(client, target, bindingMode)
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
              !clientConnectionMatchesTarget(client, target, bindingMode)
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
      authority.boundPool !== pool ||
      !poolConnectionMatchesTarget(pool, target, bindingMode)
    ) {
      throw new Error();
    }
    const client = await pool.connect();
    try {
      if (!clientConnectionMatchesTarget(client, target, bindingMode)) {
        throw new Error();
      }
      await revalidate({ client, target });
      authority.boundConnections.add(client);
      return client;
    } catch {
      client.release(true);
      throw new Error();
    }
  } catch {
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

function clientConnectionMatchesTarget(client, targetRecord, bindingMode = "target") {
  try {
    const binding = targetConnectionBinding(targetRecord, bindingMode);
      const parameters = client?.connectionParameters;
    if (!parameters || typeof parameters !== "object") return false;
    if (parameters.password) return false;
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
        return false;
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
    if (!parameters || typeof parameters !== "object") return false;
    if (parameters.password) return false;
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

function targetConnectionBinding(targetRecord, bindingMode = "target") {
  const target = targetRecord?.target;
  if (!target || !target.parsedUrl) throw new Error();
  const selectedBinding = bindingMode === "creation"
    ? target.creationBinding
    : target.mutationBinding;
  const parsed = parsedUrlValues.get(
    selectedBinding?.parsedUrl ?? target.parsedUrl,
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
      : target?.mutationBinding?.parsedUrl) ?? target?.parsedUrl,
  );
  if (!parsed) throw new Error();
  if (parsed.transportKind === "loopback") {
    return `loopback:${hostname}:${port}`;
  }
  const transport = bindingMode === "creation"
    ? target.creationTransport ?? target.operatorTransport ?? target.transport
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
  try {
    const parsedUrl = parsedUrlValues.get(target.parsedUrl);
    if (!parsedUrl) throw new Error();
    const customProbe = readOnlyProbe ?? target.readOnlyProbe;
    let client = target.client;
    let ownedPool = null;
    if (!client && (builtInProbe || !customProbe)) {
      if (clientFactory) {
        client = await clientFactory(target);
      } else {
        ownedPool = new Pool({
          connectionString: target.probeConnectionString ?? target.connectionString,
          max: 1,
        });
        client = await ownedPool.connect();
      }
    }
    if (!client) {
      client = { query() { throw new Error(); } };
    }
    try {
      const result = await customProbe({
        client: readOnlyClient(client, target),
        fixture: target,
        parsedUrl,
        postureInspector: target.postureInspector,
      });
      assertProbeResult(result, target.mode === "construction", target);
      return Object.freeze({
        catalogFingerprint: result.catalogFingerprint,
        databaseMatches: true,
        lifecycleFingerprint: result.lifecycleFingerprint,
        nonRecovery: true,
        postgres17: true,
        userMatches: true,
      });
    } finally {
      if (ownedPool) {
        client.release();
        await ownedPool.end();
      }
    }
  } catch (error) {
    if (error instanceof DisposablePostgresFixtureAdmissionError) {
      throw error;
    }
    throw new DisposablePostgresFixtureAdmissionError();
  }
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
  if (!postureInspector) throw new Error();
  const identity = await readIdentity(client, fixture);
  const posture = await postureInspector(client, fixture.expectedRuntimeRole);
  if (posture?.runtimeRoleAuthorityPosture !== "passed") {
    throw new Error();
  }

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

  const objects = normalizeExpectedObjects(fixture.expectedObjects);
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
  const result = await client.query(identitySql, [
    fixture.expectedDatabase,
    fixture.expectedUser,
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
  return { catalogFingerprint, lifecycleFingerprint };
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
  return {
    query(text, values = []) {
      assertReadOnlySql(text);
      if (!Array.isArray(values)) throw new Error();
      return client.query(text, values);
    },
    fixtureName: fixture.name,
  };
}

function assertReadOnlySql(text) {
  if (typeof text !== "string") throw new Error();
  const withoutLiterals = text
    .replace(/'(?:''|[^'])*'/gu, "''")
    .replace(/--[^\r\n]*/gu, "");
  if (
    mutationKeyword.test(withoutLiterals) ||
    sessionMutationKeyword.test(withoutLiterals)
  ) {
    throw new Error();
  }
}

function assertProbeResult(result, construction, target) {
  if (!result || typeof result !== "object") throw new Error();
  requireTrue(result, [
    "databaseMatches",
    "userMatches",
    "postgres17",
    "nonRecovery",
    "catalogIdentityPresent",
    "lifecycleIdentityPresent",
    "runtimePosturePassed",
    "ownershipAbsent",
    "expectedObjectsPresent",
  ]);
  if (construction) {
    if (typeof result.targetDatabasePresent !== "boolean") throw new Error();
    if (!result.targetDatabasePresent && !target?.allowDatabaseCreation) {
      throw new Error();
    }
  }
  requireFingerprint(result.catalogFingerprint);
  requireFingerprint(result.lifecycleFingerprint);
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

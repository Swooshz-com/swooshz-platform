import { Pool } from "pg";

import {
  inspectRuntimeDatabaseRoleAuthorityPosture,
} from "../../dist/db/runtime-posture.js";

const phases = new Set(["initialization", "final_start"]);
const safeIdentifier = /^[a-z_][a-z0-9_$]{0,62}$/u;
const safeContainerAlias = /^[a-z0-9][a-z0-9_.-]{0,62}$/u;
const loopbackHosts = new Set(["127.0.0.1", "::1"]);
const validPort = (value) => /^\d{1,5}$/u.test(value) && Number(value) >= 1 && Number(value) <= 65535;
const managedTransportValues = new WeakMap();
const parsedUrlValues = new WeakMap();
const admissionValues = new WeakMap();
const mutationClientValues = new WeakMap();

const mutationKeyword =
  /\b(?:grant|revoke|alter|create|drop|truncate|insert|update|delete|merge|copy|vacuum|refresh)\b/iu;
const sessionMutationKeyword =
  /\bset\s+(?:role|session\s+authorization|session_replication_role)\b/iu;

export class DisposablePostgresFixtureAdmissionError extends Error {
  constructor() {
    super("Disposable fixture admission failed.");
    this.name = "DisposablePostgresFixtureAdmissionError";
    this.code = "disposable_fixture_admission_failed";
  }
}

export function createManagedContainerTransportAttestation({
  alias,
  image,
  phase,
} = {}) {
  if (
    typeof alias !== "string" ||
    !safeContainerAlias.test(alias) ||
    alias.toLowerCase() === "localhost" ||
    loopbackHosts.has(alias) ||
    image !== "postgres:17" ||
    !phases.has(phase)
  ) {
    throw new DisposablePostgresFixtureAdmissionError();
  }
  const attestation = Object.freeze({});
  managedTransportValues.set(attestation, Object.freeze({ alias, image, phase }));
  return attestation;
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

    if (transportKind === "loopback") {
      if (!loopbackHosts.has(hostname)) {
        throw new Error();
      }
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
    } else {
      throw new Error();
    }

    const token = Object.freeze({});
    parsedUrlValues.set(token, Object.freeze({
      database,
      hostname,
      phase,
      transportKind,
      username,
    }));
    return token;
  } catch {
    throw new DisposablePostgresFixtureAdmissionError();
  }
}

export async function admitDisposablePostgresFixture(
  fixture,
  {
    readOnlyProbe,
    postureInspector = inspectRuntimeDatabaseRoleAuthorityPosture,
  } = {},
) {
  try {
    const normalized = normalizeFixture(fixture);
    const parsedUrl = parseDisposablePostgresUrl(
      normalized.connectionString,
      normalized,
    );
    const customProbe = readOnlyProbe ?? normalized.readOnlyProbe;
    let client = normalized.client;
    let ownedPool = null;

    if (!client && !customProbe) {
      ownedPool = new Pool({
        connectionString: normalized.connectionString,
        max: 1,
      });
      client = await ownedPool.connect();
    }
    if (!client) {
      client = {
        query() {
          throw new Error();
        },
      };
    }

    try {
      const probe = customProbe ?? defaultReadOnlyProbe;
      const result = await probe({
        client: readOnlyClient(client, normalized),
        fixture: normalized,
        parsedUrl,
        postureInspector,
      });
      assertProbeResult(result);
      const token = Object.freeze({});
      admissionValues.set(token, Object.freeze({
        fixtureName: normalized.name,
        phase: normalized.phase,
      }));
      return token;
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

export async function admitDisposablePostgresFixtures(
  fixtures,
  options = {},
) {
  try {
    if (!Array.isArray(fixtures) || fixtures.length === 0) {
      throw new Error();
    }
    const names = new Set();
    const targetTokens = new Map();
    for (const fixture of fixtures) {
      const normalized = normalizeFixture(fixture);
      if (names.has(normalized.name)) {
        throw new Error();
      }
      names.add(normalized.name);
      const token = await admitDisposablePostgresFixture(normalized, {
        postureInspector: options.postureInspector,
        readOnlyProbe: options.readOnlyProbe,
      });
      targetTokens.set(normalized.name, token);
    }
    const aggregate = Object.freeze({});
    admissionValues.set(aggregate, Object.freeze({
      fixtureNames: Object.freeze([...names]),
      targetTokens,
    }));
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
    return await mutation(admission);
  } catch (error) {
    if (error instanceof DisposablePostgresFixtureAdmissionError) {
      throw error;
    }
    throw error;
  }
}

export function requireDisposablePostgresAdmission(token) {
  if (!token || typeof token !== "object" || !admissionValues.has(token)) {
    throw new DisposablePostgresFixtureAdmissionError();
  }
}

export function createAdmittedMutationClient(client, admission) {
  try {
    requireDisposablePostgresAdmission(admission);
    if (!client || typeof client.query !== "function") {
      throw new Error();
    }
    const wrapper = Object.freeze({
      query(text, values = []) {
        if (typeof text !== "string" || !Array.isArray(values)) {
          throw new DisposablePostgresFixtureAdmissionError();
        }
        return client.query(text, values);
      },
    });
    mutationClientValues.set(wrapper, admission);
    return wrapper;
  } catch (error) {
    if (error instanceof DisposablePostgresFixtureAdmissionError) {
      throw error;
    }
    throw new DisposablePostgresFixtureAdmissionError();
  }
}

export function createAdmittedMutationPool(pool, admission) {
  try {
    requireDisposablePostgresAdmission(admission);
    if (
      !pool ||
      typeof pool.query !== "function" ||
      typeof pool.connect !== "function"
    ) {
      throw new Error();
    }
    const wrapper = Object.freeze({
      query(text, values = []) {
        if (typeof text !== "string" || !Array.isArray(values)) {
          throw new DisposablePostgresFixtureAdmissionError();
        }
        return pool.query(text, values);
      },
      async connect() {
        const client = await pool.connect();
        const admittedClient = createAdmittedMutationClient(client, admission);
        return Object.freeze({
          query: admittedClient.query,
          release: (...args) => client.release(...args),
        });
      },
      end(...args) {
        return pool.end(...args);
      },
    });
    mutationClientValues.set(wrapper, admission);
    return wrapper;
  } catch (error) {
    if (error instanceof DisposablePostgresFixtureAdmissionError) {
      throw error;
    }
    throw new DisposablePostgresFixtureAdmissionError();
  }
}

async function defaultReadOnlyProbe({
  client,
  fixture,
  postureInspector,
}) {
  if (!client) {
    throw new Error();
  }

  const identityResult = await client.query(
    `
      select
        current_database() = $1 as database_matches,
        current_user = $2 and session_user = $2 as user_matches,
        current_setting('server_version_num')::integer / 10000 = 17
          as postgres17,
        not pg_is_in_recovery() as non_recovery,
        (select count(*) = 1 from pg_control_system())
          as catalog_identity_present,
        (select count(*) = 1 from pg_database
          where datname = current_database()) as lifecycle_identity_present,
        (select count(*) = 1 from pg_roles where rolname = $3)
          as runtime_role_present
    `,
    [fixture.expectedDatabase, fixture.expectedUser, fixture.expectedRuntimeRole],
  );
  const identity = oneRow(identityResult);
  requireTrue(identity, [
    "database_matches",
    "user_matches",
    "postgres17",
    "non_recovery",
    "catalog_identity_present",
    "lifecycle_identity_present",
    "runtime_role_present",
  ]);

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
    name: fixture.name,
    phase: fixture.phase ?? fixture.transport?.phase,
    transport: fixture.transport,
  };
  if (
    typeof normalized.name !== "string" ||
    !safeIdentifier.test(normalized.name) ||
    !normalized.transport ||
    normalized.transport.phase !== normalized.phase ||
    !phases.has(normalized.phase)
  ) {
    throw new Error();
  }
  normalizeExpectedObjects(normalized.expectedObjects);
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
  if (mutationKeyword.test(withoutLiterals) || sessionMutationKeyword.test(withoutLiterals)) {
    throw new Error();
  }
}

function assertProbeResult(result) {
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

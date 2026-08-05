import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import net from "node:net";

import { Pool } from "pg";

import {
  RUNTIME_TABLE_GRANT_CONTRACT,
} from "../dist/db/runtime-grant-contract.js";
import {
  admitDisposablePostgresConstructionTargets,
  admitDisposablePostgresFixtures,
  createAuthorizedDatabaseCreationPool,
  createAuthorizedProvisioningPool,
  deriveDisposablePostgresDatabaseCreationAuthority,
  deriveDisposablePostgresProvisioningAuthority,
  invalidateDisposablePostgresAdmission,
  invalidateDisposablePostgresConstructionAdmission,
} from "../tests/support/disposable-postgres-fixture.mjs";
import { runDisposableRuntimeLifecycle } from "./disposable-runtime-lifecycle.mjs";

const databaseName = "migrator_alignment_test";
const secondaryDatabaseName = "migrator_alignment_test_secondary";
const ownedContainerName = "deepseek-platform128-pg17";
const ownedPort = 56432;
const maxChildOutputBytes = 64 * 1024;
const maxChildDurationMs = 120_000;
const expectedPostgresTestCount = 4;
const safeIdentifier = /^[a-z_][a-z0-9_$]{0,62}$/u;
const loopbackHosts = new Set(["127.0.0.1", "::1"]);
const failurePhases = new Set([
  "construct",
  "admitConstruction",
  "deriveProvisioning",
  "provision",
  "admitConfigured",
  "runFocusedTests",
  "cleanup",
  "absenceVerification",
]);
const failureCategories = new Set([
  "container_preexistence",
  "listener_preexistence",
  "container_start",
  "postgres_readiness",
  "secondary_database_creation",
  "construction_target_admission",
  "provisioning_authority",
  "primary_provisioning",
  "secondary_provisioning",
  "configured_fixture_admission",
  "child_test_spawn",
  "child_test_failure",
  "child_output_overflow",
  "child_summary_parse",
  "child_signal",
  "cleanup",
  "absence_verification",
  "ci_environment_unclassified",
]);

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1])
) {
  run().catch((error) => {
    process.stderr.write(
      `${error?.runtimeFailureReceipt ?? formatDisposableRuntimeFailureReceipt()}` +
        "\n",
    );
    process.stderr.write("Disposable migrator alignment test runner failed.\n");
    process.exitCode = 1;
  });
}

export async function run({
  env = process.env,
  spawnImpl = spawn,
} = {}) {
  let resources = null;

  try {
    return await runDisposableRuntimeLifecycle({
    construct: async (lifecycleResources) => {
      resources = lifecycleResources;
      Object.assign(resources, {
        phase: "construct",
        failurePhase: null,
        failureCategory: null,
        childExitCode: null,
        childSignal: false,
        childOutputOverflow: false,
        childSummaryParsed: false,
        containerStarted: false,
        postgresReady: false,
        constructionAdmission: false,
        provisioningComplete: false,
        configuredAdmission: false,
        childTestsStarted: false,
        cleanupComplete: false,
        absenceVerified: false,
        containerStartAttempted: false,
        ownedContainer: false,
        containerRemoved: false,
        childProcess: null,
        childExited: true,
        databaseUrls: new Map(),
        ownedDatabases: new Set(),
        ownedRoles: new Set([
          "platform_app",
          "platform_migrator",
          "platform_runtime",
          "provider_owner",
        ]),
        ownedSchemas: new Set(["drizzle", "appdata"]),
        ownedObjects: new Set([
          "drizzle.__drizzle_migrations",
          "public.users",
          "appdata.widgets",
          "appdata.widgets_label_uidx",
          "appdata.widget_status",
          "appdata.counter_seq",
          "appdata.widget_summary",
          ...contractTableNames().map((name) => `public.${name}`),
        ]),
        runnerOwned: new Set(),
        callerManaged: new Set([
          "docker daemon",
          "postgres default database",
        ]),
      });
      await runAt(resources, "construct", "container_preexistence", async () => {
        assertNoCallerSuppliedFixture(env);
        await assertExactContainerAbsent(spawnImpl);
      });
      await runAt(resources, "construct", "listener_preexistence", async () => {
        await assertOwnedListenerAbsent();
      });
      resources.containerStartAttempted = true;
      await runAt(resources, "construct", "container_start", () =>
        startOwnedContainer(spawnImpl));
      resources.ownedContainer = true;
      resources.containerStarted = true;
      resources.runnerOwned.add(`container:${ownedContainerName}`);
      resources.runnerOwned.add(`listener:127.0.0.1:${ownedPort}`);

      const urls = fixtureUrls();
      resources.databaseUrls = new Map([
        [databaseName, urls.primaryOperatorUrl],
        [secondaryDatabaseName, urls.secondaryOperatorUrl],
      ]);
      resources.ownedDatabases.add(databaseName);

      await runAt(resources, "construct", "postgres_readiness", async () => {
        await waitForPostgres(urls.primaryOperatorUrl);
        resources.postgresReady = true;
      });
      return urls;
    },

    admitConstruction: async (urls) => runAt(
      resources,
      "admitConstruction",
      "construction_target_admission",
      async () => {
        const admission = await admitDisposablePostgresConstructionTargets([
          constructionTargetDefinition("primary", urls.primaryOperatorUrl),
          constructionTargetDefinition(
            "secondary",
            urls.secondaryOperatorUrl,
            urls.rootOperatorUrl,
          ),
        ]);
        resources.constructionAdmission = true;
        return admission;
      },
    ),

    deriveProvisioning: async (constructionAuthority) => runAt(
      resources,
      "deriveProvisioning",
      "provisioning_authority",
      async () => {
        const authorities = new Map();
        for (const targetName of ["primary", "secondary"]) {
          authorities.set(
            targetName,
            deriveDisposablePostgresProvisioningAuthority(
              constructionAuthority,
              targetName,
            ),
          );
        }
        return {
          authorities,
          creationAuthorities: new Map([
            [
              "secondary",
              deriveDisposablePostgresDatabaseCreationAuthority(
                constructionAuthority,
                "secondary",
              ),
            ],
          ]),
        };
      },
    ),

    provision: async (authorities, urls, lifecycleResources) => {
      await runAt(
        lifecycleResources,
        "provision",
        "secondary_database_creation",
        () => ensureDatabase(
          urls.rootOperatorUrl,
          secondaryDatabaseName,
          authorities.creationAuthorities.get("secondary"),
          lifecycleResources,
        ),
      );
      await runAt(
        lifecycleResources,
        "provision",
        "primary_provisioning",
        () => provisionFixture(
          urls.primaryOperatorUrl,
          databaseName,
          authorities.authorities.get("primary"),
          lifecycleResources,
          "application-public",
        ),
      );
      await runAt(
        lifecycleResources,
        "provision",
        "secondary_provisioning",
        () => provisionFixture(
          urls.secondaryOperatorUrl,
          secondaryDatabaseName,
          authorities.authorities.get("secondary"),
          lifecycleResources,
          "provider-managed-public",
        ),
      );
      lifecycleResources.provisioningComplete = true;
    },

    admitConfigured: async (urls) => runAt(
      resources,
      "admitConfigured",
      "configured_fixture_admission",
      async () => {
        const admission = await admitDisposablePostgresFixtures([
          fixtureDefinition("primary", urls),
          fixtureDefinition("secondary", urls),
        ]);
        resources.configuredAdmission = true;
        return admission;
      },
    ),

    runFocusedTests: async (admission, lifecycleResources) => runAt(
      lifecycleResources,
      "runFocusedTests",
      "child_test_failure",
      () => runFocusedTests({
        admission,
        urls: lifecycleResources.construction,
        spawnImpl,
        resources: lifecycleResources,
      }),
    ),

    cleanup: async (lifecycleResources) => runAt(
      lifecycleResources,
      "cleanup",
      "cleanup",
      async () => {
        await cleanupRunnerResources(lifecycleResources, spawnImpl);
        lifecycleResources.cleanupComplete = true;
      },
    ),

    verifyAbsence: async (lifecycleResources) => runAt(
      lifecycleResources,
      "verifyAbsence",
      "absence_verification",
      async () => {
        await verifyRunnerAbsence(lifecycleResources, spawnImpl);
        lifecycleResources.absenceVerified = true;
      },
    ),
    });
  } catch (error) {
    const failure = error instanceof Error ? error : new Error();
    Object.defineProperty(failure, "runtimeFailureReceipt", {
      configurable: true,
      value: formatDisposableRuntimeFailureReceipt(resources),
    });
    throw failure;
  }
}

export function formatDisposableRuntimeFailureReceipt(resources = {}) {
  const receipt = {
    phase: failurePhases.has(resources.failurePhase)
      ? resources.failurePhase
      : "construct",
    category: failureCategories.has(resources.failureCategory)
      ? resources.failureCategory
      : "ci_environment_unclassified",
    childExitCode: Number.isInteger(resources.childExitCode)
      ? resources.childExitCode
      : null,
    childSignal: resources.childSignal === true,
    outputOverflow: resources.childOutputOverflow === true,
    summaryParsed: resources.childSummaryParsed === true,
    containerStarted: resources.containerStarted === true,
    postgresReady: resources.postgresReady === true,
    constructionAdmission: resources.constructionAdmission === true,
    provisioningComplete: resources.provisioningComplete === true,
    configuredAdmission: resources.configuredAdmission === true,
    childTestsStarted: resources.childTestsStarted === true,
    cleanupComplete: resources.cleanupComplete === true,
    absenceVerified: resources.absenceVerified === true,
  };
  return `Disposable fixture failure receipt: ${JSON.stringify(receipt)}`;
}

export function parseDisposableMigratorAlignmentTestSummary(output) {
  if (typeof output !== "string" || Buffer.byteLength(output, "utf8") > maxChildOutputBytes) {
    return null;
  }
  const normalised = output
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/gu, "")
    .replace(/\r\n?/gu, "\n");
  const lines = normalised.split("\n");
  while (lines.at(-1) === "") lines.pop();
  if (lines.length === 0) return null;

  const fieldPattern = /^\s*([#ℹ])\s+(tests|suites|pass|fail|cancelled|skipped|todo|duration_ms)(?:\s+([^\s].*?))?\s*$/u;
  const summaryStarts = [];
  for (let index = 0; index < lines.length; index += 1) {
    const match = lines[index].match(fieldPattern);
    if (match?.[2] === "tests") summaryStarts.push(index);
  }
  if (summaryStarts.length !== 1) return null;
  const start = summaryStarts[0];
  const fields = new Map();
  let marker = null;
  let expectedIndex = 0;
  const expectedFields = [
    "tests",
    "suites",
    "pass",
    "fail",
    "cancelled",
    "skipped",
    "todo",
    "duration_ms",
  ];
  for (let index = start; index < lines.length; index += 1) {
    const match = lines[index].match(fieldPattern);
    if (!match || (marker !== null && match[1] !== marker)) return null;
    marker ??= match[1];
    if (match[2] !== expectedFields[expectedIndex] || fields.has(match[2])) {
      return null;
    }
    if (typeof match[3] !== "string" || match[3].length === 0) return null;
    fields.set(match[2], match[3]);
    expectedIndex += 1;
    if (match[2] === "duration_ms") {
      if (index !== lines.length - 1) return null;
      break;
    }
  }
  if (expectedIndex !== expectedFields.length) return null;
  if (start > 0) {
    for (const line of lines.slice(0, start)) {
      if (fieldPattern.test(line)) return null;
    }
  }

  const counts = {};
  for (const field of ["tests", "suites", "pass", "fail", "cancelled", "skipped", "todo"]) {
    const value = fields.get(field);
    if (!/^(?:0|[1-9]\d*)$/u.test(value)) return null;
    const count = Number(value);
    if (!Number.isSafeInteger(count)) return null;
    counts[field] = count;
  }
  if (
    counts.tests !== expectedPostgresTestCount ||
    counts.pass !== expectedPostgresTestCount ||
    counts.fail !== 0 ||
    counts.skipped !== 0 ||
    counts.cancelled !== 0 ||
    counts.todo !== 0 ||
    counts.pass + counts.fail + counts.skipped + counts.cancelled + counts.todo !== counts.tests
  ) {
    return null;
  }
  const durationText = fields.get("duration_ms");
  if (!/^(?:0|[1-9]\d*)(?:\.\d+)?$/u.test(durationText)) {
    return null;
  }
  const durationMs = Number(durationText);
  if (
    !Number.isFinite(durationMs) ||
    durationMs < 0 ||
    durationMs > maxChildDurationMs ||
    String(durationMs) !== durationText
  ) {
    return null;
  }
  return {
    cancelled: counts.cancelled,
    failed: counts.fail,
    passed: counts.pass,
    skipped: counts.skipped,
    todo: counts.todo,
    total: counts.tests,
  };
}

async function runAt(resources, phase, category, operation) {
  resources.phase = phase;
  try {
    return await operation();
  } catch (error) {
    if (!resources.failureCategory) {
      resources.failurePhase = phase;
      resources.failureCategory = category;
    }
    throw error;
  }
}

function fixtureUrls() {
  return {
    rootOperatorUrl: buildUrl("postgres", "postgres"),
    primaryTargetUrl: buildUrl("platform_app", databaseName),
    primaryOperatorUrl: buildUrl("postgres", databaseName),
    secondaryTargetUrl: buildUrl("platform_app", secondaryDatabaseName),
    secondaryOperatorUrl: buildUrl("postgres", secondaryDatabaseName),
  };
}

function buildUrl(user, database) {
  if (!safeIdentifier.test(user) || !safeIdentifier.test(database)) {
    throw new Error();
  }
  return `postgres://${user}@127.0.0.1:${ownedPort}/${database}`;
}

function constructionTargetDefinition(
  name,
  connectionString,
  creationConnectionString,
) {
  const expectedDatabase = name === "primary"
    ? databaseName
    : secondaryDatabaseName;
  return {
    name,
    connectionString,
    ...(creationConnectionString
      ? {
          allowDatabaseCreation: true,
          creationConnectionString,
          databaseMayBeAbsent: true,
        }
      : {}),
    expectedDatabase,
    expectedUser: "postgres",
    phase: "initialization",
    transport: { kind: "loopback", phase: "initialization" },
  };
}

function fixtureDefinition(name, urls) {
  const secondary = name === "secondary";
  return {
    name,
    connectionString: secondary ? urls.secondaryTargetUrl : urls.primaryTargetUrl,
    expectedDatabase: secondary ? secondaryDatabaseName : databaseName,
    expectedUser: "platform_app",
    expectedRuntimeRole: "platform_runtime",
    expectedMutationUser: "postgres",
    operatorUrl: secondary ? urls.secondaryOperatorUrl : urls.primaryOperatorUrl,
    expectedObjects: {
      schemas: ["public", "appdata", "drizzle"],
      relations: [
        { schema: "drizzle", name: "__drizzle_migrations", kind: "r" },
        { schema: "public", name: "users", kind: "r" },
        { schema: "appdata", name: "widgets", kind: "r" },
        ...contractTableNames().map((name) => ({
          schema: "public",
          name,
          kind: "r",
        })),
      ],
      sequences: [{ schema: "appdata", name: "counter_seq" }],
      routines: [{ schema: "appdata", name: "widget_summary", kind: "f" }],
    },
    transport: { kind: "loopback", phase: "final_start" },
    operatorTransport: { kind: "loopback", phase: "final_start" },
  };
}

async function ensureDatabase(
  operatorUrl,
  expectedDatabase,
  creationAuthority,
  resources,
) {
  const operatorPool = new Pool({ connectionString: operatorUrl, max: 1 });
  try {
    const authorizedPool = createAuthorizedDatabaseCreationPool(
      operatorPool,
      creationAuthority,
    );
    const result = await authorizedPool.query(
      "select 1 from pg_database where datname = $1",
      [expectedDatabase],
    );
    if (result.rows.length === 0) {
      await authorizedPool.query(`create database ${quoteIdentifier(expectedDatabase)}`);
      resources.ownedDatabases.add(expectedDatabase);
      resources.runnerOwned.add(`database:${expectedDatabase}`);
    } else {
      throw new Error();
    }
  } finally {
    await operatorPool.end();
  }
}

async function provisionFixture(
  operatorUrl,
  expectedDatabase,
  authority,
  resources,
  variant,
) {
  const operatorPool = new Pool({ connectionString: operatorUrl, max: 1 });
  const authorizedPool = createAuthorizedProvisioningPool(operatorPool, authority);
  try {
    await authorizedPool.query(`
      do $fixture$
      begin
        if not exists (select 1 from pg_roles where rolname = 'platform_app') then
          create role platform_app login nosuperuser createdb nocreaterole
            noreplication nobypassrls;
        end if;
        if not exists (select 1 from pg_roles where rolname = 'platform_migrator') then
          create role platform_migrator login nosuperuser nocreatedb nocreaterole
            noreplication nobypassrls;
        end if;
        if not exists (select 1 from pg_roles where rolname = 'platform_runtime') then
          create role platform_runtime nologin nosuperuser nocreatedb nocreaterole
            noreplication nobypassrls;
        end if;
        if not exists (select 1 from pg_roles where rolname = 'provider_owner') then
          create role provider_owner nologin nosuperuser nocreatedb nocreaterole
            noreplication nobypassrls;
        end if;
      end
      $fixture$
    `);
    await authorizedPool.query(
      "alter role platform_app login inherit nosuperuser createdb nocreaterole noreplication nobypassrls",
    );
    await authorizedPool.query(
      "alter role platform_migrator login inherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls",
    );
    await authorizedPool.query(
      "alter role platform_runtime nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls",
    );
    await authorizedPool.query(
      "alter role provider_owner nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls",
    );
    await authorizedPool.query("revoke platform_migrator from platform_app");
    await authorizedPool.query("revoke platform_app from platform_migrator");
    await authorizedPool.query("revoke platform_runtime from platform_app");
    await authorizedPool.query("revoke platform_app from platform_runtime");
    await authorizedPool.query("revoke platform_runtime from platform_migrator");
    await authorizedPool.query("revoke platform_migrator from platform_runtime");
    await authorizedPool.query("revoke provider_owner from platform_app");
    await authorizedPool.query("revoke platform_app from provider_owner");
    await authorizedPool.query("revoke provider_owner from platform_migrator");
    await authorizedPool.query("revoke platform_migrator from provider_owner");
    await authorizedPool.query("revoke provider_owner from platform_runtime");
    await authorizedPool.query("revoke platform_runtime from provider_owner");

    const publicOwner = variant === "provider-managed-public"
      ? "provider_owner"
      : "platform_app";
    await authorizedPool.query(
      `alter database ${quoteIdentifier(expectedDatabase)} owner to platform_app`,
    );
    await authorizedPool.query(
      `alter schema public owner to ${quoteIdentifier(publicOwner)}`,
    );
    await authorizedPool.query(
      "create schema appdata authorization platform_app",
    );
    await authorizedPool.query(
      "create schema drizzle authorization platform_app",
    );
    await authorizedPool.query("alter schema appdata owner to platform_app");
    await authorizedPool.query("alter schema drizzle owner to platform_app");
    await authorizedPool.query(
      "create table drizzle.__drizzle_migrations (id integer primary key, hash text not null)",
    );
    await authorizedPool.query(
      "alter table drizzle.__drizzle_migrations owner to platform_app",
    );
    await authorizedPool.query(
      `grant connect on database ${quoteIdentifier(expectedDatabase)} to platform_app`,
    );
    await authorizedPool.query(
      `grant connect on database ${quoteIdentifier(expectedDatabase)} to platform_migrator`,
    );
    await authorizedPool.query(
      `revoke create on database ${quoteIdentifier(expectedDatabase)} from public`,
    );
    await authorizedPool.query("revoke create on schema public from public");
    await authorizedPool.query("grant usage on schema public to platform_app");
    await authorizedPool.query("grant usage on schema appdata to platform_app");
    if (variant === "provider-managed-public") {
      await authorizedPool.query(
        "grant create, usage on schema public to platform_app",
      );
      await authorizedPool.query(
        "grant create, usage on schema public to platform_migrator",
      );
    }

    await authorizedPool.query(
      "create type appdata.widget_status as enum ('active', 'disabled')",
    );
    await authorizedPool.query(
      "alter type appdata.widget_status owner to platform_app",
    );
    await authorizedPool.query(
      "create table appdata.widgets (id integer primary key, label text not null, status appdata.widget_status not null default 'active')",
    );
    await authorizedPool.query(
      "alter table appdata.widgets owner to platform_app",
    );
    await authorizedPool.query(
      "create unique index widgets_label_uidx on appdata.widgets (label)",
    );
    await authorizedPool.query(
      "create sequence appdata.counter_seq",
    );
    await authorizedPool.query(
      "alter sequence appdata.counter_seq owner to platform_app",
    );
    await authorizedPool.query(
      "create function appdata.widget_summary() returns bigint language sql as $$ select count(*)::bigint from appdata.widgets $$",
    );
    await authorizedPool.query(
      "alter function appdata.widget_summary() owner to platform_app",
    );

    for (const tableName of contractTableNames()) {
      await authorizedPool.query(
        `create table public.${quoteIdentifier(tableName)} (id integer)`,
      );
      await authorizedPool.query(
        `alter table public.${quoteIdentifier(tableName)} owner to platform_app`,
      );
      await authorizedPool.query(
        `revoke all privileges on table public.${quoteIdentifier(tableName)} from platform_runtime`,
      );
    }
    for (const [tableName, privileges] of privilegesByTable()) {
      await authorizedPool.query(
        `grant ${privileges.join(", ")} on table public.${quoteIdentifier(tableName)} to platform_runtime`,
      );
    }
    await authorizedPool.query(
      "revoke all privileges on all sequences in schema public from platform_runtime",
    );
    await authorizedPool.query(
      "revoke all privileges on all functions in schema public from platform_runtime",
    );
    await authorizedPool.query(
      "revoke all privileges on all sequences in schema appdata from platform_runtime",
    );
    await authorizedPool.query(
      "revoke all privileges on all functions in schema appdata from platform_runtime",
    );
    await authorizedPool.query(
      "revoke all privileges on all sequences in schema public from public",
    );
    await authorizedPool.query(
      "revoke all privileges on all functions in schema public from public",
    );
    await authorizedPool.query(
      "revoke all privileges on all sequences in schema appdata from public",
    );
    await authorizedPool.query(
      "revoke all privileges on all functions in schema appdata from public",
    );
    await authorizedPool.query(
      "revoke execute on function appdata.widget_summary() from public",
    );
    await authorizedPool.query(
      "alter default privileges for role postgres revoke execute on functions from public",
    );
    await authorizedPool.query(
      "alter default privileges for role platform_app revoke all privileges on tables from public",
    );
    await authorizedPool.query(
      "alter default privileges for role platform_app revoke all privileges on sequences from public",
    );
    await authorizedPool.query(
      "alter default privileges for role platform_app revoke execute on functions from public",
    );
    await authorizedPool.query(
      "alter default privileges for role platform_migrator revoke all privileges on tables from public",
    );
    await authorizedPool.query(
      "alter default privileges for role platform_migrator revoke all privileges on sequences from public",
    );
    await authorizedPool.query(
      "alter default privileges for role platform_migrator revoke execute on functions from public",
    );
    await authorizedPool.query(
      "alter default privileges for role provider_owner revoke all privileges on tables from public",
    );
    await authorizedPool.query(
      "alter default privileges for role provider_owner revoke all privileges on sequences from public",
    );
    await authorizedPool.query(
      "alter default privileges for role provider_owner revoke execute on functions from public",
    );
    resources.runnerOwned.add(`role:platform_app:${expectedDatabase}`);
    resources.runnerOwned.add(`role:platform_migrator:${expectedDatabase}`);
    resources.runnerOwned.add(`role:platform_runtime:${expectedDatabase}`);
    resources.runnerOwned.add(`role:provider_owner:${expectedDatabase}`);
    resources.runnerOwned.add(`schema:drizzle:${expectedDatabase}`);
    resources.runnerOwned.add(`schema:appdata:${expectedDatabase}`);
    for (const object of resources.ownedObjects) {
      resources.runnerOwned.add(`${object}:${expectedDatabase}`);
    }
  } finally {
    await authorizedPool.end();
  }
}

async function runFocusedTests({ admission, urls, spawnImpl, resources }) {
  const env = {
    ...process.env,
    MIGRATOR_ALIGNMENT_TEST_DATABASE_URL: urls.primaryTargetUrl,
    MIGRATOR_ALIGNMENT_TEST_OPERATOR_URL: urls.primaryOperatorUrl,
    MIGRATOR_ALIGNMENT_TEST_SECONDARY_DATABASE_URL: urls.secondaryTargetUrl,
    MIGRATOR_ALIGNMENT_TEST_SECONDARY_OPERATOR_URL: urls.secondaryOperatorUrl,
    MIGRATOR_ALIGNMENT_TEST_CONFIRM: "disposable-only",
  };
  await new Promise((resolvePromise, reject) => {
    const output = [];
    let outputLength = 0;
    let outputOverflow = false;
    let child;
    try {
      child = spawnImpl(
        process.execPath,
        [
          "--test",
          "tests/platform-migrator-alignment-postgres.test.mjs",
        ],
        { env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true },
      );
    } catch (error) {
      markChildFailure(resources, "child_test_spawn");
      throw error;
    }
    resources.childProcess = child;
    resources.childExited = false;
    resources.childTestsStarted = true;
    child.stdout?.on("data", (chunk) => {
      outputLength += chunk.length;
      if (outputLength <= 64 * 1024) {
        output.push(Buffer.from(chunk));
      } else {
        outputOverflow = true;
      }
    });
    child.stderr?.resume();
    child.once("error", (error) => {
      markChildFailure(resources, "child_test_spawn");
      reject(error);
    });
    child.once("close", (code, signal) => {
      resources.childExited = true;
      resources.childExitCode = Number.isInteger(code) ? code : null;
      resources.childSignal = signal !== null;
      if (resources.childSignal) {
        markChildFailure(resources, "child_signal");
        reject(new Error());
        return;
      }
      if (outputOverflow) {
        resources.childOutputOverflow = true;
        markChildFailure(resources, "child_output_overflow");
        reject(new Error());
        return;
      }
      if (code !== 0) {
        markChildFailure(resources, "child_test_failure");
        reject(new Error());
        return;
      }
      if (code === 0 && signal === null && !outputOverflow) {
        const summary = parseDisposableMigratorAlignmentTestSummary(
          Buffer.concat(output).toString("utf8"),
        );
        if (!summary) {
          markChildFailure(resources, "child_summary_parse");
          reject(new Error());
          return;
        }
        resources.childSummaryParsed = true;
        process.stdout.write(
          `Disposable PostgreSQL 17 migrator alignment tests: ${summary.total} total, ${summary.passed} passed, ${summary.failed} failed, ${summary.skipped} skipped.\n`,
        );
        resolvePromise();
      }
    });
  });
  void admission;
}

function markChildFailure(resources, category) {
  if (!resources.failureCategory) {
    resources.failurePhase = "runFocusedTests";
    resources.failureCategory = category;
  }
}

async function cleanupRunnerResources(resources, spawnImpl) {
  let firstError = null;
  try {
    if (resources.constructionAuthority) {
      invalidateDisposablePostgresConstructionAdmission(
        resources.constructionAuthority,
      );
    }
  } catch {
    firstError ??= new Error();
  }
  try {
    if (resources.configuredAdmission) {
      invalidateDisposablePostgresAdmission(resources.configuredAdmission);
    }
  } catch {
    firstError ??= new Error();
  }
  try {
    await terminateOwnedChild(resources);
  } catch {
    firstError ??= new Error();
  }
  try {
    await cleanupFixtureDatabases(resources);
  } catch {
    firstError ??= new Error();
  }
  if (resources.containerStartAttempted) {
    try {
      await runCommand(spawnImpl, "docker", [
        "rm",
        "--force",
        ownedContainerName,
      ]);
      resources.containerRemoved = true;
    } catch {
      firstError ??= new Error();
    }
  }
  if (firstError) throw firstError;
}

async function cleanupFixtureDatabases(resources) {
  if (!resources.ownedContainer || resources.ownedDatabases.size === 0) {
    return;
  }
  const rootUrl = buildUrl("postgres", "postgres");
  for (const database of resources.ownedDatabases) {
    const pool = new Pool({ connectionString: buildUrl("postgres", database), max: 1 });
    try {
      for (const tableName of ["users", ...contractTableNames()]) {
        await pool.query(
          `drop table if exists public.${quoteIdentifier(tableName)} cascade`,
        );
      }
      await pool.query("drop schema if exists drizzle cascade");
      await pool.query("drop schema if exists appdata cascade");
    } finally {
      await pool.end();
    }
  }
  const rootPool = new Pool({ connectionString: rootUrl, max: 1 });
  try {
    for (const database of resources.ownedDatabases) {
      await rootPool.query(
        `drop database if exists ${quoteIdentifier(database)} with (force)`,
      );
    }
    const roleResult = await rootPool.query(
      "select rolname from pg_roles where rolname <> 'postgres' and rolname not like 'pg_%'",
    );
    const roleNames = new Set(resources.ownedRoles);
    for (const row of roleResult.rows) {
      if (typeof row.rolname !== "string" || !safeIdentifier.test(row.rolname)) {
        throw new Error();
      }
      roleNames.add(row.rolname);
    }
    for (const roleName of roleNames) {
      await rootPool.query(`drop role if exists ${quoteIdentifier(roleName)}`);
    }
  } finally {
    await rootPool.end();
  }
}

async function verifyRunnerAbsence(resources, spawnImpl) {
  if (resources.childProcess && !resources.childExited) throw new Error();
  if (!resources.containerStartAttempted) return;
  const names = await assertExactContainerAbsent(spawnImpl);
  if (names !== "") throw new Error();
  if (!resources.containerRemoved) throw new Error();
  await assertPortAbsent();
}

async function terminateOwnedChild(resources) {
  const child = resources.childProcess;
  if (!child || resources.childExited) return;
  if (typeof child.kill !== "function" || !child.kill("SIGTERM")) {
    throw new Error();
  }
  await new Promise((resolvePromise, reject) => {
    const timer = setTimeout(() => reject(new Error()), 2_000);
    child.once("close", () => {
      clearTimeout(timer);
      resources.childExited = true;
      resolvePromise();
    });
  });
}

async function startOwnedContainer(spawnImpl) {
  await runCommand(spawnImpl, "docker", [
    "run",
    "--detach",
    "--name",
    ownedContainerName,
    "--publish",
    `${ownedPort}:5432`,
    "--env",
    `POSTGRES_DB=${databaseName}`,
    "--env",
    "POSTGRES_HOST_AUTH_METHOD=trust",
    "postgres:17",
  ]);
}

async function waitForPostgres(connectionString) {
  for (let attempt = 0; attempt < 240; attempt += 1) {
    const pool = new Pool({ connectionString, max: 1, connectionTimeoutMillis: 1_000 });
    try {
      await pool.query("select 1");
      return;
    } catch {
      await delay(500);
    } finally {
      await pool.end();
    }
  }
  throw new Error();
}

async function assertExactContainerAbsent(spawnImpl) {
  const output = await runCommand(spawnImpl, "docker", [
    "ps",
    "--all",
    "--filter",
    `name=^/${ownedContainerName}$`,
    "--format",
    "{{.Names}}",
  ]);
  return output.trim();
}

async function assertOwnedListenerAbsent() {
  await new Promise((resolvePromise, reject) => {
    const socket = net.createConnection({
      host: "127.0.0.1",
      port: ownedPort,
    });
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (error) reject(error);
      else resolvePromise();
    };
    socket.setTimeout(1_000, () => finish(new Error()));
    socket.once("connect", () => finish(new Error()));
    socket.once("error", (error) => {
      if (["ECONNREFUSED", "EHOSTUNREACH"].includes(error.code)) {
        finish();
      } else {
        finish(new Error());
      }
    });
  });
}

async function assertPortAbsent() {
  await assertOwnedListenerAbsent();
}

async function runCommand(spawnImpl, command, args) {
  return new Promise((resolvePromise, reject) => {
    const child = spawnImpl(command, args, {
      stdio: ["ignore", "pipe", "ignore"],
      windowsHide: true,
    });
    const output = [];
    let outputLength = 0;
    let settled = false;
    const fail = () => {
      if (settled) return;
      settled = true;
      reject(new Error());
    };
    child.once("error", fail);
    child.once("close", (code, signal) => {
      if (settled) return;
      settled = true;
      if (code !== 0 || signal !== null || outputLength > 1_024) {
        reject(new Error());
        return;
      }
      resolvePromise(Buffer.concat(output).toString("utf8"));
    });
    child.stdout?.on("data", (chunk) => {
      outputLength += chunk.length;
      if (outputLength <= maxChildOutputBytes) output.push(Buffer.from(chunk));
    });
  });
}

function assertNoCallerSuppliedFixture(env) {
  const names = [
    "MIGRATOR_ALIGNMENT_TEST_DATABASE_URL",
    "MIGRATOR_ALIGNMENT_TEST_OPERATOR_URL",
    "MIGRATOR_ALIGNMENT_TEST_SECONDARY_DATABASE_URL",
    "MIGRATOR_ALIGNMENT_TEST_SECONDARY_OPERATOR_URL",
  ];
  if (names.some((name) => typeof env?.[name] === "string" && env[name])) {
    throw new Error();
  }
}

function contractTableNames() {
  return [...new Set(
    RUNTIME_TABLE_GRANT_CONTRACT.map((record) => record.objectName),
  )];
}

function privilegesByTable() {
  const values = new Map();
  for (const record of RUNTIME_TABLE_GRANT_CONTRACT) {
    const privileges = values.get(record.objectName) ?? [];
    privileges.push(record.privilege);
    values.set(record.objectName, privileges);
  }
  return values;
}

function quoteIdentifier(value) {
  if (!safeIdentifier.test(value)) throw new Error();
  return `"${value.replaceAll('"', '""')}"`;
}

import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";

export const PLATFORM_RUNTIME_ACTIVATION_PHASES = Object.freeze([
  "dormant_role_preflight",
  "password_installation",
  "login_enablement",
  "runtime_connection_construction",
  "runtime_connection_establishment",
  "runtime_identity",
  "recursive_set_role_posture",
  "grants_and_ownership_verification",
  "success_finalisation",
  "mandatory_rollback",
]);

const safeRoleIdentifier = /^[a-z_][a-z0-9_$]{0,62}$/;
const safeDatabaseIdentifier = /^[a-z_][a-z0-9_$]{0,62}$/;
const safeNeonProjectId = /^[a-z][a-z0-9-]{2,62}$/;
const safeNeonBranchId = /^br-[a-z0-9][a-z0-9-]{2,61}$/;
const safeNeonEndpointId = /^ep-[a-z0-9][a-z0-9-]{2,61}$/;
const safeFixtureIdentity = /^[0-9]+:[0-9]+$/;
const neonProviderEvidenceKeys = Object.freeze([
  "branchId",
  "database",
  "endpoints",
  "expiresAt",
  "observedAt",
  "projectId",
  "provider",
]);
const neonEndpointEvidenceKeys = Object.freeze([
  "database",
  "host",
  "id",
  "kind",
]);
const neonEndpointKinds = new Set(["direct", "pooled"]);
const maximumProviderEvidenceValidityMs = 15 * 60 * 1_000;
const phaseSet = new Set(PLATFORM_RUNTIME_ACTIVATION_PHASES);
const targetRoles = new WeakMap();
const targetProviderValues = new WeakMap();
const providerBindingValues = new WeakMap();
const fixtureIdentityValues = new WeakMap();
const mutationErrorStates = new WeakMap();
const fixtureMismatchExitCode = 86;
const allowedConnectionParameters = new Map([
  ["sslmode", new Set(["require", "verify-ca", "verify-full"])],
  ["channel_binding", new Set(["require"])],
]);

export class PlatformRuntimeActivationError extends Error {
  constructor({ mutationMayHaveBegun = false } = {}) {
    super("Runtime activation failed.");
    this.name = "PlatformRuntimeActivationError";
    this.code = "runtime_activation_failed";
    mutationErrorStates.set(this, mutationMayHaveBegun === true);
  }
}

export class PlatformRuntimeActivationPhaseJournal {
  #activePhase = null;
  #failedPhase = null;
  #nextPhaseIndex = 0;
  #states = Object.fromEntries(
    PLATFORM_RUNTIME_ACTIVATION_PHASES.map((phase) => [phase, "pending"]),
  );

  start(phase) {
    assertPhase(phase);
    const isRollback = phase === "mandatory_rollback";
    const expectedPhase =
      PLATFORM_RUNTIME_ACTIVATION_PHASES[this.#nextPhaseIndex];
    const allowed =
      isRollback
        ? this.#failedPhase !== null
        : this.#failedPhase === null && phase === expectedPhase;
    if (
      !allowed ||
      this.#activePhase ||
      this.#states[phase] !== "pending"
    ) {
      throw new PlatformRuntimeActivationError();
    }
    this.#activePhase = phase;
    this.#states[phase] = "in_progress";
  }

  pass() {
    if (!this.#activePhase) {
      throw new PlatformRuntimeActivationError();
    }
    const completedPhase = this.#activePhase;
    this.#states[completedPhase] = "passed";
    this.#activePhase = null;
    if (completedPhase !== "mandatory_rollback") {
      this.#nextPhaseIndex += 1;
    }
  }

  fail() {
    if (!this.#activePhase) {
      throw new PlatformRuntimeActivationError();
    }
    this.#states[this.#activePhase] = "failed";
    this.#failedPhase ??= this.#activePhase;
    this.#activePhase = null;
  }

  notRequired(phase) {
    assertPhase(phase);
    if (
      phase !== "mandatory_rollback" ||
      this.#failedPhase !== null ||
      this.#nextPhaseIndex !== PLATFORM_RUNTIME_ACTIVATION_PHASES.length - 1 ||
      this.#activePhase ||
      this.#states[phase] !== "pending"
    ) {
      throw new PlatformRuntimeActivationError();
    }
    this.#states[phase] = "not_required";
  }

  safeReport() {
    return Object.freeze({
      failedPhase: this.#failedPhase,
      rollbackTriggered:
        this.#states.mandatory_rollback !== "pending" &&
        this.#states.mandatory_rollback !== "not_required",
      rollbackVerified: this.#states.mandatory_rollback === "passed",
      phases: Object.freeze({ ...this.#states }),
    });
  }
}

export class PlatformRuntimeActivationMutationTracker {
  #target;
  #validatedFixtureIdentity = null;
  #validatedProviderFingerprint = null;
  #installationStarted = false;
  #mutationMayHaveBegun = false;

  constructor(target) {
    targetRole(target);
    this.#target = target;
  }

  fixtureValidated(
    target,
    directIdentity,
    dockerIdentity,
    currentProviderBinding,
    { now = Date.now() } = {},
  ) {
    this.#assertTarget(target);
    if (
      this.#installationStarted ||
      this.#validatedFixtureIdentity ||
      this.#validatedProviderFingerprint
    ) {
      throw new PlatformRuntimeActivationError();
    }
    assertMatchingPostgresFixtureIdentities(
      directIdentity,
      dockerIdentity,
    );
    const providerValue = matchingProviderBindingValue(
      target,
      currentProviderBinding,
      { now },
    );
    this.#validatedFixtureIdentity = fixtureIdentityValue(directIdentity);
    this.#validatedProviderFingerprint = providerValue.fingerprint;
  }

  passwordInstallationStarted(target, { now = Date.now() } = {}) {
    this.#assertTarget(target);
    if (
      this.#installationStarted ||
      !this.#validatedFixtureIdentity ||
      !this.#validatedProviderFingerprint
    ) {
      throw new PlatformRuntimeActivationError();
    }
    const providerValue = activationTargetValue(target, { now });
    if (
      providerValue.providerFingerprint !==
      this.#validatedProviderFingerprint
    ) {
      throw new PlatformRuntimeActivationError();
    }
    this.#installationStarted = true;
    this.#mutationMayHaveBegun = true;
  }

  passwordInstallationFailed(target, error) {
    this.#assertTarget(target);
    if (!this.#installationStarted) {
      throw new PlatformRuntimeActivationError();
    }
    this.#mutationMayHaveBegun =
      runtimeActivationMutationMayHaveBegun(error);
  }

  rollbackRequired(target) {
    this.#assertTarget(target);
    return this.#mutationMayHaveBegun;
  }

  assertRollbackFixture(
    target,
    currentIdentity,
    currentProviderBinding,
    { now = Date.now() } = {},
  ) {
    this.#assertTarget(target);
    const providerValue = matchingProviderBindingValue(
      target,
      currentProviderBinding,
      { now },
    );
    if (
      !this.#mutationMayHaveBegun ||
      !this.#validatedFixtureIdentity ||
      !this.#validatedProviderFingerprint ||
      fixtureIdentityValue(currentIdentity) !==
        this.#validatedFixtureIdentity ||
      providerValue.fingerprint !== this.#validatedProviderFingerprint
    ) {
      throw new PlatformRuntimeActivationError();
    }
  }

  rollbackCompleted(target) {
    this.#assertTarget(target);
    if (!this.#mutationMayHaveBegun) {
      throw new PlatformRuntimeActivationError();
    }
    this.#mutationMayHaveBegun = false;
  }

  successFinalised(
    target,
    currentProviderBinding,
    { now = Date.now() } = {},
  ) {
    this.#assertTarget(target);
    const providerValue = matchingProviderBindingValue(
      target,
      currentProviderBinding,
      { now },
    );
    if (
      !this.#mutationMayHaveBegun ||
      providerValue.fingerprint !== this.#validatedProviderFingerprint
    ) {
      throw new PlatformRuntimeActivationError();
    }
    this.#mutationMayHaveBegun = false;
  }

  #assertTarget(target) {
    if (target !== this.#target) {
      throw new PlatformRuntimeActivationError();
    }
  }
}

export function createNeonProviderTargetBinding(
  evidence,
  { now = Date.now() } = {},
) {
  const value = validateNeonProviderEvidence(evidence, now);
  const binding = Object.freeze({});
  providerBindingValues.set(binding, value);
  return binding;
}

export function createRuntimeActivationTarget(
  runtimeRole,
  {
    providerBinding,
    directEndpointId,
    directOperatorUrl,
    dockerEndpointId,
    dockerEndpointKind,
    dockerOperatorUrl,
    expectedDatabase,
  } = {},
  { now = Date.now() } = {},
) {
  if (
    !safeRoleIdentifier.test(runtimeRole) ||
    !safeDatabaseIdentifier.test(expectedDatabase)
  ) {
    throw new PlatformRuntimeActivationError();
  }
  const providerValue = providerBindingValue(providerBinding, { now });
  const directEndpoint = providerEndpoint(
    providerValue,
    directEndpointId,
    expectedDatabase,
    "direct",
  );
  const dockerEndpoint = providerEndpoint(
    providerValue,
    dockerEndpointId,
    expectedDatabase,
    dockerEndpointKind,
  );
  if (
    providerValue.database !== expectedDatabase ||
    !directEndpoint ||
    !dockerEndpoint
  ) {
    throw new PlatformRuntimeActivationError();
  }
  assertProviderConnectionUrl(
    directOperatorUrl,
    directEndpoint,
    expectedDatabase,
  );
  assertProviderConnectionUrl(
    dockerOperatorUrl,
    dockerEndpoint,
    expectedDatabase,
  );
  const target = Object.freeze({});
  targetRoles.set(target, runtimeRole);
  targetProviderValues.set(
    target,
    Object.freeze({
      directEndpointId,
      directEndpointHost: directEndpoint.host,
      dockerEndpointId,
      dockerEndpointKind,
      dockerEndpointHost: dockerEndpoint.host,
      expectedDatabase,
      providerBinding,
      providerFingerprint: providerValue.fingerprint,
    }),
  );
  return target;
}

export function runtimeActivationRole(
  target,
  { now = Date.now() } = {},
) {
  activationTargetValue(target, { now });
  return targetRole(target);
}

export function runtimeActivationNonSecretProviderMetadata(target) {
  const targetValue = activationTargetValue(target);
  const providerValue = providerBindingValue(targetValue.providerBinding);
  return Object.freeze({
    classification: "non_secret_provider_target_metadata",
    provider: providerValue.provider,
    projectId: providerValue.projectId,
    branchId: providerValue.branchId,
    database: providerValue.database,
    endpoints: Object.freeze(
      providerValue.endpoints.map((endpoint) =>
        Object.freeze({ id: endpoint.id, kind: endpoint.kind }),
      ),
    ),
    observedAt: providerValue.observedAt,
    expiresAt: providerValue.expiresAt,
  });
}

export function assertRuntimeActivationProviderBinding(
  target,
  currentProviderBinding,
  { now = Date.now() } = {},
) {
  matchingProviderBindingValue(target, currentProviderBinding, { now });
}

function matchingProviderBindingValue(
  target,
  currentProviderBinding,
  { now = Date.now() } = {},
) {
  const targetValue = activationTargetValue(target, { now });
  const currentValue = providerBindingValue(currentProviderBinding, { now });
  if (
    currentProviderBinding !== targetValue.providerBinding ||
    currentValue.fingerprint !== targetValue.providerFingerprint
  ) {
    throw new PlatformRuntimeActivationError();
  }
  return currentValue;
}

export function runtimeActivationMutationMayHaveBegun(error) {
  return (
    error instanceof PlatformRuntimeActivationError &&
    mutationErrorStates.get(error) === true
  );
}

export function buildRuntimeDatabaseUrl(
  operatorUrl,
  target,
  runtimePassword,
  { now = Date.now() } = {},
) {
  const runtimeRole = targetRole(target);
  const targetValue = activationTargetValue(target, { now });
  if (
    typeof runtimePassword !== "string" ||
    runtimePassword.length === 0 ||
    containsLineBreakOrNull(runtimePassword)
  ) {
    throw new PlatformRuntimeActivationError();
  }

  const parsed = parseOperatorUrl(operatorUrl);
  assertProviderConnectionHost(parsed, targetValue.directEndpointHost);
  assertUrlDatabase(parsed, targetValue.expectedDatabase);
  const reviewedParameters = validateConnectionParameters(parsed);

  parsed.username = encodeURIComponent(runtimeRole);
  parsed.password = encodeURIComponent(runtimePassword);
  parsed.hash = "";
  parsed.search = "";
  for (const [name, value] of reviewedParameters) {
    parsed.searchParams.append(name, value);
  }
  return parsed.toString();
}

export function buildRuntimeRoleStatement(
  target,
  operation,
  { now = Date.now() } = {},
) {
  activationTargetValue(target, { now });
  const runtimeRole = targetRole(target);
  const quotedRole = `"${runtimeRole}"`;
  if (operation === "enable_login") {
    return `ALTER ROLE ${quotedRole} LOGIN`;
  }
  if (operation === "rollback") {
    return `ALTER ROLE ${quotedRole} NOLOGIN PASSWORD NULL`;
  }
  throw new PlatformRuntimeActivationError();
}

export function assertRuntimeIdentity(
  row,
  target,
  expectedDatabase,
  { now = Date.now() } = {},
) {
  const runtimeRole = targetRole(target);
  const targetValue = activationTargetValue(target, { now });
  if (
    !row ||
    typeof row !== "object" ||
    typeof expectedDatabase !== "string" ||
    expectedDatabase.length === 0 ||
    expectedDatabase !== targetValue.expectedDatabase ||
    row.current_database !== expectedDatabase ||
    row.current_user !== runtimeRole ||
    row.session_user !== runtimeRole
  ) {
    throw new PlatformRuntimeActivationError();
  }
}

export async function readPostgresFixtureIdentity(client) {
  let result;
  try {
    result = await client.query(
      `
        select
          control.system_identifier::text as system_identifier,
          database_record.oid::text as database_oid
        from pg_control_system() control
        join pg_database database_record
          on database_record.datname = current_database()
      `,
      [],
    );
  } catch {
    throw new PlatformRuntimeActivationError();
  }
  if (
    !result ||
    !Array.isArray(result.rows) ||
    result.rows.length !== 1
  ) {
    throw new PlatformRuntimeActivationError();
  }
  return createFixtureIdentity(
    result.rows[0].system_identifier,
    result.rows[0].database_oid,
  );
}

export async function readDockerPostgresFixtureIdentity({
  operatorUrl,
  target,
  dockerImage = "postgres:17",
  spawnImpl = spawn,
  terminationSpawnImpl = spawn,
  timeoutMs = 30_000,
  terminationGraceMs = 5_000,
  terminationRetryMs = 1_000,
  terminationAttempts = 2,
  now = Date.now(),
}) {
  const targetValue = activationTargetValue(target, { now });
  validateDockerInputs({ operatorUrl, dockerImage, timeoutMs });
  const parsedOperatorUrl = parseOperatorUrl(operatorUrl);
  assertProviderConnectionHost(
    parsedOperatorUrl,
    targetValue.dockerEndpointHost,
  );
  assertUrlDatabase(parsedOperatorUrl, targetValue.expectedDatabase);
  validateConnectionParameters(parsedOperatorUrl);
  validateTerminationInputs({
    terminationAttempts,
    terminationGraceMs,
    terminationRetryMs,
  });
  const containerName = dockerContainerName("identity");
  const childEnvironment = dockerEnvironment(operatorUrl);
  const input = Buffer.from(
    [
      "select control.system_identifier::text || ':' || database_record.oid::text",
      "from pg_control_system() control",
      "join pg_database database_record",
      "  on database_record.datname = current_database();",
      "\\q",
      "",
    ].join("\n"),
    "utf8",
  );

  try {
    const output = await runReadOnlyDockerPsql({
      childEnvironment,
      containerName,
      dockerImage,
      input,
      spawnImpl,
      terminationAttempts,
      terminationGraceMs,
      terminationRetryMs,
      terminationSpawnImpl,
      timeoutMs,
    });
    const value = output.trim();
    if (!safeFixtureIdentity.test(value)) {
      throw new PlatformRuntimeActivationError();
    }
    const [systemIdentifier, databaseOid] = value.split(":");
    return createFixtureIdentity(systemIdentifier, databaseOid);
  } catch {
    throw new PlatformRuntimeActivationError();
  } finally {
    input.fill(0);
  }
}

export function assertMatchingPostgresFixtureIdentities(
  directIdentity,
  dockerIdentity,
) {
  const directValue = fixtureIdentityValue(directIdentity);
  const dockerValue = fixtureIdentityValue(dockerIdentity);
  if (directValue !== dockerValue) {
    throw new PlatformRuntimeActivationError();
  }
}

export async function installRuntimePasswordWithDocker({
  operatorUrl,
  target,
  runtimePassword,
  expectedFixtureIdentity,
  dockerImage = "postgres:17",
  spawnImpl = spawn,
  terminationSpawnImpl = spawn,
  timeoutMs = 30_000,
  terminationGraceMs = 5_000,
  terminationRetryMs = 1_000,
  terminationAttempts = 2,
  now = Date.now(),
}) {
  const runtimeRole = targetRole(target);
  const targetValue = activationTargetValue(target, { now });
  const fixtureIdentity = fixtureIdentityValue(expectedFixtureIdentity);
  validateDockerInputs({ operatorUrl, dockerImage, timeoutMs });
  validateTerminationInputs({
    terminationAttempts,
    terminationGraceMs,
    terminationRetryMs,
  });
  if (!isStrongRuntimePassword(runtimePassword)) {
    throw new PlatformRuntimeActivationError();
  }
  const parsedOperatorUrl = parseOperatorUrl(operatorUrl);
  assertProviderConnectionHost(
    parsedOperatorUrl,
    targetValue.dockerEndpointHost,
  );
  assertUrlDatabase(parsedOperatorUrl, targetValue.expectedDatabase);
  validateConnectionParameters(parsedOperatorUrl);

  const containerName = dockerContainerName("password");
  const input = Buffer.from(
    [
      "\\set ON_ERROR_STOP on",
      `\\set expected_fixture_identity '${fixtureIdentity}'`,
      "select (control.system_identifier::text || ':' || database_record.oid::text)",
      "  = :'expected_fixture_identity' as fixture_matches",
      "from pg_control_system() control",
      "join pg_database database_record",
      "  on database_record.datname = current_database()",
      "\\gset",
      "\\if :fixture_matches",
      `\\password ${runtimeRole}`,
      runtimePassword,
      runtimePassword,
      "\\else",
      `\\quit ${fixtureMismatchExitCode}`,
      "\\endif",
      "\\q",
      "",
    ].join("\n"),
    "utf8",
  );
  const childEnvironment = dockerEnvironment(operatorUrl);

  try {
    await runMutationCapableDockerPsql({
      childEnvironment,
      containerName,
      dockerImage,
      input,
      spawnImpl,
      terminationAttempts,
      terminationGraceMs,
      terminationRetryMs,
      terminationSpawnImpl,
      timeoutMs,
    });
  } catch (error) {
    input.fill(0);
    if (error instanceof PlatformRuntimeActivationError) {
      throw error;
    }
    throw new PlatformRuntimeActivationError({
      mutationMayHaveBegun: true,
    });
  } finally {
    input.fill(0);
  }
}

async function runReadOnlyDockerPsql({
  childEnvironment,
  containerName,
  dockerImage,
  input,
  spawnImpl,
  terminationAttempts,
  terminationGraceMs,
  terminationRetryMs,
  terminationSpawnImpl,
  timeoutMs,
}) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const output = [];
    let outputLength = 0;
    let timeoutTimer;
    let processSucceeded = false;

    const finish = (error) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeoutTimer);
      input.fill(0);
      delete childEnvironment.DATABASE_OPERATOR_URL;
      const outputValue = error
        ? undefined
        : Buffer.concat(output).toString("utf8");
      for (const chunk of output) {
        chunk.fill(0);
      }
      if (error) {
        reject(new PlatformRuntimeActivationError());
      } else {
        resolve(outputValue);
      }
    };

    let child;
    try {
      child = spawnDockerPsql({
        childEnvironment,
        containerName,
        dockerImage,
        spawnImpl,
        stdio: ["pipe", "pipe", "ignore"],
      });
    } catch {
      const termination = createConfirmedDockerTermination({
        child: null,
        containerName,
        onConfirmed: () => finish(true),
        terminationAttempts,
        terminationGraceMs,
        terminationRetryMs,
        terminationSpawnImpl,
      });
      termination.begin();
      return;
    }

    const termination = createConfirmedDockerTermination({
      child,
      containerName,
      onConfirmed: () => finish(!processSucceeded),
      terminationAttempts,
      terminationGraceMs,
      terminationRetryMs,
      terminationSpawnImpl,
    });

    timeoutTimer = setTimeout(() => {
      processSucceeded = false;
      termination.begin();
    }, timeoutMs);

    child.once("error", () => {
      processSucceeded = false;
      termination.begin();
    });
    child.once("close", (code, signal) => {
      processSucceeded =
        !termination.started() && code === 0 && signal === null;
      termination.childDidClose();
      if (processSucceeded && !termination.started()) {
        termination.confirmAbsence();
      } else {
        termination.begin();
      }
    });
    child.stdout.on("data", (chunk) => {
      if (termination.started()) {
        return;
      }
      outputLength += chunk.length;
      if (outputLength > 256) {
        processSucceeded = false;
        termination.begin();
        return;
      }
      output.push(Buffer.from(chunk));
    });
    child.stdin.once("error", () => {
      processSucceeded = false;
      termination.begin();
    });
    try {
      child.stdin.end(input);
    } catch {
      processSucceeded = false;
      termination.begin();
    }
  });
}

function createConfirmedDockerTermination({
  child,
  containerName,
  onConfirmed,
  terminationAttempts,
  terminationGraceMs,
  terminationRetryMs,
  terminationSpawnImpl,
}) {
  let terminationStarted = false;
  let childClosed = child === null;
  let cleanupConfirmed = false;
  let cleanupAttempts = 0;
  let cleanupInProgress = false;
  let graceTimer;
  let retryTimer;
  const commandTimeoutMs = Math.max(
    1_000,
    terminationGraceMs,
    terminationRetryMs,
  );

  const finishWhenConfirmed = () => {
    if (!terminationStarted || !childClosed || !cleanupConfirmed) {
      return;
    }
    clearTimeout(graceTimer);
    clearTimeout(retryTimer);
    onConfirmed();
  };

  const scheduleCleanupRetry = () => {
    cleanupInProgress = false;
    if (cleanupAttempts >= terminationAttempts || cleanupConfirmed) {
      return;
    }
    retryTimer = setTimeout(startCleanupAttempt, terminationRetryMs);
  };

  const verifyContainerAbsent = () => {
    let verifyChild;
    try {
      verifyChild = terminationSpawnImpl(
        "docker",
        [
          "ps",
          "--all",
          "--quiet",
          "--filter",
          `name=^/${containerName}$`,
        ],
        {
          stdio: ["ignore", "pipe", "ignore"],
          windowsHide: true,
        },
      );
    } catch {
      scheduleCleanupRetry();
      return;
    }
    let verificationFinished = false;
    const verificationOutput = [];
    let verificationOutputLength = 0;
    const verificationDone = (success) => {
      if (verificationFinished || cleanupConfirmed) {
        return;
      }
      verificationFinished = true;
      clearTimeout(verificationTimer);
      const absent =
        success &&
        verificationOutputLength <= 256 &&
        Buffer.concat(verificationOutput).toString("utf8").trim() === "";
      for (const chunk of verificationOutput) {
        chunk.fill(0);
      }
      if (absent && childClosed) {
        cleanupInProgress = false;
        cleanupConfirmed = true;
        finishWhenConfirmed();
      } else if (absent) {
        cleanupInProgress = false;
      } else {
        scheduleCleanupRetry();
      }
    };
    const verificationTimer = setTimeout(() => {
      try {
        verifyChild.kill?.("SIGKILL");
      } catch {
        // The bounded verification result remains inconclusive.
      }
      verificationDone(false);
    }, commandTimeoutMs);
    verifyChild.once("error", () => verificationDone(false));
    verifyChild.once("close", (code, signal) =>
      verificationDone(code === 0 && signal === null),
    );
    verifyChild.stdout.on("data", (chunk) => {
      verificationOutputLength += chunk.length;
      if (verificationOutputLength <= 256) {
        verificationOutput.push(Buffer.from(chunk));
      }
    });
  };

  const startCleanupAttempt = () => {
    if (cleanupInProgress || cleanupConfirmed) {
      return;
    }
    cleanupInProgress = true;
    cleanupAttempts += 1;
    let cleanupChild;
    try {
      cleanupChild = terminationSpawnImpl(
        "docker",
        ["rm", "--force", containerName],
        {
          stdio: ["ignore", "ignore", "ignore"],
          windowsHide: true,
        },
      );
    } catch {
      verifyContainerAbsent();
      return;
    }
    let cleanupFinished = false;
    const cleanupDone = () => {
      if (cleanupFinished || cleanupConfirmed) {
        return;
      }
      cleanupFinished = true;
      clearTimeout(cleanupTimer);
      verifyContainerAbsent();
    };
    const cleanupTimer = setTimeout(() => {
      try {
        cleanupChild.kill?.("SIGKILL");
      } catch {
        // Exact-name absence verification remains authoritative.
      }
      cleanupDone();
    }, commandTimeoutMs);
    cleanupChild.once("error", cleanupDone);
    cleanupChild.once("close", cleanupDone);
  };

  const escalateTermination = () => {
    if (cleanupConfirmed) {
      return;
    }
    if (!childClosed && child) {
      try {
        child.kill("SIGKILL");
      } catch {
        // Exact-name Docker removal remains authoritative.
      }
    }
    startCleanupAttempt();
  };

  const begin = () => {
    if (terminationStarted || cleanupConfirmed) {
      return;
    }
    terminationStarted = true;
    if (childClosed || !child) {
      escalateTermination();
      return;
    }
    let requested = false;
    try {
      requested = child.kill("SIGTERM") === true;
    } catch {
      requested = false;
    }
    if (requested) {
      graceTimer = setTimeout(escalateTermination, terminationGraceMs);
    } else {
      escalateTermination();
    }
  };

  const childDidClose = () => {
    childClosed = true;
    if (!terminationStarted) {
      return;
    }
    clearTimeout(graceTimer);
    startCleanupAttempt();
    finishWhenConfirmed();
  };

  const confirmAbsence = () => {
    if (terminationStarted || cleanupConfirmed) {
      return;
    }
    terminationStarted = true;
    cleanupInProgress = true;
    verifyContainerAbsent();
  };

  return {
    begin,
    childDidClose,
    confirmAbsence,
    started: () => terminationStarted,
  };
}

async function runMutationCapableDockerPsql({
  childEnvironment,
  containerName,
  dockerImage,
  input,
  spawnImpl,
  terminationAttempts,
  terminationGraceMs,
  terminationRetryMs,
  terminationSpawnImpl,
  timeoutMs,
}) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let terminationMutationMayHaveBegun = true;

    const child = spawnDockerPsql({
      childEnvironment,
      containerName,
      dockerImage,
      spawnImpl,
      stdio: ["pipe", "ignore", "ignore"],
    });

    const finish = (error, mutationMayHaveBegun = false) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeoutTimer);
      input.fill(0);
      delete childEnvironment.DATABASE_OPERATOR_URL;
      if (error) {
        reject(
          new PlatformRuntimeActivationError({
            mutationMayHaveBegun,
          }),
        );
      } else {
        resolve();
      }
    };

    const termination = createConfirmedDockerTermination({
      child,
      containerName,
      onConfirmed: () =>
        finish(true, terminationMutationMayHaveBegun),
      terminationAttempts,
      terminationGraceMs,
      terminationRetryMs,
      terminationSpawnImpl,
    });

    const timeoutTimer = setTimeout(() => {
      terminationMutationMayHaveBegun = true;
      termination.begin();
    }, timeoutMs);

    child.once("error", () => {
      if (!termination.started()) {
        terminationMutationMayHaveBegun = false;
        termination.begin();
      }
    });
    child.once("close", (code, signal) => {
      termination.childDidClose();
      if (!termination.started()) {
        if (code === 0 && signal === null) {
          finish(false);
        } else {
          finish(true, code !== fixtureMismatchExitCode);
        }
        return;
      }
    });
    child.stdin.once("error", () => {
      terminationMutationMayHaveBegun = true;
      termination.begin();
    });
    try {
      child.stdin.end(input);
    } catch {
      terminationMutationMayHaveBegun = true;
      termination.begin();
    }
  });
}

function spawnDockerPsql({
  childEnvironment,
  containerName,
  dockerImage,
  spawnImpl,
  stdio,
}) {
  return spawnImpl(
    "docker",
    [
      "run",
      "--rm",
      "-i",
      "--name",
      containerName,
      "--env",
      "DATABASE_OPERATOR_URL",
      dockerImage,
      "sh",
      "-lc",
      'psql "$DATABASE_OPERATOR_URL" -X -A -t -v ON_ERROR_STOP=1',
    ],
    {
      env: childEnvironment,
      stdio,
      windowsHide: true,
    },
  );
}

function assertPhase(phase) {
  if (!phaseSet.has(phase)) {
    throw new PlatformRuntimeActivationError();
  }
}

function targetRole(target) {
  const runtimeRole =
    target && typeof target === "object" ? targetRoles.get(target) : undefined;
  if (!runtimeRole) {
    throw new PlatformRuntimeActivationError();
  }
  return runtimeRole;
}

function activationTargetValue(
  target,
  { now = Date.now() } = {},
) {
  targetRole(target);
  const value =
    target && typeof target === "object"
      ? targetProviderValues.get(target)
      : undefined;
  if (!value) {
    throw new PlatformRuntimeActivationError();
  }
  const providerValue = providerBindingValue(value.providerBinding, { now });
  if (providerValue.fingerprint !== value.providerFingerprint) {
    throw new PlatformRuntimeActivationError();
  }
  return value;
}

function validateNeonProviderEvidence(evidence, now) {
  if (
    !Number.isInteger(now) ||
    !evidence ||
    typeof evidence !== "object" ||
    Array.isArray(evidence) ||
    !hasExactKeys(evidence, neonProviderEvidenceKeys) ||
    evidence.provider !== "neon" ||
    !safeNeonProjectId.test(evidence.projectId) ||
    !safeNeonBranchId.test(evidence.branchId) ||
    !safeDatabaseIdentifier.test(evidence.database) ||
    !Array.isArray(evidence.endpoints) ||
    evidence.endpoints.length === 0 ||
    evidence.endpoints.length > 8
  ) {
    throw new PlatformRuntimeActivationError();
  }

  const observedMs = parseEvidenceTimestamp(evidence.observedAt);
  const expiresMs = parseEvidenceTimestamp(evidence.expiresAt);
  if (
    observedMs > now ||
    expiresMs <= now ||
    expiresMs <= observedMs ||
    expiresMs - observedMs > maximumProviderEvidenceValidityMs
  ) {
    throw new PlatformRuntimeActivationError();
  }

  const endpointIdentities = new Set();
  const endpoints = evidence.endpoints.map((endpoint) => {
    const endpointIdentity = `${endpoint?.id}:${endpoint?.kind}`;
    if (
      !endpoint ||
      typeof endpoint !== "object" ||
      Array.isArray(endpoint) ||
      !hasExactKeys(endpoint, neonEndpointEvidenceKeys) ||
      !safeNeonEndpointId.test(endpoint.id) ||
      !neonEndpointKinds.has(endpoint.kind) ||
      !safeProviderHost(endpoint.host) ||
      endpoint.database !== evidence.database ||
      endpointIdentities.has(endpointIdentity)
    ) {
      throw new PlatformRuntimeActivationError();
    }
    endpointIdentities.add(endpointIdentity);
    return Object.freeze({
      database: endpoint.database,
      host: endpoint.host.toLowerCase(),
      id: endpoint.id,
      kind: endpoint.kind,
    });
  });
  endpoints.sort((left, right) =>
    `${left.id}:${left.kind}`.localeCompare(`${right.id}:${right.kind}`),
  );

  const normalized = {
    branchId: evidence.branchId,
    database: evidence.database,
    endpoints: Object.freeze(endpoints),
    expiresAt: evidence.expiresAt,
    expiresMs,
    observedAt: evidence.observedAt,
    observedMs,
    projectId: evidence.projectId,
    provider: evidence.provider,
  };
  return Object.freeze({
    ...normalized,
    fingerprint: JSON.stringify({
      branchId: normalized.branchId,
      database: normalized.database,
      endpoints: normalized.endpoints,
      expiresAt: normalized.expiresAt,
      observedAt: normalized.observedAt,
      projectId: normalized.projectId,
      provider: normalized.provider,
    }),
  });
}

function providerBindingValue(
  binding,
  { now = Date.now() } = {},
) {
  const value =
    binding && typeof binding === "object"
      ? providerBindingValues.get(binding)
      : undefined;
  if (
    !value ||
    !Number.isInteger(now) ||
    value.observedMs > now ||
    value.expiresMs <= now
  ) {
    throw new PlatformRuntimeActivationError();
  }
  return value;
}

function providerEndpoint(
  providerValue,
  endpointId,
  expectedDatabase,
  expectedKind,
) {
  if (
    !safeNeonEndpointId.test(endpointId) ||
    !neonEndpointKinds.has(expectedKind)
  ) {
    return undefined;
  }
  const endpoint = providerValue.endpoints.find(
    (candidate) =>
      candidate.id === endpointId && candidate.kind === expectedKind,
  );
  return endpoint &&
    endpoint.database === expectedDatabase &&
    endpoint.kind === expectedKind
    ? endpoint
    : undefined;
}

function parseEvidenceTimestamp(value) {
  if (typeof value !== "string") {
    throw new PlatformRuntimeActivationError();
  }
  const milliseconds = Date.parse(value);
  if (
    !Number.isInteger(milliseconds) ||
    new Date(milliseconds).toISOString() !== value
  ) {
    throw new PlatformRuntimeActivationError();
  }
  return milliseconds;
}

function hasExactKeys(value, expectedKeys) {
  const keys = Object.keys(value).sort();
  return (
    keys.length === expectedKeys.length &&
    keys.every((key, index) => key === expectedKeys[index])
  );
}

function parseOperatorUrl(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new PlatformRuntimeActivationError();
  }
  if (
    !["postgres:", "postgresql:"].includes(parsed.protocol) ||
    !parsed.hostname ||
    !parsed.username ||
    parsed.pathname.length <= 1 ||
    parsed.hash
  ) {
    throw new PlatformRuntimeActivationError();
  }
  return parsed;
}

function assertUrlDatabase(parsed, expectedDatabase) {
  let database;
  try {
    database = decodeURIComponent(parsed.pathname.slice(1));
  } catch {
    throw new PlatformRuntimeActivationError();
  }
  if (
    parsed.pathname.includes("/", 1) ||
    database !== expectedDatabase
  ) {
    throw new PlatformRuntimeActivationError();
  }
}

function assertProviderConnectionUrl(
  connectionUrl,
  endpoint,
  expectedDatabase,
) {
  const parsed = parseOperatorUrl(connectionUrl);
  assertProviderConnectionHost(parsed, endpoint.host);
  assertUrlDatabase(parsed, expectedDatabase);
  validateConnectionParameters(parsed);
}

function assertProviderConnectionHost(parsed, expectedHost) {
  if (parsed.hostname.toLowerCase() !== expectedHost) {
    throw new PlatformRuntimeActivationError();
  }
}

function safeProviderHost(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 253 &&
    value === value.toLowerCase() &&
    /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/u.test(value) &&
    !value.includes("..")
  );
}

function validateConnectionParameters(parsed) {
  const seen = new Set();
  const reviewed = [];
  for (const [name, value] of parsed.searchParams.entries()) {
    const allowedValues = allowedConnectionParameters.get(name);
    if (!allowedValues || seen.has(name) || !allowedValues.has(value)) {
      throw new PlatformRuntimeActivationError();
    }
    seen.add(name);
    reviewed.push([name, value]);
  }
  return reviewed.sort(([left], [right]) => left.localeCompare(right));
}

function validateDockerInputs({ operatorUrl, dockerImage, timeoutMs }) {
  if (
    typeof operatorUrl !== "string" ||
    operatorUrl.length === 0 ||
    dockerImage !== "postgres:17" ||
    !Number.isInteger(timeoutMs) ||
    timeoutMs < 10 ||
    timeoutMs > 120_000
  ) {
    throw new PlatformRuntimeActivationError();
  }
  parseOperatorUrl(operatorUrl);
}

function validateTerminationInputs({
  terminationAttempts,
  terminationGraceMs,
  terminationRetryMs,
}) {
  if (
    !Number.isInteger(terminationGraceMs) ||
    terminationGraceMs < 1 ||
    terminationGraceMs > 30_000 ||
    !Number.isInteger(terminationRetryMs) ||
    terminationRetryMs < 1 ||
    terminationRetryMs > 30_000 ||
    !Number.isInteger(terminationAttempts) ||
    terminationAttempts < 1 ||
    terminationAttempts > 5
  ) {
    throw new PlatformRuntimeActivationError();
  }
}

function dockerEnvironment(operatorUrl) {
  const childEnvironment = {
    ...process.env,
    DATABASE_OPERATOR_URL: operatorUrl,
  };
  delete childEnvironment.DATABASE_URL;
  delete childEnvironment.NEONDB_SWOOSHZ_PLATFORM_DATABASE_OPERATOR_URL;
  delete childEnvironment.NEONDB_SWOOSHZ_PLATFORM_DATABASE_RUNTIME_PASSWORD;
  delete childEnvironment.NEONDB_SWOOSHZ_PLATFORM_DATABASE_URL;
  return childEnvironment;
}

function dockerContainerName(purpose) {
  return `swooshz-runtime-${purpose}-${randomUUID()}`;
}

function createFixtureIdentity(systemIdentifier, databaseOid) {
  const value = `${systemIdentifier}:${databaseOid}`;
  if (!safeFixtureIdentity.test(value)) {
    throw new PlatformRuntimeActivationError();
  }
  const identity = Object.freeze({});
  fixtureIdentityValues.set(identity, value);
  return identity;
}

function fixtureIdentityValue(identity) {
  const value =
    identity && typeof identity === "object"
      ? fixtureIdentityValues.get(identity)
      : undefined;
  if (!value) {
    throw new PlatformRuntimeActivationError();
  }
  return value;
}

function containsLineBreakOrNull(value) {
  return /[\r\n\u0000]/u.test(value);
}

function isStrongRuntimePassword(value) {
  return (
    typeof value === "string" &&
    value.length >= 32 &&
    !containsLineBreakOrNull(value) &&
    /[a-z]/u.test(value) &&
    /[A-Z]/u.test(value) &&
    /[0-9]/u.test(value) &&
    /[^A-Za-z0-9]/u.test(value)
  );
}

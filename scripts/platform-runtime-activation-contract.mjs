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
const phaseSet = new Set(PLATFORM_RUNTIME_ACTIVATION_PHASES);

export class PlatformRuntimeActivationError extends Error {
  constructor() {
    super("Runtime activation failed.");
    this.name = "PlatformRuntimeActivationError";
    this.code = "runtime_activation_failed";
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

export function buildRuntimeDatabaseUrl(
  operatorUrl,
  runtimeRole,
  runtimePassword,
) {
  if (
    !safeRoleIdentifier.test(runtimeRole) ||
    typeof runtimePassword !== "string" ||
    runtimePassword.length === 0 ||
    containsLineBreakOrNull(runtimePassword)
  ) {
    throw new PlatformRuntimeActivationError();
  }

  const parsed = parseOperatorUrl(operatorUrl);

  parsed.username = encodeURIComponent(runtimeRole);
  parsed.password = encodeURIComponent(runtimePassword);
  return parsed.toString();
}

export async function installRuntimePasswordWithDocker({
  operatorUrl,
  runtimeRole,
  runtimePassword,
  dockerImage = "postgres:17",
  spawnImpl = spawn,
  timeoutMs = 30_000,
}) {
  if (
    typeof operatorUrl !== "string" ||
    operatorUrl.length === 0 ||
    !safeRoleIdentifier.test(runtimeRole) ||
    !isStrongRuntimePassword(runtimePassword) ||
    dockerImage !== "postgres:17" ||
    !Number.isInteger(timeoutMs) ||
    timeoutMs < 1_000 ||
    timeoutMs > 120_000
  ) {
    throw new PlatformRuntimeActivationError();
  }
  parseOperatorUrl(operatorUrl);

  const input = Buffer.from(
    `\\password ${runtimeRole}\n${runtimePassword}\n${runtimePassword}\n\\q\n`,
    "utf8",
  );
  const childEnvironment = {
    ...process.env,
    DATABASE_OPERATOR_URL: operatorUrl,
  };
  delete childEnvironment.DATABASE_URL;
  delete childEnvironment.NEONDB_SWOOSHZ_PLATFORM_DATABASE_OPERATOR_URL;
  delete childEnvironment.NEONDB_SWOOSHZ_PLATFORM_DATABASE_RUNTIME_PASSWORD;
  delete childEnvironment.NEONDB_SWOOSHZ_PLATFORM_DATABASE_URL;

  try {
    await new Promise((resolve, reject) => {
      let settled = false;
      const child = spawnImpl(
        "docker",
        [
          "run",
          "--rm",
          "-i",
          "--env",
          "DATABASE_OPERATOR_URL",
          dockerImage,
          "sh",
          "-lc",
          'psql "$DATABASE_OPERATOR_URL" -X -v ON_ERROR_STOP=1',
        ],
        {
          env: childEnvironment,
          stdio: ["pipe", "ignore", "ignore"],
          windowsHide: true,
        },
      );

      const timer = setTimeout(() => {
        child.kill();
        finish(true);
      }, timeoutMs);
      timer.unref?.();

      const finish = (error) => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        input.fill(0);
        if (error) {
          reject(new PlatformRuntimeActivationError());
        } else {
          resolve();
        }
      };

      child.once("error", () => finish(true));
      child.once("close", (code, signal) =>
        finish(code !== 0 || signal !== null),
      );
      child.stdin.once("error", () => finish(true));
      child.stdin.end(input);
    });
  } catch {
    input.fill(0);
    throw new PlatformRuntimeActivationError();
  }
}

function assertPhase(phase) {
  if (!phaseSet.has(phase)) {
    throw new PlatformRuntimeActivationError();
  }
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
    parsed.pathname.length <= 1
  ) {
    throw new PlatformRuntimeActivationError();
  }
  return parsed;
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

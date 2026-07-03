#!/usr/bin/env node

import { pathToFileURL } from "node:url";

const REQUIRED = "Required";
const OPTIONAL = "Optional";
const MIGRATION_ONLY = "Required for migrations only";
const BOOTSTRAP_ONLY = "Required for bootstrap only";
const KQAG_HANDOFF_ONLY = "Required when server_handoff";

export const HOSTED_READINESS_ENV_CHECKS = [
  required("PLATFORM_PUBLIC_BASE_URL", "public_runtime", validateHostedBaseUrl),
  required("NODE_ENV", "runtime_mode", validateNodeEnv),
  required("PLATFORM_HTTP_HOST", "public_runtime"),
  required("PLATFORM_HTTP_PORT", "public_runtime", validatePort),
  required("PLATFORM_ALLOWED_ORIGINS", "allowed_origins", validateAllowedOrigins),
  required("PLATFORM_COOKIE_SECURE", "cookie_session", validateCookieSecure),
  required("DATABASE_URL", "database", validatePresent, { secret: true }),
  optional("DATABASE_SSL_MODE", "database", validateDatabaseSslMode),
  migrationOnly("DATABASE_MIGRATIONS_CONFIRM", "database", validateMigrationConfirm),
  required("SESSION_SECRET", "cookie_session", validateMinimumLength(32), { secret: true }),
  required("CSRF_TOKEN_HASH_SECRET", "csrf", validateMinimumLength(32), { secret: true }),
  required("AUTH_STATE_HASH_SECRET", "oidc", validateMinimumLength(32), { secret: true }),
  required("APP_LAUNCH_TOKEN_HASH_SECRET", "app_launch", validateMinimumLength(32), { secret: true }),
  required("PLATFORM_AUTH_PROVIDER_MODE", "oidc", validateAuthProviderMode),
  required("AUTH_PROVIDER_KEY", "oidc"),
  required("AUTH_ISSUER_URL", "oidc", validateHttpsUrl),
  required("AUTH_AUTHORIZATION_URL", "oidc", validateHttpsUrl),
  required("AUTH_TOKEN_URL", "oidc", validateHttpsUrl),
  required("AUTH_JWKS_URL", "oidc", validateHttpsUrl),
  optional("AUTH_USERINFO_URL", "oidc", validateHttpsUrl),
  required("AUTH_CLIENT_ID", "oidc"),
  required("AUTH_CLIENT_SECRET", "oidc", validatePresent, { secret: true }),
  required("AUTH_REDIRECT_URI", "oidc", validateHostedAuthRedirectUri),
  required("AUTH_ALLOWED_EMAILS", "oidc"),
  optional("AUTH_ALLOWED_DOMAINS", "oidc"),
  required("PLATFORM_KQAG_LAUNCH_MODE", "kqag_handoff", validateKqagLaunchMode),
  conditional(
    "PLATFORM_KQAG_APP_BASE_URL",
    "kqag_handoff",
    validateHostedBaseUrl,
    (env) => readEnv(env, "PLATFORM_KQAG_LAUNCH_MODE") === "server_handoff",
  ),
  bootstrapOnly("PLATFORM_SEED_CONFIRM", "bootstrap", validateSeedConfirm),
  bootstrapOnly("PLATFORM_SEED_USER_EMAIL", "bootstrap"),
  optional("PLATFORM_SEED_MEMBERSHIP_ROLE", "bootstrap", validateSeedRole),
];

export function createPlatformReadinessReport(env = {}) {
  const entries = HOSTED_READINESS_ENV_CHECKS.map((check) => evaluateCheck(check, env));
  const missingRequired = entries.filter((entry) => entry.status === "missing_required");
  const missingConditional = entries.filter((entry) => entry.status === "missing_conditional");
  const missingOptional = entries.filter((entry) => entry.status === "missing_optional");
  const invalid = entries.filter((entry) => entry.status === "invalid");

  return {
    ok: missingRequired.length === 0 && missingConditional.length === 0 && invalid.length === 0,
    entries,
    missingRequired,
    missingConditional,
    missingOptional,
    invalid,
  };
}

export function runPlatformReadinessCheck({
  env = process.env,
  writeLine = console.log,
  writeError = console.error,
} = {}) {
  const report = createPlatformReadinessReport(env);
  const write = report.ok ? writeLine : writeError;

  write(`Swooshz Platform hosted internal-alpha readiness_check=${report.ok ? "pass" : "fail"}`);
  write("manual_migrations=explicit");

  if (report.missingRequired.length === 0) {
    write("required env: present");
  } else {
    for (const entry of report.missingRequired) {
      write(`missing required env: ${entry.name} category=${entry.category}`);
    }
  }

  for (const entry of report.missingConditional) {
    write(`missing conditional env: ${entry.name} category=${entry.category}`);
  }

  for (const entry of report.invalid) {
    const label = entry.secret ? "invalid secret env" : "invalid env";
    write(`${label}: ${entry.name} category=${entry.category} reason=${entry.reason}`);
  }

  if (report.missingOptional.length > 0) {
    write(
      `optional env missing: ${report.missingOptional.map((entry) => entry.name).join(", ")}`,
    );
  }

  write("dry_run_only=true");
  return report;
}

function evaluateCheck(check, env) {
  const value = readEnv(env, check.name);
  const conditionApplies = check.condition ? check.condition(env) : true;

  if (!value) {
    if (check.required === REQUIRED) {
      return entry(check, "missing_required");
    }

    if (check.required === KQAG_HANDOFF_ONLY && conditionApplies) {
      return entry(check, "missing_conditional");
    }

    return entry(check, "missing_optional");
  }

  if (conditionApplies) {
    const validation = check.validate(value, env);
    if (!validation.ok) {
      return entry(check, "invalid", validation.reason);
    }
  }

  return entry(check, "present");
}

function entry(check, status, reason = undefined) {
  return {
    name: check.name,
    category: check.category,
    required: check.required,
    secret: check.secret,
    status,
    ...(reason ? { reason } : {}),
  };
}

function required(name, category, validate = validatePresent, options = {}) {
  return check(name, category, REQUIRED, validate, options);
}

function optional(name, category, validate = validatePresent, options = {}) {
  return check(name, category, OPTIONAL, validate, options);
}

function migrationOnly(name, category, validate = validatePresent) {
  return check(name, category, MIGRATION_ONLY, validate);
}

function bootstrapOnly(name, category, validate = validatePresent) {
  return check(name, category, BOOTSTRAP_ONLY, validate);
}

function conditional(name, category, validate, condition) {
  return check(name, category, KQAG_HANDOFF_ONLY, validate, { condition });
}

function check(name, category, required, validate, options = {}) {
  return {
    name,
    category,
    required,
    validate,
    secret: Boolean(options.secret),
    condition: options.condition,
  };
}

function readEnv(env, name) {
  const value = env?.[name];
  return typeof value === "string" ? value.trim() : "";
}

function validatePresent(value) {
  return value ? ok() : invalid("missing");
}

function validateMinimumLength(length) {
  return (value) => value.length >= length ? ok() : invalid("too_short");
}

function parseHttpsUrl(value) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" ? { ok: true, parsed } : invalid("must_be_https");
  } catch {
    return invalid("invalid_url");
  }
}

function validateHttpsUrl(value) {
  const result = parseHttpsUrl(value);

  return result.ok ? ok() : result;
}

function validateHostedBaseUrl(value) {
  const result = parseHttpsUrl(value);
  if (!result.ok) {
    return result;
  }

  return hasQueryOrFragment(result.parsed) ? invalid("query_or_fragment_not_allowed") : ok();
}

function validateHostedAuthRedirectUri(value) {
  const result = validateHostedBaseUrl(value);
  if (!result.ok) {
    return result;
  }

  const parsed = new URL(value);
  return parsed.pathname.endsWith("/api/platform/auth/callback")
    ? ok()
    : invalid("must_end_with_platform_auth_callback");
}

function validateAllowedOrigins(value) {
  const origins = value.split(",").map((item) => item.trim()).filter(Boolean);

  if (origins.length === 0) {
    return invalid("missing");
  }

  for (const origin of origins) {
    const result = parseHttpsUrl(origin);
    if (!result.ok) {
      return result;
    }

    if (!isOriginShape(origin) || result.parsed.username || result.parsed.password) {
      return invalid("must_be_origin");
    }
  }

  return ok();
}

function validateNodeEnv(value) {
  return value === "production" ? ok() : invalid("hosted_requires_production");
}

function validatePort(value) {
  const port = Number(value);
  return Number.isInteger(port) && port >= 1 && port <= 65535
    ? ok()
    : invalid("invalid_port");
}

function validateCookieSecure(value, env) {
  if (value !== "true" && value !== "false") {
    return invalid("must_be_true_or_false");
  }

  if (readEnv(env, "NODE_ENV") === "production" && value !== "true") {
    return invalid("production_requires_true");
  }

  return ok();
}

function validateDatabaseSslMode(value) {
  return ["disable", "require"].includes(value) ? ok() : invalid("must_be_disable_or_require");
}

function validateMigrationConfirm(value) {
  return value === "apply-reviewed-migrations" ? ok() : invalid("unexpected_confirmation");
}

function validateAuthProviderMode(value) {
  return value === "generic_oidc" ? ok() : invalid("must_be_generic_oidc");
}

function validateKqagLaunchMode(value) {
  return ["manual", "server_handoff"].includes(value) ? ok() : invalid("unsupported_mode");
}

function validateSeedConfirm(value) {
  return value === "seed-reviewed-internal-access" ? ok() : invalid("unexpected_confirmation");
}

function validateSeedRole(value) {
  return ["owner", "admin", "member"].includes(value) ? ok() : invalid("unsupported_role");
}

function hasQueryOrFragment(parsed) {
  return parsed.search !== "" || parsed.hash !== "";
}

function isOriginShape(value) {
  return /^https:\/\/[^/?#]+$/i.test(value);
}

function ok() {
  return { ok: true };
}

function invalid(reason) {
  return { ok: false, reason };
}

async function main() {
  const report = runPlatformReadinessCheck();
  process.exitCode = report.ok ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}

#!/usr/bin/env node

import { pathToFileURL } from "node:url";

import {
  createDatabaseRepositories,
} from "../dist/db/client.js";
import {
  InternalAccessSeedError,
  ensureFirstOwnerBootstrapApproval,
  ensureInternalWorkspaceAppAccess,
  normalizeEmail,
} from "../dist/index.js";

export const PLATFORM_SEED_CONFIRM_VALUE = "seed-reviewed-internal-access";

const defaultAppKey = "sqag";
const defaultAppName = "SQAG";
const defaultMembershipRole = "owner";
const allowedRoles = new Set(["owner", "admin", "member"]);
const FIRST_OWNER_BOOTSTRAP_MODE = "first-owner-pending-approval";

export class PlatformSeedInternalAccessError extends Error {
  constructor(code) {
    super(readPublicMessage(code));
    this.name = "PlatformSeedInternalAccessError";
    this.code = code;
    this.publicMessage = this.message;
  }
}

export function readPlatformSeedInternalAccessConfig(env) {
  if (env.PLATFORM_SEED_CONFIRM !== PLATFORM_SEED_CONFIRM_VALUE) {
    throw new PlatformSeedInternalAccessError("missing_confirm");
  }

  if (readOptional(env.PLATFORM_SEED_APP_KEY) || readOptional(env.PLATFORM_SEED_APP_NAME)) {
    throw new PlatformSeedInternalAccessError("unsupported_app_identity_override");
  }

  const workspaceSlug = readOptional(env.PLATFORM_SEED_WORKSPACE_SLUG);
  const workspaceName = readOptional(env.PLATFORM_SEED_WORKSPACE_NAME);

  if (!workspaceSlug || !workspaceName) {
    throw new PlatformSeedInternalAccessError("missing_workspace_identity");
  }

  const rawEmail = env.PLATFORM_SEED_USER_EMAIL?.trim();

  if (!rawEmail) {
    throw new PlatformSeedInternalAccessError("missing_user_email");
  }

  const role = readOptional(env.PLATFORM_SEED_MEMBERSHIP_ROLE) ?? defaultMembershipRole;

  if (!allowedRoles.has(role)) {
    throw new PlatformSeedInternalAccessError("unsupported_role");
  }

  const bootstrapMode = readOptional(env.PLATFORM_SEED_BOOTSTRAP_MODE);

  if (bootstrapMode && bootstrapMode !== FIRST_OWNER_BOOTSTRAP_MODE) {
    throw new PlatformSeedInternalAccessError("unsupported_bootstrap_mode");
  }

  if (bootstrapMode === FIRST_OWNER_BOOTSTRAP_MODE && role !== "owner") {
    throw new PlatformSeedInternalAccessError("first_owner_requires_owner_role");
  }

  return {
    bootstrapMode: bootstrapMode ?? "existing-provider-backed-user",
    normalizedUserEmail: normalizeEmail(rawEmail),
    workspaceSlug,
    workspaceName,
    appKey: defaultAppKey,
    appName: defaultAppName,
    membershipRole: role,
    appLaunchUrl: readLaunchUrl(env.PLATFORM_SEED_APP_LAUNCH_URL),
  };
}

export async function seedFirstOwnerBootstrapApproval(
  repositories,
  config,
  now,
) {
  try {
    return await ensureFirstOwnerBootstrapApproval(
      repositories,
      buildFirstOwnerBootstrapInput(config, now),
    );
  } catch (error) {
    if (error instanceof InternalAccessSeedError) {
      throw new PlatformSeedInternalAccessError("seed_failed");
    }

    throw new PlatformSeedInternalAccessError("seed_failed");
  }
}

export async function seedInternalAccessForExistingUser(
  repositories,
  config,
  now,
) {
  const user = await repositories.users.findByNormalizedEmail(config.normalizedUserEmail);

  if (!user) {
    throw new PlatformSeedInternalAccessError("user_not_found");
  }

  if (!repositories.providerIdentities) {
    throw new PlatformSeedInternalAccessError(
      "provider_identity_repository_unavailable",
    );
  }

  const providerIdentities =
    await repositories.providerIdentities.listForUser(user.id);

  if (providerIdentities.length === 0) {
    throw new PlatformSeedInternalAccessError("missing_provider_identity");
  }

  try {
    const result = await ensureInternalWorkspaceAppAccess(
      repositories,
      buildSeedInput(config, user.id, now),
    );

    return {
      ...result,
      providerIdentity: providerIdentities[0],
    };
  } catch (error) {
    if (error instanceof InternalAccessSeedError) {
      throw new PlatformSeedInternalAccessError("seed_failed");
    }

    throw new PlatformSeedInternalAccessError("seed_failed");
  }
}

export async function executePlatformSeedInternalAccess({
  env,
  now = () => new Date().toISOString(),
  createDatabaseRepositories: createRepositories = createDatabaseRepositories,
  writeLine = console.log,
}) {
  const config = readPlatformSeedInternalAccessConfig(env);
  const client = createRepositories(env);

  try {
    if (config.bootstrapMode === FIRST_OWNER_BOOTSTRAP_MODE) {
      const result = await seedFirstOwnerBootstrapApproval(
        client.repositories,
        config,
        now(),
      );
      writeLine(formatFirstOwnerBootstrapSummary(config, result));
      return result;
    }

    const result = await seedInternalAccessForExistingUser(
      client.repositories,
      config,
      now(),
    );
    writeLine(formatSeedSummary(config, result));
    return result;
  } finally {
    await client.pool?.end?.();
  }
}

export function formatFirstOwnerBootstrapSummary(config, result) {
  return [
    "Internal platform first-owner bootstrap prepared.",
    "first_owner_bootstrap=pending_approval",
    `outcome=${readCreatedSummary(result.created)}`,
    "workspace=configured",
    `app=${config.appKey}`,
    "user=created_by_real_oidc_sign_in",
    `role=${config.membershipRole}`,
  ].join(" ");
}

export function formatSeedSummary(config, result) {
  return [
    "Internal platform access seed completed.",
    `outcome=${readCreatedSummary(result.created)}`,
    "workspace=configured",
    `app=${config.appKey}`,
    "user=existing_provider_backed_user",
    `role=${config.membershipRole}`,
  ].join(" ");
}

function buildSeedInput(config, userId, now) {
  const workspaceKey = safeIdentifier(config.workspaceSlug);
  const appKey = safeIdentifier(config.appKey);
  const userKey = safeIdentifier(userId);

  return {
    now,
    workspace: {
      id: `workspace_${workspaceKey}_seed`,
      slug: config.workspaceSlug,
      displayName: config.workspaceName,
    },
    app: {
      id: `app_${appKey}`,
      key: config.appKey,
      name: config.appName,
      status: "private_preview",
      launchUrl: config.appLaunchUrl,
    },
    entitlement: {
      id: `entitlement_${workspaceKey}_${appKey}_seed`,
      status: "enabled",
      grantedByUserId: userId,
    },
    membership: {
      id: `membership_${workspaceKey}_${appKey}_${userKey}_seed`,
      role: config.membershipRole,
    },
    user: {
      mode: "existing",
      userId,
      normalizedEmail: config.normalizedUserEmail,
    },
  };
}

function buildFirstOwnerBootstrapInput(config, now) {
  const workspaceKey = safeIdentifier(config.workspaceSlug);
  const appKey = safeIdentifier(config.appKey);

  return {
    now,
    workspace: {
      id: `workspace_${workspaceKey}_seed`,
      slug: config.workspaceSlug,
      displayName: config.workspaceName,
    },
    app: {
      id: `app_${appKey}`,
      key: config.appKey,
      name: config.appName,
      status: "private_preview",
      launchUrl: config.appLaunchUrl,
    },
    entitlement: {
      id: `entitlement_${workspaceKey}_${appKey}_seed`,
      status: "enabled",
      grantedByUserId: null,
    },
    approval: {
      id: `approval_${workspaceKey}_${appKey}_first_owner_seed`,
      email: config.normalizedUserEmail,
      role: "owner",
    },
  };
}

function readCreatedSummary(created) {
  const createdKeys = Object.entries(created)
    .filter(([, wasCreated]) => wasCreated)
    .map(([key]) => key);

  return createdKeys.length > 0
    ? `created:${createdKeys.join(",")}`
    : "existing";
}

function readLaunchUrl(value) {
  const rawUrl = readOptional(value);

  if (!rawUrl) {
    return null;
  }

  try {
    const parsed = new URL(rawUrl);

    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      throw new Error("unsupported protocol");
    }

    return parsed.toString();
  } catch {
    throw new PlatformSeedInternalAccessError("invalid_app_launch_url");
  }
}

function readOptional(value) {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

function safeIdentifier(value) {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");

  return normalized || "internal";
}

function readPublicMessage(code) {
  switch (code) {
    case "missing_confirm":
      return `PLATFORM_SEED_CONFIRM must be set to ${PLATFORM_SEED_CONFIRM_VALUE}.`;
    case "missing_user_email":
      return "PLATFORM_SEED_USER_EMAIL is required.";
    case "missing_workspace_identity":
      return "PLATFORM_SEED_WORKSPACE_SLUG and PLATFORM_SEED_WORKSPACE_NAME are required.";
    case "unsupported_role":
      return "PLATFORM_SEED_MEMBERSHIP_ROLE must be owner, admin, or member.";
    case "unsupported_bootstrap_mode":
      return "PLATFORM_SEED_BOOTSTRAP_MODE is not supported.";
    case "first_owner_requires_owner_role":
      return "First-owner bootstrap requires PLATFORM_SEED_MEMBERSHIP_ROLE to be owner when set.";
    case "unsupported_app_identity_override":
      return "PLATFORM_SEED_APP_KEY and PLATFORM_SEED_APP_NAME are not supported.";
    case "invalid_app_launch_url":
      return "PLATFORM_SEED_APP_LAUNCH_URL must be an HTTP(S) URL when set.";
    case "user_not_found":
      return "Existing platform user was not found.";
    case "provider_identity_repository_unavailable":
      return "Provider identity lookup is required before seeding access.";
    case "missing_provider_identity":
      return "Existing platform user has no provider identity.";
    case "seed_failed":
      return "Internal platform access seed could not be completed.";
    default:
      return "Internal platform access seed could not be completed.";
  }
}

async function main() {
  try {
    await executePlatformSeedInternalAccess({
      env: process.env,
    });
  } catch (error) {
    if (error instanceof PlatformSeedInternalAccessError) {
      console.error(error.publicMessage);
    } else {
      console.error("Internal platform access seed could not be completed.");
    }
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}

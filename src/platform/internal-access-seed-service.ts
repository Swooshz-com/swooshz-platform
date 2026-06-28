import { normalizeEmail } from "../accounts/normalization.js";
import {
  MembershipStatus,
  Role,
  UserStatus,
  WorkspaceStatus,
  type Membership,
  type User,
  type Workspace,
} from "../accounts/types.js";
import {
  AppStatus,
  EntitlementStatus,
  type App,
  type AppEntitlement,
} from "../apps/types.js";
import type {
  PlatformRepositories,
  ProviderIdentity,
} from "./repositories.js";

export type InternalAccessSeedErrorCode =
  | "workspace_conflict"
  | "app_conflict"
  | "entitlement_conflict"
  | "membership_conflict"
  | "role_not_seedable"
  | "user_not_found"
  | "user_conflict"
  | "email_only_user_creation_forbidden"
  | "existing_email_without_provider_identity"
  | "provider_identity_conflict"
  | "provider_identity_required"
  | "repository_failure";

export class InternalAccessSeedError extends Error {
  readonly code: InternalAccessSeedErrorCode;
  readonly publicMessage = "Internal access seed could not be completed.";

  constructor(code: InternalAccessSeedErrorCode) {
    super("Internal access seed could not be completed.");
    this.name = "InternalAccessSeedError";
    this.code = code;
  }
}

export interface InternalWorkspaceSeedInput {
  id: string;
  slug: string;
  displayName: string;
}

export interface InternalAppSeedInput {
  id: string;
  key?: string;
  name: string;
  status?: AppStatus;
}

export interface InternalEntitlementSeedInput {
  id: string;
  status?: EntitlementStatus;
  grantedByUserId?: string | null;
}

export interface InternalMembershipSeedInput {
  id: string;
  role?: Role;
}

export type InternalAccessSeedUserInput =
  | {
      mode: "existing";
      userId?: string;
      normalizedEmail?: string;
    }
  | {
      mode: "create_with_provider_identity";
      userId?: string;
      providerIdentityId?: string;
      providerKey?: string;
      providerSubject?: string;
      verifiedEmail?: string;
      displayName?: string;
    };

export interface InternalAccessSeedInput {
  now: string;
  workspace: InternalWorkspaceSeedInput;
  app: InternalAppSeedInput;
  entitlement: InternalEntitlementSeedInput;
  membership: InternalMembershipSeedInput;
  user: InternalAccessSeedUserInput;
}

export interface InternalAccessSeedCreatedFlags {
  workspace: boolean;
  app: boolean;
  entitlement: boolean;
  membership: boolean;
  user: boolean;
  providerIdentity: boolean;
}

export interface InternalAccessSeedResult {
  outcome: "seeded";
  workspace: Workspace;
  app: App;
  entitlement: AppEntitlement;
  membership: Membership;
  user: User;
  providerIdentity: ProviderIdentity | null;
  created: InternalAccessSeedCreatedFlags;
}

const defaultAppKey = "kqag";
const defaultAppStatus = AppStatus.PrivatePreview;
const defaultEntitlementStatus = EntitlementStatus.Enabled;
const defaultMembershipRole = Role.Owner;
const seedableRoles = new Set<Role>([Role.Owner, Role.Admin, Role.Member]);

export async function ensureInternalWorkspaceAppAccess(
  repositories: PlatformRepositories,
  input: InternalAccessSeedInput,
): Promise<InternalAccessSeedResult> {
  try {
    return await ensureInternalWorkspaceAppAccessSafely(repositories, input);
  } catch (error) {
    if (error instanceof InternalAccessSeedError) {
      throw error;
    }

    throw new InternalAccessSeedError("repository_failure");
  }
}

async function ensureInternalWorkspaceAppAccessSafely(
  repositories: PlatformRepositories,
  input: InternalAccessSeedInput,
): Promise<InternalAccessSeedResult> {
  const created: InternalAccessSeedCreatedFlags = {
    workspace: false,
    app: false,
    entitlement: false,
    membership: false,
    user: false,
    providerIdentity: false,
  };
  const role = input.membership.role ?? defaultMembershipRole;

  if (!seedableRoles.has(role)) {
    throw new InternalAccessSeedError("role_not_seedable");
  }

  const workspace = await ensureWorkspace(repositories, input, created);
  const app = await ensureApp(repositories, input, created);
  const identityResult = await ensureSeedUser(repositories, input, created);
  const entitlement = await ensureEntitlement(
    repositories,
    input,
    workspace,
    app,
    created,
  );
  const membership = await ensureMembership(
    repositories,
    input,
    workspace,
    identityResult.user,
    role,
    created,
  );

  return {
    outcome: "seeded",
    workspace,
    app,
    entitlement,
    membership,
    user: identityResult.user,
    providerIdentity: identityResult.providerIdentity,
    created,
  };
}

async function ensureWorkspace(
  repositories: PlatformRepositories,
  input: InternalAccessSeedInput,
  created: InternalAccessSeedCreatedFlags,
): Promise<Workspace> {
  const existing = await repositories.workspaces.findBySlug(input.workspace.slug);

  if (existing) {
    if (
      existing.id !== input.workspace.id ||
      existing.displayName !== input.workspace.displayName ||
      existing.status !== WorkspaceStatus.Active
    ) {
      throw new InternalAccessSeedError("workspace_conflict");
    }

    return existing;
  }

  created.workspace = true;
  return repositories.workspaces.create({
    id: input.workspace.id,
    slug: input.workspace.slug,
    displayName: input.workspace.displayName,
    status: WorkspaceStatus.Active,
    createdAt: input.now,
    updatedAt: input.now,
  });
}

async function ensureApp(
  repositories: PlatformRepositories,
  input: InternalAccessSeedInput,
  created: InternalAccessSeedCreatedFlags,
): Promise<App> {
  const key = input.app.key ?? defaultAppKey;
  const status = input.app.status ?? defaultAppStatus;
  const existing = await repositories.apps.findByKey(key);

  if (existing) {
    if (
      existing.id !== input.app.id ||
      existing.name !== input.app.name ||
      existing.status !== status ||
      existing.launchUrl !== null
    ) {
      throw new InternalAccessSeedError("app_conflict");
    }

    return existing;
  }

  created.app = true;
  return repositories.apps.create({
    id: input.app.id,
    key,
    name: input.app.name,
    status,
    launchUrl: null,
    createdAt: input.now,
    updatedAt: input.now,
  });
}

async function ensureEntitlement(
  repositories: PlatformRepositories,
  input: InternalAccessSeedInput,
  workspace: Workspace,
  app: App,
  created: InternalAccessSeedCreatedFlags,
): Promise<AppEntitlement> {
  const status = input.entitlement.status ?? defaultEntitlementStatus;
  const grantedByUserId = input.entitlement.grantedByUserId ?? null;
  const existing = await repositories.appEntitlements.findForWorkspaceApp(
    workspace.id,
    app.id,
  );

  if (existing) {
    if (
      existing.status !== status ||
      (input.entitlement.grantedByUserId !== undefined &&
        existing.grantedByUserId !== grantedByUserId)
    ) {
      throw new InternalAccessSeedError("entitlement_conflict");
    }

    return existing;
  }

  created.entitlement = true;
  return repositories.appEntitlements.create({
    id: input.entitlement.id,
    workspaceId: workspace.id,
    appId: app.id,
    status,
    grantedByUserId,
    createdAt: input.now,
    updatedAt: input.now,
  });
}

async function ensureMembership(
  repositories: PlatformRepositories,
  input: InternalAccessSeedInput,
  workspace: Workspace,
  user: User,
  role: Role,
  created: InternalAccessSeedCreatedFlags,
): Promise<Membership> {
  const existing = await repositories.memberships.findForUserInWorkspace(
    user.id,
    workspace.id,
  );

  if (existing) {
    if (existing.role !== role || existing.status !== MembershipStatus.Active) {
      throw new InternalAccessSeedError("membership_conflict");
    }

    return existing;
  }

  created.membership = true;
  return repositories.memberships.create({
    id: input.membership.id,
    workspaceId: workspace.id,
    userId: user.id,
    role,
    status: MembershipStatus.Active,
    createdAt: input.now,
    updatedAt: input.now,
  });
}

async function ensureSeedUser(
  repositories: PlatformRepositories,
  input: InternalAccessSeedInput,
  created: InternalAccessSeedCreatedFlags,
): Promise<{ user: User; providerIdentity: ProviderIdentity | null }> {
  if (input.user.mode === "existing") {
    return {
      user: await findExistingUser(repositories, input.user),
      providerIdentity: null,
    };
  }

  return ensureProviderIdentityUser(repositories, input, created);
}

async function findExistingUser(
  repositories: PlatformRepositories,
  input: Extract<InternalAccessSeedUserInput, { mode: "existing" }>,
): Promise<User> {
  const byId = input.userId
    ? await repositories.users.findById(input.userId)
    : null;
  const normalizedEmail = input.normalizedEmail
    ? normalizeEmail(input.normalizedEmail)
    : null;
  const byEmail = normalizedEmail
    ? await repositories.users.findByNormalizedEmail(normalizedEmail)
    : null;
  const user = byId ?? byEmail;

  if (!user) {
    throw new InternalAccessSeedError("user_not_found");
  }

  if (byId && byEmail && byId.id !== byEmail.id) {
    throw new InternalAccessSeedError("user_conflict");
  }

  if (normalizedEmail && user.email !== normalizedEmail) {
    throw new InternalAccessSeedError("user_conflict");
  }

  if (user.status !== UserStatus.Active) {
    throw new InternalAccessSeedError("user_conflict");
  }

  return user;
}

async function ensureProviderIdentityUser(
  repositories: PlatformRepositories,
  input: InternalAccessSeedInput,
  created: InternalAccessSeedCreatedFlags,
): Promise<{ user: User; providerIdentity: ProviderIdentity }> {
  const userInput = input.user as Extract<
    InternalAccessSeedUserInput,
    { mode: "create_with_provider_identity" }
  >;
  const providerIdentities = repositories.providerIdentities;

  if (!providerIdentities) {
    throw new InternalAccessSeedError("provider_identity_required");
  }

  if (
    !userInput.userId ||
    !userInput.providerIdentityId ||
    !userInput.providerKey ||
    !userInput.providerSubject ||
    !userInput.verifiedEmail
  ) {
    throw new InternalAccessSeedError("email_only_user_creation_forbidden");
  }

  const verifiedEmail = normalizeEmail(userInput.verifiedEmail);
  const existingIdentity = await providerIdentities.findByProviderSubject(
    userInput.providerKey,
    userInput.providerSubject,
  );

  if (existingIdentity) {
    const existingUser = await repositories.users.findById(existingIdentity.userId);

    if (
      !existingUser ||
      existingUser.id !== existingIdentity.userId ||
      existingUser.id !== userInput.userId ||
      existingUser.email !== verifiedEmail ||
      existingUser.status !== UserStatus.Active
    ) {
      throw new InternalAccessSeedError("provider_identity_conflict");
    }

    return {
      user: existingUser,
      providerIdentity: existingIdentity,
    };
  }

  const existingEmailUser = await repositories.users.findByNormalizedEmail(verifiedEmail);

  if (existingEmailUser) {
    throw new InternalAccessSeedError("existing_email_without_provider_identity");
  }

  const user = await repositories.users.create({
    id: userInput.userId,
    email: verifiedEmail,
    displayName: userInput.displayName?.trim() || verifiedEmail,
    status: UserStatus.Active,
    createdAt: input.now,
    updatedAt: input.now,
    lastLoginAt: null,
  });
  const providerIdentity = await providerIdentities.create({
    id: userInput.providerIdentityId,
    userId: user.id,
    providerKey: userInput.providerKey,
    providerSubject: userInput.providerSubject,
    createdAt: input.now,
    updatedAt: input.now,
  });

  created.user = true;
  created.providerIdentity = true;

  return { user, providerIdentity };
}

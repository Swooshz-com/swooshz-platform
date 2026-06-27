import { UserStatus, type Session, type User } from "../accounts/types.js";
import type {
  ProviderIdentity,
  ProviderIdentityRepository,
  SessionRepository,
  UserRepository,
} from "../platform/repositories.js";
import type {
  AuthCallbackPlatformIdentityResolution,
  AuthCallbackPlatformIdentityResolver,
  AuthenticatedPlatformIdentityInput,
} from "./callback-service.js";
import { AuthCallbackError } from "./errors.js";

export interface PlatformIdentitySessionResolverRepositories {
  users: UserRepository;
  providerIdentities: ProviderIdentityRepository;
  sessions: SessionRepository;
}

export interface PlatformIdentitySessionResolverDependencies {
  repositories: PlatformIdentitySessionResolverRepositories;
  sessionIdFactory(input: SessionIdFactoryInput): string;
  userIdFactory(input: UserIdFactoryInput): string;
  providerIdentityIdFactory(input: ProviderIdentityIdFactoryInput): string;
  sessionDurationMs: number;
}

export interface SessionIdFactoryInput {
  userId: string;
  providerKey: string;
  providerSubject: string;
  now: string;
}

export interface UserIdFactoryInput {
  providerKey: string;
  providerSubject: string;
  verifiedEmail: string;
  now: string;
}

export interface ProviderIdentityIdFactoryInput {
  userId: string;
  providerKey: string;
  providerSubject: string;
  now: string;
}

export function createPlatformIdentitySessionResolver(
  dependencies: PlatformIdentitySessionResolverDependencies,
): AuthCallbackPlatformIdentityResolver {
  return {
    async resolveAuthenticatedIdentity(input) {
      return resolveAuthenticatedIdentity(dependencies, input);
    },
  };
}

async function resolveAuthenticatedIdentity(
  dependencies: PlatformIdentitySessionResolverDependencies,
  input: AuthenticatedPlatformIdentityInput,
): Promise<AuthCallbackPlatformIdentityResolution> {
  const providerIdentity = await findProviderIdentitySafely(dependencies, input);

  if (providerIdentity) {
    const user = await findUserByIdSafely(dependencies, providerIdentity.userId);

    if (!user) {
      throw new AuthCallbackError(
        "invalid_platform_identity_state",
        "Authenticated platform identity could not be resolved.",
      );
    }

    assertUserCanCreateSession(user);

    return {
      platformUserId: user.id,
      providerIdentityId: providerIdentity.id,
      session: await createSession(dependencies, user.id, input),
    };
  }

  const user = await createUserForNewProviderIdentity(dependencies, input);
  const linkedProviderIdentity = await createProviderIdentity(
    dependencies,
    user.id,
    input,
  );

  return {
    platformUserId: user.id,
    providerIdentityId: linkedProviderIdentity.id,
    session: await createSession(dependencies, user.id, input),
  };
}

async function createUserForNewProviderIdentity(
  dependencies: PlatformIdentitySessionResolverDependencies,
  input: AuthenticatedPlatformIdentityInput,
): Promise<User> {
  if (!input.identity.verifiedEmail) {
    throw new AuthCallbackError(
      "verified_email_required",
      "Verified provider email is required to create a platform user.",
    );
  }

  const existingUser = await findUserByNormalizedEmailSafely(
    dependencies,
    input.identity.verifiedEmail,
  );

  if (existingUser) {
    throw new AuthCallbackError(
      "provider_identity_link_failed",
      "Authenticated provider identity could not be linked.",
    );
  }

  try {
    return await dependencies.repositories.users.create({
      id: dependencies.userIdFactory({
        providerKey: input.identity.providerKey,
        providerSubject: input.identity.providerSubject,
        verifiedEmail: input.identity.verifiedEmail,
        now: input.now,
      }),
      email: input.identity.verifiedEmail,
      displayName: input.identity.displayName?.trim() || input.identity.verifiedEmail,
      status: UserStatus.Active,
      createdAt: input.now,
      updatedAt: input.now,
      lastLoginAt: input.now,
    });
  } catch {
    throw new AuthCallbackError(
      "provider_identity_link_failed",
      "Authenticated provider identity could not be linked.",
    );
  }
}

async function findProviderIdentitySafely(
  dependencies: PlatformIdentitySessionResolverDependencies,
  input: AuthenticatedPlatformIdentityInput,
): Promise<ProviderIdentity | null> {
  try {
    return await dependencies.repositories.providerIdentities.findByProviderSubject(
      input.identity.providerKey,
      input.identity.providerSubject,
    );
  } catch {
    throw new AuthCallbackError(
      "provider_identity_link_failed",
      "Authenticated provider identity could not be linked.",
    );
  }
}

async function findUserByIdSafely(
  dependencies: PlatformIdentitySessionResolverDependencies,
  userId: string,
): Promise<User | null> {
  try {
    return await dependencies.repositories.users.findById(userId);
  } catch {
    throw new AuthCallbackError(
      "provider_identity_link_failed",
      "Authenticated provider identity could not be linked.",
    );
  }
}

async function findUserByNormalizedEmailSafely(
  dependencies: PlatformIdentitySessionResolverDependencies,
  email: string,
): Promise<User | null> {
  try {
    return await dependencies.repositories.users.findByNormalizedEmail(email);
  } catch {
    throw new AuthCallbackError(
      "provider_identity_link_failed",
      "Authenticated provider identity could not be linked.",
    );
  }
}

async function createProviderIdentity(
  dependencies: PlatformIdentitySessionResolverDependencies,
  userId: string,
  input: AuthenticatedPlatformIdentityInput,
): Promise<ProviderIdentity> {
  try {
    return await dependencies.repositories.providerIdentities.create({
      id: dependencies.providerIdentityIdFactory({
        userId,
        providerKey: input.identity.providerKey,
        providerSubject: input.identity.providerSubject,
        now: input.now,
      }),
      userId,
      providerKey: input.identity.providerKey,
      providerSubject: input.identity.providerSubject,
      createdAt: input.now,
      updatedAt: input.now,
    });
  } catch {
    throw new AuthCallbackError(
      "provider_identity_link_failed",
      "Authenticated provider identity could not be linked.",
    );
  }
}

async function createSession(
  dependencies: PlatformIdentitySessionResolverDependencies,
  userId: string,
  input: AuthenticatedPlatformIdentityInput,
): Promise<Session> {
  const session = {
    id: dependencies.sessionIdFactory({
      userId,
      providerKey: input.identity.providerKey,
      providerSubject: input.identity.providerSubject,
      now: input.now,
    }),
    userId,
    createdAt: input.now,
    expiresAt: addMilliseconds(input.now, dependencies.sessionDurationMs),
    lastSeenAt: input.now,
    revokedAt: null,
  };

  try {
    return await dependencies.repositories.sessions.create(session);
  } catch {
    throw new AuthCallbackError(
      "session_creation_failed",
      "Platform session could not be created.",
    );
  }
}

function assertUserCanCreateSession(user: User): void {
  if (user.status !== UserStatus.Active) {
    throw new AuthCallbackError(
      "user_not_active",
      "Platform user cannot create a session.",
    );
  }
}

function addMilliseconds(timestamp: string, milliseconds: number): string {
  return new Date(Date.parse(timestamp) + milliseconds).toISOString();
}

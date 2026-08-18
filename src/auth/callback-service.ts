import type { AuthConfig } from "./config.js";
import type { Session } from "../accounts/types.js";
import type {
  AuthCallbackParams,
  AuthStateStore,
  RawAuthCallbackParams,
  StoredAuthState,
} from "./callback.js";
import { parseAuthCallbackParams } from "./callback.js";
import { AuthCallbackError } from "./errors.js";
import type {
  AuthProviderIdentity,
  OidcProviderAdapter,
} from "./oidc.js";
import { createAuthProviderIdentity } from "./oidc.js";

export type StateReferenceFactory = (state: string) => string;

export interface AuthCallbackServiceDependencies {
  authConfig: AuthConfig;
  oidcAdapter: OidcProviderAdapter;
  stateStore: AuthStateStore;
  stateReferenceFactory: StateReferenceFactory;
  platformIdentityResolver: AuthCallbackPlatformIdentityResolver;
}

export interface AuthCallbackServiceInput {
  params: RawAuthCallbackParams | AuthCallbackParams;
  now: string;
}

export interface AuthCallbackPlatformIdentityResolver {
  resolveAuthenticatedIdentity(
    input: AuthenticatedPlatformIdentityInput,
  ): Promise<AuthCallbackPlatformIdentityResolution>;
}

export interface AuthenticatedPlatformIdentityInput {
  identity: AuthProviderIdentity;
  stateReference: AuthStateReference;
  now: string;
}

export interface AuthStateReference {
  providerKey: string;
  stateHash: string;
  nonceHash: string;
}

export interface AuthCallbackPlatformIdentityResolution {
  platformUserId: string;
  providerIdentityId: string;
  session: Session;
  workspaceMembershipGranted?: boolean;
}

export interface AuthCallbackServiceResult {
  outcome: "authenticated";
  platformUserId: string;
  providerIdentity: AuthCallbackProviderIdentityResult;
  session: Session;
  verifiedEmail: string | null;
  displayName: string | null;
  workspaceMembershipGranted: boolean;
  appAccessGranted: false;
}

export interface AuthCallbackProviderIdentityResult {
  id: string;
  providerKey: string;
  providerSubject: string;
}

export async function handleAuthCallback(
  dependencies: AuthCallbackServiceDependencies,
  input: AuthCallbackServiceInput,
): Promise<AuthCallbackServiceResult> {
  const params = parseAuthCallbackParams(input.params);
  const stateHash = dependencies.stateReferenceFactory(params.state);
  const storedState = await dependencies.stateStore.consumeState({
    providerKey: dependencies.authConfig.providerKey,
    stateHash,
    now: input.now,
  });

  assertStoredStateUsable(
    storedState,
    dependencies.authConfig.providerKey,
    stateHash,
    input.now,
  );

  const tokenExchange = await dependencies.oidcAdapter.exchangeCodeForTokens({
    providerKey: dependencies.authConfig.providerKey,
    code: params.code,
    redirectUri: storedState.redirectUri,
    now: input.now,
  });
  const verifiedIdentity = await dependencies.oidcAdapter.verifyTokens({
    providerKey: dependencies.authConfig.providerKey,
    tokenExchange,
    expectedNonceHash: storedState.nonceHash,
  });
  const identity = createAuthProviderIdentity(verifiedIdentity);
  const resolution = await dependencies.platformIdentityResolver.resolveAuthenticatedIdentity({
    identity,
    stateReference: {
      providerKey: storedState.providerKey,
      stateHash: storedState.stateHash,
      nonceHash: storedState.nonceHash,
    },
    now: input.now,
  });

  return {
    outcome: "authenticated",
    platformUserId: resolution.platformUserId,
    providerIdentity: {
      id: resolution.providerIdentityId,
      providerKey: identity.providerKey,
      providerSubject: identity.providerSubject,
    },
    session: resolution.session,
    verifiedEmail: identity.verifiedEmail,
    displayName: identity.displayName,
    workspaceMembershipGranted: resolution.workspaceMembershipGranted === true,
    appAccessGranted: false,
  };
}

function assertStoredStateUsable(
  storedState: StoredAuthState | null,
  providerKey: string,
  stateHash: string,
  now: string,
): asserts storedState is StoredAuthState {
  if (
    !storedState ||
    storedState.providerKey !== providerKey ||
    storedState.stateHash !== stateHash
  ) {
    throw new AuthCallbackError(
      "missing_stored_state",
      "Authentication callback state could not be verified.",
    );
  }

  if (Date.parse(storedState.expiresAt) <= Date.parse(now)) {
    throw new AuthCallbackError(
      "expired_state",
      "Authentication callback state has expired.",
    );
  }
}

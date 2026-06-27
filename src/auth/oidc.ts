import { normalizeEmail } from "../accounts/normalization.js";
import type { AuthCallbackParams, StoredAuthState } from "./callback.js";
import { normalizeProviderKey } from "./config.js";
import { AuthProviderError } from "./errors.js";

export type OidcMetadataValue = string | number | boolean | null;
export type OidcSafeMetadata = Readonly<Record<string, OidcMetadataValue>>;

export interface OidcAuthorizationUrlInput {
  providerKey: string;
  authorizationUrl: string;
  clientId: string;
  redirectUri: string;
  state: string;
  nonce: string;
  scopes?: readonly string[];
  additionalParams?: Readonly<Record<string, string>>;
}

export interface OidcAuthorizationRequest {
  url: string;
}

export interface OidcTokenExchangeInput {
  providerKey: string;
  code: string;
  redirectUri: string;
  now: string;
}

export interface OidcTokenExchangeResult {
  providerKey: string;
  receivedAt: string;
  expiresAt?: string | null;
  tokenSetRef: "adapter_internal";
}

export interface OidcVerifyTokensInput {
  providerKey: string;
  tokenExchange: OidcTokenExchangeResult;
  expectedNonceHash?: string | null;
}

export interface OidcVerifiedIdentity {
  providerKey: string;
  providerSubject: string;
  verifiedEmail: string | null;
  displayName: string | null;
  metadata: OidcSafeMetadata;
}

export interface AuthProviderIdentity extends OidcVerifiedIdentity {}

export interface AuthCallbackInput {
  params: AuthCallbackParams;
  storedState: StoredAuthState;
  now: string;
}

export interface AuthCallbackResult {
  identity: AuthProviderIdentity;
  shouldCreatePlatformSession: true;
}

export interface OidcProviderAdapter {
  buildAuthorizationUrl(input: OidcAuthorizationUrlInput): Promise<OidcAuthorizationRequest>;
  exchangeCodeForTokens(input: OidcTokenExchangeInput): Promise<OidcTokenExchangeResult>;
  verifyTokens(input: OidcVerifyTokensInput): Promise<OidcVerifiedIdentity>;
}

export function createAuthProviderIdentity(
  identity: OidcVerifiedIdentity,
): AuthProviderIdentity {
  const providerKey = normalizeProviderKey(identity.providerKey);
  const providerSubject = identity.providerSubject.trim();

  if (!providerSubject) {
    throw new AuthProviderError(
      "invalid_verified_identity",
      "Verified identity is missing a provider subject.",
    );
  }

  return {
    providerKey,
    providerSubject,
    verifiedEmail: identity.verifiedEmail ? normalizeEmail(identity.verifiedEmail) : null,
    displayName: normalizeNullableText(identity.displayName),
    metadata: normalizeSafeMetadata(identity.metadata),
  };
}

function normalizeNullableText(value: string | null): string | null {
  const normalized = value?.trim() ?? "";

  return normalized ? normalized : null;
}

function normalizeSafeMetadata(metadata: OidcSafeMetadata): OidcSafeMetadata {
  return Object.freeze({ ...metadata });
}

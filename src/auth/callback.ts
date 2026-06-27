import { normalizeProviderKey } from "./config.js";
import { AuthCallbackError } from "./errors.js";

export interface AuthCallbackParams {
  code: string;
  state: string;
}

export interface RawAuthCallbackParams {
  code?: string | null;
  state?: string | null;
  error?: string | null;
  error_description?: string | null;
  errorDescription?: string | null;
}

export interface StoredAuthState {
  providerKey: string;
  stateHash: string;
  nonceHash: string;
  redirectUri: string;
  createdAt: string;
  expiresAt: string;
}

export interface StoredAuthStateInput {
  providerKey: string;
  stateHash: string;
  nonceHash: string;
  redirectUri: string;
  createdAt: string;
  expiresAt: string;
}

export interface AuthStateStore {
  consumeState(input: AuthStateLookupInput): Promise<StoredAuthState | null>;
}

export interface AuthStateIssueStore {
  storeState(input: StoredAuthStateInput): Promise<StoredAuthState>;
}

export interface AuthStateLookupInput {
  providerKey: string;
  stateHash: string;
  now: string;
}

export function parseAuthCallbackParams(params: RawAuthCallbackParams): AuthCallbackParams {
  if (params.error) {
    throw new AuthCallbackError(
      "provider_error",
      "Authentication provider returned an error.",
    );
  }

  const code = params.code?.trim();
  const state = params.state?.trim();

  if (!code) {
    throw new AuthCallbackError(
      "missing_code",
      "Authentication callback is missing required parameters.",
    );
  }

  if (!state) {
    throw new AuthCallbackError(
      "missing_state",
      "Authentication callback is missing required parameters.",
    );
  }

  return { code, state };
}

export function createStoredAuthStateRecord(input: StoredAuthStateInput): StoredAuthState {
  return {
    providerKey: normalizeProviderKey(input.providerKey),
    stateHash: input.stateHash,
    nonceHash: input.nonceHash,
    redirectUri: input.redirectUri,
    createdAt: input.createdAt,
    expiresAt: input.expiresAt,
  };
}

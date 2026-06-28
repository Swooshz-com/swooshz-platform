import { normalizeEmail } from "../accounts/normalization.js";
import type { AuthConfig } from "./config.js";
import { normalizeProviderKey } from "./config.js";
import { AuthProviderError } from "./errors.js";
import type {
  OidcAuthorizationRequest,
  OidcAuthorizationUrlInput,
  OidcProviderAdapter,
  OidcSafeMetadata,
  OidcTokenExchangeInput,
  OidcTokenExchangeResult,
  OidcVerifiedIdentity,
  OidcVerifyTokensInput,
} from "./oidc.js";
import { createAuthProviderIdentity } from "./oidc.js";

const defaultScopes = ["openid", "email", "profile"] as const;

export interface GenericOidcHttpRequest {
  url: string;
  method: "GET" | "POST";
  headers: Readonly<Record<string, string>>;
  body?: string;
}

export interface GenericOidcHttpResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}

export type GenericOidcHttpClient = (
  request: GenericOidcHttpRequest,
) => Promise<GenericOidcHttpResponse>;

export interface GenericOidcTokenVerifierInput {
  providerKey: string;
  idToken: string;
  issuerUrl: string | null;
  jwksUrl: string | null;
  clientId: string;
  now: string;
}

export interface GenericOidcVerifiedClaims {
  subject: string;
  email?: string | null;
  emailVerified?: boolean | null;
  displayName?: string | null;
  nonce?: string | null;
  metadata?: OidcSafeMetadata;
}

export interface GenericOidcTokenVerifier {
  verify(input: GenericOidcTokenVerifierInput): Promise<GenericOidcVerifiedClaims>;
}

export type GenericOidcNonceReferenceFactory = (nonce: string) => string;

export interface GenericOidcProviderAdapterDependencies {
  authConfig: AuthConfig;
  httpClient?: GenericOidcHttpClient;
  tokenVerifier: GenericOidcTokenVerifier;
  nonceReferenceFactory: GenericOidcNonceReferenceFactory;
}

interface GenericOidcTokenSet {
  providerKey: string;
  idToken: string;
  accessToken: string | null;
  receivedAt: string;
}

export function createGenericOidcProviderAdapter(
  dependencies: GenericOidcProviderAdapterDependencies,
): OidcProviderAdapter {
  const httpClient = dependencies.httpClient ?? createDefaultGenericOidcHttpClient();
  const tokenSets = new WeakMap<OidcTokenExchangeResult, GenericOidcTokenSet>();

  return {
    async buildAuthorizationUrl(input) {
      return buildAuthorizationUrl(input);
    },
    async exchangeCodeForTokens(input) {
      return exchangeCodeForTokens(
        dependencies.authConfig,
        httpClient,
        tokenSets,
        input,
      );
    },
    async verifyTokens(input) {
      return verifyTokens(dependencies, httpClient, tokenSets, input);
    },
  };
}

export function createDefaultGenericOidcHttpClient(): GenericOidcHttpClient {
  return async (request) => {
    const fetchImplementation = globalThis.fetch;

    if (typeof fetchImplementation !== "function") {
      throw new AuthProviderError(
        "provider_verification_failed",
        "OIDC HTTP client is unavailable.",
      );
    }

    const response = await fetchImplementation(request.url, {
      method: request.method,
      headers: request.headers,
      body: request.body,
    });

    return {
      ok: response.ok,
      status: response.status,
      async json() {
        return response.json();
      },
    };
  };
}

function buildAuthorizationUrl(
  input: OidcAuthorizationUrlInput,
): OidcAuthorizationRequest {
  try {
    const url = new URL(input.authorizationUrl);
    const scopes = input.scopes?.length ? input.scopes : defaultScopes;

    for (const [key, value] of Object.entries(input.additionalParams ?? {})) {
      url.searchParams.set(key, value);
    }

    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", input.clientId);
    url.searchParams.set("redirect_uri", input.redirectUri);
    url.searchParams.set("scope", scopes.join(" "));
    url.searchParams.set("state", input.state);
    url.searchParams.set("nonce", input.nonce);

    return { url: url.toString() };
  } catch {
    throw new AuthProviderError(
      "provider_verification_failed",
      "OIDC authorization URL could not be built.",
    );
  }
}

async function exchangeCodeForTokens(
  authConfig: AuthConfig,
  httpClient: GenericOidcHttpClient,
  tokenSets: WeakMap<OidcTokenExchangeResult, GenericOidcTokenSet>,
  input: OidcTokenExchangeInput,
): Promise<OidcTokenExchangeResult> {
  assertConfiguredProvider(authConfig, input.providerKey);

  const form = new URLSearchParams({
    grant_type: "authorization_code",
    code: input.code,
    redirect_uri: input.redirectUri,
    client_id: authConfig.clientId,
    client_secret: authConfig.clientSecret,
  });

  try {
    const response = await httpClient({
      url: authConfig.tokenUrl,
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      },
      body: form.toString(),
    });

    if (!response.ok) {
      throw createProviderFailure("OIDC token exchange failed.");
    }

    const tokenResponse = await response.json();
    const tokenSet = parseTokenResponse(tokenResponse, input);
    const result: OidcTokenExchangeResult = {
      providerKey: authConfig.providerKey,
      receivedAt: input.now,
      expiresAt: readExpiresAt(tokenResponse, input.now),
      tokenSetRef: "adapter_internal",
    };

    tokenSets.set(result, tokenSet);

    return result;
  } catch (error) {
    if (error instanceof AuthProviderError) {
      throw error;
    }

    throw createProviderFailure("OIDC token exchange failed.");
  }
}

async function verifyTokens(
  dependencies: GenericOidcProviderAdapterDependencies,
  httpClient: GenericOidcHttpClient,
  tokenSets: WeakMap<OidcTokenExchangeResult, GenericOidcTokenSet>,
  input: OidcVerifyTokensInput,
): Promise<OidcVerifiedIdentity> {
  assertConfiguredProvider(dependencies.authConfig, input.providerKey);

  const tokenSet = tokenSets.get(input.tokenExchange);

  if (!tokenSet || tokenSet.providerKey !== dependencies.authConfig.providerKey) {
    throw createProviderFailure("OIDC token verification failed.");
  }

  try {
    const verifiedClaims = await dependencies.tokenVerifier.verify({
      providerKey: dependencies.authConfig.providerKey,
      idToken: tokenSet.idToken,
      issuerUrl: dependencies.authConfig.issuerUrl,
      jwksUrl: dependencies.authConfig.jwksUrl,
      clientId: dependencies.authConfig.clientId,
      now: tokenSet.receivedAt,
    });

    assertNonceMatches(
      verifiedClaims,
      input.expectedNonceHash,
      dependencies.nonceReferenceFactory,
    );

    const userinfo = await readVerifiedUserinfo(
      dependencies.authConfig,
      httpClient,
      tokenSet,
      verifiedClaims.subject,
      verifiedClaims,
    );

    return createAuthProviderIdentity({
      providerKey: dependencies.authConfig.providerKey,
      providerSubject: verifiedClaims.subject,
      verifiedEmail: readVerifiedEmail(verifiedClaims, userinfo),
      displayName: readDisplayName(verifiedClaims, userinfo),
      metadata: normalizeMetadata(verifiedClaims.metadata),
    });
  } catch (error) {
    if (error instanceof AuthProviderError) {
      throw error;
    }

    throw createProviderFailure("OIDC token verification failed.");
  }
}

async function readVerifiedUserinfo(
  authConfig: AuthConfig,
  httpClient: GenericOidcHttpClient,
  tokenSet: GenericOidcTokenSet,
  subject: string,
  verifiedClaims: GenericOidcVerifiedClaims,
): Promise<Record<string, unknown> | null> {
  const hasVerifiedEmail = verifiedClaims.emailVerified === true && !!verifiedClaims.email;
  const hasDisplayName = !!verifiedClaims.displayName?.trim();

  if (
    !authConfig.userinfoUrl ||
    !tokenSet.accessToken ||
    (hasVerifiedEmail && hasDisplayName)
  ) {
    return null;
  }

  const response = await httpClient({
    url: authConfig.userinfoUrl,
    method: "GET",
    headers: {
      accept: "application/json",
      authorization: `Bearer ${tokenSet.accessToken}`,
    },
  });

  if (!response.ok) {
    throw createProviderFailure("OIDC userinfo request failed.");
  }

  const body = await response.json();

  if (!isRecord(body)) {
    throw createProviderFailure("OIDC userinfo response was invalid.");
  }

  const userinfoSubject = readString(body.sub);

  if (!userinfoSubject || userinfoSubject !== subject) {
    throw createProviderFailure("OIDC userinfo subject did not match.");
  }

  return body;
}

function parseTokenResponse(
  tokenResponse: unknown,
  input: OidcTokenExchangeInput,
): GenericOidcTokenSet {
  if (!isRecord(tokenResponse)) {
    throw createProviderFailure("OIDC token response was invalid.");
  }

  const idToken = readString(tokenResponse.id_token);
  const accessToken = readString(tokenResponse.access_token);

  if (!idToken) {
    throw createProviderFailure("OIDC token response was invalid.");
  }

  return {
    providerKey: normalizeProviderKey(input.providerKey),
    idToken,
    accessToken,
    receivedAt: input.now,
  };
}

function readExpiresAt(tokenResponse: unknown, now: string): string | null {
  if (!isRecord(tokenResponse) || typeof tokenResponse.expires_in !== "number") {
    return null;
  }

  if (!Number.isFinite(tokenResponse.expires_in) || tokenResponse.expires_in <= 0) {
    return null;
  }

  const nowMs = Date.parse(now);

  if (!Number.isFinite(nowMs)) {
    return null;
  }

  return new Date(nowMs + tokenResponse.expires_in * 1000).toISOString();
}

function assertNonceMatches(
  verifiedClaims: GenericOidcVerifiedClaims,
  expectedNonceHash: string | null | undefined,
  nonceReferenceFactory: GenericOidcNonceReferenceFactory,
): void {
  if (!expectedNonceHash) {
    return;
  }

  const nonce = verifiedClaims.nonce?.trim() ?? "";

  if (!nonce || nonceReferenceFactory(nonce) !== expectedNonceHash) {
    throw createProviderFailure("OIDC nonce could not be verified.");
  }
}

function readVerifiedEmail(
  verifiedClaims: GenericOidcVerifiedClaims,
  userinfo: Record<string, unknown> | null,
): string | null {
  if (verifiedClaims.emailVerified === true && verifiedClaims.email) {
    return normalizeEmail(verifiedClaims.email);
  }

  if (
    userinfo?.email_verified === true &&
    typeof userinfo.email === "string" &&
    userinfo.email.trim()
  ) {
    return normalizeEmail(userinfo.email);
  }

  return null;
}

function readDisplayName(
  verifiedClaims: GenericOidcVerifiedClaims,
  userinfo: Record<string, unknown> | null,
): string | null {
  const claimName = verifiedClaims.displayName?.trim() ?? "";

  if (claimName) {
    return claimName;
  }

  const userinfoName = readString(userinfo?.name);

  return userinfoName || null;
}

function normalizeMetadata(metadata: OidcSafeMetadata | undefined): OidcSafeMetadata {
  if (!metadata) {
    return {};
  }

  const normalized: Record<string, string | number | boolean | null> = {};

  for (const [key, value] of Object.entries(metadata)) {
    if (
      typeof value === "string" ||
      typeof value === "number" ||
      typeof value === "boolean" ||
      value === null
    ) {
      normalized[key] = value;
    }
  }

  return normalized;
}

function assertConfiguredProvider(authConfig: AuthConfig, providerKey: string): void {
  if (normalizeProviderKey(providerKey) !== authConfig.providerKey) {
    throw createProviderFailure("OIDC provider key did not match configuration.");
  }
}

function createProviderFailure(message: string): AuthProviderError {
  return new AuthProviderError("provider_verification_failed", message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

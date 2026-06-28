import {
  createPublicKey,
  createVerify,
  type JsonWebKeyInput,
  type KeyObject,
} from "node:crypto";

import { normalizeProviderKey } from "./config.js";
import { AuthProviderError } from "./errors.js";
import {
  createDefaultGenericOidcHttpClient,
  type GenericOidcHttpClient,
  type GenericOidcTokenVerifier,
  type GenericOidcTokenVerifierInput,
  type GenericOidcVerifiedClaims,
} from "./generic-oidc-provider-adapter.js";
import type { OidcSafeMetadata } from "./oidc.js";

export interface GenericOidcJwksTokenVerifierDependencies {
  httpClient?: GenericOidcHttpClient;
  clockToleranceSeconds?: number;
}

interface JwtHeader {
  alg: string;
  kid?: string;
  typ?: string;
}

interface ParsedJwt {
  header: JwtHeader;
  payload: Record<string, unknown>;
  signingInput: string;
  signature: Buffer;
}

const supportedAlgorithm = "RS256";
const defaultClockToleranceSeconds = 60;
const standardClaims = new Set([
  "iss",
  "sub",
  "aud",
  "exp",
  "nbf",
  "iat",
  "jti",
  "auth_time",
  "nonce",
  "azp",
  "at_hash",
  "c_hash",
  "email",
  "email_verified",
  "name",
  "given_name",
  "family_name",
  "middle_name",
  "nickname",
  "preferred_username",
  "profile",
  "picture",
  "website",
  "gender",
  "birthdate",
  "zoneinfo",
  "locale",
  "phone_number",
  "phone_number_verified",
  "address",
  "updated_at",
]);

export function createGenericOidcJwksTokenVerifier(
  dependencies: GenericOidcJwksTokenVerifierDependencies = {},
): GenericOidcTokenVerifier {
  const httpClient =
    dependencies.httpClient ?? createDefaultGenericOidcHttpClient();
  const clockToleranceSeconds =
    dependencies.clockToleranceSeconds ?? defaultClockToleranceSeconds;

  return {
    async verify(input) {
      return verifyIdToken(input, httpClient, clockToleranceSeconds);
    },
  };
}

async function verifyIdToken(
  input: GenericOidcTokenVerifierInput,
  httpClient: GenericOidcHttpClient,
  clockToleranceSeconds: number,
): Promise<GenericOidcVerifiedClaims> {
  try {
    normalizeProviderKey(input.providerKey);

    if (!input.issuerUrl?.trim() || !input.jwksUrl?.trim()) {
      throw createProviderFailure("OIDC verifier configuration is incomplete.");
    }

    const parsed = parseJwt(input.idToken);
    assertSupportedAlgorithm(parsed.header);

    const key = await readSigningKey(httpClient, input.jwksUrl, parsed.header);
    assertSignature(parsed, key);
    assertClaims(parsed.payload, input, clockToleranceSeconds);

    return readVerifiedClaims(parsed.payload);
  } catch (error) {
    if (error instanceof AuthProviderError) {
      throw error;
    }

    throw createProviderFailure("OIDC ID token could not be verified.");
  }
}

function parseJwt(idToken: string): ParsedJwt {
  const parts = idToken.split(".");

  if (parts.length !== 3 || parts.some((part) => !part)) {
    throw createProviderFailure("OIDC ID token was invalid.");
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const header = parseBase64UrlJson(encodedHeader);
  const payload = parseBase64UrlJson(encodedPayload);

  if (!isRecord(header) || !isRecord(payload)) {
    throw createProviderFailure("OIDC ID token was invalid.");
  }

  const alg = readString(header.alg);

  if (!alg) {
    throw createProviderFailure("OIDC ID token was invalid.");
  }

  return {
    header: {
      alg,
      kid: readString(header.kid) ?? undefined,
      typ: readString(header.typ) ?? undefined,
    },
    payload,
    signingInput: `${encodedHeader}.${encodedPayload}`,
    signature: Buffer.from(encodedSignature, "base64url"),
  };
}

function parseBase64UrlJson(value: string): unknown {
  try {
    return JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
  } catch {
    throw createProviderFailure("OIDC ID token was invalid.");
  }
}

function assertSupportedAlgorithm(header: JwtHeader): void {
  if (header.alg !== supportedAlgorithm) {
    throw createProviderFailure("OIDC ID token algorithm is not supported.");
  }
}

async function readSigningKey(
  httpClient: GenericOidcHttpClient,
  jwksUrl: string,
  header: JwtHeader,
): Promise<KeyObject> {
  try {
    const response = await httpClient({
      url: jwksUrl,
      method: "GET",
      headers: {
        accept: "application/json",
      },
    });

    if (!response.ok) {
      throw createProviderFailure("OIDC JWKS request failed.");
    }

    const jwks = await response.json();
    const jwk = selectSigningJwk(jwks, header);

    return createPublicKey({
      key: jwk as JsonWebKeyInput["key"],
      format: "jwk",
    });
  } catch (error) {
    if (error instanceof AuthProviderError) {
      throw error;
    }

    throw createProviderFailure("OIDC JWKS could not be used.");
  }
}

function selectSigningJwk(jwks: unknown, header: JwtHeader): Record<string, unknown> {
  if (!isRecord(jwks) || !Array.isArray(jwks.keys)) {
    throw createProviderFailure("OIDC JWKS response was invalid.");
  }

  const candidates = jwks.keys.filter(isUsableRsaSigningJwk);
  const selected = header.kid
    ? candidates.find((key) => key.kid === header.kid)
    : candidates.length === 1
      ? candidates[0]
      : undefined;

  if (!selected) {
    throw createProviderFailure("OIDC signing key was not found.");
  }

  return selected;
}

function isUsableRsaSigningJwk(value: unknown): value is Record<string, unknown> {
  if (!isRecord(value)) {
    return false;
  }

  return (
    value.kty === "RSA" &&
    (value.use === undefined || value.use === "sig") &&
    (value.alg === undefined || value.alg === supportedAlgorithm)
  );
}

function assertSignature(parsed: ParsedJwt, key: KeyObject): void {
  const verified = createVerify("RSA-SHA256")
    .update(parsed.signingInput)
    .end()
    .verify(key, parsed.signature);

  if (!verified) {
    throw createProviderFailure("OIDC ID token signature could not be verified.");
  }
}

function assertClaims(
  claims: Record<string, unknown>,
  input: GenericOidcTokenVerifierInput,
  clockToleranceSeconds: number,
): void {
  const nowSeconds = readNowSeconds(input.now);
  const issuer = readString(claims.iss);
  const subject = readString(claims.sub);

  if (issuer !== input.issuerUrl) {
    throw createProviderFailure("OIDC issuer did not match.");
  }

  if (!audienceIncludesClientId(claims.aud, input.clientId)) {
    throw createProviderFailure("OIDC audience did not match.");
  }

  if (!subject) {
    throw createProviderFailure("OIDC subject was missing.");
  }

  assertExpiration(claims.exp, nowSeconds, clockToleranceSeconds);
  assertNotBefore(claims.nbf, nowSeconds, clockToleranceSeconds);
  assertIssuedAt(claims.iat, nowSeconds, clockToleranceSeconds);
}

function readNowSeconds(now: string): number {
  const nowMs = Date.parse(now);

  if (!Number.isFinite(nowMs)) {
    throw createProviderFailure("OIDC verifier time was invalid.");
  }

  return Math.floor(nowMs / 1000);
}

function audienceIncludesClientId(audience: unknown, clientId: string): boolean {
  if (typeof audience === "string") {
    return audience === clientId;
  }

  if (Array.isArray(audience)) {
    return audience.includes(clientId);
  }

  return false;
}

function assertExpiration(
  exp: unknown,
  nowSeconds: number,
  clockToleranceSeconds: number,
): void {
  if (typeof exp !== "number" || !Number.isFinite(exp)) {
    throw createProviderFailure("OIDC expiry was invalid.");
  }

  if (nowSeconds > exp + clockToleranceSeconds) {
    throw createProviderFailure("OIDC ID token expired.");
  }
}

function assertNotBefore(
  nbf: unknown,
  nowSeconds: number,
  clockToleranceSeconds: number,
): void {
  if (nbf === undefined) {
    return;
  }

  if (typeof nbf !== "number" || !Number.isFinite(nbf)) {
    throw createProviderFailure("OIDC not-before claim was invalid.");
  }

  if (nowSeconds + clockToleranceSeconds < nbf) {
    throw createProviderFailure("OIDC ID token is not yet valid.");
  }
}

function assertIssuedAt(
  iat: unknown,
  nowSeconds: number,
  clockToleranceSeconds: number,
): void {
  if (iat === undefined) {
    return;
  }

  if (typeof iat !== "number" || !Number.isFinite(iat)) {
    throw createProviderFailure("OIDC issued-at claim was invalid.");
  }

  if (nowSeconds + clockToleranceSeconds < iat) {
    throw createProviderFailure("OIDC ID token issued-at claim is in the future.");
  }
}

function readVerifiedClaims(
  claims: Record<string, unknown>,
): GenericOidcVerifiedClaims {
  const subject = readString(claims.sub);

  if (!subject) {
    throw createProviderFailure("OIDC subject was missing.");
  }

  const emailVerified =
    typeof claims.email_verified === "boolean" ? claims.email_verified : null;
  const email =
    emailVerified === true ? readString(claims.email) : null;

  return {
    subject,
    email,
    emailVerified,
    displayName: readString(claims.name),
    nonce: readString(claims.nonce),
    metadata: readSafeMetadata(claims),
  };
}

function readSafeMetadata(claims: Record<string, unknown>): OidcSafeMetadata {
  const metadata: Record<string, string | number | boolean | null> = {};

  for (const [key, value] of Object.entries(claims)) {
    if (standardClaims.has(key) || isUnsafeMetadataKey(key)) {
      continue;
    }

    if (
      typeof value === "string" ||
      typeof value === "number" ||
      typeof value === "boolean" ||
      value === null
    ) {
      metadata[key] = value;
    }
  }

  return metadata;
}

function isUnsafeMetadataKey(key: string): boolean {
  const normalized = key.trim().toLowerCase();
  const compact = normalized.replace(/[^a-z0-9]/g, "");

  if (!compact) {
    return true;
  }

  return (
    compact.startsWith("raw") ||
    compact.includes("providerresponse") ||
    compact.includes("providerpayload") ||
    compact.includes("token") ||
    compact.includes("secret") ||
    compact.includes("password") ||
    compact.includes("credential") ||
    compact.includes("apikey") ||
    compact.includes("privatekey") ||
    compact === "key" ||
    compact.endsWith("key") ||
    compact === "code" ||
    compact.includes("authcode") ||
    compact.includes("authorizationcode")
  );
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

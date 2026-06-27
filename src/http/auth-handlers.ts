import type {
  AuthStateIssueStore,
  RawAuthCallbackParams,
  StoredAuthStateInput,
} from "../auth/callback.js";
import type { AuthCallbackServiceDependencies } from "../auth/callback-service.js";
import { handleAuthCallback } from "../auth/callback-service.js";
import type { AuthConfig } from "../auth/config.js";
import type { OidcProviderAdapter } from "../auth/oidc.js";
import type { HttpResponseLike } from "./handlers.js";
import {
  buildBrowserSessionSetCookie,
  type BrowserSessionCookieConfig,
} from "./session-cookie.js";

export interface AuthStartValueFactory {
  createState(): string;
}

export interface AuthNonceValueFactory {
  createNonce(): string;
}

export type AuthReferenceFactory = (value: string) => string;

export interface AuthStartHttpDependencies {
  authConfig: AuthConfig;
  oidcAdapter: Pick<OidcProviderAdapter, "buildAuthorizationUrl">;
  stateStore: AuthStateIssueStore;
  stateFactory: AuthStartValueFactory;
  nonceFactory: AuthNonceValueFactory;
  stateReferenceFactory: AuthReferenceFactory;
  nonceReferenceFactory?: AuthReferenceFactory;
  ttlSeconds: number;
}

export interface AuthStartHttpRequest {
  now: string;
}

export interface AuthCallbackHttpDependencies
  extends AuthCallbackServiceDependencies {
  successRedirectPath?: string;
}

export interface AuthCallbackHttpRequest {
  query: RawAuthCallbackParams;
  now: string;
  cookie?: BrowserSessionCookieConfig;
}

const defaultAuthSuccessRedirectPath = "/app";

export async function handleAuthStartRequest(
  dependencies: AuthStartHttpDependencies,
  request: AuthStartHttpRequest,
): Promise<HttpResponseLike> {
  try {
    const state = readFactoryValue(
      dependencies.stateFactory.createState(),
    );
    const nonce = readFactoryValue(
      dependencies.nonceFactory.createNonce(),
    );
    const stateHash = readReference(
      dependencies.stateReferenceFactory(state),
    );
    const nonceHash = readReference(
      (dependencies.nonceReferenceFactory ?? dependencies.stateReferenceFactory)(
        nonce,
      ),
    );
    const expiresAt = addSeconds(request.now, dependencies.ttlSeconds);
    const stateRecord: StoredAuthStateInput = {
      providerKey: dependencies.authConfig.providerKey,
      stateHash,
      nonceHash,
      redirectUri: dependencies.authConfig.redirectUri,
      createdAt: request.now,
      expiresAt,
    };

    await dependencies.stateStore.storeState(stateRecord);

    const authorization = await dependencies.oidcAdapter.buildAuthorizationUrl({
      providerKey: dependencies.authConfig.providerKey,
      authorizationUrl: dependencies.authConfig.authorizationUrl,
      clientId: dependencies.authConfig.clientId,
      redirectUri: dependencies.authConfig.redirectUri,
      state,
      nonce,
    });
    const location = readRedirectUrl(authorization.url);

    return {
      status: 302,
      headers: {
        location,
      },
      body: {
        outcome: "redirecting",
      },
    };
  } catch {
    return authStartFailure();
  }
}

export async function handleAuthCallbackRequest(
  dependencies: AuthCallbackHttpDependencies,
  request: AuthCallbackHttpRequest,
): Promise<HttpResponseLike> {
  try {
    const result = await handleAuthCallback(dependencies, {
      params: request.query,
      now: request.now,
    });

    return {
      status: 302,
      headers: {
        location: normalizeLocalRedirectPath(dependencies.successRedirectPath),
        "set-cookie": buildBrowserSessionSetCookie(
          result.session.id,
          request.cookie,
        ),
      },
      body: {
        outcome: "authenticated",
      },
    };
  } catch {
    return authCallbackFailure();
  }
}

function readFactoryValue(value: string): string {
  const normalized = value.trim();

  if (!normalized) {
    throw new Error("Invalid auth value.");
  }

  return normalized;
}

function readReference(value: string): string {
  const normalized = value.trim();

  if (!normalized) {
    throw new Error("Invalid auth reference.");
  }

  return normalized;
}

function addSeconds(now: string, ttlSeconds: number): string {
  const timestamp = Date.parse(now);

  if (!Number.isFinite(timestamp) || !Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
    throw new Error("Invalid auth state expiry.");
  }

  return new Date(timestamp + ttlSeconds * 1000).toISOString();
}

function readRedirectUrl(value: string): string {
  const parsed = new URL(value);

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("Invalid auth redirect.");
  }

  return parsed.toString();
}

function normalizeLocalRedirectPath(value: string | undefined): string {
  const candidate = value?.trim() || defaultAuthSuccessRedirectPath;

  if (!candidate.startsWith("/") || candidate.startsWith("//") || candidate.includes("\\")) {
    return defaultAuthSuccessRedirectPath;
  }

  return candidate;
}

function authStartFailure(): HttpResponseLike {
  return {
    status: 500,
    body: {
      outcome: "error",
      message: "Authentication start could not be completed.",
    },
  };
}

function authCallbackFailure(): HttpResponseLike {
  return {
    status: 400,
    body: {
      outcome: "error",
      message: "Authentication callback could not be completed.",
    },
  };
}

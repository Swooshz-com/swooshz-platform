import type { CsrfTokenValidator } from "./csrf.js";
import type {
  CsrfTokenPurpose,
  CsrfTokenRecord,
  CsrfTokenRepository,
} from "./csrf-token-repositories.js";

export type CsrfTokenServiceErrorCode =
  | "invalid_session"
  | "token_factory_failed"
  | "token_hash_failed"
  | "token_store_failed";

export class CsrfTokenServiceError extends Error {
  readonly code: CsrfTokenServiceErrorCode;
  readonly publicMessage = "CSRF token operation could not be completed.";

  constructor(code: CsrfTokenServiceErrorCode) {
    super("CSRF token operation could not be completed.");
    this.name = "CsrfTokenServiceError";
    this.code = code;
  }
}

export interface CsrfTokenFactory {
  createToken(): Promise<string>;
}

export interface CsrfTokenHasher {
  hashToken(token: string): Promise<string>;
}

export interface CsrfTokenIdFactory {
  createId(): string;
}

export interface CsrfTokenServiceDependencies {
  tokens: CsrfTokenRepository;
  tokenFactory: CsrfTokenFactory;
  tokenHasher: CsrfTokenHasher;
  idFactory: CsrfTokenIdFactory;
}

export interface IssueCsrfTokenForSessionInput {
  sessionId: string;
  now: string;
  ttlSeconds: number;
  purpose: CsrfTokenPurpose;
}

export interface IssuedCsrfToken {
  csrfToken: string;
  expiresAt: string;
}

export type RepositoryBackedCsrfTokenInvalidReason =
  | "missing_session"
  | "unknown_token"
  | "expired_token"
  | "inactive_token"
  | "validation_failed";

export async function issueCsrfTokenForSession(
  dependencies: CsrfTokenServiceDependencies,
  input: IssueCsrfTokenForSessionInput,
): Promise<IssuedCsrfToken> {
  if (!input.sessionId.trim()) {
    throw new CsrfTokenServiceError("invalid_session");
  }

  const csrfToken = await createTokenSafely(dependencies.tokenFactory);
  const tokenHash = await hashTokenSafely(dependencies.tokenHasher, csrfToken);
  const expiresAt = addSeconds(input.now, input.ttlSeconds);

  await createRecordSafely(dependencies.tokens, {
    id: dependencies.idFactory.createId(),
    sessionId: input.sessionId,
    tokenHash,
    purpose: input.purpose,
    createdAt: input.now,
    expiresAt,
    consumedAt: null,
    revokedAt: null,
    replacedByTokenId: null,
  });

  return {
    csrfToken,
    expiresAt,
  };
}

export function createRepositoryBackedCsrfTokenValidator(
  dependencies: Pick<CsrfTokenServiceDependencies, "tokens" | "tokenHasher">,
  purpose: CsrfTokenPurpose = "browser_session",
): CsrfTokenValidator {
  return {
    async validate(input) {
      if (!input.sessionId?.trim()) {
        return invalid("missing_session");
      }

      try {
        const tokenHash = await dependencies.tokenHasher.hashToken(input.csrfToken);
        const record = await dependencies.tokens.findBySessionAndTokenHash(
          input.sessionId,
          tokenHash,
          purpose,
        );

        if (!record) {
          return invalid("unknown_token");
        }

        if (isInactive(record)) {
          return invalid("inactive_token");
        }

        if (isExpired(record, input.now)) {
          return invalid("expired_token");
        }

        return { valid: true };
      } catch {
        return invalid("validation_failed");
      }
    },
  };
}

async function createTokenSafely(
  tokenFactory: CsrfTokenFactory,
): Promise<string> {
  try {
    return await tokenFactory.createToken();
  } catch {
    throw new CsrfTokenServiceError("token_factory_failed");
  }
}

async function hashTokenSafely(
  tokenHasher: CsrfTokenHasher,
  csrfToken: string,
): Promise<string> {
  try {
    return await tokenHasher.hashToken(csrfToken);
  } catch {
    throw new CsrfTokenServiceError("token_hash_failed");
  }
}

async function createRecordSafely(
  tokens: CsrfTokenRepository,
  record: CsrfTokenRecord,
): Promise<CsrfTokenRecord> {
  try {
    return await tokens.create(record);
  } catch {
    throw new CsrfTokenServiceError("token_store_failed");
  }
}

function addSeconds(now: string, ttlSeconds: number): string {
  return new Date(new Date(now).getTime() + ttlSeconds * 1000).toISOString();
}

function isInactive(record: CsrfTokenRecord): boolean {
  return Boolean(record.consumedAt || record.revokedAt);
}

function isExpired(record: CsrfTokenRecord, now: string): boolean {
  return new Date(record.expiresAt).getTime() <= new Date(now).getTime();
}

function invalid(reason: RepositoryBackedCsrfTokenInvalidReason) {
  return {
    valid: false as const,
    reason,
  };
}

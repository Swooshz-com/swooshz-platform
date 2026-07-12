export type CsrfTokenPurpose = "browser_session";

export interface CsrfTokenRecord {
  id: string;
  sessionId: string;
  tokenHash: string;
  purpose: CsrfTokenPurpose;
  createdAt: string;
  expiresAt: string;
  consumedAt: string | null;
  revokedAt: string | null;
  replacedByTokenId: string | null;
}

export interface CreateCsrfTokenRecordInput {
  id: string;
  sessionId: string;
  tokenHash: string;
  purpose: CsrfTokenPurpose;
  createdAt: string;
  expiresAt: string;
  consumedAt: string | null;
  revokedAt: string | null;
  replacedByTokenId: string | null;
}

export interface CsrfTokenRepository {
  createBoundedForSession(input: CreateCsrfTokenRecordInput): Promise<CsrfTokenRecord>;
  findBySessionAndTokenHash(
    sessionId: string,
    tokenHash: string,
    purpose: CsrfTokenPurpose,
  ): Promise<CsrfTokenRecord | null>;
}

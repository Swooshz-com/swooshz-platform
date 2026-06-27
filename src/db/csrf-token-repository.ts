import { and, eq } from "drizzle-orm";

import {
  mapCsrfTokenRow,
  toDate,
  type CsrfTokenRow,
} from "./mappers.js";
import { csrfTokens } from "./schema.js";
import type { DrizzleDatabase } from "./repositories.js";
import type {
  CreateCsrfTokenRecordInput,
  CsrfTokenPurpose,
  CsrfTokenRecord,
  CsrfTokenRepository,
} from "../http/csrf-token-repositories.js";

type Row = Record<string, unknown>;

export function createDrizzleCsrfTokenRepository(
  db: Pick<DrizzleDatabase, "select" | "insert">,
): CsrfTokenRepository {
  return {
    async create(input) {
      const rows = await db
        .insert(csrfTokens)
        .values(csrfTokenToValues(input))
        .returning();

      return mapOneRequired(rows[0], mapCsrfTokenRow);
    },
    async findBySessionAndTokenHash(sessionId, tokenHash, purpose) {
      return mapOne(
        await selectOne(
          db,
          and(
            eq(csrfTokens.sessionId, sessionId),
            eq(csrfTokens.tokenHash, tokenHash),
            eq(csrfTokens.purpose, purpose),
          ),
        ),
        mapCsrfTokenRow,
      );
    },
  };
}

async function selectOne(
  db: Pick<DrizzleDatabase, "select">,
  condition: unknown,
): Promise<Row | undefined> {
  const rows = await db.select().from(csrfTokens).where(condition).limit(1);
  return rows[0];
}

function mapOne<T, RowType>(
  row: Row | undefined,
  mapper: (row: RowType) => T,
): T | null {
  return row ? mapper(row as unknown as RowType) : null;
}

function mapOneRequired<T, RowType>(
  row: Row | undefined,
  mapper: (row: RowType) => T,
): T {
  if (!row) {
    throw new Error("Expected CSRF token repository write to return a row.");
  }

  return mapper(row as unknown as RowType);
}

function csrfTokenToValues(input: CreateCsrfTokenRecordInput): Row {
  return {
    id: input.id,
    sessionId: input.sessionId,
    tokenHash: input.tokenHash,
    purpose: input.purpose satisfies CsrfTokenPurpose,
    createdAt: toDate(input.createdAt),
    expiresAt: toDate(input.expiresAt),
    consumedAt: toDate(input.consumedAt),
    revokedAt: toDate(input.revokedAt),
    replacedByTokenId: input.replacedByTokenId,
  } satisfies Omit<CsrfTokenRecord, "createdAt" | "expiresAt" | "consumedAt" | "revokedAt"> & {
    createdAt: Date;
    expiresAt: Date;
    consumedAt: Date | null;
    revokedAt: Date | null;
  };
}

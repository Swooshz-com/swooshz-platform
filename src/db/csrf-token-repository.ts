import { and, eq, gt, inArray, isNotNull, isNull, lte, or } from "drizzle-orm";

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

export const maxActiveCsrfTokensPerSessionPurpose = 8;

export function createDrizzleCsrfTokenRepository(
  db: Pick<DrizzleDatabase, "select" | "insert" | "delete" | "transaction">,
): CsrfTokenRepository {
  return {
    async createBoundedForSession(input) {
      if (!db.transaction) {
        throw new Error("Bounded CSRF token persistence requires transaction support.");
      }

      return db.transaction(async (tx) => {
        const sessionPurpose = and(
          eq(csrfTokens.sessionId, input.sessionId),
          eq(csrfTokens.purpose, input.purpose),
        );
        const createdAt = toDate(input.createdAt);

        await tx
          .delete(csrfTokens)
          .where(
            and(
              sessionPurpose,
              or(
                lte(csrfTokens.expiresAt, createdAt),
                isNotNull(csrfTokens.consumedAt),
                isNotNull(csrfTokens.revokedAt),
              ),
            ),
          );

        const activeRows = await tx
          .select()
          .from(csrfTokens)
          .where(
            and(
              sessionPurpose,
              gt(csrfTokens.expiresAt, createdAt),
              isNull(csrfTokens.consumedAt),
              isNull(csrfTokens.revokedAt),
            ),
          );
        const idsToEvict = selectOldestCsrfTokenIds(
          activeRows,
          maxActiveCsrfTokensPerSessionPurpose - 1,
        );

        if (idsToEvict.length > 0) {
          await tx
            .delete(csrfTokens)
            .where(
              and(
                sessionPurpose,
                inArray(csrfTokens.id, idsToEvict),
              ),
            );
        }

        const rows = await tx
          .insert(csrfTokens)
          .values(csrfTokenToValues(input))
          .returning();

        return mapOneRequired(rows[0], mapCsrfTokenRow);
      }, { isolationLevel: "serializable" });
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


function selectOldestCsrfTokenIds(
  rows: readonly Row[],
  retainedBeforeInsert: number,
): string[] {
  return [...rows]
    .sort((left, right) => compareNewestFirst(left, right))
    .slice(retainedBeforeInsert)
    .map((row) => String(row.id));
}

function compareNewestFirst(left: Row, right: Row): number {
  const createdDifference = toTimestamp(right.createdAt) - toTimestamp(left.createdAt);

  if (createdDifference !== 0) {
    return createdDifference;
  }

  return String(right.id).localeCompare(String(left.id));
}

function toTimestamp(value: unknown): number {
  const timestamp = value instanceof Date ? value.getTime() : Date.parse(String(value));

  if (!Number.isFinite(timestamp)) {
    throw new Error("Expected persisted CSRF token creation time to be valid.");
  }

  return timestamp;
}

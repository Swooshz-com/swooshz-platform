import { and, eq, isNull } from "drizzle-orm";

import {
  mapAppLaunchTokenRow,
  toDate,
  type AppLaunchTokenRow,
} from "./mappers.js";
import { appLaunchTokens } from "./schema.js";
import type { DrizzleDatabase } from "./repositories.js";
import type {
  AppLaunchTokenRecord,
  AppLaunchTokenRepository,
} from "../platform/repositories.js";

type Row = Record<string, unknown>;

export function createDrizzleAppLaunchTokenRepository(
  db: Pick<DrizzleDatabase, "insert" | "select" | "update">,
): AppLaunchTokenRepository {
  return {
    async create(input) {
      const rows = await db
        .insert(appLaunchTokens)
        .values(appLaunchTokenToValues(input))
        .returning();

      return mapOneRequired(rows[0], mapAppLaunchTokenRow);
    },
    async findByTokenHash(tokenHash) {
      const rows = await db
        .select()
        .from(appLaunchTokens)
        .where(eq(appLaunchTokens.tokenHash, tokenHash))
        .limit(1);

      return mapOne(rows[0], mapAppLaunchTokenRow);
    },
    async consumeUnconsumed(id, consumedAt) {
      const rows = await db
        .update(appLaunchTokens)
        .set({ consumedAt: toDate(consumedAt) })
        .where(
          and(
            eq(appLaunchTokens.id, id),
            isNull(appLaunchTokens.consumedAt),
            isNull(appLaunchTokens.revokedAt),
          ),
        )
        .returning();

      return mapOne(rows[0], mapAppLaunchTokenRow);
    },
  };
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
    throw new Error("Expected app launch token repository write to return a row.");
  }

  return mapper(row as unknown as RowType);
}

function appLaunchTokenToValues(input: AppLaunchTokenRecord): Row {
  return {
    id: input.id,
    sessionId: input.sessionId,
    userId: input.userId,
    workspaceId: input.workspaceId,
    appId: input.appId,
    tokenHash: input.tokenHash,
    createdAt: toDate(input.createdAt),
    expiresAt: toDate(input.expiresAt),
    consumedAt: toDate(input.consumedAt),
    revokedAt: toDate(input.revokedAt),
  } satisfies Omit<
    AppLaunchTokenRow,
    "createdAt" | "expiresAt" | "consumedAt" | "revokedAt"
  > & {
    createdAt: Date;
    expiresAt: Date;
    consumedAt: Date | null;
    revokedAt: Date | null;
  };
}

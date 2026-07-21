import { and, eq, isNull } from "drizzle-orm";
import { accessValidationGrants } from "./schema.js";
import { toDate } from "./mappers.js";
import type { DrizzleDatabase } from "./repositories.js";
import type { AccessValidationGrantRecord, AccessValidationGrantRepository } from "../platform/repositories.js";

type Row = Record<string, unknown>;

export function createDrizzleAccessValidationGrantRepository(
  db: Pick<DrizzleDatabase, "insert" | "select" | "update">,
): AccessValidationGrantRepository {
  return {
    async create(record) {
      const rows = await db.insert(accessValidationGrants).values(toValues(record)).returning();
      return mapRequired(rows[0]);
    },
    async findById(id) {
      const rows = await db.select().from(accessValidationGrants).where(eq(accessValidationGrants.id, id)).limit(1);
      return rows[0] ? map(rows[0]) : null;
    },
    async registerHandle(id, handleHash, expiresAt) {
      const rows = await db.update(accessValidationGrants).set({ handleHash, handleExpiresAt: toDate(expiresAt) }).where(and(eq(accessValidationGrants.id, id), isNull(accessValidationGrants.handleHash), isNull(accessValidationGrants.consumedAt), isNull(accessValidationGrants.revokedAt))).returning();
      return rows[0] ? map(rows[0]) : null;
    },
    async consumeByHandleHash(handleHash, consumedAt) {
      const rows = await db.update(accessValidationGrants).set({ consumedAt: toDate(consumedAt) }).where(and(eq(accessValidationGrants.handleHash, handleHash), isNull(accessValidationGrants.consumedAt), isNull(accessValidationGrants.revokedAt))).returning();
      return rows[0] ? map(rows[0]) : null;
    },
    async revoke(id, revokedAt) {
      const rows = await db.update(accessValidationGrants).set({ revokedAt: toDate(revokedAt) }).where(and(eq(accessValidationGrants.id, id), isNull(accessValidationGrants.revokedAt))).returning();
      return rows[0] ? map(rows[0]) : null;
    },
  };
}

function map(row: Row): AccessValidationGrantRecord {
  const iso = (value: unknown) => value instanceof Date ? value.toISOString() : value as string;
  return { id: row.id as string, sessionId: row.sessionId as string, userId: row.userId as string, workspaceId: row.workspaceId as string, appId: row.appId as string, intendedOrigin: row.intendedOrigin as string, launchTokenExpiresAt: iso(row.launchTokenExpiresAt), handleHash: row.handleHash as string | null, createdAt: iso(row.createdAt), handleExpiresAt: row.handleExpiresAt ? iso(row.handleExpiresAt) : null, consumedAt: row.consumedAt ? iso(row.consumedAt) : null, revokedAt: row.revokedAt ? iso(row.revokedAt) : null };
}
function mapRequired(row: Row | undefined) { if (!row) throw new Error("Expected access validation grant write to return a row."); return map(row); }
function toValues(record: AccessValidationGrantRecord): Row { return { ...record, createdAt: toDate(record.createdAt), launchTokenExpiresAt: toDate(record.launchTokenExpiresAt), handleExpiresAt: toDate(record.handleExpiresAt), consumedAt: toDate(record.consumedAt), revokedAt: toDate(record.revokedAt) }; }

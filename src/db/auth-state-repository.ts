import { and, eq, isNull } from "drizzle-orm";

import {
  mapAuthStateRow,
  toDate,
  type AuthStateRow,
} from "./mappers.js";
import type { DrizzleDatabase } from "./repositories.js";
import { authStates } from "./schema.js";
import type {
  AuthStateIssueStore,
  AuthStateStore,
  StoredAuthState,
  StoredAuthStateInput,
} from "../auth/callback.js";

type Row = Record<string, unknown>;

export function createDrizzleAuthStateStore(
  db: Pick<DrizzleDatabase, "select" | "insert" | "update">,
): AuthStateIssueStore & AuthStateStore {
  return {
    async storeState(input) {
      const rows = await db
        .insert(authStates)
        .values(authStateToValues(input))
        .returning();

      return toStoredAuthState(mapOneRequired(rows[0], mapAuthStateRow));
    },
    async consumeState(input) {
      const row = await selectOne(
        db,
        and(
          eq(authStates.providerKey, input.providerKey),
          eq(authStates.stateHash, input.stateHash),
        ),
      );

      if (!row) {
        return null;
      }

      const record = mapAuthStateRow(row as unknown as AuthStateRow);

      if (record.consumedAt || record.revokedAt) {
        return null;
      }

      const rows = await db
        .update(authStates)
        .set({ consumedAt: toDate(input.now) })
        .where(
          and(
            eq(authStates.providerKey, input.providerKey),
            eq(authStates.stateHash, input.stateHash),
            isNull(authStates.consumedAt),
            isNull(authStates.revokedAt),
          ),
        )
        .returning();

      return rows[0]
        ? toStoredAuthState(mapAuthStateRow(rows[0] as unknown as AuthStateRow))
        : null;
    },
  };
}

async function selectOne(
  db: Pick<DrizzleDatabase, "select">,
  condition: unknown,
): Promise<Row | undefined> {
  const rows = await db.select().from(authStates).where(condition).limit(1);
  return rows[0];
}

function mapOneRequired<T, RowType>(
  row: Row | undefined,
  mapper: (row: RowType) => T,
): T {
  if (!row) {
    throw new Error("Expected auth state store write to return a row.");
  }

  return mapper(row as unknown as RowType);
}

function authStateToValues(input: StoredAuthStateInput): Row {
  return {
    providerKey: input.providerKey,
    stateHash: input.stateHash,
    nonceHash: input.nonceHash,
    redirectUri: input.redirectUri,
    createdAt: toDate(input.createdAt),
    expiresAt: toDate(input.expiresAt),
  };
}

function toStoredAuthState(record: StoredAuthState): StoredAuthState {
  return {
    providerKey: record.providerKey,
    stateHash: record.stateHash,
    nonceHash: record.nonceHash,
    redirectUri: record.redirectUri,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
  };
}

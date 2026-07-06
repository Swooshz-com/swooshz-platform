import { and, eq, isNull } from "drizzle-orm";

import {
  appEntitlements,
  appLaunchTokens,
  apps,
  auditEvents,
  invitations,
  memberships,
  providerIdentities,
  sessions,
  users,
  workspaceMembershipApprovals,
  workspaces,
} from "./schema.js";
import {
  mapAppEntitlementRow,
  mapAppLaunchTokenRow,
  mapAppRow,
  mapAuditEventRow,
  mapInvitationRow,
  mapMembershipRow,
  mapProviderIdentityRow,
  mapSessionRow,
  mapUserRow,
  mapWorkspaceMembershipApprovalRow,
  mapWorkspaceRow,
  toDate,
  type AppEntitlementRow,
  type AppLaunchTokenRow,
  type AppRow,
  type AuditEventRow,
  type InvitationRow,
  type MembershipRow,
  type ProviderIdentityRow,
  type SessionRow,
  type UserRow,
  type WorkspaceMembershipApprovalRow,
  type WorkspaceRow,
} from "./mappers.js";
import type {
  AuditEvent,
  InvitationStatus,
  Membership,
  Session,
  User,
  Workspace,
} from "../accounts/types.js";
import type { App, AppEntitlement } from "../apps/types.js";
import type {
  InvitationRecord,
  InvitationStatusTimestamps,
  AppLaunchTokenRecord,
  PlatformRepositories,
  ProviderIdentity,
  WorkspaceMembershipApprovalRecord,
  WorkspaceMembershipApprovalStatus,
  WorkspaceMembershipApprovalStatusTimestamps,
} from "../platform/repositories.js";

type Table = unknown;
type Condition = unknown;
type Row = Record<string, unknown>;

export interface DrizzleSelectResult extends PromiseLike<readonly Row[]> {
  limit(limit: number): Promise<readonly Row[]>;
}

export interface DrizzleDatabase {
  select(): {
    from(table: Table): DrizzleSelectResult & {
      where(condition: Condition): DrizzleSelectResult;
    };
  };
  insert(table: Table): {
    values(values: Row): {
      returning(): Promise<readonly Row[]>;
    };
  };
  update(table: Table): {
    set(values: Row): {
      where(condition: Condition): {
        returning(): Promise<readonly Row[]>;
      };
    };
  };
  delete(table: Table): {
    where(condition: Condition): {
      returning(): Promise<readonly Row[]>;
    };
  };
  transaction?<T>(operation: (transactionDb: DrizzleDatabase) => Promise<T>): Promise<T>;
}

export function createDrizzlePlatformRepositories(
  db: DrizzleDatabase,
): PlatformRepositories {
  const transaction = db.transaction?.bind(db);

  return {
    users: {
      async findById(id) {
        return mapOne(await selectOne(db, users, eq(users.id, id)), mapUserRow);
      },
      async findByNormalizedEmail(email) {
        return mapOne(await selectOne(db, users, eq(users.email, email)), mapUserRow);
      },
      async create(user) {
        const rows = await db.insert(users).values(userToValues(user)).returning();
        return mapOneRequired(rows[0], mapUserRow);
      },
    },
    providerIdentities: {
      async findByProviderSubject(providerKey, providerSubject) {
        return mapOne(
          await selectOne(
            db,
            providerIdentities,
            and(
              eq(providerIdentities.providerKey, providerKey),
              eq(providerIdentities.providerSubject, providerSubject),
            ),
          ),
          mapProviderIdentityRow,
        );
      },
      async listForUser(userId) {
        const rows = await db
          .select()
          .from(providerIdentities)
          .where(eq(providerIdentities.userId, userId));
        return rows.map((row) => mapProviderIdentityRow(row as unknown as ProviderIdentityRow));
      },
      async create(identity) {
        const rows = await db
          .insert(providerIdentities)
          .values(providerIdentityToValues(identity))
          .returning();
        return mapOneRequired(rows[0], mapProviderIdentityRow);
      },
    },
    sessions: {
      async findById(id) {
        return mapOne(await selectOne(db, sessions, eq(sessions.id, id)), mapSessionRow);
      },
      async create(session) {
        const rows = await db.insert(sessions).values(sessionToValues(session)).returning();
        return mapOneRequired(rows[0], mapSessionRow);
      },
      async revoke(id, revokedAt) {
        const rows = await db
          .update(sessions)
          .set({ revokedAt: toDate(revokedAt) })
          .where(eq(sessions.id, id))
          .returning();
        return mapOne(rows[0], mapSessionRow);
      },
    },
    workspaces: {
      async findById(id) {
        return mapOne(await selectOne(db, workspaces, eq(workspaces.id, id)), mapWorkspaceRow);
      },
      async findBySlug(slug) {
        return mapOne(
          await selectOne(db, workspaces, eq(workspaces.slug, slug)),
          mapWorkspaceRow,
        );
      },
      async create(workspace) {
        const rows = await db
          .insert(workspaces)
          .values(workspaceToValues(workspace))
          .returning();
        return mapOneRequired(rows[0], mapWorkspaceRow);
      },
    },
    memberships: {
      async findForUserInWorkspace(userId, workspaceId) {
        return mapOne(
          await selectOne(
            db,
            memberships,
            and(eq(memberships.userId, userId), eq(memberships.workspaceId, workspaceId)),
          ),
          mapMembershipRow,
        );
      },
      async listForUser(userId) {
        const rows = await db
          .select()
          .from(memberships)
          .where(eq(memberships.userId, userId));
        return rows.map((row) => mapMembershipRow(row as unknown as MembershipRow));
      },
      async listForWorkspace(workspaceId) {
        const rows = await db
          .select()
          .from(memberships)
          .where(eq(memberships.workspaceId, workspaceId));
        return rows.map((row) => mapMembershipRow(row as unknown as MembershipRow));
      },
      async create(membership) {
        const rows = await db
          .insert(memberships)
          .values(membershipToValues(membership))
          .returning();
        return mapOneRequired(rows[0], mapMembershipRow);
      },
      async updateRole(id, role, updatedAt) {
        const rows = await db
          .update(memberships)
          .set({ role, updatedAt: toDate(updatedAt) })
          .where(eq(memberships.id, id))
          .returning();
        return mapOne(rows[0], mapMembershipRow);
      },
      async updateStatus(id, status, updatedAt) {
        const rows = await db
          .update(memberships)
          .set({ status, updatedAt: toDate(updatedAt) })
          .where(eq(memberships.id, id))
          .returning();
        return mapOne(rows[0], mapMembershipRow);
      },
      async removeIfCurrentTarget(target) {
        const rows = await db
          .delete(memberships)
          .where(
            and(
              eq(memberships.id, target.id),
              eq(memberships.workspaceId, target.workspaceId),
              eq(memberships.userId, target.userId),
              eq(memberships.role, target.role),
              eq(memberships.status, target.status),
            ),
          )
          .returning();
        return mapOne(rows[0], mapMembershipRow);
      },
    },
    invitations: {
      async findById(id) {
        return mapOne(
          await selectOne(db, invitations, eq(invitations.id, id)),
          mapInvitationRow,
        );
      },
      async create(invitation) {
        const rows = await db.insert(invitations).values(invitationToValues(invitation)).returning();
        return mapOneRequired(rows[0], mapInvitationRow);
      },
      async updateStatus(id, status, timestamps) {
        const rows = await db
          .update(invitations)
          .set(invitationStatusToValues(status, timestamps))
          .where(eq(invitations.id, id))
          .returning();
        return mapOne(rows[0], mapInvitationRow);
      },
    },
    membershipApprovals: {
      async findById(id) {
        return mapOne(
          await selectOne(
            db,
            workspaceMembershipApprovals,
            eq(workspaceMembershipApprovals.id, id),
          ),
          mapWorkspaceMembershipApprovalRow,
        );
      },
      async findPendingForWorkspaceEmail(workspaceId, email) {
        return mapOne(
          await selectOne(
            db,
            workspaceMembershipApprovals,
            and(
              eq(workspaceMembershipApprovals.workspaceId, workspaceId),
              eq(workspaceMembershipApprovals.email, email),
              eq(workspaceMembershipApprovals.status, "pending"),
            ),
          ),
          mapWorkspaceMembershipApprovalRow,
        );
      },
      async listPendingForEmail(email) {
        const rows = await db
          .select()
          .from(workspaceMembershipApprovals)
          .where(
            and(
              eq(workspaceMembershipApprovals.email, email),
              eq(workspaceMembershipApprovals.status, "pending"),
            ),
          );
        return rows.map((row) =>
          mapWorkspaceMembershipApprovalRow(row as unknown as WorkspaceMembershipApprovalRow),
        );
      },
      async listPendingForWorkspace(workspaceId) {
        const rows = await db
          .select()
          .from(workspaceMembershipApprovals)
          .where(
            and(
              eq(workspaceMembershipApprovals.workspaceId, workspaceId),
              eq(workspaceMembershipApprovals.status, "pending"),
            ),
          );
        return rows.map((row) =>
          mapWorkspaceMembershipApprovalRow(row as unknown as WorkspaceMembershipApprovalRow),
        );
      },
      async create(approval) {
        const rows = await db
          .insert(workspaceMembershipApprovals)
          .values(workspaceMembershipApprovalToValues(approval))
          .returning();
        return mapOneRequired(rows[0], mapWorkspaceMembershipApprovalRow);
      },
      async updatePendingStatus(id, status, timestamps) {
        const rows = await db
          .update(workspaceMembershipApprovals)
          .set(workspaceMembershipApprovalStatusToValues(status, timestamps))
          .where(
            and(
              eq(workspaceMembershipApprovals.id, id),
              eq(workspaceMembershipApprovals.status, "pending"),
            ),
          )
          .returning();
        return mapOne(rows[0], mapWorkspaceMembershipApprovalRow);
      },
    },
    apps: {
      async findByKey(key) {
        return mapOne(await selectOne(db, apps, eq(apps.key, key)), mapAppRow);
      },
      async findById(id) {
        return mapOne(await selectOne(db, apps, eq(apps.id, id)), mapAppRow);
      },
      async listAll() {
        const rows = await db.select().from(apps);
        return rows.map((row) => mapAppRow(row as unknown as AppRow));
      },
      async create(app) {
        const rows = await db.insert(apps).values(appToValues(app)).returning();
        return mapOneRequired(rows[0], mapAppRow);
      },
    },
    appEntitlements: {
      async findForWorkspaceApp(workspaceId, appId) {
        return mapOne(
          await selectOne(
            db,
            appEntitlements,
            and(
              eq(appEntitlements.workspaceId, workspaceId),
              eq(appEntitlements.appId, appId),
            ),
          ),
          mapAppEntitlementRow,
        );
      },
      async listForWorkspace(workspaceId) {
        const rows = await db
          .select()
          .from(appEntitlements)
          .where(eq(appEntitlements.workspaceId, workspaceId));
        return rows.map((row) => mapAppEntitlementRow(row as unknown as AppEntitlementRow));
      },
      async create(entitlement) {
        const rows = await db
          .insert(appEntitlements)
          .values(appEntitlementToValues(entitlement))
          .returning();
        return mapOneRequired(rows[0], mapAppEntitlementRow);
      },
      async updateStatus(id, status, grantedByUserId, updatedAt) {
        const rows = await db
          .update(appEntitlements)
          .set({
            status,
            grantedByUserId,
            updatedAt: toDate(updatedAt),
          })
          .where(eq(appEntitlements.id, id))
          .returning();
        return mapOne(rows[0], mapAppEntitlementRow);
      },
    },
    auditEvents: {
      async append(event) {
        const rows = await db.insert(auditEvents).values(auditEventToValues(event)).returning();
        return mapOneRequired(rows[0], mapAuditEventRow);
      },
      async listForWorkspace(workspaceId, limit) {
        const rows = await db
          .select()
          .from(auditEvents)
          .where(eq(auditEvents.workspaceId, workspaceId));
        return rows
          .map((row) => mapAuditEventRow(row as unknown as AuditEventRow))
          .filter((event) => event.workspaceId === workspaceId)
          .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
          .slice(0, limit);
      },
    },
    workspaceAdminTransactions: transaction
      ? {
          run(operation) {
            return transaction((transactionDb) =>
              operation(createDrizzlePlatformRepositories(transactionDb)),
            );
          },
        }
      : undefined,
    appLaunchTokens: {
      async create(record) {
        const rows = await db
          .insert(appLaunchTokens)
          .values(appLaunchTokenToValues(record))
          .returning();
        return mapOneRequired(rows[0], mapAppLaunchTokenRow);
      },
      async findByTokenHash(tokenHash) {
        return mapOne(
          await selectOne(db, appLaunchTokens, eq(appLaunchTokens.tokenHash, tokenHash)),
          mapAppLaunchTokenRow,
        );
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
    },
  };
}

async function selectOne(
  db: DrizzleDatabase,
  table: Table,
  condition: Condition,
): Promise<Row | undefined> {
  const rows = await db.select().from(table).where(condition).limit(1);
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
    throw new Error("Expected repository write to return a row.");
  }

  return mapper(row as unknown as RowType);
}

function userToValues(user: User): Row {
  return {
    id: user.id,
    email: user.email,
    displayName: user.displayName,
    status: user.status,
    createdAt: toDate(user.createdAt),
    updatedAt: toDate(user.updatedAt),
    lastLoginAt: toDate(user.lastLoginAt),
  };
}

function providerIdentityToValues(identity: ProviderIdentity): Row {
  return {
    id: identity.id,
    userId: identity.userId,
    providerKey: identity.providerKey,
    providerSubject: identity.providerSubject,
    createdAt: toDate(identity.createdAt),
    updatedAt: toDate(identity.updatedAt),
  };
}

function sessionToValues(session: Session): Row {
  return {
    id: session.id,
    userId: session.userId,
    createdAt: toDate(session.createdAt),
    expiresAt: toDate(session.expiresAt),
    lastSeenAt: toDate(session.lastSeenAt),
    revokedAt: toDate(session.revokedAt),
  };
}

function workspaceToValues(workspace: Workspace): Row {
  return {
    id: workspace.id,
    slug: workspace.slug,
    displayName: workspace.displayName,
    status: workspace.status,
    createdAt: toDate(workspace.createdAt),
    updatedAt: toDate(workspace.updatedAt),
  };
}

function membershipToValues(membership: Membership): Row {
  return {
    id: membership.id,
    workspaceId: membership.workspaceId,
    userId: membership.userId,
    role: membership.role,
    status: membership.status,
    createdAt: toDate(membership.createdAt),
    updatedAt: toDate(membership.updatedAt),
  };
}

function appToValues(app: App): Row {
  return {
    id: app.id,
    key: app.key,
    name: app.name,
    status: app.status,
    launchUrl: app.launchUrl,
    createdAt: toDate(app.createdAt),
    updatedAt: toDate(app.updatedAt),
  };
}

function appEntitlementToValues(entitlement: AppEntitlement): Row {
  return {
    id: entitlement.id,
    workspaceId: entitlement.workspaceId,
    appId: entitlement.appId,
    status: entitlement.status,
    grantedByUserId: entitlement.grantedByUserId,
    createdAt: toDate(entitlement.createdAt),
    updatedAt: toDate(entitlement.updatedAt),
  };
}

function invitationToValues(invitation: InvitationRecord): Row {
  return {
    id: invitation.id,
    workspaceId: invitation.workspaceId,
    email: invitation.email,
    role: invitation.role,
    status: invitation.status,
    tokenHash: invitation.tokenHash,
    invitedByUserId: invitation.invitedByUserId,
    createdAt: toDate(invitation.createdAt),
    expiresAt: toDate(invitation.expiresAt),
    acceptedAt: toDate(invitation.acceptedAt),
    revokedAt: toDate(invitation.revokedAt),
  };
}

function invitationStatusToValues(
  status: InvitationStatus,
  timestamps: InvitationStatusTimestamps | undefined,
): Row {
  return {
    status,
    ...(timestamps?.acceptedAt !== undefined
      ? { acceptedAt: toDate(timestamps.acceptedAt) }
      : {}),
    ...(timestamps?.revokedAt !== undefined
      ? { revokedAt: toDate(timestamps.revokedAt) }
      : {}),
  };
}

function workspaceMembershipApprovalToValues(
  approval: WorkspaceMembershipApprovalRecord,
): Row {
  return {
    id: approval.id,
    workspaceId: approval.workspaceId,
    email: approval.email,
    role: approval.role,
    status: approval.status,
    requestedByUserId: approval.requestedByUserId,
    createdAt: toDate(approval.createdAt),
    updatedAt: toDate(approval.updatedAt),
    acceptedAt: toDate(approval.acceptedAt),
    revokedAt: toDate(approval.revokedAt),
    acceptedUserId: approval.acceptedUserId,
    revokedByUserId: approval.revokedByUserId,
  };
}

function workspaceMembershipApprovalStatusToValues(
  status: WorkspaceMembershipApprovalStatus,
  timestamps: WorkspaceMembershipApprovalStatusTimestamps,
): Row {
  return {
    status,
    updatedAt: toDate(timestamps.updatedAt),
    ...(timestamps.acceptedAt !== undefined
      ? { acceptedAt: toDate(timestamps.acceptedAt) }
      : {}),
    ...(timestamps.revokedAt !== undefined
      ? { revokedAt: toDate(timestamps.revokedAt) }
      : {}),
    ...(timestamps.acceptedUserId !== undefined
      ? { acceptedUserId: timestamps.acceptedUserId }
      : {}),
    ...(timestamps.revokedByUserId !== undefined
      ? { revokedByUserId: timestamps.revokedByUserId }
      : {}),
  };
}

function auditEventToValues(event: AuditEvent): Row {
  return {
    id: event.id,
    workspaceId: event.workspaceId,
    actorUserId: event.actorUserId,
    eventType: event.eventType,
    targetType: event.targetType,
    targetId: event.targetId,
    createdAt: toDate(event.createdAt),
    metadata: event.metadata,
  };
}

function appLaunchTokenToValues(record: AppLaunchTokenRecord): Row {
  return {
    id: record.id,
    sessionId: record.sessionId,
    userId: record.userId,
    workspaceId: record.workspaceId,
    appId: record.appId,
    tokenHash: record.tokenHash,
    createdAt: toDate(record.createdAt),
    expiresAt: toDate(record.expiresAt),
    consumedAt: toDate(record.consumedAt),
    revokedAt: toDate(record.revokedAt),
  };
}

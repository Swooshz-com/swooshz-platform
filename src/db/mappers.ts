import type {
  AuditEvent,
  IsoTimestamp,
  Membership,
  MembershipStatus,
  Role,
  Session,
  User,
  UserStatus,
  Workspace,
  WorkspaceStatus,
} from "../accounts/types.js";
import type {
  App,
  AppEntitlement,
  AppStatus,
  EntitlementStatus,
} from "../apps/types.js";
import type {
  InvitationRecord,
  ProviderIdentity,
  WorkspaceMembershipApprovalRecord,
  WorkspaceMembershipApprovalStatus,
} from "../platform/repositories.js";
import type { AppLaunchTokenRecord } from "../platform/repositories.js";
import type { InvitationStatus } from "../accounts/types.js";
import type { StoredAuthStateLifecycleRecord } from "../auth/auth-state-repositories.js";
import type { CsrfTokenRecord } from "../http/csrf-token-repositories.js";

type TimestampValue = Date | string;

export interface UserRow {
  id: string;
  email: string;
  displayName: string;
  status: UserStatus;
  createdAt: TimestampValue;
  updatedAt: TimestampValue;
  lastLoginAt: TimestampValue | null;
}

export interface ProviderIdentityRow {
  id: string;
  userId: string;
  providerKey: string;
  providerSubject: string;
  createdAt: TimestampValue;
  updatedAt: TimestampValue;
}

export interface WorkspaceRow {
  id: string;
  slug: string;
  displayName: string;
  status: WorkspaceStatus;
  createdAt: TimestampValue;
  updatedAt: TimestampValue;
}

export interface MembershipRow {
  id: string;
  workspaceId: string;
  userId: string;
  role: Role;
  status: MembershipStatus;
  createdAt: TimestampValue;
  updatedAt: TimestampValue;
}

export interface InvitationRow {
  id: string;
  workspaceId: string;
  email: string;
  role: Role;
  status: InvitationStatus;
  tokenHash: string | null;
  invitedByUserId: string | null;
  createdAt: TimestampValue;
  expiresAt: TimestampValue;
  acceptedAt: TimestampValue | null;
  revokedAt: TimestampValue | null;
}

export interface WorkspaceMembershipApprovalRow {
  id: string;
  workspaceId: string;
  email: string;
  role: Role;
  status: WorkspaceMembershipApprovalStatus;
  requestedByUserId: string;
  createdAt: TimestampValue;
  updatedAt: TimestampValue;
  acceptedAt: TimestampValue | null;
  revokedAt: TimestampValue | null;
  acceptedUserId: string | null;
  revokedByUserId: string | null;
}

export interface SessionRow {
  id: string;
  userId: string;
  createdAt: TimestampValue;
  expiresAt: TimestampValue;
  lastSeenAt: TimestampValue;
  revokedAt: TimestampValue | null;
}

export interface CsrfTokenRow {
  id: string;
  sessionId: string;
  tokenHash: string;
  purpose: CsrfTokenRecord["purpose"];
  createdAt: TimestampValue;
  expiresAt: TimestampValue;
  consumedAt: TimestampValue | null;
  revokedAt: TimestampValue | null;
  replacedByTokenId: string | null;
}

export interface AuthStateRow {
  providerKey: string;
  stateHash: string;
  nonceHash: string;
  redirectUri: string;
  createdAt: TimestampValue;
  expiresAt: TimestampValue;
  consumedAt: TimestampValue | null;
  revokedAt: TimestampValue | null;
}

export interface AuditEventRow {
  id: string;
  workspaceId: string | null;
  actorUserId: string | null;
  eventType: string;
  targetType: string;
  targetId: string;
  createdAt: TimestampValue;
  metadata: Record<string, unknown>;
}

export interface AppRow {
  id: string;
  key: string;
  name: string;
  status: AppStatus;
  launchUrl: string | null;
  createdAt: TimestampValue;
  updatedAt: TimestampValue;
}

export interface AppEntitlementRow {
  id: string;
  workspaceId: string;
  appId: string;
  status: EntitlementStatus;
  grantedByUserId: string | null;
  createdAt: TimestampValue;
  updatedAt: TimestampValue;
}

export interface AppLaunchTokenRow {
  id: string;
  sessionId: string;
  userId: string;
  workspaceId: string;
  appId: string;
  tokenHash: string;
  createdAt: TimestampValue;
  expiresAt: TimestampValue;
  consumedAt: TimestampValue | null;
  revokedAt: TimestampValue | null;
}

export function mapUserRow(row: UserRow): User {
  return {
    id: row.id,
    email: row.email,
    displayName: row.displayName,
    status: row.status,
    createdAt: toIsoTimestamp(row.createdAt),
    updatedAt: toIsoTimestamp(row.updatedAt),
    lastLoginAt: toNullableIsoTimestamp(row.lastLoginAt),
  };
}

export function mapProviderIdentityRow(row: ProviderIdentityRow): ProviderIdentity {
  return {
    id: row.id,
    userId: row.userId,
    providerKey: row.providerKey,
    providerSubject: row.providerSubject,
    createdAt: toIsoTimestamp(row.createdAt),
    updatedAt: toIsoTimestamp(row.updatedAt),
  };
}

export function mapWorkspaceRow(row: WorkspaceRow): Workspace {
  return {
    id: row.id,
    slug: row.slug,
    displayName: row.displayName,
    status: row.status,
    createdAt: toIsoTimestamp(row.createdAt),
    updatedAt: toIsoTimestamp(row.updatedAt),
  };
}

export function mapMembershipRow(row: MembershipRow): Membership {
  return {
    id: row.id,
    workspaceId: row.workspaceId,
    userId: row.userId,
    role: row.role,
    status: row.status,
    createdAt: toIsoTimestamp(row.createdAt),
    updatedAt: toIsoTimestamp(row.updatedAt),
  };
}

export function mapInvitationRow(row: InvitationRow): InvitationRecord {
  return {
    id: row.id,
    workspaceId: row.workspaceId,
    email: row.email,
    role: row.role,
    status: row.status,
    tokenHash: row.tokenHash,
    invitedByUserId: row.invitedByUserId,
    createdAt: toIsoTimestamp(row.createdAt),
    expiresAt: toIsoTimestamp(row.expiresAt),
    acceptedAt: toNullableIsoTimestamp(row.acceptedAt),
    revokedAt: toNullableIsoTimestamp(row.revokedAt),
  };
}

export function mapWorkspaceMembershipApprovalRow(
  row: WorkspaceMembershipApprovalRow,
): WorkspaceMembershipApprovalRecord {
  return {
    id: row.id,
    workspaceId: row.workspaceId,
    email: row.email,
    role: row.role,
    status: row.status,
    requestedByUserId: row.requestedByUserId,
    createdAt: toIsoTimestamp(row.createdAt),
    updatedAt: toIsoTimestamp(row.updatedAt),
    acceptedAt: toNullableIsoTimestamp(row.acceptedAt),
    revokedAt: toNullableIsoTimestamp(row.revokedAt),
    acceptedUserId: row.acceptedUserId,
    revokedByUserId: row.revokedByUserId,
  };
}

export function mapSessionRow(row: SessionRow): Session {
  return {
    id: row.id,
    userId: row.userId,
    createdAt: toIsoTimestamp(row.createdAt),
    expiresAt: toIsoTimestamp(row.expiresAt),
    lastSeenAt: toIsoTimestamp(row.lastSeenAt),
    revokedAt: toNullableIsoTimestamp(row.revokedAt),
  };
}

export function mapCsrfTokenRow(row: CsrfTokenRow): CsrfTokenRecord {
  return {
    id: row.id,
    sessionId: row.sessionId,
    tokenHash: row.tokenHash,
    purpose: row.purpose,
    createdAt: toIsoTimestamp(row.createdAt),
    expiresAt: toIsoTimestamp(row.expiresAt),
    consumedAt: toNullableIsoTimestamp(row.consumedAt),
    revokedAt: toNullableIsoTimestamp(row.revokedAt),
    replacedByTokenId: row.replacedByTokenId,
  };
}

export function mapAuthStateRow(row: AuthStateRow): StoredAuthStateLifecycleRecord {
  return {
    providerKey: row.providerKey,
    stateHash: row.stateHash,
    nonceHash: row.nonceHash,
    redirectUri: row.redirectUri,
    createdAt: toIsoTimestamp(row.createdAt),
    expiresAt: toIsoTimestamp(row.expiresAt),
    consumedAt: toNullableIsoTimestamp(row.consumedAt),
    revokedAt: toNullableIsoTimestamp(row.revokedAt),
  };
}

export function mapAuditEventRow(row: AuditEventRow): AuditEvent {
  return {
    id: row.id,
    workspaceId: row.workspaceId,
    actorUserId: row.actorUserId,
    eventType: row.eventType,
    targetType: row.targetType,
    targetId: row.targetId,
    createdAt: toIsoTimestamp(row.createdAt),
    metadata: row.metadata,
  };
}

export function mapAppRow(row: AppRow): App {
  return {
    id: row.id,
    key: row.key,
    name: row.name,
    status: row.status,
    launchUrl: row.launchUrl,
    createdAt: toIsoTimestamp(row.createdAt),
    updatedAt: toIsoTimestamp(row.updatedAt),
  };
}

export function mapAppEntitlementRow(row: AppEntitlementRow): AppEntitlement {
  return {
    id: row.id,
    workspaceId: row.workspaceId,
    appId: row.appId,
    status: row.status,
    grantedByUserId: row.grantedByUserId,
    createdAt: toIsoTimestamp(row.createdAt),
    updatedAt: toIsoTimestamp(row.updatedAt),
  };
}

export function mapAppLaunchTokenRow(
  row: AppLaunchTokenRow,
): AppLaunchTokenRecord {
  return {
    id: row.id,
    sessionId: row.sessionId,
    userId: row.userId,
    workspaceId: row.workspaceId,
    appId: row.appId,
    tokenHash: row.tokenHash,
    createdAt: toIsoTimestamp(row.createdAt),
    expiresAt: toIsoTimestamp(row.expiresAt),
    consumedAt: toNullableIsoTimestamp(row.consumedAt),
    revokedAt: toNullableIsoTimestamp(row.revokedAt),
  };
}

export function toDate(value: IsoTimestamp): Date;
export function toDate(value: IsoTimestamp | null): Date | null;
export function toDate(value: IsoTimestamp | null | undefined): Date | null | undefined;
export function toDate(
  value: IsoTimestamp | null | undefined,
): Date | null | undefined {
  if (value === null || value === undefined) {
    return value;
  }

  return new Date(value);
}

function toIsoTimestamp(value: TimestampValue): IsoTimestamp {
  return value instanceof Date ? value.toISOString() : value;
}

function toNullableIsoTimestamp(value: TimestampValue | null): IsoTimestamp | null {
  return value === null ? null : toIsoTimestamp(value);
}

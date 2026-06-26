export type IsoTimestamp = string;

export const UserStatus = {
  Active: "active",
  Invited: "invited",
  Disabled: "disabled",
} as const;

export type UserStatus = (typeof UserStatus)[keyof typeof UserStatus];

export const WorkspaceStatus = {
  Active: "active",
  Suspended: "suspended",
  Archived: "archived",
} as const;

export type WorkspaceStatus = (typeof WorkspaceStatus)[keyof typeof WorkspaceStatus];

export const MembershipStatus = {
  Active: "active",
  Disabled: "disabled",
} as const;

export type MembershipStatus = (typeof MembershipStatus)[keyof typeof MembershipStatus];

export const Role = {
  Owner: "owner",
  Admin: "admin",
  Member: "member",
  Viewer: "viewer",
} as const;

export type Role = (typeof Role)[keyof typeof Role];

export const InvitationStatus = {
  Pending: "pending",
  Accepted: "accepted",
  Expired: "expired",
  Revoked: "revoked",
} as const;

export type InvitationStatus = (typeof InvitationStatus)[keyof typeof InvitationStatus];

export interface User {
  id: string;
  email: string;
  displayName: string;
  status: UserStatus;
  createdAt: IsoTimestamp;
  updatedAt: IsoTimestamp;
  lastLoginAt: IsoTimestamp | null;
}

export interface Workspace {
  id: string;
  slug: string;
  displayName: string;
  status: WorkspaceStatus;
  createdAt: IsoTimestamp;
  updatedAt: IsoTimestamp;
}

export interface Membership {
  id: string;
  workspaceId: string;
  userId: string;
  role: Role;
  status: MembershipStatus;
  createdAt: IsoTimestamp;
  updatedAt: IsoTimestamp;
}

export interface Invitation {
  id: string;
  workspaceId: string;
  email: string;
  role: Role;
  status: InvitationStatus;
  invitedByUserId: string;
  createdAt: IsoTimestamp;
  expiresAt: IsoTimestamp;
  acceptedAt: IsoTimestamp | null;
}

export interface Session {
  id: string;
  userId: string;
  createdAt: IsoTimestamp;
  expiresAt: IsoTimestamp;
  lastSeenAt: IsoTimestamp;
  revokedAt: IsoTimestamp | null;
}

export interface AuditEvent {
  id: string;
  workspaceId: string | null;
  actorUserId: string | null;
  eventType: string;
  targetType: string;
  targetId: string;
  createdAt: IsoTimestamp;
  metadata: Record<string, unknown>;
}

export type BillingReservedConcept =
  | "billing_customer"
  | "subscription"
  | "invoice"
  | "credit_pool"
  | "credit_transaction"
  | "usage_event";

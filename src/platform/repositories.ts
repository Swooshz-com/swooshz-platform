import type {
  AuditEvent,
  Invitation,
  InvitationStatus,
  IsoTimestamp,
  Membership,
  MembershipStatus,
  Role,
  Session,
  User,
  Workspace,
} from "../accounts/types.js";
import type { App, AppEntitlement, EntitlementStatus } from "../apps/types.js";

export interface ProviderIdentity {
  id: string;
  userId: string;
  providerKey: string;
  providerSubject: string;
  createdAt: IsoTimestamp;
  updatedAt: IsoTimestamp;
}

export interface InvitationRecord extends Omit<Invitation, "invitedByUserId"> {
  tokenHash: string | null;
  invitedByUserId: string | null;
  revokedAt: IsoTimestamp | null;
}

export interface InvitationStatusTimestamps {
  acceptedAt?: IsoTimestamp | null;
  revokedAt?: IsoTimestamp | null;
}

export type WorkspaceMembershipApprovalStatus = "pending" | "accepted" | "revoked";

export interface WorkspaceMembershipApprovalRecord {
  id: string;
  workspaceId: string;
  email: string;
  role: Role;
  status: WorkspaceMembershipApprovalStatus;
  requestedByUserId: string;
  createdAt: IsoTimestamp;
  updatedAt: IsoTimestamp;
  acceptedAt: IsoTimestamp | null;
  revokedAt: IsoTimestamp | null;
  acceptedUserId: string | null;
  revokedByUserId: string | null;
}

export interface WorkspaceMembershipApprovalStatusTimestamps {
  updatedAt: IsoTimestamp;
  acceptedAt?: IsoTimestamp | null;
  revokedAt?: IsoTimestamp | null;
  acceptedUserId?: string | null;
  revokedByUserId?: string | null;
}

export interface AppLaunchTokenRecord {
  id: string;
  sessionId: string;
  userId: string;
  workspaceId: string;
  appId: string;
  tokenHash: string;
  createdAt: IsoTimestamp;
  expiresAt: IsoTimestamp;
  consumedAt: IsoTimestamp | null;
  revokedAt: IsoTimestamp | null;
}

export interface UserRepository {
  findById(id: string): Promise<User | null>;
  findByNormalizedEmail(email: string): Promise<User | null>;
  create(user: User): Promise<User>;
}

export interface ProviderIdentityRepository {
  findByProviderSubject(
    providerKey: string,
    providerSubject: string,
  ): Promise<ProviderIdentity | null>;
  listForUser(userId: string): Promise<readonly ProviderIdentity[]>;
  create(identity: ProviderIdentity): Promise<ProviderIdentity>;
}

export interface SessionRepository {
  findById(id: string): Promise<Session | null>;
  create(session: Session): Promise<Session>;
  revoke(id: string, revokedAt: IsoTimestamp): Promise<Session | null>;
  revokeActiveForUser(userId: string, revokedAt: IsoTimestamp): Promise<readonly Session[]>;
}

export interface WorkspaceRepository {
  findById(id: string): Promise<Workspace | null>;
  findBySlug(slug: string): Promise<Workspace | null>;
  create(workspace: Workspace): Promise<Workspace>;
}

export type MembershipRemovalTarget = Pick<
  Membership,
  "id" | "workspaceId" | "userId" | "role" | "status"
>;

export interface MembershipRepository {
  findForUserInWorkspace(userId: string, workspaceId: string): Promise<Membership | null>;
  listForUser(userId: string): Promise<readonly Membership[]>;
  listForWorkspace(workspaceId: string): Promise<readonly Membership[]>;
  create(membership: Membership): Promise<Membership>;
  updateRole(
    id: string,
    role: Role,
    updatedAt: IsoTimestamp,
  ): Promise<Membership | null>;
  updateStatus(
    id: string,
    status: MembershipStatus,
    updatedAt: IsoTimestamp,
  ): Promise<Membership | null>;
  removeIfCurrentTarget(target: MembershipRemovalTarget): Promise<Membership | null>;
}

export interface InvitationRepository {
  findById(id: string): Promise<InvitationRecord | null>;
  create(invitation: InvitationRecord): Promise<InvitationRecord>;
  updateStatus(
    id: string,
    status: InvitationStatus,
    timestamps?: InvitationStatusTimestamps,
  ): Promise<InvitationRecord | null>;
}

export interface WorkspaceMembershipApprovalRepository {
  findById(id: string): Promise<WorkspaceMembershipApprovalRecord | null>;
  findPendingForWorkspaceEmail(
    workspaceId: string,
    email: string,
  ): Promise<WorkspaceMembershipApprovalRecord | null>;
  listPendingForEmail(
    email: string,
  ): Promise<readonly WorkspaceMembershipApprovalRecord[]>;
  listPendingForWorkspace(
    workspaceId: string,
  ): Promise<readonly WorkspaceMembershipApprovalRecord[]>;
  create(
    approval: WorkspaceMembershipApprovalRecord,
  ): Promise<WorkspaceMembershipApprovalRecord>;
  updatePendingStatus(
    id: string,
    status: WorkspaceMembershipApprovalStatus,
    timestamps: WorkspaceMembershipApprovalStatusTimestamps,
  ): Promise<WorkspaceMembershipApprovalRecord | null>;
}

export interface AppRepository {
  findByKey(key: string): Promise<App | null>;
  findById(id: string): Promise<App | null>;
  listAll(): Promise<readonly App[]>;
  create(app: App): Promise<App>;
}

export interface AppEntitlementRepository {
  findForWorkspaceApp(workspaceId: string, appId: string): Promise<AppEntitlement | null>;
  listForWorkspace(workspaceId: string): Promise<readonly AppEntitlement[]>;
  create(entitlement: AppEntitlement): Promise<AppEntitlement>;
  updateStatus(
    id: string,
    status: EntitlementStatus,
    grantedByUserId: string | null,
    updatedAt: IsoTimestamp,
  ): Promise<AppEntitlement | null>;
}

export interface AuditEventRepository {
  append(event: AuditEvent): Promise<AuditEvent>;
  listForWorkspace(workspaceId: string, limit: number): Promise<readonly AuditEvent[]>;
}

export interface WorkspaceAdminTransactionRepository {
  run<T>(operation: (repositories: PlatformRepositories) => Promise<T>): Promise<T>;
}

export interface AppLaunchTokenRepository {
  create(record: AppLaunchTokenRecord): Promise<AppLaunchTokenRecord>;
  findByTokenHash(tokenHash: string): Promise<AppLaunchTokenRecord | null>;
  consumeUnconsumed(
    id: string,
    consumedAt: IsoTimestamp,
  ): Promise<AppLaunchTokenRecord | null>;
}

export interface PlatformRepositories {
  users: UserRepository;
  providerIdentities?: ProviderIdentityRepository;
  sessions: SessionRepository;
  workspaces: WorkspaceRepository;
  memberships: MembershipRepository;
  invitations?: InvitationRepository;
  membershipApprovals?: WorkspaceMembershipApprovalRepository;
  apps: AppRepository;
  appEntitlements: AppEntitlementRepository;
  auditEvents?: AuditEventRepository;
  workspaceAdminTransactions?: WorkspaceAdminTransactionRepository;
  appLaunchTokens?: AppLaunchTokenRepository;
}

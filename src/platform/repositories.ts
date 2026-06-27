import type {
  AuditEvent,
  Invitation,
  InvitationStatus,
  IsoTimestamp,
  Membership,
  Session,
  User,
  Workspace,
} from "../accounts/types.js";
import type { App, AppEntitlement } from "../apps/types.js";

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
}

export interface WorkspaceRepository {
  findById(id: string): Promise<Workspace | null>;
  findBySlug(slug: string): Promise<Workspace | null>;
}

export interface MembershipRepository {
  findForUserInWorkspace(userId: string, workspaceId: string): Promise<Membership | null>;
  listForUser(userId: string): Promise<readonly Membership[]>;
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

export interface AppRepository {
  findByKey(key: string): Promise<App | null>;
  findById(id: string): Promise<App | null>;
}

export interface AppEntitlementRepository {
  findForWorkspaceApp(workspaceId: string, appId: string): Promise<AppEntitlement | null>;
}

export interface AuditEventRepository {
  append(event: AuditEvent): Promise<AuditEvent>;
}

export interface PlatformRepositories {
  users: UserRepository;
  providerIdentities?: ProviderIdentityRepository;
  sessions: SessionRepository;
  workspaces: WorkspaceRepository;
  memberships: MembershipRepository;
  invitations?: InvitationRepository;
  apps: AppRepository;
  appEntitlements: AppEntitlementRepository;
  auditEvents?: AuditEventRepository;
}

export interface WorkspaceAdminIdFactory {
  createAuditEventId(): string;
  createEntitlementId(): string;
  createMembershipId(): string;
}

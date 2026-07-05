export interface WorkspaceAdminIdFactory {
  createAuditEventId(): string;
  createApprovalId(): string;
  createEntitlementId(): string;
  createMembershipId(): string;
}

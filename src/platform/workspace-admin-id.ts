export interface WorkspaceAdminIdFactory {
  createAuditEventId(): string;
  createEntitlementId(): string;
}

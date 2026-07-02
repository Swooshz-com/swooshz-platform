import { randomBytes } from "node:crypto";

import type { WorkspaceAdminIdFactory } from "./workspace-admin-id.js";

export interface SecureWorkspaceAdminIdFactoryOptions {
  byteLength?: number;
}

const defaultByteLength = 18;

export function createSecureWorkspaceAdminIdFactory(
  options: SecureWorkspaceAdminIdFactoryOptions = {},
): WorkspaceAdminIdFactory {
  const byteLength = options.byteLength ?? defaultByteLength;

  return {
    createAuditEventId() {
      return `workspace_admin_audit_${randomId(byteLength)}`;
    },
    createEntitlementId() {
      return `workspace_admin_entitlement_${randomId(byteLength)}`;
    },
  };
}

function randomId(byteLength: number): string {
  return randomBytes(byteLength).toString("base64url");
}

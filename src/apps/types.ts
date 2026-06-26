import type { IsoTimestamp } from "../accounts/types.js";

export const AppStatus = {
  Available: "available",
  PrivatePreview: "private_preview",
  Disabled: "disabled",
} as const;

export type AppStatus = (typeof AppStatus)[keyof typeof AppStatus];

export const EntitlementStatus = {
  Enabled: "enabled",
  Disabled: "disabled",
  Trial: "trial",
  Suspended: "suspended",
} as const;

export type EntitlementStatus = (typeof EntitlementStatus)[keyof typeof EntitlementStatus];

export interface App {
  id: string;
  key: string;
  name: string;
  status: AppStatus;
  launchUrl: string | null;
  createdAt: IsoTimestamp;
  updatedAt: IsoTimestamp;
}

export interface AppEntitlement {
  id: string;
  workspaceId: string;
  appId: string;
  status: EntitlementStatus;
  grantedByUserId: string | null;
  createdAt: IsoTimestamp;
  updatedAt: IsoTimestamp;
}

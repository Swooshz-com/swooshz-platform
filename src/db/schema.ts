import {
  index,
  jsonb,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
} from "drizzle-orm/pg-core";

export const userStatusEnum = pgEnum("user_status", ["active", "invited", "disabled"]);
export const workspaceStatusEnum = pgEnum("workspace_status", [
  "active",
  "suspended",
  "archived",
]);
export const membershipStatusEnum = pgEnum("membership_status", ["active", "disabled"]);
export const roleEnum = pgEnum("role", ["owner", "admin", "member", "viewer"]);
export const invitationStatusEnum = pgEnum("invitation_status", [
  "pending",
  "accepted",
  "expired",
  "revoked",
]);
export const appStatusEnum = pgEnum("app_status", [
  "available",
  "private_preview",
  "disabled",
]);
export const entitlementStatusEnum = pgEnum("entitlement_status", [
  "enabled",
  "disabled",
  "trial",
  "suspended",
]);

const timestamps = {
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
};

export const users = pgTable(
  "users",
  {
    id: text("id").primaryKey(),
    email: text("email").notNull(),
    displayName: text("display_name").notNull(),
    status: userStatusEnum("status").notNull(),
    ...timestamps,
    lastLoginAt: timestamp("last_login_at", { withTimezone: true }),
  },
  (table) => [
    uniqueIndex("users_email_unique").on(table.email),
    index("users_status_idx").on(table.status),
  ],
);

export const providerIdentities = pgTable(
  "provider_identities",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    providerKey: text("provider_key").notNull(),
    providerSubject: text("provider_subject").notNull(),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("provider_identities_provider_subject_unique").on(
      table.providerKey,
      table.providerSubject,
    ),
    uniqueIndex("provider_identities_provider_user_unique").on(
      table.providerKey,
      table.userId,
    ),
    index("provider_identities_user_id_idx").on(table.userId),
  ],
);

export const workspaces = pgTable(
  "workspaces",
  {
    id: text("id").primaryKey(),
    slug: text("slug").notNull(),
    displayName: text("display_name").notNull(),
    status: workspaceStatusEnum("status").notNull(),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("workspaces_slug_unique").on(table.slug),
    index("workspaces_status_idx").on(table.status),
  ],
);

export const memberships = pgTable(
  "memberships",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "restrict" }),
    userId: text("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    role: roleEnum("role").notNull(),
    status: membershipStatusEnum("status").notNull(),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("memberships_workspace_user_unique").on(table.workspaceId, table.userId),
    index("memberships_user_id_idx").on(table.userId),
    index("memberships_workspace_status_idx").on(table.workspaceId, table.status),
  ],
);

export const invitations = pgTable(
  "invitations",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "restrict" }),
    email: text("email").notNull(),
    role: roleEnum("role").notNull(),
    status: invitationStatusEnum("status").notNull(),
    tokenHash: text("token_hash"),
    invitedByUserId: text("invited_by_user_id").references(() => users.id, {
      onDelete: "set null",
    }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    acceptedAt: timestamp("accepted_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (table) => [
    index("invitations_email_status_idx").on(table.email, table.status),
    index("invitations_workspace_status_idx").on(table.workspaceId, table.status),
    index("invitations_expires_at_idx").on(table.expiresAt),
    index("invitations_invited_by_user_id_idx").on(table.invitedByUserId),
  ],
);

export const sessions = pgTable(
  "sessions",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    metadata: jsonb("metadata").$type<Record<string, unknown>>(),
  },
  (table) => [
    index("sessions_user_id_idx").on(table.userId),
    index("sessions_expires_at_idx").on(table.expiresAt),
    index("sessions_revoked_at_idx").on(table.revokedAt),
    index("sessions_user_expiry_idx").on(table.userId, table.expiresAt),
  ],
);

export const auditEvents = pgTable(
  "audit_events",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id").references(() => workspaces.id, {
      onDelete: "set null",
    }),
    actorUserId: text("actor_user_id").references(() => users.id, {
      onDelete: "set null",
    }),
    eventType: text("event_type").notNull(),
    targetType: text("target_type").notNull(),
    targetId: text("target_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    metadata: jsonb("metadata").$type<Record<string, unknown>>().notNull(),
  },
  (table) => [
    index("audit_events_workspace_created_at_idx").on(table.workspaceId, table.createdAt),
    index("audit_events_actor_user_id_idx").on(table.actorUserId),
    index("audit_events_target_idx").on(table.targetType, table.targetId),
    index("audit_events_event_type_idx").on(table.eventType),
  ],
);

export const apps = pgTable(
  "apps",
  {
    id: text("id").primaryKey(),
    key: text("key").notNull(),
    name: text("name").notNull(),
    status: appStatusEnum("status").notNull(),
    launchUrl: text("launch_url"),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("apps_key_unique").on(table.key),
    index("apps_status_idx").on(table.status),
  ],
);

export const appEntitlements = pgTable(
  "app_entitlements",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "restrict" }),
    appId: text("app_id")
      .notNull()
      .references(() => apps.id, { onDelete: "restrict" }),
    status: entitlementStatusEnum("status").notNull(),
    grantedByUserId: text("granted_by_user_id").references(() => users.id, {
      onDelete: "set null",
    }),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("app_entitlements_workspace_app_unique").on(table.workspaceId, table.appId),
    index("app_entitlements_workspace_status_idx").on(table.workspaceId, table.status),
    index("app_entitlements_app_id_idx").on(table.appId),
    index("app_entitlements_granted_by_user_id_idx").on(table.grantedByUserId),
  ],
);

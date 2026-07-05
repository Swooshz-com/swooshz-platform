CREATE TYPE "public"."workspace_membership_approval_status" AS ENUM('pending', 'accepted', 'revoked');--> statement-breakpoint
CREATE TABLE "workspace_membership_approvals" (
	"id" text PRIMARY KEY NOT NULL,
	"workspace_id" text NOT NULL,
	"email" text NOT NULL,
	"role" "role" NOT NULL,
	"status" "workspace_membership_approval_status" NOT NULL,
	"requested_by_user_id" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"accepted_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"accepted_user_id" text,
	"revoked_by_user_id" text
);
--> statement-breakpoint
ALTER TABLE "workspace_membership_approvals" ADD CONSTRAINT "workspace_membership_approvals_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "workspace_membership_approvals" ADD CONSTRAINT "workspace_membership_approvals_requested_by_user_id_users_id_fk" FOREIGN KEY ("requested_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "workspace_membership_approvals" ADD CONSTRAINT "workspace_membership_approvals_accepted_user_id_users_id_fk" FOREIGN KEY ("accepted_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "workspace_membership_approvals" ADD CONSTRAINT "workspace_membership_approvals_revoked_by_user_id_users_id_fk" FOREIGN KEY ("revoked_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "workspace_membership_approvals_pending_unique" ON "workspace_membership_approvals" USING btree ("workspace_id","email") WHERE "workspace_membership_approvals"."status" = 'pending';--> statement-breakpoint
CREATE INDEX "workspace_membership_approvals_email_status_idx" ON "workspace_membership_approvals" USING btree ("email","status");--> statement-breakpoint
CREATE INDEX "workspace_membership_approvals_workspace_status_idx" ON "workspace_membership_approvals" USING btree ("workspace_id","status");--> statement-breakpoint
CREATE INDEX "workspace_membership_approvals_requested_by_user_id_idx" ON "workspace_membership_approvals" USING btree ("requested_by_user_id");
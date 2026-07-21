CREATE TABLE "access_validation_grants" (
	"id" text PRIMARY KEY NOT NULL,
	"session_id" text NOT NULL,
	"user_id" text NOT NULL,
	"workspace_id" text NOT NULL,
	"app_id" text NOT NULL,
	"intended_origin" text NOT NULL,
	"launch_token_expires_at" timestamp with time zone NOT NULL,
	"handle_hash" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"handle_expires_at" timestamp with time zone,
	"consumed_at" timestamp with time zone,
	"revoked_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "access_validation_grants" ADD CONSTRAINT "access_validation_grants_session_id_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "access_validation_grants" ADD CONSTRAINT "access_validation_grants_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "access_validation_grants" ADD CONSTRAINT "access_validation_grants_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "access_validation_grants" ADD CONSTRAINT "access_validation_grants_app_id_apps_id_fk" FOREIGN KEY ("app_id") REFERENCES "public"."apps"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "access_validation_grants_handle_hash_unique" ON "access_validation_grants" USING btree ("handle_hash");--> statement-breakpoint
CREATE INDEX "access_validation_grants_session_id_idx" ON "access_validation_grants" USING btree ("session_id");--> statement-breakpoint
CREATE INDEX "access_validation_grants_expiry_idx" ON "access_validation_grants" USING btree ("handle_expires_at");
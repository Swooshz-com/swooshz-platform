CREATE TABLE "app_launch_tokens" (
	"id" text PRIMARY KEY NOT NULL,
	"session_id" text NOT NULL,
	"user_id" text NOT NULL,
	"workspace_id" text NOT NULL,
	"app_id" text NOT NULL,
	"token_hash" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"consumed_at" timestamp with time zone,
	"revoked_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "app_launch_tokens" ADD CONSTRAINT "app_launch_tokens_session_id_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "app_launch_tokens" ADD CONSTRAINT "app_launch_tokens_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "app_launch_tokens" ADD CONSTRAINT "app_launch_tokens_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "app_launch_tokens" ADD CONSTRAINT "app_launch_tokens_app_id_apps_id_fk" FOREIGN KEY ("app_id") REFERENCES "public"."apps"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "app_launch_tokens_token_hash_unique" ON "app_launch_tokens" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "app_launch_tokens_session_id_idx" ON "app_launch_tokens" USING btree ("session_id");--> statement-breakpoint
CREATE INDEX "app_launch_tokens_workspace_app_idx" ON "app_launch_tokens" USING btree ("workspace_id","app_id");--> statement-breakpoint
CREATE INDEX "app_launch_tokens_expires_at_idx" ON "app_launch_tokens" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "app_launch_tokens_consumed_at_idx" ON "app_launch_tokens" USING btree ("consumed_at");
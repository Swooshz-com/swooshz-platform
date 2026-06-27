CREATE TYPE "public"."csrf_token_purpose" AS ENUM('browser_session');--> statement-breakpoint
CREATE TABLE "csrf_tokens" (
	"id" text PRIMARY KEY NOT NULL,
	"session_id" text NOT NULL,
	"token_hash" text NOT NULL,
	"purpose" "csrf_token_purpose" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"consumed_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"replaced_by_token_id" text
);
--> statement-breakpoint
ALTER TABLE "csrf_tokens" ADD CONSTRAINT "csrf_tokens_session_id_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "csrf_tokens_session_id_idx" ON "csrf_tokens" USING btree ("session_id");--> statement-breakpoint
CREATE UNIQUE INDEX "csrf_tokens_session_hash_purpose_unique" ON "csrf_tokens" USING btree ("session_id","token_hash","purpose");--> statement-breakpoint
CREATE INDEX "csrf_tokens_expires_at_idx" ON "csrf_tokens" USING btree ("expires_at");
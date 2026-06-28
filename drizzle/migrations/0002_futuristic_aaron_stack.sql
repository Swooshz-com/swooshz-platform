CREATE TABLE "auth_states" (
	"provider_key" text NOT NULL,
	"state_hash" text NOT NULL,
	"nonce_hash" text NOT NULL,
	"redirect_uri" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"consumed_at" timestamp with time zone,
	"revoked_at" timestamp with time zone
);
--> statement-breakpoint
CREATE UNIQUE INDEX "auth_states_provider_state_unique" ON "auth_states" USING btree ("provider_key","state_hash");--> statement-breakpoint
CREATE INDEX "auth_states_expires_at_idx" ON "auth_states" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "auth_states_consumed_at_idx" ON "auth_states" USING btree ("consumed_at");
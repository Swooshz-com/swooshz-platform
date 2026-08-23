--> statement-breakpoint
-- The standard Drizzle migrator wraps this migration in one transaction.
-- Preflight rejects invalid current state before the old enum is replaced.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM "workspace_membership_approvals" AS approval
    LEFT JOIN "workspaces" AS workspace ON workspace."id" = approval."workspace_id"
    WHERE approval."status" = 'pending'
      AND approval."requested_by_user_id" IS NULL
      AND NOT (
        workspace."status" = 'active'
        AND NOT EXISTS (
          SELECT 1
          FROM "memberships" AS membership
          WHERE membership."workspace_id" = approval."workspace_id"
        )
        AND approval."role"::text IN ('owner', 'admin')
      )
  ) THEN
    RAISE EXCEPTION 'invalid nullable requester state for current membership approval';
  END IF;

  IF EXISTS (
    SELECT approval."workspace_id"
    FROM "workspace_membership_approvals" AS approval
    WHERE approval."status" = 'pending'
      AND approval."requested_by_user_id" IS NULL
      AND approval."role"::text IN ('owner', 'admin')
    GROUP BY approval."workspace_id"
    HAVING COUNT(*) <> 1
  ) THEN
    RAISE EXCEPTION 'duplicate or missing first-admin bootstrap approval';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM "workspaces" AS workspace
    WHERE workspace."status" = 'active'
      AND NOT EXISTS (
        SELECT 1
        FROM "memberships" AS membership
        WHERE membership."workspace_id" = workspace."id"
      )
      AND NOT EXISTS (
        SELECT 1
        FROM "workspace_membership_approvals" AS approval
        WHERE approval."workspace_id" = workspace."id"
          AND approval."status" = 'pending'
          AND approval."requested_by_user_id" IS NULL
          AND approval."role"::text IN ('owner', 'admin')
      )
  ) THEN
    RAISE EXCEPTION 'active zero-member workspace lacks first-admin bootstrap approval';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM "workspaces" AS workspace
    WHERE workspace."status" = 'active'
      AND EXISTS (
        SELECT 1
        FROM "memberships" AS membership
        WHERE membership."workspace_id" = workspace."id"
      )
      AND NOT EXISTS (
        SELECT 1
        FROM "memberships" AS membership
        WHERE membership."workspace_id" = workspace."id"
          AND membership."status" = 'active'
          AND membership."role"::text IN ('owner', 'admin')
      )
  ) THEN
    RAISE EXCEPTION 'active workspace would have no active admin after role collapse';
  END IF;
END
$$;--> statement-breakpoint

ALTER TYPE "public"."role" RENAME TO "role_old";--> statement-breakpoint

ALTER TABLE "invitations" ALTER COLUMN "role" SET DATA TYPE text USING "role"::text;--> statement-breakpoint
ALTER TABLE "memberships" ALTER COLUMN "role" SET DATA TYPE text USING "role"::text;--> statement-breakpoint
ALTER TABLE "workspace_membership_approvals" ALTER COLUMN "role" SET DATA TYPE text USING "role"::text;--> statement-breakpoint

UPDATE "invitations"
SET "role" = CASE "role"
  WHEN 'owner' THEN 'admin'
  WHEN 'admin' THEN 'admin'
  WHEN 'member' THEN 'operator'
  WHEN 'viewer' THEN 'viewer'
END;--> statement-breakpoint
UPDATE "memberships"
SET "role" = CASE "role"
  WHEN 'owner' THEN 'admin'
  WHEN 'admin' THEN 'admin'
  WHEN 'member' THEN 'operator'
  WHEN 'viewer' THEN 'viewer'
END;--> statement-breakpoint
UPDATE "workspace_membership_approvals"
SET "role" = CASE "role"
  WHEN 'owner' THEN 'admin'
  WHEN 'admin' THEN 'admin'
  WHEN 'member' THEN 'operator'
  WHEN 'viewer' THEN 'viewer'
END;--> statement-breakpoint

CREATE TYPE "public"."role" AS ENUM('admin', 'operator', 'viewer');--> statement-breakpoint
ALTER TABLE "invitations" ALTER COLUMN "role" SET DATA TYPE "public"."role" USING "role"::"public"."role";--> statement-breakpoint
ALTER TABLE "memberships" ALTER COLUMN "role" SET DATA TYPE "public"."role" USING "role"::"public"."role";--> statement-breakpoint
ALTER TABLE "workspace_membership_approvals" ALTER COLUMN "role" SET DATA TYPE "public"."role" USING "role"::"public"."role";--> statement-breakpoint
DROP TYPE "public"."role_old";
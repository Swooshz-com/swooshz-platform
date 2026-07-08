INSERT INTO "apps" ("id", "key", "name", "status", "launch_url", "created_at", "updated_at")
SELECT 'app_sqag', 'sqag', 'SQAG', "status", "launch_url", "created_at", now()
FROM "apps"
WHERE "key" = 'kqag'
  AND NOT EXISTS (SELECT 1 FROM "apps" WHERE "key" = 'sqag')
LIMIT 1
ON CONFLICT ("id") DO NOTHING;--> statement-breakpoint
UPDATE "apps"
SET "key" = 'sqag',
    "name" = 'SQAG',
    "updated_at" = now()
WHERE "id" = 'app_sqag'
  AND NOT EXISTS (
    SELECT 1
    FROM "apps" AS "existing_sqag"
    WHERE "existing_sqag"."key" = 'sqag'
      AND "existing_sqag"."id" <> 'app_sqag'
  );--> statement-breakpoint
UPDATE "app_launch_tokens"
SET "app_id" = 'app_sqag'
WHERE "app_id" IN (SELECT "id" FROM "apps" WHERE "key" = 'kqag')
  AND EXISTS (SELECT 1 FROM "apps" WHERE "id" = 'app_sqag');--> statement-breakpoint
UPDATE "app_entitlements"
SET "app_id" = 'app_sqag',
    "updated_at" = now()
WHERE "app_id" IN (SELECT "id" FROM "apps" WHERE "key" = 'kqag')
  AND EXISTS (SELECT 1 FROM "apps" WHERE "id" = 'app_sqag')
  AND NOT EXISTS (
    SELECT 1
    FROM "app_entitlements" AS "existing_sqag_entitlement"
    WHERE "existing_sqag_entitlement"."workspace_id" = "app_entitlements"."workspace_id"
      AND "existing_sqag_entitlement"."app_id" = 'app_sqag'
  );--> statement-breakpoint
DELETE FROM "app_entitlements"
WHERE "app_id" IN (SELECT "id" FROM "apps" WHERE "key" = 'kqag')
  AND EXISTS (
    SELECT 1
    FROM "app_entitlements" AS "existing_sqag_entitlement"
    WHERE "existing_sqag_entitlement"."workspace_id" = "app_entitlements"."workspace_id"
      AND "existing_sqag_entitlement"."app_id" = 'app_sqag'
  );--> statement-breakpoint
DELETE FROM "apps"
WHERE "key" = 'kqag';

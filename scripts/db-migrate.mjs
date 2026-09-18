#!/usr/bin/env node

if (process.env.DATABASE_OPERATOR_URL?.trim()) {
  process.stderr.write("Direct production database operator credentials are prohibited.\n");
} else {
  process.stderr.write("Production migrations require the reviewed provider broker adapter. support_ref=platform_db_broker_unavailable\n");
}
process.exitCode = 1;

import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { Writable } from "node:stream";
import test from "node:test";

import {
  PLATFORM_RUNTIME_ACTIVATION_PHASES,
  PlatformRuntimeActivationError,
  PlatformRuntimeActivationPhaseJournal,
  buildRuntimeDatabaseUrl,
  installRuntimePasswordWithDocker,
} from "../scripts/platform-runtime-activation-contract.mjs";

test("activation phase contract covers the complete rollback-gated sequence", () => {
  assert.deepEqual(PLATFORM_RUNTIME_ACTIVATION_PHASES, [
    "dormant_role_preflight",
    "password_installation",
    "login_enablement",
    "runtime_connection_construction",
    "runtime_connection_establishment",
    "runtime_identity",
    "recursive_set_role_posture",
    "grants_and_ownership_verification",
    "success_finalisation",
    "mandatory_rollback",
  ]);
});

test("activation phase journal preserves the original failure through rollback", () => {
  const journal = new PlatformRuntimeActivationPhaseJournal();
  journal.start("dormant_role_preflight");
  journal.pass();
  journal.start("password_installation");
  journal.fail();
  journal.start("mandatory_rollback");
  journal.pass();

  assert.deepEqual(journal.safeReport(), {
    failedPhase: "password_installation",
    rollbackTriggered: true,
    rollbackVerified: true,
    phases: {
      dormant_role_preflight: "passed",
      password_installation: "failed",
      login_enablement: "pending",
      runtime_connection_construction: "pending",
      runtime_connection_establishment: "pending",
      runtime_identity: "pending",
      recursive_set_role_posture: "pending",
      grants_and_ownership_verification: "pending",
      success_finalisation: "pending",
      mandatory_rollback: "passed",
    },
  });
});

test("activation phase journal rejects skipped or out-of-order phases", () => {
  const journal = new PlatformRuntimeActivationPhaseJournal();
  assert.throws(
    () => journal.start("login_enablement"),
    PlatformRuntimeActivationError,
  );
});

test("activation phase journal marks rollback as not required on success", () => {
  const journal = new PlatformRuntimeActivationPhaseJournal();
  for (const phase of PLATFORM_RUNTIME_ACTIVATION_PHASES.slice(0, -1)) {
    journal.start(phase);
    journal.pass();
  }
  journal.notRequired("mandatory_rollback");

  const report = journal.safeReport();
  assert.equal(report.failedPhase, null);
  assert.equal(report.rollbackTriggered, false);
  assert.equal(report.rollbackVerified, false);
  assert.equal(report.phases.success_finalisation, "passed");
  assert.equal(report.phases.mandatory_rollback, "not_required");
});

test("runtime URL construction encodes credentials and preserves endpoint shape", () => {
  const result = buildRuntimeDatabaseUrl(
    "postgresql://operator:ignored@db.example.test:5544/platform?sslmode=require&channel_binding=require",
    "platform_runtime",
    "Synthetic!éΩ:/?#[]@%",
  );
  const parsed = new URL(result);

  assert.equal(decodeURIComponent(parsed.username), "platform_runtime");
  assert.equal(decodeURIComponent(parsed.password), "Synthetic!éΩ:/?#[]@%");
  assert.equal(parsed.hostname, "db.example.test");
  assert.equal(parsed.port, "5544");
  assert.equal(parsed.pathname, "/platform");
  assert.equal(parsed.searchParams.get("sslmode"), "require");
  assert.equal(parsed.searchParams.get("channel_binding"), "require");
});

test("password transport rejects line breaks before spawning Docker", async () => {
  let spawnCalled = false;
  await assert.rejects(
    () =>
      installRuntimePasswordWithDocker({
        operatorUrl: "postgresql://operator:synthetic@db.example.test/platform",
        runtimeRole: "platform_runtime",
        runtimePassword: "SyntheticRuntime_2026!ExtraLength\n\\q",
        spawnImpl() {
          spawnCalled = true;
        },
      }),
    PlatformRuntimeActivationError,
  );
  assert.equal(spawnCalled, false);
});

test("Docker password installation ignores prompt stderr and writes UTF-8 stdin", async () => {
  const captured = {};
  const runtimePassword = "SyntheticRuntime_2026!éΩ漢字_ExtraLength";

  await installRuntimePasswordWithDocker({
    operatorUrl:
      "postgresql://operator:synthetic@db.example.test/platform?sslmode=require",
    runtimeRole: "platform_runtime",
    runtimePassword,
    spawnImpl(command, args, options) {
      captured.command = command;
      captured.args = args;
      captured.options = options;
      captured.stdin = [];

      const child = new EventEmitter();
      child.kill = () => {};
      child.stderr = new EventEmitter();
      child.stdin = new Writable({
        write(chunk, _encoding, callback) {
          captured.stdin.push(Buffer.from(chunk));
          callback();
        },
      });
      queueMicrotask(() => {
        child.stderr.emit(
          "data",
          Buffer.from('Enter new password for user "platform_runtime": '),
        );
        child.emit("close", 0, null);
      });
      return child;
    },
  });

  assert.equal(captured.command, "docker");
  assert.equal(captured.options.stdio[2], "ignore");
  assert.equal(captured.options.windowsHide, true);
  assert.equal(
    captured.args.includes(
      "postgresql://operator:synthetic@db.example.test/platform?sslmode=require",
    ),
    false,
  );
  assert.equal(captured.args.includes(runtimePassword), false);
  assert.equal(
    Buffer.concat(captured.stdin).toString("utf8"),
    `\\password platform_runtime\n${runtimePassword}\n${runtimePassword}\n\\q\n`,
  );
});

test("Docker password installation exposes only a generic failure", async () => {
  const operatorUrl =
    "postgresql://operator:synthetic@db.example.test/platform";
  const runtimePassword = "SyntheticRuntime_2026!Lab_ExtraLength";

  await assert.rejects(
    () =>
      installRuntimePasswordWithDocker({
        operatorUrl,
        runtimeRole: "platform_runtime",
        runtimePassword,
        spawnImpl() {
          const child = new EventEmitter();
          child.kill = () => {};
          child.stdin = new Writable({
            write(_chunk, _encoding, callback) {
              callback();
            },
          });
          queueMicrotask(() => child.emit("close", 1, null));
          return child;
        },
      }),
    (error) => {
      assert.equal(error instanceof PlatformRuntimeActivationError, true);
      assert.equal(error.code, "runtime_activation_failed");
      assert.equal(error.message, "Runtime activation failed.");
      assert.doesNotMatch(String(error), /operator|synthetic|platform_runtime/i);
      return true;
    },
  );
});

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  formatDisposableRuntimeFailureReceipt,
  parseDisposableRuntimeTestSummary,
} from "../scripts/run-disposable-runtime-postgres-tests.mjs";

test("summary parser accepts Node 22 TAP and Node 24 spec markers", () => {
  const expected = { total: 53, passed: 53, skipped: 0 };
  assert.deepEqual(
    parseDisposableRuntimeTestSummary(
      "# tests 53\n# pass 53\n# skipped 0\n",
    ),
    expected,
  );
  assert.deepEqual(
    parseDisposableRuntimeTestSummary(
      "ℹ tests 53\nℹ pass 53\nℹ skipped 0\n",
    ),
    expected,
  );
  assert.equal(
    parseDisposableRuntimeTestSummary("# tests 53\n# fail 1\n"),
    null,
  );
});

test("disposable runtime failure receipt is bounded and public-safe", () => {
  const receipt = formatDisposableRuntimeFailureReceipt({
    failurePhase: "runFocusedTests",
    failureCategory: "child_test_failure",
    childExitCode: 1,
    childSignal: false,
    childOutputOverflow: false,
    childSummaryParsed: false,
    containerStarted: true,
    postgresReady: true,
    constructionAdmission: true,
    provisioningComplete: true,
    configuredAdmission: true,
    childTestsStarted: true,
    cleanupComplete: true,
    absenceVerified: true,
  });

  assert.ok(Buffer.byteLength(receipt, "utf8") <= 1024);
  assert.match(receipt, /"category":"child_test_failure"/);
  assert.match(receipt, /"childExitCode":1/);
  assert.doesNotMatch(receipt, /postgres(?:ql)?:\/\/|127\.0\.0\.1|55432/i);
  assert.doesNotMatch(receipt, /password[=:]|secret[=:]|authorization[=:]|token[=:]/i);
});

test("failure receipt ignores untrusted diagnostic values", () => {
  const receipt = formatDisposableRuntimeFailureReceipt({
    failurePhase: "untrusted-phase",
    failureCategory: "raw database error",
    childExitCode: "untrusted-exit-code",
  });

  assert.match(receipt, /"phase":"construct"/);
  assert.match(receipt, /"category":"ci_environment_unclassified"/);
  assert.doesNotMatch(receipt, /untrusted|database error|postgres(?:ql)?:\/\//i);
});

test("child stderr remains consumed and diagnostic output is not child output", async () => {
  const source = await readFile(
    "scripts/run-disposable-runtime-postgres-tests.mjs",
    "utf8",
  );

  assert.match(source, /child\.stderr\?\.resume\(\)/);
  assert.doesNotMatch(source, /child\.stderr\?\.(?:on|pipe)\(/);
  assert.doesNotMatch(
    formatDisposableRuntimeFailureReceipt({ childOutput: "sensitive-output" }),
    /postgres(?:ql)?:\/\/|secret[=:]/i,
  );
});

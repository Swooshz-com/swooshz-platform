import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  formatDisposableRuntimeFailureReceipt,
  parseDisposableRuntimeTestSummary,
} from "../scripts/run-disposable-runtime-postgres-tests.mjs";

test("summary parser accepts Node 22 TAP and Node 24 spec markers", () => {
  const expected = {
    cancelled: 0,
    failed: 0,
    passed: 53,
    skipped: 0,
    todo: 0,
    total: 53,
  };
  assert.deepEqual(parseDisposableRuntimeTestSummary(nativeSummary("#")), expected);
  assert.deepEqual(
    parseDisposableRuntimeTestSummary(nativeSummary(String.fromCodePoint(0x2139))),
    expected,
  );
});

test("summary parser requires one exact coherent 53/53/0 terminal block", () => {
  const rejected = [
    nativeSummary("#", { pass: 52, fail: 1 }),
    nativeSummary("#", { skipped: 1 }),
    nativeSummary("#", { pass: 52, skipped: 1, fail: 0 }),
    nativeSummary("#", { tests: 52, pass: 52 }),
    nativeSummary("#", { fail: null }),
    nativeSummary("#", { skipped: null }),
    nativeSummary("#", { duplicate: "pass" }),
    nativeSummary("#", { conflict: "pass" }),
    nativeSummary("#", { interleaved: "ordinary output" }),
    `${nativeSummary("#")}\nordinary child output`,
    nativeSummary("#", { tests: "+53" }),
    nativeSummary("#", { tests: "53.0" }),
    nativeSummary("#", { tests: "999999999999999999999999" }),
    nativeSummary("#", { marker: "mixed" }),
    nativeSummary("#", { omit: "skipped" }),
    "# tests 53\n# suites 1\n# pass 53\n# cancelled 0\n# skipped 0\n# todo 0\n# duration_ms 1",
  ];
  for (const output of rejected) assert.equal(parseDisposableRuntimeTestSummary(output), null);

  const ansi = nativeSummary("#").replace("# pass", "\u001b[31m# pass\u001b[0m");
  assert.deepEqual(parseDisposableRuntimeTestSummary(ansi), {
    cancelled: 0,
    failed: 0,
    passed: 53,
    skipped: 0,
    todo: 0,
    total: 53,
  });
  assert.equal(parseDisposableRuntimeTestSummary(`${nativeSummary("#")}x`.repeat(1000)), null);
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

function nativeSummary(marker, overrides = {}) {
  const values = {
    tests: 53,
    suites: 1,
    pass: 53,
    fail: 0,
    cancelled: 0,
    skipped: 0,
    todo: 0,
    duration_ms: 1,
    ...overrides,
  };
  const lines = [
    `${marker} tests ${values.tests}`,
    `${marker} suites ${values.suites}`,
    `${marker} pass ${values.pass}`,
    `${marker} fail ${values.fail ?? ""}`,
    `${marker} cancelled ${values.cancelled}`,
    `${marker} skipped ${values.skipped ?? ""}`,
    `${marker} todo ${values.todo}`,
    `${marker} duration_ms ${values.duration_ms}`,
  ];
  if (values.duplicate) lines.splice(3, 0, `${marker} pass 53`);
  if (values.conflict) lines.splice(4, 0, `${marker} pass 52`);
  if (values.interleaved) lines.splice(2, 0, values.interleaved);
  if (values.omit) lines.splice(5, 1);
  if (values.marker === "mixed") {
    lines[1] = `${String.fromCodePoint(0x2139)} suites ${values.suites}`;
  }
  return lines.join("\n");
}

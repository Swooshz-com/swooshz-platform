const shaPattern = /^[0-9a-f]{40}$/;
const emailPattern = /[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[a-z0-9-]+\.)+[a-z]{2,}/gi;
const sensitivePattern = /(?:postgres(?:ql)?:\/\/|-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:sk|gh[opsu]|xox[baprs])-[a-z0-9_-]{12,}|(?:auth|session|launch)[_-]?token\s*[:=])/i;

export const requiredAuthenticatedScreenshots = Object.freeze([
  "launcher-desktop-available.png",
  "launcher-mobile-390-available.png",
  "launcher-mobile-320-available.png",
  "launcher-multiple-workspaces.png",
  "launcher-product-unavailable.png",
  "launcher-controlled-launch-failure.png",
  "launcher-keyboard-focus.png",
  "admin-desktop-members.png",
  "admin-desktop-pending-approvals.png",
  "admin-desktop-product-access.png",
  "admin-desktop-audit-activity.png",
  "admin-desktop-action-disclosure.png",
  "admin-desktop-add-member-modal.png",
  "admin-desktop-add-member-busy.png",
  "admin-mobile-390-members.png",
  "admin-mobile-390-product-access.png",
  "admin-mobile-390-add-member-modal.png",
  "admin-mobile-320-members.png",
  "admin-enlarged-layout-200pct-equivalent.png",
]);

export const requiredAuthenticatedInteractions = Object.freeze([
  "keyboard-tab-reaches-four-admin-buttons",
  "enter-or-space-activates-each-admin-section",
  "active-section-alone-has-aria-current-page",
  "mobile-selector-changes-sections",
  "manage-opens-action-disclosure",
  "disclosure-focuses-first-action",
  "disclosure-tab-reaches-next-action",
  "disclosure-escape-closes-and-restores-focus",
  "add-member-modal-receives-focus",
  "add-member-modal-focus-contained",
  "add-member-modal-escape-restores-focus",
  "no-horizontal-overflow",
  "no-console-or-page-errors",
  "launcher-primary-content-visible-at-390-and-320",
  "unique-disclosure-ids",
  "opening-another-disclosure-closes-previous",
  "outside-click-closes-disclosure-safely",
]);

export function validateEvidenceHeadSha(value) {
  const headSha = String(value ?? "").trim().toLowerCase();
  if (!shaPattern.test(headSha)) throw new Error("EVIDENCE_HEAD_SHA must be the exact 40-character checked-out commit SHA.");
  return headSha;
}

export function assertAllowedEvidenceRequest(requestUrl, expectedOrigin) {
  const parsed = new URL(requestUrl);
  if (parsed.origin !== expectedOrigin) throw new Error(`External network request blocked: ${parsed.origin}`);
  return parsed;
}

export function assertSyntheticIdentitySafety(value) {
  const serialized = JSON.stringify(value);
  const emails = serialized.match(emailPattern) ?? [];
  for (const email of emails) {
    const domain = email.toLowerCase().split("@").pop() ?? "";
    if (!(domain.endsWith(".example") || domain.endsWith(".invalid"))) {
      throw new Error(`Evidence fixture contains a non-synthetic identity domain: ${domain}`);
    }
  }
  if (sensitivePattern.test(serialized)) throw new Error("Evidence fixture contains secret-, credential-, or private-runtime-like material.");
  return true;
}

export function validateAuthenticatedEvidenceSummary(summary) {
  validateEvidenceHeadSha(summary?.headSha);
  assertSyntheticIdentitySafety(summary?.syntheticFixtureSummary ?? {});
  const screenshotSet = new Set(summary?.screenshots ?? []);
  const missingScreenshots = requiredAuthenticatedScreenshots.filter((name) => !screenshotSet.has(name));
  if (missingScreenshots.length) throw new Error(`Authenticated evidence is missing required screenshots: ${missingScreenshots.join(", ")}`);
  const interactionMap = new Map((summary?.interactions ?? []).map((item) => [item.id, item]));
  const missingInteractions = requiredAuthenticatedInteractions.filter((id) => !interactionMap.has(id));
  if (missingInteractions.length) throw new Error(`Authenticated evidence is missing interaction checks: ${missingInteractions.join(", ")}`);
  const failedInteractions = requiredAuthenticatedInteractions.filter((id) => interactionMap.get(id)?.passed !== true);
  if (failedInteractions.length) throw new Error(`Authenticated evidence interaction checks failed: ${failedInteractions.join(", ")}`);
  const browserErrors = [...(summary?.consoleErrors ?? []), ...(summary?.pageErrors ?? [])];
  if (browserErrors.length) throw new Error(`Authenticated evidence contains browser errors: ${browserErrors.join(" | ")}`);
  if ((summary?.blockedExternalRequests ?? []).length) throw new Error(`Authenticated evidence attempted external network access: ${summary.blockedExternalRequests.join(" | ")}`);
  if ((summary?.captures ?? []).some((capture) => capture.horizontalOverflow === true)) throw new Error("Authenticated evidence contains a viewport with horizontal overflow.");
  if (!String(summary?.browser ?? "").startsWith("Chromium ")) throw new Error("Authenticated evidence is missing Chromium version metadata.");
  return true;
}
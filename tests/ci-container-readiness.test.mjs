import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workflowPath = ".github/workflows/ci.yml";
const dockerfilePath = "Dockerfile";
const dockerignorePath = ".dockerignore";
const coolifyDocPath = "docs/coolify-deployment-readiness.md";
const cicdStatusPath = "docs/ci-cd/CURRENT_CICD_STATUS.md";
const roadmapPath = "docs/production-readiness-roadmap.md";

test("CI workflow runs guardrails, install, typecheck, build, test, and container build without deploy", async () => {
  const workflow = await readFile(workflowPath, "utf8");

  const requiredPhrases = [
    "workflow_dispatch:",
    "permissions:",
    "contents: read",
    "Repository guardrails",
    "node --test tests/ci-container-readiness.test.mjs",
    "npm ci",
    "npm run typecheck",
    "npm run build",
    "npm test",
    "image: postgres:17",
    "POSTGRES_HOST_AUTH_METHOD: trust",
    "RUNTIME_POSTURE_TEST_DATABASE_URL",
    "RUNTIME_POSTURE_TEST_CONFIRM: disposable-only",
    "docker build --pull --tag swooshz-platform:ci .",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(workflow, new RegExp(escapeRegExp(phrase), "i"));
  }

  assert.match(workflow, /needs:\s*guardrails/i);
  assert.doesNotMatch(workflow, /deploy|kubectl|coolify.*webhook|ssh |scp |rsync |docker push|gh release/i);
  assert.doesNotMatch(workflow, /\$\{\{\s*secrets\.[A-Z0-9_]+\s*\}\}/i);
  assert.doesNotMatch(workflow, /gitleaks-action|GITLEAKS_LICENSE/i);
});

test("Dockerfile defines a production-safe runtime image and healthcheck", async () => {
  const dockerfile = await readFile(dockerfilePath, "utf8");

  const requiredPhrases = [
    "FROM node:22-bookworm-slim AS build",
    "RUN npm ci",
    "RUN npm run build",
    "RUN npm prune --omit=dev",
    "FROM node:22-bookworm-slim AS runtime",
    "ENV NODE_ENV=production",
    "ENV PLATFORM_HTTP_HOST=0.0.0.0",
    "ENV PLATFORM_HTTP_PORT=3000",
    "USER node",
    "EXPOSE 3000",
    "HEALTHCHECK",
    "/healthz",
    "CMD [\"npm\", \"run\", \"platform:start\"]",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(dockerfile, new RegExp(escapeRegExp(phrase), "i"));
  }

  assert.doesNotMatch(dockerfile, /DATABASE_URL=|SESSION_SECRET=|AUTH_CLIENT_SECRET=|COPY \. \./);
  assert.doesNotMatch(dockerfile, /db:migrate|platform:seed-internal-access|platform:sqag-smoke-readiness/);
});

test(".dockerignore excludes secrets local files logs caches and private design exports", async () => {
  const dockerignore = await readFile(dockerignorePath, "utf8");

  const requiredEntries = [
    ".git",
    "node_modules",
    ".env",
    ".env.*",
    "_logs",
    ".tmp",
    "coverage",
    "dist",
    "backups",
    "exports",
    "screenshots",
    "stitch_*",
  ];

  for (const entry of requiredEntries) {
    assert.match(dockerignore, new RegExp(`^${escapeRegExp(entry)}$`, "im"));
  }
});

test("Coolify readiness doc keeps deployment disabled and records exact public origins", async () => {
  const doc = await readFile(coolifyDocPath, "utf8");

  const requiredPhrases = [
    "# Coolify Deployment Readiness",
    "does not deploy",
    "shared Hostinger/Coolify foundation is not created yet",
    "shared across Swooshz Platform, Swooshz Quote Auto Generator, and SKR",
    "Container build command",
    "Container smoke command",
    "Expected runtime port",
    "GET /healthz",
    "Dockerfile",
    ".dockerignore",
    "secret names",
    "https://swooshz.com",
    "https://swooshz.com/api/platform/auth/callback",
    "staging/internal-alpha",
    "production",
    "Production deploy requires manual approval",
    "Production should not deploy blindly on every push",
    "This document is not hosted evidence",
    "not a production readiness claim",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(doc, new RegExp(escapeRegExp(phrase), "i"));
  }

  assertSecretNamesOnly(doc, { allowApprovedPublicOrigins: true });
  assert.doesNotMatch(doc, /coolify deploy --|docker push|ssh .*@|dns record type/i);
});

test("CI/CD status doc records current checks and disabled deployment state", async () => {
  const doc = await readFile(cicdStatusPath, "utf8");

  const requiredPhrases = [
    "# Current CI/CD Status",
    "Deployment status: disabled/planning-only",
    "pull requests, pushes to `main`, and manual `workflow_dispatch`",
    "Repository guardrails",
    "`npm ci`",
    "`npm run typecheck`",
    "`npm run build`",
    "`npm test`",
    "`docker build --pull --tag swooshz-platform:ci .`",
    "built but not pushed or deployed",
    "Current CI requires no repository secrets",
    "staging/internal-alpha",
    "production",
    "Production deployment must require manual approval",
    "Do not deploy",
    "Do not claim production readiness",
    "Privacy-Safe Observability Baseline",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(doc, new RegExp(escapeRegExp(phrase), "i"));
  }

  assertSecretNamesOnly(doc);
});

test("production roadmap records only repo-side CI/container readiness and keeps hosted gates unchecked", async () => {
  const roadmap = await readFile(roadmapPath, "utf8");

  assert.match(roadmap, /Repo-side CI and container readiness/i);
  assert.match(roadmap, /\.github\/workflows\/ci\.yml/i);
  assert.match(roadmap, /Docker image build without push\/deploy/i);
  assert.match(roadmap, /docs\/coolify-deployment-readiness\.md/i);
  assert.match(roadmap, /- \[ \] Coolify Platform app created/i);
  assert.match(roadmap, /- \[ \] Hosted Google OAuth client\/redirect configured outside repo/i);
  assert.match(roadmap, /- \[ \] Platform entitlement and launch-token flow smoke tested/i);
  assert.match(roadmap, /- \[ \] Hosted visual evidence complete/i);
  assert.match(roadmap, /- \[ \] Restore test evidence/i);
  assert.match(roadmap, /- \[ \] Final launch checklist/i);
  assert.doesNotMatch(roadmap, /- \[x\] Coolify Platform app created/i);
  assert.doesNotMatch(roadmap, /- \[x\] Hosted Google OAuth client\/redirect configured outside repo/i);
  assert.doesNotMatch(roadmap, /- \[x\] Platform entitlement and launch-token flow smoke tested/i);
});

function assertSecretNamesOnly(value, options = {}) {
  assert.doesNotMatch(value, /sk-[A-Za-z0-9]{20,}/);
  assert.doesNotMatch(value, /AKIA[0-9A-Z]{16}/);
  assert.doesNotMatch(value, /-----BEGIN [A-Z ]*PRIVATE KEY-----/);
  assert.doesNotMatch(value, /postgres(?:ql)?:\/\/[^\s>]+@/i);
  assert.doesNotMatch(value, /ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/);
  assert.doesNotMatch(value, /access_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(value, /refresh_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(value, /id_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(value, /auth[_-]?code[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(value, /cookie[=:][A-Za-z0-9._-]{12,}/i);
  const valueWithoutApprovedOrigins = options.allowApprovedPublicOrigins
    ? value.replaceAll("https://swooshz.com", "<platform-origin>")
        .replaceAll("https://www.swooshz.com", "<platform-redirect-origin>")
        .replaceAll("https://quote.swooshz.com", "<sqag-origin>")
    : value;
  assert.doesNotMatch(valueWithoutApprovedOrigins, /https?:\/\/(?!<)[^\s>)]+/i);
  assert.doesNotMatch(value, /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

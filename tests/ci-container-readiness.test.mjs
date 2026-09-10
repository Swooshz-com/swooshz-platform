import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import test from "node:test";

const workflowPath = ".github/workflows/ci.yml";
const roleCollapseRunnerPath = "scripts/run-disposable-role-collapse-postgres-tests.mjs";
const dockerfilePath = "Dockerfile";
const dockerignorePath = ".dockerignore";
const coolifyDocPath = "docs/coolify-deployment-readiness.md";
const cicdStatusPath = "docs/ci-cd/CURRENT_CICD_STATUS.md";
const roadmapPath = "docs/production-readiness-roadmap.md";

test("CI workflow runs guardrails, install, typecheck, build, test, and container build without deploy", async () => {
  const workflow = await readFile(workflowPath, "utf8");
  const roleCollapseRunner = await readFile(roleCollapseRunnerPath, "utf8");

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
    "npm run test:disposable-runtime-postgres",
    "npm run test:disposable-role-collapse-postgres",
    "codex-platform127-pg17",
    "POSTGRES_HOST_AUTH_METHOD=trust",
    "postgres:17",
    "npm run test:disposable-runtime-postgres",
    "docker build --pull --tag swooshz-platform:ci .",
  ];

  assert.match(roleCollapseRunner, /codex-platform153-role-collapse-pg17/i);
  assert.match(roleCollapseRunner, /postgres:17/i);
  assert.match(roleCollapseRunner, /POSTGRES_HOST_AUTH_METHOD=trust/i);

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

  assert.match(dockerfile, /new URL\(process\.env\.PLATFORM_PUBLIC_BASE_URL\)\.host/i);
  assert.match(dockerfile, /require\(['"]node:http['"]\)/i);
  assert.match(dockerfile, /http\.get\(/i);
  assert.match(dockerfile, /hostname:\s*['"]127\.0\.0\.1['"]/i);
  assert.match(dockerfile, /path:\s*['"]\/healthz['"]/i);
  assert.match(dockerfile, /headers:\s*\{\s*Host:\s*host\s*\}/i);
  assert.match(dockerfile, /response\.statusCode\s*<\s*200|response\.statusCode\s*>=\s*300/i);
  assert.doesNotMatch(dockerfile, /fetch\s*\(/i);
  assert.doesNotMatch(dockerfile, /DATABASE_URL=|SESSION_SECRET=|OIDC_CLIENT_SECRET=|COPY \. \./);
  assert.doesNotMatch(dockerfile, /db:migrate|platform:seed-internal-access|platform:sqag-smoke-readiness/);
});

test("Docker healthcheck preserves the configured public Host over loopback node:http transport", async () => {
  const dockerfile = await readFile(dockerfilePath, "utf8");
  const healthcheckScript = extractHealthcheckScript(dockerfile);
  const observedHosts = [];
  let responseStatusCode = 204;
  const server = createServer((request, response) => {
    observedHosts.push(request.headers.host);
    response.writeHead(responseStatusCode);
    response.end();
  });
  const port = await listenOnLoopback(server);

  try {
    const environment = {
      PLATFORM_PUBLIC_BASE_URL: "https://platform-alpha.swooshz.com",
      PLATFORM_HTTP_PORT: String(port),
    };
    const success = await runHealthcheck(healthcheckScript, environment);

    assert.equal(success.code, 0);
    assert.equal(success.signal, null);
    assert.deepEqual(observedHosts, ["platform-alpha.swooshz.com"]);

    responseStatusCode = 503;
    const failure = await runHealthcheck(healthcheckScript, environment);

    assert.notEqual(failure.code, 0);
    assert.equal(failure.signal, null);
    assert.deepEqual(observedHosts, [
      "platform-alpha.swooshz.com",
      "platform-alpha.swooshz.com",
    ]);
  } finally {
    await closeServer(server);
  }
});

test("Docker healthcheck fails when loopback transport is refused", async () => {
  const dockerfile = await readFile(dockerfilePath, "utf8");
  const healthcheckScript = extractHealthcheckScript(dockerfile);
  const server = createServer();
  const port = await listenOnLoopback(server);
  await closeServer(server);

  const failure = await runHealthcheck(healthcheckScript, {
    PLATFORM_PUBLIC_BASE_URL: "https://platform-alpha.swooshz.com",
    PLATFORM_HTTP_PORT: String(port),
  });

  assert.notEqual(failure.code, 0);
  assert.equal(failure.signal, null);
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
  assert.match(roadmap, /- \[ \] Hosted Auth0 passwordless email OTP connection\/redirect configured outside repo/i);
  assert.match(roadmap, /- \[ \] Platform entitlement and launch-token flow smoke tested/i);
  assert.match(roadmap, /- \[ \] Hosted visual evidence complete/i);
  assert.match(roadmap, /- \[ \] Restore test evidence/i);
  assert.match(roadmap, /- \[ \] Final launch checklist/i);
  assert.doesNotMatch(roadmap, /- \[x\] Coolify Platform app created/i);
  assert.doesNotMatch(roadmap, /- \[x\] Hosted Auth0 passwordless email OTP connection\/redirect configured outside repo/i);
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

function extractHealthcheckScript(dockerfile) {
  const match = dockerfile.match(/^HEALTHCHECK .* CMD node -e "([^"]+)"$/m);
  assert.ok(match, "Dockerfile healthcheck must expose an executable node -e script");
  return match[1];
}

function listenOnLoopback(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      assert.ok(address && typeof address === "object");
      resolve(address.port);
    });
  });
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

function runHealthcheck(script, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["-e", script], {
      env,
      stdio: ["ignore", "ignore", "ignore"],
    });
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

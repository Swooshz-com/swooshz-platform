# Swooshz Platform Public Website Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign the Swooshz Platform public website and provider-backed access entry into a warm, premium AI solutions platform surface while preserving every authentication, session, security, product, and protected-shell boundary.

**Architecture:** Add a focused `platform-public-shell.ts` module with public renderers, navigation, footer, inline SVG helpers, and public-only CSS. Keep `platform-shell.ts` and its protected `/app` and `/app/admin` document/style system intact, preserving existing exported renderer names through compatibility wrappers.

**Tech Stack:** Framework-free server-rendered TypeScript HTML, inline CSS/SVG, small inline browser scripts, existing Node adapter, Node test runner, and Playwright CLI.

## Global Constraints

- Redesign only `/`, `/solutions`, `/resources`, `/resources/platform-launch-boundaries`, `/about`, `/contact`, `/request-access`, `/login`, shared public navigation/footer, and public visual states.
- Do not redesign `/app` or `/app/admin`; preserve their DOM, workflows, API calls, visual structure, and tests.
- Preserve provider-backed authentication, `/api/platform/auth/start`, signed-out notice behavior, `/app` continuation, sessions, cookies, CSRF, Origin/Referer enforcement, workspace authorization, entitlements, launch tokens, SQAG handoff, memberships, database code, migrations, readiness logic, and environment handling.
- Use no React, Next.js, Vue, Tailwind, bundler, client router, external fonts, runtime CDNs, analytics, external images, or component libraries.
- Swooshz is an AI solutions platform. AutoQuote is currently exhibition/interior-design-first, with future expansion described without fabricated availability claims. Seozilla is separate, whitelabel, vendor-pending, and unavailable.
- Use `Swooshz Quote Auto Generator` and app key `sqag`; never add `kqag`, `KQAG_*`, or `SAQG_*`.
- No billing, pricing, plan, upgrade, credits, checkout, subscription, public signup, fake forms, fake contact details, testimonials, metrics, customer names, authors, dates, addresses, or hosted-readiness claims.
- Meet practical accessibility: landmarks, one `h1`, visible focus, keyboard-operable mobile navigation, `aria-expanded`/`aria-controls`, reduced motion, touch-sized controls, and no horizontal overflow.

---

### Task 1: Add public renderer regression and copy-safety tests

**Files:**
- Modify: `tests/platform-shell.test.mjs`
- Modify: `tests/http-node-adapter.test.mjs`
- Preserve: `tests/http-route-contracts.test.mjs`

**Interfaces:** Existing renderer exports and route adapter responses remain the test surface.

- [ ] Replace obsolete expectations for placeholder/editorial-review wording, visible text icon placeholders, and launch-planning footer copy with assertions for AI-solutions positioning, AutoQuote exhibition/interior-design-first language, provider-backed access, separate-app ownership, and Seozilla vendor-pending status.
- [ ] Add public navigation assertions for a menu button with `aria-expanded="false"`, `aria-controls`, semantic navigation, visible focus selectors, and decorative inline SVGs marked `aria-hidden="true"` and `focusable="false"`.
- [ ] Assert resources link only to `/resources/platform-launch-boundaries`; future topic cards are inert/non-linked; article has section navigation and no author/date metadata.
- [ ] Preserve all `/app` and `/app/admin` assertions for API references, DOM IDs, CSRF actions, admin controls, modal keyboard behavior, safe activity labels, and signed-out redirect behavior.
- [ ] Update only stale public copy assertions in the Node adapter tests; keep status, content type, no-store headers, route paths, and zero-session/CSRF call-count checks unchanged.
- [ ] Run `npm run build` and the three focused test files. The new public-copy assertions should fail until the renderer is replaced; protected and route-contract assertions must continue to pass.

---

### Task 2: Implement the isolated public renderer and visual system

**Files:**
- Create: `src/http/platform-public-shell.ts`
- Modify: `src/http/platform-shell.ts`
- Inspect only: `src/http/node-adapter.ts`, `src/http/route-contracts.ts`, `src/index.ts`

**Interfaces:** Export the same pure renderer signatures: `renderLandingPage`, `renderSolutionsPage`, `renderResourcesPage`, `renderResourceArticlePage`, `renderAboutPage`, `renderContactPage`, `renderRequestAccessPage`, `renderLoginPage`, and `renderAuthErrorPage`.

- [ ] Define `.public-site` as the root scope and create a separate public document wrapper. Use warm ivory/cream surfaces, deep charcoal ink, muted terracotta, soft olive, restrained borders, and system fonts so protected-shell styles remain untouched.
- [ ] Build the slim ivory header shown in the approved mockup: Swooshz wordmark, `Overview`, `Solutions`, `Resources`, `About`, and one `Access workspace` CTA. Add a real button-based mobile menu with `aria-expanded`, `aria-controls`, Escape handling, focus restoration, and a no-JavaScript visible fallback.
- [ ] Build the shared footer from existing routes only, with a concise AI-solutions-platform statement and approved-workspace access note. Do not render unavailable legal/status items as fake controls.
- [ ] Build `/` with `One trusted place for your Swooshz tools.`, access/explore CTAs, account -> workspace -> approved application artwork, capability cards, current AutoQuote highlight, quiet Seozilla unavailable state, access steps, and final CTA.
- [ ] Build `/solutions` around the current AutoQuote product and Platform access layer without fabricated screenshots or workflow data. Present Seozilla as a separate whitelabel offering that is vendor-pending/unavailable.
- [ ] Build `/resources` as an honest editorial index with one linked article and inert future topics. Build the article with a 680-760px reading column, section navigation, CSS/SVG boundary diagram, factual callouts, and no fake metadata.
- [ ] Build `/about`, `/contact`, and `/request-access` around AI solutions, access ownership, sponsor/admin guidance, approved provider accounts, and informational-only access requirements. Do not create forms, intake claims, or invented contact details.
- [ ] Build `/login` as a premium secure entry with provider CTA to `/api/platform/auth/start`, workspace-approval explanation, existing `/app` continuation, existing `signedOut=1` notice, and no password/signup/false SSO choices. Keep auth-error retry/back behavior safe.
- [ ] Add restrained hover/focus/connector/hero effects, scoped to `.public-site`, with reduced-motion fallbacks. Use inline SVG icons and CSS artwork; no visible text placeholders.

---

### Task 3: Preserve route wiring and protected shell boundaries

**Files:**
- Modify: `src/http/platform-shell.ts` only for compatibility delegation
- Verify: `src/http/node-adapter.ts`, `src/http/route-contracts.ts`
- Test: `tests/platform-shell.test.mjs`, `tests/http-route-contracts.test.mjs`, `tests/http-node-adapter.test.mjs`

- [ ] Keep `platform-shell.ts` as the stable import surface by delegating the nine public renderers to `platform-public-shell.ts` without changing names or return types.
- [ ] Verify each public Node adapter branch still returns `htmlResponse(200, renderer(), noStoreHeaders())`; do not alter auth/API branches.
- [ ] Compare `/app` and `/app/admin` renderer bodies and selectors before/after. Only compatibility plumbing may differ; protected markup, inline scripts, API strings, and styles must remain unchanged.
- [ ] Run the focused build and test command and require all public, route-contract, protected-shell, and auth behavior assertions to pass.

---

### Task 4: Run local browser QA and capture evidence

**Files:**
- Create locally only: `output/playwright/final/*.png`
- Do not stage: screenshots or temporary server harness files

- [ ] Start a local in-memory Node adapter harness on a free localhost port without a database, provider credentials, live handoff, or hosted service.
- [ ] Capture `home`, `solutions`, `resources`, `resource-article`, `about`, `contact`, `request-access`, and `login` at exact 1440x900 and 390x844 viewports.
- [ ] Check console errors, broken links, overflow at 1440/768/390/320px, mobile menu keyboard behavior, focus visibility, signed-out notice, login URL behavior, no forms, no fake controls, and no SKR/billing/placeholder copy bleed.
- [ ] Spot-check `/app` and `/app/admin` at desktop/mobile widths for unchanged DOM/API references and initial safe states; do not redesign them.

---

### Task 5: Run validation and documentation closure

**Files:**
- Modify only if required: `tests/platform-shell.test.mjs`, `tests/http-node-adapter.test.mjs`, and narrow frontend docs whose obsolete visual assumptions are explicitly contradicted by the implementation
- Do not modify: auth/session/security/backend/database/readiness implementation files

- [ ] Run `npm ci`, `npm run typecheck`, `npm run build`, the focused frontend shell/route/adapter tests, full `npm test`, local `docker build -t swooshz-platform-public-redesign .`, and `git diff --check`.
- [ ] Review the diff for public-only scope, no secrets or private values, no backend/security changes, no app/admin redesign, no generated screenshot staging, and no readiness overclaim.
- [ ] Search changed files for `TBD`, `TODO`, fake metadata, `kqag`, `KQAG_`, `SAQG_`, `SKR`, pricing/billing claims, placeholder copy, and external runtime dependencies. Resolve any result before commit.

---

### Task 6: Commit, push, open, and verify the PR

**Files:** Stage only reviewed source, tests, and narrow docs; exclude `output/`.

- [ ] Confirm branch `luna/public-website-redesign`, base SHA `567fa25003be840198bea1edc663b46aede11b2f`, and clean staged diff.
- [ ] Commit with `Redesign Swooshz Platform public website`.
- [ ] Push the non-main branch with `git push -u origin luna/public-website-redesign`.
- [ ] Run `gh auth status` and `gh api user --jq .login`; stop if the active account is not the intended GitHub user.
- [ ] Open one non-draft PR titled `Redesign Swooshz Platform public website` with exact base/head SHAs, routes, files, design/copy/accessibility decisions, absolute screenshot paths, exact validation results, untouched app/admin/backend/security confirmation, production-readiness-false confirmation, and remaining follow-up scope.
- [ ] Check PR CI with local `gh pr checks`; if checks fail, make at most two targeted fixes and re-check before reporting.

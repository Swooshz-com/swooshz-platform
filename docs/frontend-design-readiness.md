# Swooshz Platform Frontend Design Readiness

production readiness is not approved. This document is a readiness and design gate for the Swooshz Platform frontend. It is not implementation proof, not hosted evidence, and not approval for deployment or launch.

Goal: define the target frontend structure and the evidence required before Codex ports broad frontend work. The user will use Google Stitch to create the approved design reference. Codex must keep the current platform ownership boundaries, preserve existing security behavior, and avoid turning planning artifacts into fake product implementation.

Platform owns auth, provider identities, sessions, workspaces, roles/memberships, app registry, entitlements, launch checks/tokens, audit/activity events, hosted runbooks/operator decisions, public Swooshz website/content planning, and future billing/credits only when approved. Platform must not own product workflow/runtime data.

SQAG is a separate product app launched from Platform, not embedded in Platform. SKR is a separate website/app and must not be mixed into Swooshz Platform. SEO/GEO/Seozilla integration is not confirmed; it remains design/planning only until explicitly approved.

## Current Frontend Surface Reviewed

Reviewed source and tests:

- `src/http/platform-shell.ts`: renders the current public sign-in page, authenticated app launcher, workspace admin shell, add-member form, pending approvals, member actions modal, entitlements, activity preview, loading/error/empty states, and inline CSS/JS shell behavior.
- `src/http/route-contracts.ts` and `src/http/node-adapter.ts`: define and wire the current route set for `/`, `/app`, `/app/admin`, `/healthz`, auth, session, workspace admin, entitlement, launch, and logout routes.
- `tests/platform-shell.test.mjs`, `tests/http-route-contracts.test.mjs`, `tests/http-admin-routes.test.mjs`, `tests/auth-http-handlers.test.mjs`, and related tests: guard current route coverage, auth/login/callback failure behavior, admin/member/activity behavior, CSRF/origin protection, and privacy-safe output.
- `docs/production-readiness-roadmap.md`, `docs/internal-alpha-design-direction.md`, `docs/internal-alpha-platform-contract.md`, `docs/internal-alpha-go-no-go-checklist.md`, and hosted/internal-alpha runbooks: establish the current internal-alpha shell, boundaries, and launch blockers.

Current implementation evidence is limited to the existing shell and tests. Design docs are not implemented UI. Local visual success is not hosted evidence.

## Target Frontend Structure

The target Swooshz Platform frontend includes these surfaces. This list is a planning baseline for Stitch and future implementation, not a claim that the routes already exist.

- Public Swooshz website: home, product/solution positioning, about, trust/security copy, and contact/request-access paths.
- Blog/resources: public index and article detail surface. A static/Git-backed blog is acceptable for Phase 1 if the publishing workflow is reviewed and evidence-gated.
- Login/access states: provider-backed login, access denied/not approved, callback failure, session expired/logout, and friendly no-public-signup states.
- Authenticated workspace/product portal: workspace home, apps/product launcher, entitlement denial/unavailable states, account/session-safe copy, and audit/activity preview.
- Customer workspace admin: members, pending approvals, add member, member action menus/modals, loading/error/empty states, and role-safe copy.
- Swooshz internal admin/content admin concept: internal operator overview, public site content management, Blog/resources management, blog editor planning, products/apps admin placeholder, workspace/entitlement admin placeholder, and internal audit/activity. This is concept/planning only unless explicitly scoped later.

## Google Stitch Design Gate

Google Stitch is the approved design reference source before broad frontend implementation.

- Codex must not freestyle a broad visual redesign.
- Codex must port approved Stitch designs only after user approval.
- Codex must preserve existing auth, membership, DB, entitlement, launch, and audit logic while porting approved UI.
- Codex must compare implementation screenshots against approved Stitch screenshots until parity is acceptable.
- Codex must keep current route, auth, session, CSRF/origin, membership, entitlement, launch-token, and audit behavior intact unless a separate implementation task explicitly changes them.
- Codex must not introduce fake backend flows, fake signup, fake product runtime data, ecommerce, checkout, booking, payment, or product workflow screens.
- Codex must not include secrets, private customer data, raw IDs, cookies, tokens, provider console values, private staff identities, screenshots with private data, table exports, or backup exports in design assets/docs.
- Codex must keep SQAG as a separate app launch from Platform, and must not mix SKR into Swooshz Platform.
- Codex must keep SEO/GEO/Seozilla as planning-only. Seozilla-assisted publishing is Phase 3 and blocked until vendor confirms workflow.

## Evidence And Ticking Rules

Do not tick checklist items without evidence.

Evidence can be:

- approved Stitch screenshot/design reference.
- implemented route/component.
- screenshot comparison.
- deterministic test.
- local visual review note.
- hosted smoke after deployment.

Evidence limits:

- Local visual success is not hosted evidence.
- Design docs are not implemented UI.
- Static/Git-backed blog is acceptable for Phase 1.
- Internal content admin is concept/planning only unless explicitly scoped later.
- Seozilla-assisted publishing is Phase 3 and blocked until vendor confirms workflow.
- Hosted smoke can be recorded only after a future approved deployment; this document does not approve deployment.
- A checked item must name the evidence type and point to the source, such as PR number/commit, test file/command, approved Stitch screenshot, screenshot comparison, local visual note, or hosted smoke note.

## Public Website Checklist

- [ ] Home.
  Evidence required: approved Stitch design, implemented route/component, screenshot comparison, deterministic test, and local visual note; hosted smoke after deployment before launch.
- [ ] Solutions/products.
  Evidence required: approved Stitch design and copy review that separates Platform, SQAG, and SKR without embedding product workflow/runtime data.
- [ ] About.
  Evidence required: approved Stitch design, implemented route/component, deterministic route/content test, and copy review.
- [ ] Contact/request access.
  Evidence required: approved Stitch design and implementation that does not create fake signup, fake request flow, secrets intake, or unapproved backend workflow.
- [ ] Blog/resources index.
  Evidence required: approved Stitch design, static/Git-backed blog or approved CMS plan, deterministic content route/test, and local visual note.
- [ ] Blog article detail.
  Evidence required: approved Stitch design, static/Git-backed article detail route or approved CMS plan, deterministic article rendering test, and local visual note.

## Auth Checklist

- [ ] Login.
  Evidence required: approved Stitch design, implemented provider-backed login route/state, deterministic shell/auth test, and screenshot comparison.
- [ ] Access denied/not approved.
  Evidence required: approved Stitch design, friendly denial copy, deterministic auth/member denial test, and screenshot comparison.
- [ ] Callback failure.
  Evidence required: approved Stitch design, generic failure copy with safe reference/category behavior, deterministic callback failure test, and screenshot comparison.
- [ ] Session expired/logout.
  Evidence required: approved Stitch design, POST-only logout/session behavior preserved, deterministic logout/session test, and screenshot comparison.

## Portal Checklist

- [ ] Workspace home.
  Evidence required: approved Stitch design, implemented workspace/product portal route/component, deterministic session-context test, and screenshot comparison.
- [ ] Apps/product launcher.
  Evidence required: approved Stitch design, implemented app registry/launcher UI, entitlement-aware deterministic tests, and screenshot comparison.
- [ ] Product unavailable/entitlement denied.
  Evidence required: approved Stitch design, friendly denial copy, deterministic entitlement/access tests, and screenshot comparison.
- [ ] Activity/audit preview.
  Evidence required: approved Stitch design, privacy-minimized activity implementation, deterministic audit/activity test, and screenshot comparison.

## Customer Workspace Admin Checklist

- [ ] Members list.
  Evidence required: approved Stitch design, implemented member list route/component, owner/admin authorization test, and screenshot comparison.
- [ ] Pending approvals.
  Evidence required: approved Stitch design, implemented pending approvals route/component, deterministic approval list/revoke tests, and screenshot comparison.
- [ ] Add member modal.
  Evidence required: approved Stitch design, implemented add-member UI that preserves pending-approval behavior, deterministic add-member tests, and screenshot comparison.
- [ ] Member action menu/modal.
  Evidence required: approved Stitch design, implemented role/disable/reactivate/remove controls, deterministic member action tests, and screenshot comparison.
- [ ] Loading/error/empty states.
  Evidence required: approved Stitch design, deterministic UI tests or local visual notes for loading/error/empty states, and screenshot comparison.

## Swooshz Internal Admin/Content Admin Concept Checklist

- [ ] Internal overview.
  Evidence required: approved Stitch concept and explicit future implementation approval before code.
- [ ] Public site content management.
  Evidence required: approved Stitch concept, content ownership model, and future implementation approval before code.
- [ ] Blog/resources management.
  Evidence required: approved Stitch concept and static/Git-backed or approved CMS workflow decision.
- [ ] Blog editor.
  Evidence required: approved Stitch concept, review-before-publish content copy, and future implementation approval before code.
- [ ] Products/apps admin placeholder.
  Evidence required: approved Stitch concept that does not create product workflow/runtime screens or fake product data.
- [ ] Workspace/entitlement admin placeholder.
  Evidence required: approved Stitch concept that preserves existing entitlement and audit logic.
- [ ] Internal audit/activity.
  Evidence required: approved Stitch concept, privacy-safe audit copy, and future implementation approval before code.

## Responsive/Mobile Checklist

- [ ] Public home.
  Evidence required: approved Stitch mobile screenshot, implemented responsive behavior, screenshot comparison, and local visual note.
- [ ] Blog index/article.
  Evidence required: approved Stitch mobile screenshot, implemented responsive behavior, screenshot comparison, and local visual note.
- [ ] Login.
  Evidence required: approved Stitch mobile screenshot, implemented responsive behavior, keyboard/focus check, and local visual note.
- [ ] Portal home.
  Evidence required: approved Stitch mobile screenshot, implemented responsive behavior, screenshot comparison, and local visual note.
- [ ] Workspace admin members.
  Evidence required: approved Stitch mobile screenshot, implemented responsive table/control behavior, screenshot comparison, and local visual note.
- [ ] Activity log.
  Evidence required: approved Stitch mobile screenshot, implemented privacy-safe activity layout, screenshot comparison, and local visual note.
- [ ] Internal admin overview.
  Evidence required: approved Stitch mobile concept and future implementation approval before code.

## Accessibility Checklist

- [ ] Keyboard navigation.
  Evidence required: implemented keyboard path review, deterministic test where practical, and local visual note.
- [ ] Focus states.
  Evidence required: approved Stitch focus spec, implemented visible focus states, and screenshot/local visual evidence.
- [ ] Semantic headings.
  Evidence required: heading audit for each implemented route and deterministic markup test where practical.
- [ ] Form labels/errors.
  Evidence required: labels and safe validation/error copy for every implemented form, plus deterministic tests where practical.
- [ ] Contrast.
  Evidence required: approved Stitch color tokens, contrast review, and screenshot/local visual evidence.

## Security/Privacy Copy Checklist

- [ ] No raw IDs/tokens/errors.
  Evidence required: deterministic tests and manual review proving UI avoids raw internal IDs, tokens, stack traces, provider payloads, cookies, database URLs, and private product data.
- [ ] Friendly denial states.
  Evidence required: approved Stitch designs, deterministic denial tests, and copy review that avoids user/workspace enumeration.
- [ ] Workspace-approved access copy.
  Evidence required: login and denial copy that states workspace approval is required without offering public signup or fake access paths.
- [ ] Review-before-publish content copy.
  Evidence required: approved content-admin concept showing draft/review/publish language only; no unapproved CMS, Seozilla, SEO/GEO, or automated publishing integration.

## Non-Goals For This Gate

- Do not deploy.
- Do not configure DNS.
- Do not configure real OAuth values.
- Do not add secrets.
- Do not ask the user to paste secrets.
- Do not integrate hosted KQAG/SQAG launch.
- Do not integrate SEO/GEO/Seozilla.
- Do not reintroduce local/demo/fallback business-state behavior.
- Do not claim production readiness.
- Do not broadly redesign implementation unless an approved Stitch design pack is provided and explicitly approved.
- Do not move product workflow/runtime data into Platform.

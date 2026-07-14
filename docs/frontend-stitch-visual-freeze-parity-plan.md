# Frontend Stitch Visual Freeze Parity Plan

> Product-direction notice (2026-07-14): SEO/GEO/Seozilla is retired. Any two-product or vendor-pending material below is historical design-study context and must not be implemented. The current customer-facing Platform has one product: Swooshz Quote Auto Generator.

Production readiness is not approved. This document is a frontend implementation plan and parity checklist for the approved Stitch visual pack. It does not implement the frontend, approve hosted execution, approve production copy, or replace the existing Platform security and product contracts.

The latest Stitch pack is the visual/layout freeze candidate only. During this planning PR, the local Stitch pack was inspected without committing screenshots, source paths, or private design assets. The required 34 screen directories were present. Raw Stitch copy is not production copy and must be corrected before screenshot parity is judged.

## Source Of Truth

- Visual/layout reference: latest approved Stitch pack, 34 screens, desktop and mobile.
- Product and security source of truth: existing Platform docs, route contracts, services, and tests.
- Copy source of truth: this document's canonical copy override rules plus approved future copy review.
- Implementation source of truth: future scoped frontend PRs only. This PR must not port broad frontend UI.

Codex must not freestyle redesign. Future implementation should match the approved Stitch layout, spacing, hierarchy, responsive behavior, and component composition, while applying the canonical copy corrections below.

## Product Boundaries

Platform owns auth, provider identities, sessions, workspaces, memberships, roles, app registry, entitlements, launch checks/tokens, audit/activity events, hosted runbooks/operator decisions, public website/content planning, and future billing/credits only when approved.

Platform must not own Swooshz Quote Auto Generator product workflow/runtime data. Swooshz Quote Auto Generator is a separate product app launched from Platform, not embedded in Platform. Quote workflow data, quote sessions, pricing references, generated artifacts, and product runtime state stay in the product app.

SKR is a separate website/app and must not be mixed into Swooshz Platform. SEO/GEO/Seozilla is unconfirmed and remains planning-only, coming soon, unavailable, or vendor workflow pending until a separate product contract approves it.

## 34-Screen Inventory

Each row below represents one desktop Stitch screen and one mobile Stitch screen. All 17 rows, across two breakpoints, are required for the 34-screen parity set.

| # | Surface | Desktop screen | Mobile screen | Implementation boundary |
| --- | --- | --- | --- | --- |
| 1 | Public homepage | `swooshz_homepage_desktop_freeze_final` | `swooshz_homepage_mobile_freeze_final` | Public website layout only; copy must be reviewed before production. |
| 2 | Solutions/products | `solutions_products_desktop_freeze_final` | `solutions_products_mobile_freeze_final` | Must separate Platform, Swooshz Quote Auto Generator, SKR, and unconfirmed SEO/GEO/Seozilla. |
| 3 | Blog/resources | `blog_resources_desktop_freeze_final` | `blog_resources_mobile_freeze_final` | Draft/placeholder content only until editorial approval. |
| 4 | Blog article detail | `blog_article_detail_desktop_freeze_final` | `blog_article_detail_mobile_freeze_final` | Draft article layout only; no fake authors, dates, metrics, case studies, or API examples. |
| 5 | About | `about_swooshz_desktop_freeze_final` | `about_swooshz_mobile_freeze_final` | Public company/story layout only; avoid unsupported claims. |
| 6 | Contact | `contact_desktop_freeze_final` | `contact_mobile_freeze_final` | Safe placeholder contact copy only; no fake private emails, phone numbers, or addresses. |
| 7 | Request access | `request_access_desktop_freeze_final` | `request_access_mobile_freeze_final` | Must not claim email-provider rejection unless implemented. |
| 8 | Login | `login_desktop_freeze_final` | `login_mobile_freeze_final` | Must preserve provider-backed auth flow and no public signup. |
| 9 | Access pending/status | `access_status_desktop_freeze_final` | `access_status_mobile_freeze_final` | Must stay access/status messaging only; no fake invitation delivery. |
| 10 | Portal home | `portal_home_desktop_freeze_final` | `portal_home_mobile_freeze_final` | Authenticated workspace/product portal; no product workflow data. |
| 11 | App launcher | `app_launcher_desktop_freeze_final` | `app_launcher_mobile_freeze_final` | Launches separate apps through existing entitlement and launch-token logic. |
| 12 | Product unavailable | `product_unavailable_desktop_freeze_final` | `product_unavailable_mobile_freeze_final` | Entitlement/access wording only; no billing or upgrade prompt unless approved. |
| 13 | Workspace members | `workspace_members_desktop_freeze_final` | `workspace_members_mobile_freeze_final` | Preserve owner/admin/member/pending access model and existing admin checks. |
| 14 | Pending approvals | `pending_approvals_desktop_freeze_final` | `pending_approvals_mobile_freeze_final` | Pending approval state only; do not imply sent email invitations. |
| 15 | Add member modal | `add_member_modal_desktop_freeze_final` | `add_member_modal_mobile_freeze_final` | Must preserve pending approval and provider-backed activation behavior. |
| 16 | Member actions | `member_actions_desktop_freeze_final` | `member_actions_mobile_freeze_final` | Workspace access actions only; no project/data-loss wording. |
| 17 | Activity/audit log | `activity_log_desktop_freeze_final` | `activity_log_mobile_freeze_final` | Safe generic audit events only; no fake production metadata. |

Inventory count: 17 surfaces x 2 breakpoints = 34 required screens.

## Public Site Screens

Public site parity covers homepage, solutions/products, Blog/resources, blog article detail, about, contact, request access, login, and access pending/status. The public pages may use draft placeholder content only when clearly marked in implementation planning. Production copy requires a separate review pass before launch.

Acceptable public Blog/resources topics:

- How Swooshz Platform launches workspace apps.
- Preparing workspace access before launch.
- Designing safer internal AI workflows.
- Quote workflow automation with Swooshz Quote Auto Generator.

Do not include fake authors, fake dates, fake case studies, fake metrics, unsupported performance claims, API-looking snippets, or production integration examples.

## Portal Screens

Portal parity covers portal home, app launcher, and product unavailable states. These screens must remain workspace/access surfaces. They must not show quote counts, quote histories, pricing files, client data, product runtime records, SEO/GEO analytics, Seozilla workflow data, or SKR content.

Swooshz Quote Auto Generator launches as a separate product app through Platform-owned access checks and launch-token logic. The visual implementation must preserve existing session, CSRF/origin, entitlement, and launch behavior.

## Access, Member, And Admin State Screens

Access/member/admin parity covers workspace members, pending approvals, add member modal, member actions, and activity/audit log. These screens must preserve existing owner/admin authorization, membership guardrails, pending approval activation, session revocation on removal, entitlement checks, audit appends, no-store responses, and privacy-minimized output.

Visible roles for the Stitch parity target are:

- Owner.
- Admin.
- Member.
- Pending.

Do not introduce Viewer or Editor as visible production copy unless a later product decision explicitly approves those roles for this frontend. This visible-copy rule does not change current backend contracts by itself.

## Canonical Copy Override Rules

These rules override raw Stitch copy before screenshot parity is judged.

1. Swooshz Quote Auto Generator:
   - SQAG means Swooshz Quote Auto Generator.
   - User-facing copy should use "Swooshz Quote Auto Generator" for the product name.
   - Do not use Split-Pane Auto Generator.
   - Do not use Structured Query Auto Generator.
   - Do not use query, data, vector, search, or data-lake language for this product.
   - State that Swooshz Quote Auto Generator is a separate app launched from Platform.
   - Keep quote workflow inside Swooshz Quote Auto Generator, not inside Platform.

2. SEO/GEO/Seozilla:
   - Keep SEO/GEO/Seozilla coming soon, unavailable, vendor workflow pending, or planning-only.
   - Do not present SEO/GEO/Seozilla as a live module.
   - Do not describe SEO/GEO/Seozilla as a confirmed advanced analytics suite.
   - Do not add SEO/GEO/Seozilla integration, app registration, entitlements, workflow screens, or production copy in this planning PR.

3. Product unavailable and entitlement denied:
   - Use entitlement/access wording.
   - Do not say "upgrade your plan" unless billing/plan upgrades are explicitly approved.
   - Prefer "Request access", "Return to apps", or "Contact workspace admin".
   - Do not imply payment, plan, trial countdown, or upgrade workflows until billing is approved.

4. Member/access flows:
   - Use visible roles Owner, Admin, Member, and Pending.
   - Avoid Viewer and Editor unless explicitly approved later.
   - Do not imply email invitation delivery unless implemented.
   - Do not reference projects, files, data loss, quote history, or product records during member removal.
   - Member removal copy should describe workspace access only.

5. Activity/audit log:
   - Use safe generic audit events only: Member added, Member removed, Role changed, App launch allowed, App launch denied, Login blocked for unapproved user.
   - Do not use fake exact production timestamps.
   - Do not use fake IPs, commit hashes, production API labels, billing/payment events, raw ids, or private-looking data.
   - Avoid "api" or "System Process" actor language unless the current audit implementation actually supports that actor model.

6. Request access/contact:
   - Do not claim free email providers are automatically rejected unless the current implementation enforces it.
   - Do not include fake private emails, phone numbers, addresses, provider console values, or private identities.
   - Use safe placeholder contact copy where needed.

7. Blog/resources:
   - Treat content as draft/placeholder until editorial approval.
   - Use safe Swooshz/Swooshz Quote Auto Generator topics listed in this document.
   - Do not include fake authors, dates, case studies, metrics, claims, snippets, private examples, or production integration instructions.

8. Security/privacy:
   - Preserve generic user-facing errors with support-safe reference behavior where implemented.
   - Do not render tokens, cookies, provider payloads, database URLs, private table data, raw launch tokens, secret values, or product runtime data.
   - Do not add local/demo/fallback business-state behavior.

## Screenshot Parity Acceptance Process

Future implementation PRs must apply canonical copy overrides before comparing screenshots. A screenshot that matches raw Stitch copy but violates this document fails parity.

Required parity process:

1. Map every implemented route/component state to the corresponding Stitch screen row above.
2. Apply the canonical copy override rules before the first screenshot comparison.
3. Capture desktop and mobile screenshots for every implemented surface.
4. Compare layout, spacing, hierarchy, component grouping, responsive behavior, and visual states against the approved Stitch reference.
5. Record any intentional deviations with source-of-truth reason, not taste preference.
6. Run deterministic tests for route/content/security boundaries before claiming parity.
7. Confirm no screenshots with private data, private paths, tokens, cookies, provider values, table exports, or product runtime data are committed.

Parity cannot be accepted from design docs alone. It requires implemented UI, screenshots, local visual review, deterministic tests, and later hosted smoke evidence after deployment is separately approved.

## Mobile Parity Expectations

Mobile parity is first-class, not a follow-up polish pass. Each mobile Stitch screen must map to an implemented narrow-viewport state with:

- Layout order matching the approved mobile reference unless a documented accessibility issue requires a change.
- Tap targets and form controls that remain usable on mobile.
- Text that wraps cleanly without overlapping controls.
- Auth, member, entitlement, launch, and audit states preserved.
- No desktop-only admin affordances that become hidden business logic on mobile.
- No new mobile routes, app embeds, product workflow widgets, or unsupported fallbacks.

## Implementation Checklist For The Future PR

- [ ] Create the frontend implementation scope from this parity plan.
- [ ] Preserve existing auth, provider identity, session, CSRF/origin, membership, entitlement, audit, and Swooshz Quote Auto Generator launch logic.
- [ ] Implement only Platform/public website surfaces, not product workflow/runtime data.
- [ ] Apply canonical copy override rules before screenshot comparison.
- [ ] Add deterministic route/content/security tests for implemented surfaces.
- [ ] Capture desktop and mobile local parity screenshots with sanitized data only.
- [ ] Leave hosted visual evidence unchecked until a reviewed hosted deployment exists.
- [ ] Leave production readiness unchecked until all launch gates pass.

## Non-Goals

- Do not implement the frontend redesign in this PR.
- Do not deploy.
- Do not configure DNS.
- Do not configure real OAuth values.
- Do not run live Platform-to-Swooshz Quote Auto Generator smoke.
- Do not integrate hosted Swooshz Quote Auto Generator launch.
- Do not integrate SEO/GEO/Seozilla.
- Do not add billing, upgrade, plan, payment, checkout, credits, or pricing behavior.
- Do not claim production readiness.
- Do not commit private screenshots, private paths, raw Stitch exports, tokens, cookies, provider values, secrets, table data, or product runtime data.

## Current Blockers

- Frontend implementation is not started by this PR.
- Production copy is not approved; raw Stitch copy must be corrected before parity.
- Public site and Blog/resources content remain draft/placeholder until approved.
- SEO/GEO/Seozilla remains unconfirmed and vendor workflow pending.
- Hosted visual evidence does not exist.
- Hosted OAuth/provider configuration remains unchecked.
- Hosted Platform deployment evidence remains unchecked.
- Hosted Swooshz Quote Auto Generator deployment and launch handoff evidence remain unchecked.
- Live Platform-to-Swooshz Quote Auto Generator smoke remains unchecked.
- Hosted monitoring, logging, alerting, backup/restore, and final go/no-go remain unchecked.

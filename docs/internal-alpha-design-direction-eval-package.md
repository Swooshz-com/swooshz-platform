# Swooshz Platform — design direction package (for external evaluation)

## 0. Evaluator brief

You are evaluating a **design direction and UX spec** (no code) for Swooshz Platform, an internal-alpha account/workspace/product-access hub built by a very small team whose current priority is backend/security correctness.

Evaluate against these required outputs:
1. Information architecture for: public website, internal login, product launcher, workspace management, team management, product entitlement management, activity/audit view — revised for a **two-product** platform.
2. Three visual directions (minimal enterprise / premium tech studio / warm approachable), each with page structure, component list, copy tone, strengths/risks.
3. A single recommended direction with justification, and a page-by-page spec implementable 1:1 by a coding agent.
4. Product launcher card concepts for both products; homepage positioning that does not over-focus on quotes; copy samples (hero, login, launcher, both cards).
5. Security/privacy UX requirements honoured throughout (Section 7).
6. Risks of the platform UI becoming too product-specific too early, with guardrails.

Hard constraints the spec must NOT violate (flag any violation you find):
- No billing, credits, public signup, password auth, 2FA, fallback auth, marketplace, heavy analytics, invitation email delivery, session-management UI, or theme toggles.
- Platform surfaces show ONLY access/entitlement/launch/status per product — never product-runtime data (quote counts, articles, site lists, CMS details, client payloads).
- Provider-backed OIDC login only; no public signup; mandated copy strings preserved verbatim (Section 6).
- No raw tokens, provider claims, cookies, OAuth values, DB URLs, secrets, or stack traces anywhere in UI.
- Framework-agnostic guidance only.

## 1. Context and fixed facts

- **Swooshz Platform** owns: auth (generic OIDC, Google first), users, sessions, workspaces, memberships, roles, per-workspace app entitlements, one-time launch handoff, audit events.
- **Products own their own runtime data.** Two products:
  1. **KQAG / SAQG** — quote automation (app key `kqag`, status `private_preview`). Quote sessions, pricing, files, history live inside KQAG.
  2. **SEO/GEO Content Automation** — white-label SEO/content product (no app key registered; placeholder `sgca` proposed). Content planning, AI article generation, CMS publishing, approvals, scheduling, site management, visibility reporting all live inside the product. (A reference product supplied by the owner was used as category inspiration only; nothing derives from its branding, layout, or copy.)
- **Roles** (lowercase): owner, admin, member, viewer. Viewer cannot launch products (no read-only mode). Entitlement statuses: enabled, disabled, trial, suspended (suspension is operator-imposed; workspace admins cannot change it).
- **Access decision outcomes** rendered privacy-safe: role_not_permitted, app_not_enabled_for_workspace, app_not_available (+ internal ones never rendered).
- **Route set is fixed**: `/` (public + sign-in), `/app` (launcher), `/app/admin?workspaceId=…` (admin). No new routes.
- **Launch flow**: Launch click → server issues a one-time token server-to-server → browser receives only a safe launch URL. Tokens have no visual slot.
- **Sessions**: HttpOnly cookie; all state-changing actions are CSRF-protected POSTs. Logout is Platform-only.
- **Existing baseline being restyled**: Inter/system font stack, CSS custom properties (--bg, --surface, --ink, --muted, --line, --accent, --accent-strong, --danger-soft), 1120px max width, light colour-scheme only, 44px minimum control height, tables stack on mobile. Self-hosted assets only.

## 2. Information architecture (revised, two-product)

```
/            PUBLIC WEBSITE + SIGN-IN GATEHOUSE (one page, 4 exclusive states)
/app         PRODUCT LAUNCHER
             alpha strip -> header -> status line -> identity block ->
             one group per workspace:
               WS record tag + "role: {role}" chip + "Manage workspace" link
               (link only where role in THAT workspace is owner/admin)
               product card grid in registry order: APP-KQAG, APP-SGCA
/app/admin?workspaceId=…   WORKSPACE ADMIN (owner/admin of that workspace)
             01 Workspace | 02 Add member | 03 Owner transfer (placeholder)
             04 Members | 05 Product access (per-app table) | 06 Activity
             (one scrolling document, anchor links, no tabs)
```

IA rules:
1. Admin entry is per-workspace (inside each workspace group), resolving mixed-role ambiguity (owner in A, viewer in B).
2. Six admin sections in contract order with stable anchors.
3. **Registry order everywhere**: cards and entitlement rows sort ascending by app key; no pinning, no recents, no featured slots. Launcher and admin must never disagree on order.
4. More products = more cards/rows, never more navigation. Grid and table are n-ary from day one.
5. Return/denial contract: logout → `/` + mandated notice; auth error → `/` + generic sentence + per-incident reference code; non-admin or mis-scoped admin access → redirect to `/app` with a role-safe generic notice (never confirms workspace existence).
6. Sign-in states mutually exclusive; precedence: auth error > post-logout > already-signed-in > default.

## 3. Three visual directions and judge results

| | A. Quiet Registry (minimal enterprise) | B. Registry Console (premium tech studio, light) | C. Friendly Gatehouse (warm internal tool) |
|---|---|---|---|
| Thesis | A well-kept registry of keys; trust through how little the interface performs | Precision-machined access hardware; identifiers as engineered typographic objects | A gatehouse run by friends; warm chrome around a visibly stricter record layer |
| Ground / accent | Mineral #F2F5F4 / Verdigris #0B5A50 | Cool paper #F5F7F6 / Vault teal #0E6B5C | Fern white #F4F6F1 / Spruce #2F6B4F |
| Type | Inter + IBM Plex Mono | Inter Display + Inter + IBM Plex Mono | Bricolage Grotesque + Inter + IBM Plex Mono |
| Signature element | Record tag: mono label seated on every block's top border with a small accent tick | System Rail: full-width mono strip "INTERNAL ALPHA · workspace · role" | Die-cut key-tag chip (punched-hole CSS silhouette) for platform-issued statuses |
| Copy tone | Plain, declarative, operational | Fact → consequence → next step | Colleague-at-the-next-desk, reassuring, precise |
| Strengths | Cheapest to build (token restyle of the shipped baseline, no modal, ~30 lines JS); security model legible in the design language (mono = system truth, denial is a designed state); scales by adding tagged cards | Security rules become structural (constrained chip vocabulary means the safest rendering is the default); glyph+text status grammar | Only genuinely ownable visual asset; keyring metaphor compounds with more products; warmth without the cream/serif cliché |
| Risks | Austerity fragile in maintenance; can read cold; needs grouping past ~8-10 apps | Visually generic ("engineered console" is the current AI-design attractor); requires a focus-trapped modal (the component small teams get wrong); its Rail reads as a debug bar | Highest-risk CSS (die-cut cutout must render cleanly in two contexts); new display typeface to subset/tune; warm copy makes promises the backend must keep |
| Judge: security-and-trust | **9** | 8 | 6.5 |
| Judge: implementability (1:1 by coding agent) | **9** | 7 | 6.5 |
| Judge: brand distinctiveness | 7 | 5 | **8** |
| Total | **25** | 20 | 21 |

Note: directions A and B converged independently on near-identical palettes — evidence that "quiet engineered console" is a template attractor. A's record tag is what rescues it from anonymity; grafts below import C's warmth and B's rigour.

## 4. Recommendation

**Adopt A (Quiet Registry)** with seven grafts:
1. Workspace/role context folded into the alpha strip: `INTERNAL ALPHA · {WORKSPACE} · role: {role}` (launcher with n>1 workspaces: `INTERNAL ALPHA · {n} workspaces`; admin: always the scoped workspace).
2. Glyph+text entitlement chips: `● enabled  ○ disabled  ◔ trial  ⊘ suspended` (glyph accent-coloured for enabled/trial, muted otherwise; text always present; never colour-only).
3. Existence-neutral add-member outcome copy framed as instruction (Section 5.3).
4. Guardrail-blocked controls render as static text + hidden reason, never greyed controls.
5. Error reference codes as copyable mono chips: `ref SWZ-XXXXXX` (per-incident, server-issued, never static).
6. Scroll-into-view when an inline destructive confirm row opens.
7. "Name the fixer" denial grammar; reassurance clauses only where the backend guarantees them; post-logout notice styled as a calm neutral banner (logout is a success).

**Two-product adjustments** (what changed vs a single-product design): cards gain a one-line description; grid explicitly n-ary (auto-fill 320–420px tracks, bottom-anchored footers so Launch buttons align); admin Product access becomes a per-app table; alpha-strip multi-workspace variant; homepage widens to "AI-powered business tools" with one capability line naming both categories. Nothing else changed — the direction absorbed the second product without redesign.

### Design tokens
| Token | Name | Hex | Use |
|---|---|---|---|
| --bg | Mineral | #F2F5F4 | Page ground (cool grey-green) |
| --surface | Paper | #FFFFFF | Blocks, cards, tables, inputs |
| --ink | Gault | #15201F | Text; hover fill of accent buttons (~14.5:1 on bg) |
| --muted | Slate | #536067 | Secondary text (~5.4:1, AA) |
| --line | Hairline | #D7DEDB | 1px borders and rules (decorative only) |
| --accent | Verdigris | #0B5A50 | Reserved for granting access: primary buttons, tag ticks, focus rings, links (white-on ~7.4:1) |
| --accent-strong | — | #07423B | Hover/pressed |
| --danger-soft | Clay wash | #F4E5DE | Confirm-row and error backgrounds only; text on it always Gault |

Type: Inter 400/500/600 (display+body) + IBM Plex Mono 400/500 ("record register": tags, chips, emails, ids, timestamps, event types, reference codes, alpha strip). Self-hosted subset WOFF2 only. Scale 11/13/15/20/28. Rules encoded in the stylesheet: mono = system truth only; body copy never in mono; mono never contains secrets; do not add colours. Layout: 1120px max, 8px grid, 6px radius, 44px controls, light-only, 120ms opacity/border motion max, none under prefers-reduced-motion.

### Component inventory (17)
Internal-alpha strip · record tag · registry block · primary button · quiet button · inline destructive confirm row (no modal) · status line (role=status, aria-live) · notice/error banner · reference-code chip · identity block · product card · role/status chip · data table (stacks on mobile) · form field + select · section index (mono anchors 01–06) · empty-state block · footer.

## 5. Page-by-page spec

### 5.1 Public website + sign-in (`/`)

Centred 440px column on Mineral. No nav, no pricing, no request-access form. Order:
1. Mono eyebrow (mandated verbatim): `Swooshz Platform internal access`
2. Wordmark "Swooshz Platform" + mono chip `internal alpha`
3. Headline (recommended): **"Access your workspace's AI business tools."**
4. Capability line (the only product-describing sentence; categories, not features; must not grow): "Swooshz builds and hosts AI-powered tools for business operations — from quote automation to SEO and AI-search content."
5. ACCESS block (record tag `ACCESS`): heading "Sign in to continue." → mandated body line → primary CTA `Continue with Google` (the page's only accent element) → helper "Expecting access? Ask a workspace owner or admin to add your account." → notice slot (role=status).
6. Footer: one plain-text line + contact. No legal page links until such routes exist.

States (mutually exclusive): default · post-logout (calm neutral notice, mandated verbatim: "You are signed out of Swooshz Platform. Your Google account may still be signed in.") · auth error (Clay banner: "Sign-in did not complete. Nothing was changed on your account." + `ref SWZ-XXXXXX`; one category sentence covers all causes — never distinguishes wrong-account / not-approved / provider-outage) · already signed in (no CTA/body line; "You are signed in." + mono email + primary "Go to your workspaces" + quiet "Sign out of Swooshz Platform").

### 5.2 Product launcher (`/app`)

```
| INTERNAL ALPHA · ORCHARD OPS · role: admin                      |
| Swooshz Platform [internal alpha]     [Sign out of Swooshz Platform] |
| signed in as jamie@orchard-ops.example · 1 workspace            |
| [ID]  Jamie Tan / jamie@orchard-ops.example · active            |
| [WS – ORCHARD OPS]  Orchard Ops  [role: admin]  Manage workspace|
|   +--APP – KQAG--------------+  +--APP – SGCA – UNAVAILABLE---+ |
|   | KQAG      private preview|  | SEO/GEO Content   private   | |
|   | ● enabled                |  | Automation        preview   | |
|   | Generate quotes and      |  | ○ disabled                  | |
|   | manage quotation         |  | Create, approve, and publish| |
|   | workflows.               |  | SEO and GEO content for     | |
|   |                          |  | search and AI discovery.    | |
|   | [ Launch KQAG ]          |  | Unavailable                 | |
|   |                          |  | SEO/GEO Content Automation  | |
|   |                          |  | is not enabled for this     | |
|   |                          |  | workspace. Ask a workspace  | |
|   |                          |  | owner or admin about access.| |
|   +--------------------------+  +-----------------------------+ |
```

**Card anatomy (a system rule, identical for every product):** record tag `APP – {KEY}` on the top border (tick greys + `– UNAVAILABLE` suffix in denied states) → header row: name (18px) + app-status chip right-aligned (`private preview`, mono, no glyph — lifecycle, not entitlement) → entitlement chip alone beneath the name → one-line description (fixed string from the app registry; never changes across states) → bottom-anchored footer: Launch button OR `Unavailable` + one reason line. **Cards carry zero product-runtime data.**

**Card 1 — KQAG / SAQG.** Key `kqag`; description "Generate quotes and manage quotation workflows."; button `Launch KQAG`.
**Card 2 — SEO/GEO Content Automation.** Placeholder key `sgca` (flagged assumption); description "Create, approve, and publish SEO and GEO content for search and AI discovery."; button label `Launch` (full accessible name "Launch SEO/GEO Content Automation").

Entitlement matrix (both cards): enabled → `● enabled` + Launch · trial → `◔ trial` + Launch (no countdown, no billing language) · disabled → `○ disabled` + Unavailable + reason · suspended → `⊘ suspended` + "Access is suspended for this workspace. A workspace owner or admin can contact the platform operator."

Denial templates (one per token; app name is the only variable):
- role_not_permitted: "Your role does not permit launching apps. Ask a workspace owner or admin about access." (identical across cards; entitlement chip still renders truthfully)
- app_not_enabled_for_workspace: "{App} is not enabled for this workspace. Ask a workspace owner or admin about access."
- app_not_available: "{App} is not available right now. No action is needed from you." (sanctioned exception to name-the-fixer: there is genuinely no user step)

Launch flow: click → button locks immediately (double-click protection), label "Opening…", aria-live announces → browser navigates to the safe launch URL only. Failure: one Clay strip below the footer: "Could not open {App}. Try again." + `ref SWZ-XXXXXX` chip, updated in place on retry, never stacked.

Empty states: no workspaces → "Your sign-in worked, but this account is not a member of any workspace yet. Ask a workspace owner or admin to add you." (no retry button — the fix is human). No products enabled → "No products are enabled for this workspace. Ask a workspace owner or admin about access." All-unavailable → cards still render in denied states; hiding an app would misreport the registry.

### 5.3 Workspace admin (`/app/admin?workspaceId=…`)

Frame: alpha strip (scoped workspace) → header + "Back to launcher" → title + mono workspace name → section index `01–06` (anchors) → six blocks in contract order. Non-admin/mis-scoped → redirect to `/app` + "Workspace admin is available to owners and admins."

- **01 Workspace**: Name / Workspace id (mono, safe display form) / Your role.
- **02 Add member**: email + role select (admin/member/viewer — owner never offered) + mandated helper verbatim: "Teammate must sign in once first. No invitation delivery." Outcome banner identical on every path: "Request submitted. If this teammate has signed in to Swooshz Platform before, they now appear in Members. If they haven't, ask them to sign in once, then add them again. No invitation email is sent." (A successful add necessarily reveals existence in the table — documented, accepted for internal alpha.)
- **03 Owner transfer**: inert placeholder, mandated copy: "Owner transfer is not available in internal alpha yet." No fake button.
- **04 Members**: table Name / Email (mono) / Role / Status / Last login (mono absolute + visible muted relative) / Actions. Guardrails render as static text + hidden reason: own row ("You cannot change your own role."), sole owner ("A workspace must keep at least one active owner."), inactive member. Disable opens an inline Clay confirm row (focus moves in, scrolls into view): "Disable {name} for this workspace? They keep their history but cannot use this workspace. Nothing is deleted." → [Disable member] [Cancel].
- **05 Product access**: context line "Control which apps this workspace can launch. Changes apply to all workspace members immediately." Per-app table in registry order:

```
| APP                                   | STATUS     | GRANTED BY        | UPDATED          | ACTION  |
| KQAG  KQAG  private preview           | ● enabled  | jamie@…example    | 2026-07-03 14:12 | Disable |
| SGCA  SEO/GEO Content Automation  pp  | ○ disabled | —                 | —                | Enable  |
```

  Enable confirm (neutral): "Enable {App} for this workspace? Owners, admins, and members will be able to launch it. A viewer role cannot launch apps." → [Enable app] (accent — granting is the reserved accent act) [Cancel]. Disable confirm (Clay): "Disable {App} for this workspace? Members lose the ability to launch it immediately. Nothing inside {App} is deleted or changed." → [Disable app] (ink solid, deliberately not accent) [Keep enabled]. One confirm strip open at a time; buttons lock in flight; success updates row in place + aria-live + Activity entry. Suspended row: no action button — "Suspended by the platform operator. Workspace admins cannot change this." Trial row: Disable available; no end dates, counters, credits, upgrade prompts.
- **06 Activity**: `AUD – LAST 50 · newest first`. Columns: Action (human copy — "Member added", "KQAG access enabled" — with raw event type e.g. `workspace.membership.added` beneath in small mono) / Subject / Actor (system actions attributed to "Swooshz Platform") / Time (mono absolute + visible relative) / Details (allowlisted fragments only: previous/new role or status, app key — never tokens, claims, payloads). Truncation footer whenever 50 rows render: "Showing the 50 most recent events. Older events are retained but not shown here."

### 5.4 Copy sample sheet (canonical strings)

| Slot | Copy |
|---|---|
| Hero eyebrow (mandated) | Swooshz Platform internal access |
| Hero headline (recommended) | Access your workspace's AI business tools. |
| Capability line | Swooshz builds and hosts AI-powered tools for business operations — from quote automation to SEO and AI-search content. |
| Hero body (mandated) | Access requires an approved provider-backed account for your workspace. No public signup is available. |
| CTA (mandated) | Continue with Google |
| Login helper | Expecting access? Ask a workspace owner or admin to add your account. |
| Post-logout notice (mandated) | You are signed out of Swooshz Platform. Your Google account may still be signed in. |
| Launcher status line | signed in as {email} · {n} workspaces |
| Workspace group | WS – {NAME} · role: {role} |
| KQAG card | KQAG · private preview · "Generate quotes and manage quotation workflows." · [Launch KQAG] |
| SEO card | SEO/GEO Content Automation · private preview · "Create, approve, and publish SEO and GEO content for search and AI discovery." · [Launch] |
| Sign-out button (mandated) | Sign out of Swooshz Platform |
| Alpha strip | INTERNAL ALPHA · {WORKSPACE} · role: {role} |

Voice rules: verbs first; no exclamation marks; no marketing adjectives; roles/statuses lowercase in labels; Singapore English in prose; system tokens rendered exactly as emitted; buttons carry no trailing punctuation; the accent colour appears only where access is being granted.

## 6. Mandated copy (must appear verbatim)

1. "Swooshz Platform internal access"
2. "Access requires an approved provider-backed account for your workspace. No public signup is available."
3. "Continue with Google"
4. "Sign out of Swooshz Platform"
5. "You are signed out of Swooshz Platform. Your Google account may still be signed in."
6. "Teammate must sign in once first. No invitation delivery."
7. "Owner transfer is not available in internal alpha yet."

## 7. Security/privacy UX requirements (consolidated)

1. No public signup; one action on the public page (provider sign-in); no request-access form or waitlist.
2. Provider-backed login only; no password fields, magic links, fallback or demo auth on any state.
3. No component may render raw tokens (session/CSRF/launch), provider claims, cookies, OAuth values, DB URLs, stack traces, CMS credentials, quote/article/content data, generated artifacts, or client payloads. The error component has one sentence slot + a reference-code chip — no slot for exception text.
4. Raw access-decision tokens never appear on cards; they render verbatim in mono only in the audit view.
5. Platform-only logout stated explicitly (mandated button + notice); logout is a CSRF-protected POST, never a link.
6. Internal-alpha status visible on every authenticated surface (strip first in DOM + header chip that survives cropped screenshots); public page carries it in the mandated eyebrow.
7. Errors: one generic category sentence + per-incident mono reference code (pattern SWZ-XXXXXX), never static.
8. No user enumeration: add-member outcome copy identical on every path.
9. Denial is a designed, calm, full-contrast state (no dead buttons), reasons only from the fixed enum, naming who can fix it.
10. Reassurance clauses ("Nothing was changed.") only where the backend genuinely guarantees them; otherwise dropped, never softened.
11. Accessibility: WCAG AA contrast (all pairs verified in the palette), 2px focus rings, 44px targets, role=status/aria-live for async, glyph+text chips (never colour-only), static skeletons, motion removed under prefers-reduced-motion.

## 8. Risks of over-product-specific UI, with guardrails

| Risk | Consequence | Guardrail |
|---|---|---|
| Hardcoded product names/copy in shared components and audit copy | Platform silently becomes "the KQAG admin panel"; string hunt when product 2 ships | Single app registry {app_key, display_name, app_status} is the only legal home for product-name literals; CI grep fails builds elsewhere |
| Launcher cards grow runtime widgets (quote counts, article stats) | Platform starts fetching product data — a second data-security surface | Frozen card contract: app_key, display_name, app_status, entitlement_state, can_launch, denial_reason — nothing else |
| Entitlement UI shaped around one product | Product 2 unrepresentable without redesign; data model bent to match UI | Generic workspace-by-app matrix, four canonical states, copy templated on {app_name} |
| Audit vocabulary coupled to product 1 | Two naming dialects in one log; renaming rewrites history | Platform-verb event names (app.launched, entitlement.changed) with app_key as a field, never in the name |
| Platform brand welds to KQAG | White-label SEO product forever looks like a bolt-on | Platform keeps a neutral wordmark/palette; product identity only inside registry-supplied cards |
| Product-capability copy in Platform ("No quotes yet…") | Nonsense for mixed-entitlement workspaces; normalises product dashboards in the hub | Copy rule: Platform speaks access, never capability |
| Per-product denial copy | Copy drifts and leaks entitlement detail | Denial UI renders exclusively from the fixed three-token enum, one template per token |
| Admin IA assumes one app (singleton pages, implicit filters) | Routing rework mid-alpha; ambiguous defaults — the bug class that produces access-control mistakes | "Design for N=2, ship with N=2": every surface/query keyed by app_key; no default app |
| Ad-hoc identifier for product 2 | Fragmented entitlement checks and audit rows; migration on security-relevant tables | Reserve the key now (sgca, to confirm); keys immutable once written; only display_name may change |
| App status rendered as a bespoke one-product badge | Each lifecycle state needs new bespoke UI | One shared status chip driven by the registry enum with an unknown-value fallback |

## 9. Open assumptions (flagged, not decided)

1. SEO product app key: placeholder `sgca` — must be confirmed before minting (propagates into tags, ordering, entitlement rows, denial templates, audit payloads).
2. Canonical display names: KQAG vs SAQG; "SEO/GEO Content Automation" is a working name. Long names shorten the button label to "Launch" with the full accessible name retained.
3. SEO product app status assumed `private_preview`.
4. Reassurance clauses assume backend guarantees (failed sign-in writes nothing; entitlement toggles never touch product data; failed POSTs apply nothing).
5. No legal-page routes exist; public footer is one plain-text line + contact until they are added to the route contract.

## 10. Questions for the evaluator

1. Does any element violate the hard constraints in Section 0 (especially product-runtime data on Platform surfaces, or forbidden features)?
2. Is the recommended direction justified against the alternatives, or would you weight the judging lenses differently for a security-first internal alpha?
3. Are the denial/error/empty states sufficient and privacy-safe? Any state missing?
4. Does the two-product launcher card system genuinely scale to 5+ products without redesign?
5. Is the homepage positioning appropriately restrained for a gated internal alpha while still reading as multi-product?
6. Any copy that breaks the stated voice rules, over-promises, or creates a support/trust liability?
7. Are the anti-product-specificity guardrails practical for a two-person team, and is anything important missing?

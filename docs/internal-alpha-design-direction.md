# Swooshz Platform — Design Direction and Page-by-Page UX Spec (Internal Alpha)

Status: DRAFT for approval — design direction and UX concepts only, no production code.
Revision 2026-07-05: Add member redesigned around the pending-approval membership
model (the previous add-existing-user flow is bootstrap-only, not target UX);
SEO/GEO product kept as an unconfirmed conceptual placeholder.
Scope: two-product platform (KQAG / SAQG + SEO/GEO Content Automation).
Grounded in: `docs/internal-alpha-platform-contract.md`, `docs/app-access-contract.md`,
`docs/accounts-contract.md`, `docs/auth-session-security-contract.md`,
`docs/kqag-integration-contract.md`, ADRs 0001–0007, and the shipped surface in
`src/http/platform-shell.ts`.
Date: 2026-07-05.

---

## 1. Recommendation

Adopt **Direction A — "Quiet Registry" (minimal enterprise)** as the Platform's visual
direction, with seven specific grafts from the other two directions (Section 5).

Why: a three-lens judge panel scored it highest on security-and-trust (9/10) and
implementability (9/10) — it is a token-level restyle of the existing
`platform-shell.ts` baseline (same custom-property names, Inter kept, 1120px, 44px
buttons, light-only), needs no modal, no framework, and roughly 30 lines of JS. Its
registry/ledger grammar is subject-grounded (the Platform literally keeps a ledger of
identities, entitlements and audit events) and it *improves* as more products join:
every new product is another `APP –` tagged card in the same grid.

The two-product update does not change the recommendation — it strengthens it
(Section 5.2).

---

## 2. Information architecture (revised for a two-product platform)

The route set is fixed: `/`, `/app`, `/app/admin` (+ existing `/api/platform/*`).
No new routes are invented.

```
swooshz platform
│
├─ /                      PUBLIC WEBSITE + SIGN-IN GATEHOUSE (one page, 4 states)
│   ├─ brand + mono "internal alpha" chip
│   ├─ hero: eyebrow (mandated) · headline · capability line · body line (mandated)
│   ├─ ACCESS block: "Continue with Google" (mandated) + state notice slot
│   └─ footer: single plain-text line + contact (no invented legal routes)
│
├─ /app                   PRODUCT LAUNCHER (authenticated)
│   ├─ internal-alpha strip (mandated visibility, every authenticated page)
│   ├─ header: brand · identity · "Sign out of Swooshz Platform"
│   ├─ status line (role=status, aria-live=polite)
│   ├─ identity block (name · email · user status)
│   └─ one WS group per membership:
│       ├─ record tag "WS – {NAME}" + chip "role: {role}"
│       ├─ "Manage workspace" link (only if role in THIS workspace is owner/admin)
│       │     → /app/admin?workspaceId=…
│       └─ product card grid (registry order by app key):
│           ├─ APP – KQAG   (quote automation)
│           └─ APP – SGCA   (SEO/GEO Content Automation; placeholder key)
│
└─ /app/admin?workspaceId=…   WORKSPACE ADMIN (owner/admin of that workspace only)
    ├─ same strip + header + "Back to launcher"
    ├─ section index: 01–06 anchor links (one document, no tabs)
    ├─ 01 WORKSPACE      #workspace       name · id · your role
    ├─ 02 ADD MEMBER     #add-member      email + role select (admin/member/viewer)
    ├─ 03 OWNER TRANSFER #owner-transfer  placeholder (mandated copy)
    ├─ 04 MEMBERS        #members         table + guardrails
    ├─ 05 PRODUCT ACCESS #app-access      per-app entitlement table (2 rows)
    └─ 06 ACTIVITY       #activity        last 50 audit events
```

IA rules (these resolve every issue raised by the adversarial IA review):

1. **Admin is workspace-scoped.** The admin entry point lives inside each workspace
   group on `/app` ("Manage workspace"), shown only where the viewer's role in that
   workspace is owner/admin, carrying `?workspaceId=…` — matching the shipped
   implementation. No global header Admin link.
2. **Six admin sections in contract order** (as documented and guarded by tests),
   one scrolling document with stable anchor ids. Anchors, not tabs (simpler
   keyboard/a11y story).
3. **Registry order everywhere.** Launcher cards and the admin entitlement table sort
   ascending by app key (`kqag` before `sgca`). No pinning, no recents, no featured
   slots. Launcher and admin must never disagree on order.
4. **More products = more cards/rows, never more navigation.** The card grid and the
   entitlement table are n-ary from day one ("design for N=2, ship with N=2").
5. **Return/denial contract:** logout → `/` with the mandated verbatim signed-out
   notice; auth error → `/` with one generic category sentence + per-incident
   reference code; non-admin or mis-scoped `/app/admin` access → redirect to `/app`
   with a generic role-safe notice that does not confirm or deny the target
   workspace's existence.
6. **Sign-in page states are mutually exclusive**, precedence: auth error >
   post-logout > already-signed-in > default.
7. Domain and legal pages are deployment configuration, not IA. No Privacy/Terms
   routes unless first added to the route contract and tests.

---

## 3. The three visual directions

| | A · Quiet Registry (minimal enterprise) | B · Registry Console (premium tech studio) | C · Friendly Gatehouse (warm internal tool) |
|---|---|---|---|
| Thesis | A well-kept registry of keys: one sans for speech, one mono for record; trust through how little the interface performs | Precision-machined access hardware: identifiers and statuses as engineered, first-class typographic objects | A gatehouse run by friends: warm chrome and forgiving copy around a visibly stricter record layer |
| Ground / accent | Mineral `#F2F5F4` / Verdigris `#0B5A50` | Cool paper `#F5F7F6` / Vault teal `#0E6B5C` | Fern white `#F4F6F1` / Spruce `#2F6B4F` |
| Type | Inter + IBM Plex Mono | Inter Display + Inter + IBM Plex Mono | Bricolage Grotesque + Inter + IBM Plex Mono |
| Signature | **Record tag** — mono label seated on every block's top border with a Verdigris tick | **System Rail** — full-width mono strip: `INTERNAL ALPHA · workspace · role` | **Key-tag chip** — die-cut keyring-tag with punched CSS hole for platform-issued statuses |
| Alpha marker | 28px mono strip + header chip | The System Rail itself | Toffee key-tag beside the wordmark |

### 3.1 Direction A — Quiet Registry (minimal enterprise)

- **Page structure:** single centred 1120px column on Mineral; every content unit is a
  "registry block" (Paper card, 1px hairline, 6px radius, mono record tag on its top
  edge). Launcher stacks identity then workspace groups with a card grid; admin is one
  document with a mono numbered section index. No sidebar anywhere.
- **Component list (16):** internal-alpha strip · record tag · registry block ·
  primary button · quiet button · destructive confirm row (inline, no modal) · status
  line · notice/error banner · identity block · product card · role/status chip ·
  data table (stacks on mobile) · form field + select · section index · empty-state
  block · footer.
- **Copy tone:** plain, declarative, operational. Verbs first, no exclamation marks,
  no marketing adjectives, no apology theatre. Denials name the fact, the next step
  and who can fix it. Errors: one generic sentence + per-incident mono reference code.
- **Strengths:** subject-grounded signature; cheapest to implement and maintain (a
  token restyle of the shipped baseline; ~2 extra font files; no modal); security
  model expressed by the design language (mono = system truth; denial is a designed
  state); ages well — new apps are new tagged cards; accessibility structural.
- **Risks:** austerity is fragile in maintenance (one coloured badge breaks it — the
  rules must live in the stylesheet); can read cold to non-technical stakeholders;
  card grid needs grouping beyond ~8–10 apps; single accent means low affordance
  contrast in dense admin rows; the inline confirm row's focus move is load-bearing.

### 3.2 Direction B — Registry Console (premium tech studio, light-mode)

- **Page structure:** same single-column skeleton as A, with a 36px System Rail as the
  only full-bleed element; 64px section gaps; strict chip grammar throughout.
- **Component list (19):** as A, plus registry chip with glyph grammar (`● enabled`,
  `○ disabled`, `◔ trial`, `⊘ suspended`), denial notice, reference-code block with
  Copy button, focus-trapped confirmation dialog, workspace group wrapper.
- **Copy tone:** engineered plain-speech — fact, consequence, next step, in that
  order; system facts never paraphrased (`role: viewer`, not "you're just a viewer").
- **Strengths:** security rules become structural (constrained chip vocabulary means
  the safest rendering is the default); zero dark-scheme delta; excellent hygiene.
- **Risks:** visually generic ("premium engineered console" is the emerging AI-era
  default — the brand judge scored it 5/10 for exactly this); its one memorable
  element (the Rail) reads as a debug bar to some stakeholders; concentrates
  implementation risk in the focus-trapped modal — the component class small teams
  most often get wrong; 4 font files.

### 3.3 Direction C — Friendly Gatehouse (warm approachable internal tool)

- **Page structure:** same skeleton; white cards with 16px radius and willow borders,
  no shadows; generous padding; inline confirmation panels instead of modals.
- **Component list (17):** as A, plus the key-tag chip (three sanctioned roles: alpha
  marker, app status, entitlement status), destructive button tier, and warm
  empty-state panels.
- **Copy tone:** colleague-at-the-next-desk — contractions welcome, reassurance
  clauses ("nothing was changed", "nothing is deleted"), denials name the fixer;
  machine-true values stay strict mono so the friendliness stops where the record
  starts.
- **Strengths:** the only direction with a genuinely ownable visual asset (no
  template ships a punched-hole status chip); the keyring metaphor compounds with
  scale — five products read as a fuller keyring; warm without the cream-serif
  default.
- **Risks:** the die-cut CSS cutout is the panel's highest-risk visual (soft edges or
  wrong rim contrast on `--bg` vs `--surface` repeats everywhere); a new display
  typeface to subset and tune; largest visual delta from the shipped baseline; warm
  copy makes promises the backend must genuinely keep; tag-usage rule erodes easily.

### 3.4 Judge panel results

| Lens | A · Quiet Registry | B · Registry Console | C · Friendly Gatehouse |
|---|---|---|---|
| Security & trust | **9** | 8 | 6.5 |
| Implementability (1:1 by a coding agent) | **9** | 7 | 6.5 |
| Brand distinctiveness | 7 | 5 | **8** |
| **Total** | **25** | 20 | 21 |

The brand judge's dissent is instructive: A and B independently converged on nearly
the same palette and type pairing, evidence that "quiet engineered console" is an
attractor. A's record tag rescues it; the grafts below import C's warmth and B's
rigour to close the gap.

---

## 4. Security and privacy UX requirements (consolidated, all directions)

1. **No public signup.** The public page offers exactly one action: provider sign-in.
   Mandated copy verbatim: "Access requires an approved provider-backed account for
   your workspace. No public signup is available." No request-access form, no
   waitlist, no pricing.
2. **Provider-backed login only.** CTA verbatim: "Continue with Google". No password
   fields, no magic links, no fallback auth, no demo mode — ever, on any state.
3. **Nothing secret has a home.** No component may render: raw tokens (session, CSRF,
   launch), provider claims, cookies, OAuth values, DB URLs, stack traces, CMS
   credentials, private quote data, private article/content data, generated
   artifacts, or customer/client payloads. The launch flow's only visible artefacts
   are a busy button label and a navigation to the safe launch URL.
4. **Raw access-decision tokens** (`role_not_permitted`, …) never surface on cards;
   they render verbatim in mono only inside the admin audit register.
5. **Platform-only logout, said explicitly.** Button verbatim: "Sign out of Swooshz
   Platform" (a CSRF-protected POST, never a link). Post-logout notice verbatim:
   "You are signed out of Swooshz Platform. Your Google account may still be signed
   in." Styled as a calm neutral notice — logout is a success, not an error.
6. **Internal-alpha status always visible** on every authenticated surface: the 28px
   mono strip (first in DOM) plus a mono "internal alpha" chip beside the brand mark
   (survives partial screenshots). Public page: the mandated eyebrow carries it.
7. **Errors are generic + reference code.** One category sentence; beneath it a mono
   chip `ref SWZ-XXXXXX` (per-incident, server-issued, never static) with a quiet
   Copy button. The error component has no slot for exception text.
8. **No user enumeration.** The add-member outcome banner is identical on every
   path. Membership state (active vs pending) is visible only to that workspace's
   owners and admins in the Members table — documented, accepted for internal alpha.
9. **Denial is a designed state**, not an error: full-contrast copy, no dead buttons,
   reason from the fixed enum only, naming who can fix it.
10. **State-changing actions are forms with real buttons** (matching their
    CSRF-protected POST nature). Reads never mutate.
11. **Reassurance clauses** ("Nothing was changed.") ship only where the backend
    genuinely guarantees them; otherwise dropped, never softened.
12. **Accessibility gates:** WCAG AA contrast, 2px visible focus rings, 44px targets,
    `role=status`/`aria-live=polite` for async status, glyph+text status chips (never
    colour-only), static skeletons, motion ≤120ms opacity/border and removed under
    `prefers-reduced-motion`.

Out of scope by mandate (do not design, do not tease): billing, credits, public
signup, password auth, 2FA, broad fallback auth, marketplace, heavy analytics,
invitation delivery, session-management UI, theme toggles, any KQAG or SEO-product
workflow data inside Platform.

---

## 5. Recommended direction, grafts, and two-product adjustments

### 5.1 Grafts onto Quiet Registry (judge-sourced, all near-zero cost)

1. From B: fold workspace/role context into the alpha strip —
   `INTERNAL ALPHA · {WORKSPACE} · role: {role}` (on `/app` with n>1 workspaces:
   `INTERNAL ALPHA · {n} workspaces`; on `/app/admin`: always the scoped workspace).
2. From B: glyph+text entitlement chip grammar — `● enabled`, `○ disabled`,
   `◔ trial`, `⊘ suspended`.
3. From B: existence-neutral add-member result framed as instruction, not error
   (copy in §7.3, section 02).
4. From B: guardrail-blocked row controls render as static text + visually-hidden
   reason — nothing that looks operable but isn't.
5. From B: reference codes as copyable mono chips (`ref SWZ-XXXXXX` + quiet Copy,
   progressive enhancement).
6. From C: scroll-into-view when an inline destructive confirm row opens (instant
   under reduced motion) — mitigates A's own stated risk on long tables.
7. From C: transactional reassurance clauses and "name the fixer" denial grammar;
   post-logout notice styled as a calm neutral banner.

### 5.2 What changes now that there are (at least) two products

- **Card anatomy gains a one-line description** (Slate 13px, category-true, fixed
  string from the app registry). With one product a description was decoration; with
  two it is how a colleague picks the right door.
- **Card grid is explicitly n-ary:** auto-fill columns, 320px min / 420px max track,
  16px gap; two cards side by side ≥720px, stacked below. Footers bottom-anchored so
  Launch buttons align across cards. Equal-height rows.
- **Admin Product access becomes a per-app table** (two rows now) instead of a
  KQAG-shaped singleton — columns App / Status / Granted by / Updated / Action.
- **Alpha strip multi-workspace variant** specified (above).
- **Homepage positioning widens** to "platform of AI-powered business tools" with one
  quiet capability line naming both categories (§7.1). No product sections, feature
  lists, screenshots or logo walls.
- **Everything else is unchanged.** The registry grammar was designed for this: a
  second product is a second `APP –` tag. That the direction absorbs the update
  without redesign is the strongest evidence it is the right one.

---

## 6. Design tokens and component inventory (implementation-ready)

### 6.1 Tokens (map 1:1 onto the existing custom-property names)

| Token | Name | Hex | Use |
|---|---|---|---|
| `--bg` | Mineral | `#F2F5F4` | Page ground (cool grey-green) |
| `--surface` | Paper | `#FFFFFF` | Registry blocks, cards, tables, inputs |
| `--ink` | Gault | `#15201F` | Text; hover/pressed fill of accent buttons (≈14.5:1 on bg) |
| `--muted` | Slate | `#536067` | Secondary text, helper copy, timestamps (≈5.4:1, AA) |
| `--line` | Hairline | `#D7DEDB` | 1px borders, table rules, skeletons (decorative only) |
| `--accent` | Verdigris | `#0B5A50` | Reserved for the act of granting access: primary buttons, tag ticks, focus rings, links (white-on ≈7.4:1, AA) |
| `--accent-strong` | — | `#07423B` | Hover / pressed / current-section |
| `--danger-soft` | Clay wash | `#F4E5DE` | Confirm-row and error-banner backgrounds only; text on it always Gault |

Type: Inter 400/500/600 (display + body; already the baseline) and IBM Plex Mono
400/500 (the "record" register: tags, chips, emails, ids, timestamps, event types,
reference codes, the alpha strip). Both self-hosted subset WOFF2, `font-display:
swap`, no CDNs. Fixed scale 11/13/15/20/28; `tabular-nums` in tables. Rule encoded in
the stylesheet: *mono = system truth only; body copy never sets in mono; mono never
contains secrets; do not add colours.*

Layout: 1120px max width, 8px grid, 40–56px block gaps, 6px radius, 44px minimum
control height, light `color-scheme` only, tables stack to labelled cards <720px.
Motion: 120ms opacity/border only; none under `prefers-reduced-motion`.

### 6.2 Component inventory (17)

| Component | Purpose | Key states |
|---|---|---|
| Internal-alpha strip | 28px mono environment strip, first in DOM on authenticated pages | static; workspace/role readout; `{n} workspaces` variant |
| Record tag (signature) | Mono label seated on every block's top border + Verdigris tick | denied context: tick greys AND tag gains text suffix `– UNAVAILABLE` |
| Registry block | Base container for every content unit | loading skeleton bars; inert placeholder (Mineral fill); inline error |
| Primary button | Continue with Google, Launch, submits | hover/focus/disabled(+reason)/busy (label swap, aria-live mirror) |
| Quiet button | Sign out, Cancel, Keep enabled, Copy | sign-out is always a POST form |
| Destructive confirm row | Inline expanding confirm (no modal) on Clay wash | focus moves in on open + scroll-into-view; Escape collapses; error inside with ref chip |
| Status line | `role=status aria-live=polite` session/async line | idle/busy/error |
| Notice / error banner | Landing notices, admin outcomes | NOTICE (Paper) vs ERROR (Clay wash + ref chip) |
| Reference-code chip | `ref SWZ-XXXXXX` mono + quiet Copy button | per-incident, updates in place, never stacks |
| Identity block | Name; mono email + user status | inactive: text + explanation, no colour-only badge |
| Product card | One per registered app per workspace (spec §7.2) | idle/busy/failure/denied ×4 entitlement states |
| Role/status chip | Mono lowercase words; glyph+text for entitlements | `role: member`; `● enabled ○ disabled ◔ trial ⊘ suspended` |
| Data table | Members, Activity, Product access | mobile stacking; empty; skeleton; static-text guardrail cells |
| Form field + select | Email input, role select (owner never offered) | focus ring; existence-safe errors; disabled + adjacent reason |
| Section index | Mono anchor row `01–06` on admin | current section underlined + bold (not colour-only) |
| Empty-state block | Mineral fill, mono tag EMPTY, one sentence + one next step | permission-derived emptiness stays privacy-safe |
| Footer | Public: one plain-text line + contact; authenticated: one mono line | no invented legal routes |

---

## 7. Page-by-page spec

### 7.1 Public website + sign-in (`/`)

One page, one job: state what Swooshz is and let approved people in. Centred 440px
column on Mineral; no nav, no pricing, no request-access form.

Order, top to bottom:

1. Mono eyebrow (mandated, verbatim): **Swooshz Platform internal access**
2. Wordmark "Swooshz Platform" — Inter 600 28px + mono chip `internal alpha`
3. Headline (recommended): **"Access your workspace's AI business tools."**
   (alternatives: "One sign-in for the tools your workspace runs on." /
   "AI-powered tools, issued per workspace.")
4. Capability line, Slate 13px — the only sentence describing products, categories
   not features, must not grow: *"Swooshz builds and hosts AI-powered tools for
   business operations — from quote automation to SEO and AI-search content."*
5. ACCESS registry block (record tag `ACCESS`):
   - Body line (mandated, verbatim): "Access requires an approved provider-backed
     account for your workspace. No public signup is available."
   - Primary CTA (mandated, verbatim): **Continue with Google** — the page's only
     Verdigris element
   - Helper line: "Expecting access? Ask a workspace owner or admin to add your
     account."
   - Notice slot (`role=status`) directly above the heading — one banner at a time
6. Footer: single plain-text hairline row + contact address. Privacy/Terms links only
   if those routes are first added to the route contract.

Entry states (mutually exclusive; precedence: error > post-logout > signed-in):

| State | Rendering |
|---|---|
| 1 Default | Heading "Sign in to continue." + block as above |
| 2 Post-logout | Calm neutral NOTICE above the heading, verbatim: "You are signed out of Swooshz Platform. Your Google account may still be signed in." CTA unchanged |
| 3 Auth error | ERROR banner on Clay wash: "Sign-in did not complete. Nothing was changed on your account." + mono chip `ref SWZ-XXXXXX`. Heading "Try signing in again." One category sentence covers all causes — never distinguishes wrong-account / not-approved / provider-outage. Helper: "If this repeats, give the reference above to a workspace owner or admin." |
| 4 Already signed in | No CTA, no body line. Heading "You are signed in." + mono identity row. Primary "Go to your workspaces" (→ `/app`); quiet "Sign out of Swooshz Platform" |

### 7.2 Product launcher (`/app`)

Top to bottom: alpha strip → header (wordmark + `internal alpha` chip; right:
"Sign out of Swooshz Platform" quiet POST button) → status line → identity block →
workspace groups → footer.

- **Status line** (mono, Slate): `signed in as {email} · {n} workspaces`
  (singular: `1 workspace`). No greeting, no first names, no time-of-day copy.
- **Workspace group:** record tag `WS – {NAME}` + chip `role: {role}`; a
  "Manage workspace" quiet link (owner/admin in that workspace only) →
  `/app/admin?workspaceId=…`; then the card grid (auto-fill, 320–420px tracks,
  16px gap, registry order by app key).

**Card anatomy (identical for every product — a system rule, not a per-app design):**

```
┌─ APP – KQAG ───────────────────────────┐   ┌─ APP – SGCA ───────────────────────────┐
│ KQAG                   private preview │   │ SEO/GEO Content        private preview │
│ ● enabled                              │   │ Automation                             │
│ Generate quotes and manage             │   │ ○ disabled                             │
│ quotation workflows.                   │   │ Create, approve, and publish SEO and   │
│                                        │   │ GEO content for search and AI          │
│ [ Launch KQAG ]                        │   │ discovery.                             │
└────────────────────────────────────────┘   │ Unavailable                            │
                                             │ SEO/GEO Content Automation is not      │
                                             │ enabled for this workspace. Ask a      │
                                             │ workspace owner or admin about access. │
                                             └────────────────────────────────────────┘
```

1. Record tag `APP – {KEY}` on the top border (tick greys + `– UNAVAILABLE` suffix in
   denied states)
2. Header row: app name (18px Inter 600) + app-status chip right-aligned
   (`private preview`, mono, no glyph — lifecycle, not entitlement)
3. Entitlement chip alone beneath the name: `● enabled` / `◔ trial` / `○ disabled` /
   `⊘ suspended` (glyph `--accent` for enabled/trial, `--muted` otherwise; text
   always present)
4. One-line description, Slate 13px — fixed string from the app registry; never
   changes across states
5. Bottom-anchored footer: primary Launch button OR `Unavailable` + one reason line

**Card 1 — KQAG / SAQG (quote automation).** Key `kqag`, tag `APP – KQAG`, name
"KQAG" (confirm whether SAQG is the canonical display string — anatomy unchanged
either way), description "Generate quotes and manage quotation workflows.", status
chip `private preview`, button **Launch KQAG**. Hard boundary: zero KQAG runtime data
on the card — no quote counts, recent quotes, file lists, or last-activity
timestamps. The card is an access record; launch is a navigation handoff.

**Card 2 — SEO/GEO Content Automation (white-label SEO/content).** Placeholder key
`sgca`, tag `APP – SGCA`, working display name "SEO/GEO Content Automation" (both
flagged for confirmation), description "Create, approve, and publish SEO and GEO
content for search and AI discovery.", status chip `private preview` (assumed),
button label **Launch** (name too long for the button; accessible name "Launch
SEO/GEO Content Automation"). Hard boundary: no site lists, article counts,
publishing schedules, approval queues, client names, CMS details, or visibility data
anywhere on Platform. Being white-label, Platform (internal-only) carries the internal
name even if clients see other brands. The reference product from the brief was
treated as category context only; nothing here derives from it.

This card is a **conceptual placeholder only**: `sgca` must not be minted as final,
and it remains unconfirmed until vendor SSO/API/workspace/billing details are
confirmed. Implementation must not register the app, create entitlements, or add any
SEO integration until the product contract is approved — the design shows the second
card to prove the system is n-ary, not to authorise integration work.

**Entitlement rendering matrix (both cards, verbatim shared templates):**

| State | Chip | Footer |
|---|---|---|
| enabled | `● enabled` | Launch button (if role permits) |
| trial | `◔ trial` | Launch button, identical to enabled — no countdown, no billing language |
| disabled | `○ disabled` | `Unavailable` + "{App} is not enabled for this workspace. Ask a workspace owner or admin about access." |
| suspended | `⊘ suspended` | `Unavailable` + "Access is suspended for this workspace. A workspace owner or admin can contact the platform operator." |

**Denial templates (one per token, app name the only variable):**

- `role_not_permitted` (chip still renders truthfully): "Your role does not permit
  launching apps. Ask a workspace owner or admin about access." — identical across
  cards by design; no read-only mode offered.
- `app_not_enabled_for_workspace`: "{App} is not enabled for this workspace. Ask a
  workspace owner or admin about access."
- `app_not_available`: "{App} is not available right now. No action is needed from
  you." (Sanctioned exception to the name-the-fixer grammar: there is genuinely no
  user step.)

**Launch flow:** click → button locks immediately (double-click protection), label
"Opening…", aria-live announces "Opening {App}." → browser receives only the safe
launch URL and navigates (the one-time token exchange is server-to-server and has no
visual slot). Failure: button returns to idle; one Clay-wash strip below the footer —
"Could not open {App}. Try again." + `ref SWZ-XXXXXX` chip; strip updates in place on
retry, never stacks.

**Empty states:** no workspaces → ACCESS block: "No workspaces are linked to this
account." / "Your sign-in worked, but this account is not a member of any workspace
yet. Ask a workspace owner or admin to add you." (no retry button — the fix is
human). Workspace with no products enabled → quiet row: "No products are enabled for
this workspace. Ask a workspace owner or admin about access." All-unavailable: cards
still render in their denied states — hiding an app would misreport the registry.

### 7.3 Workspace admin (`/app/admin?workspaceId=…`)

Frame: alpha strip (always the scoped workspace: `INTERNAL ALPHA · {WS} ·
role: {role}`) → header + "Back to launcher" → title "Workspace admin" + mono
workspace name → section index `01 Workspace / 02 Add member / 03 Owner transfer /
04 Members / 05 Product access / 06 Activity` (anchors) → six registry blocks in
contract order. Non-admin or mis-scoped access → redirect to `/app` with generic
notice: "Workspace admin is available to owners and admins." — no partial render, no
workspace-existence leak.

**01 Workspace** (`#workspace`) — definition rows: Name / Workspace id (mono, safe
display form, copyable) / Your role (`role: owner`).

**02 Add member** (`#add-member`) — email input + role select (admin / member /
viewer — owner never offered) + primary "Add to workspace" (CSRF POST). Helper:
"No invitation email is sent. Ask the teammate to sign in with the approved Google
account."

Flow (pending-approval membership model): the owner/admin enters email + role. If a
provider-backed user with that normalised email already exists, Platform adds an
active membership immediately. If the user has not signed in yet, Platform records a
**pending workspace approval**; when the teammate later completes a real
provider-backed sign-in with the same normalised email, Platform activates and links
the membership. No fake users, no fake provider identities, no email delivery, no
public signup. A pending approval grants no launch or admin access until activated.

Outcome banner, identical on every path: "Access request recorded. If this account
already exists, the membership is active now. If not, it will activate after the
teammate signs in with the approved Google account." Server failure: generic
sentence + `ref` chip.

Members table: pending memberships render as ordinary rows with a mono `pending`
status chip and no launch/admin effect; row actions on pending rows follow the
pending-approval backend contract once it lands. The registry reports pending
entries honestly rather than hiding them.

> **Implementation dependency.** This Add member design assumes the pending-approval
> backend lands before implementation. If it has not landed, implementation must
> either wait or ship the current add-existing-user flow ("Teammate must sign in
> once first. No invitation delivery.") strictly as a temporary bootstrap state — it
> is not the target production UX and must not be presented as such.

**03 Owner transfer** (`#owner-transfer`) — inert placeholder sub-block (Mineral
fill, tag `OWNER TRANSFER`), mandated copy: "Owner transfer is not available in
internal alpha yet." No fake button.

**04 Members** (`#members`) — table: Name / Email (mono) / Role / Status / Last login
(mono absolute + visible muted relative) / Actions. Guardrails render as static text
+ visually-hidden reason, never greyed controls: own row → role as static chip,
"You cannot change your own role.", no Disable; sole owner → "A workspace must keep
at least one active owner."; inactive member → static role + status text. Disable
opens the inline destructive confirm row beneath the member row (Clay wash, focus
moves in, scrolls into view): "Disable {name} for this workspace? They keep their
history but cannot use this workspace. Nothing is deleted." → [Disable member]
[Cancel]. Role changes announce via the status line and appear in Activity.

**05 Product access** (`#app-access`) — context line: "Control which apps this
workspace can launch. Changes apply to all workspace members immediately." Per-app
table, registry order (two rows: `kqag`, `sgca`):

| App | Status | Granted by | Updated | Action |
|---|---|---|---|---|
| `KQAG` KQAG `private preview` | `● enabled` | mono email or `platform operator` | `2026-07-03 14:12 SGT` | Disable |
| `SGCA` SEO/GEO Content Automation `private preview` | `○ disabled` | — | — | **Enable** |

- Enable confirm (neutral, Paper): "Enable {App} for this workspace? Owners, admins,
  and members will be able to launch it. A viewer role cannot launch apps." →
  [Enable app] (Verdigris — granting is the reserved accent act) [Cancel].
- Disable confirm (Clay wash): "Disable {App} for this workspace? Members lose the
  ability to launch it immediately. Nothing inside {App} is deleted or changed." →
  [Disable app] (ink solid, deliberately not Verdigris) [Keep enabled].
- One confirm strip open at a time; buttons lock in flight ("Applying…"); success
  collapses the strip, updates Status/Granted by/Updated in place, announces via
  aria-live, and appears in Activity. Failure: "Could not update access. Try again.
  Nothing was changed." + `ref` chip.
- Suspended row: `⊘ suspended`, Granted by `platform operator`, no action button —
  "Suspended by the platform operator. Workspace admins cannot change this."
- Trial row: `◔ trial` + Disable available; no end dates, counters, credits or
  upgrade prompts anywhere.

**06 Activity** (`#activity`) — caption `AUD – LAST 50 · newest first`. Table: Action
(human copy first — "Member added", "KQAG access enabled" — with the raw event type
`workspace.membership.added` beneath in mono 11px Slate) / Subject / Actor (system
actions attributed to "Swooshz Platform") / Time (mono absolute + visible muted
relative) / Details (allowlisted fragments only: previous/new role or status, app
key — never tokens, claims, or payloads). Truncation footer whenever 50 rows render:
"Showing the 50 most recent events. Older events are retained but not shown here."
Empty: "No activity recorded yet. Workspace events will appear here as they happen."
Error: "Activity could not be loaded." + `ref` chip + quiet Retry.

### 7.4 Copy sample sheet (canonical strings)

| Slot | Copy |
|---|---|
| Hero eyebrow (mandated) | Swooshz Platform internal access |
| Hero headline (recommended) | Access your workspace's AI business tools. |
| Hero capability line | Swooshz builds and hosts AI-powered tools for business operations — from quote automation to SEO and AI-search content. |
| Hero body (mandated) | Access requires an approved provider-backed account for your workspace. No public signup is available. |
| CTA (mandated) | Continue with Google |
| Login helper | Expecting access? Ask a workspace owner or admin to add your account. |
| Post-logout notice (mandated) | You are signed out of Swooshz Platform. Your Google account may still be signed in. |
| Add-member helper | No invitation email is sent. Ask the teammate to sign in with the approved Google account. |
| Add-member outcome (all paths) | Access request recorded. If this account already exists, the membership is active now. If not, it will activate after the teammate signs in with the approved Google account. |
| Launcher status line | signed in as {email} · {n} workspaces |
| Workspace header | WS – {NAME} · role: {role} |
| KQAG card | KQAG · private preview · "Generate quotes and manage quotation workflows." · [Launch KQAG] |
| SEO card | SEO/GEO Content Automation · private preview · "Create, approve, and publish SEO and GEO content for search and AI discovery." · [Launch] |
| Denied — role | Your role does not permit launching apps. Ask a workspace owner or admin about access. |
| Denied — not enabled | {App} is not enabled for this workspace. Ask a workspace owner or admin about access. |
| Launch busy / failure | Opening… / Could not open {App}. Try again. `ref SWZ-XXXXXX` |
| Sign-out button (mandated) | Sign out of Swooshz Platform |
| Alpha strip | INTERNAL ALPHA · {WORKSPACE} · role: {role} (multi: INTERNAL ALPHA · {n} workspaces) |

Voice rules: verbs first; no exclamation marks; no marketing adjectives; roles and
statuses lowercase in labels (prose recast to avoid sentence-initial role words);
Singapore English spelling in prose; system tokens rendered exactly as emitted;
buttons carry no trailing punctuation; Verdigris appears only where access is being
granted.

---

## 8. Risks if the UI becomes too product-specific too early

| # | Risk | Consequence | Guardrail |
|---|---|---|---|
| 1 | Hardcoded product names/copy ("KQAG", "quote") scattered through shared components and audit copy | Adding product #2 becomes a string hunt; misses ship quote-flavoured copy on SEO surfaces; Platform silently becomes "the KQAG admin panel" | Single-source app registry `{app_key, display_name, app_status}` is the only place a product name may be literal; CI grep fails the build on product-name literals elsewhere |
| 2 | Launcher cards grow product-runtime widgets (quote counts, article stats, site lists) | Platform starts fetching product data — a second data-security surface; every future product must build a bespoke widget to look "complete" | Freeze the card contract to six props: `app_key, display_name, app_status, entitlement_state, can_launch, denial_reason`; anything not derivable from access data belongs inside the product |
| 3 | Entitlement UI shaped around one product ("Enable quoting") | Product #2 cannot be represented without redesign; data model gets bent to match the UI | Generic workspace-by-app matrix, four canonical states only, all copy templated on `{app_name}` |
| 4 | Audit vocabulary coupled to product #1 (`kqag_access_granted`) | Two naming dialects in one log the day product #2 ships; renaming rewrites history | Event names are platform verbs (`app.launched`, `entitlement.changed`) with `app_key` as a structured field, never in the name |
| 5 | Platform brand welds to KQAG (logo, palette, tone in Platform chrome) | The white-label SEO product forever looks like a bolt-on inside a quoting tool | Platform keeps its own neutral wordmark and palette; product identity appears only inside registry-supplied cards |
| 6 | Product-capability copy in Platform empty states ("No quotes yet…") | Nonsense the moment a workspace has SEO but not KQAG; normalises product dashboards in the hub | Copy rule: Platform speaks only about access, never capability |
| 7 | Per-product denial copy ("Your quoting trial has ended") | Copy drifts per app and leaks entitlement/business detail; a copy matrix nobody maintains | Denial UI renders exclusively from the fixed three-token enum, one template per token |
| 8 | Admin IA assumes one app (singleton settings page, implicit `kqag` filters) | IA/routing rework mid-alpha; "the app" defaults ambiguously — the class of bug that produces access-control mistakes | "Design for N=2, ship with N=2": every surface and query keyed by `app_key`, rendered as a registry list; no default app anywhere |
| 9 | Product #2 integrated with an ad-hoc identifier | Inconsistent keys fragment entitlement checks and audit queries; migration on security-relevant tables later | Agree the key before any integration (placeholder `sgca` — unconfirmed until the product contract is approved; do not mint as final); keys 3–5 lowercase ASCII letters, immutable once written; only `display_name` may change |
| 10 | `private_preview` rendered as a bespoke KQAG-only badge | Each product lifecycle state needs new bespoke UI; status semantics diverge | One shared app-status chip driven solely by the registry enum, with a documented unknown-value fallback |

Summary: the whole class collapses to one architectural habit plus three cheap rules —
(1) a single app registry consumed everywhere via `app_key`, enforced by one CI grep;
(2) a frozen six-prop launcher-card contract; (3) "Platform speaks access, never
capability"; (4) design for N=2 from day one. Naming conventions, one config file,
one component contract, one grep — no process overhead.

---

## 9. Assumptions and open items to confirm

1. **App key for the SEO product:** `sgca` is a placeholder only and must NOT be
   minted as final. It remains unconfirmed until vendor SSO/API/workspace/billing
   details are confirmed and the product contract is approved. It propagates into
   record tags, ordering, entitlement rows, denial templates and audit payloads, and
   is expensive to change once alpha data exists — so no registration, entitlements,
   or SEO integration work until then; the second card in this spec is conceptual.
2. **Pending-approval backend dependency:** the Add member design (§7.3-02) assumes
   the pending-approval membership backend lands before implementation. Until it
   lands, the current add-existing-user flow may ship only as a temporary bootstrap
   state, never presented as the target production UX.
3. **Canonical display names:** "KQAG" vs "SAQG" for the quote product;
   "SEO/GEO Content Automation" is a working name only. If a confirmed name is long,
   the button label shortens to "Launch" with the full accessible name retained.
4. **SEO product app status:** assumed `private_preview` to match KQAG until
   registered.
5. **Reassurance clauses** assume the backend guarantees: failed sign-in writes no
   user-visible state; entitlement toggles never touch product data; failed POSTs
   apply nothing. If any guarantee does not hold, drop the clause.
6. **Legal footer:** no Privacy/Terms routes exist; the public footer is one
   plain-text line + contact until legal pages are added to the route contract.
7. **Dark scheme:** out of scope by mandate; the Mineral/Verdigris relationship does
   not invert trivially — a future dark theme is a re-derivation, not a token flip.
8. The reference product linked in the brief was used as category context only: it
   was not visited during this work, and no branding, naming, layout or copy derives
   from it.

## 10. Next steps

1. Confirm the naming/status assumptions (§9.1, §9.3–9.4) with the product owner.
2. Land the pending-approval membership backend before implementing Add member
   (§7.3-02); until then the existing add-existing-user flow is bootstrap-only.
3. Approve the direction (or request changes) — the spec above is written so a coding
   agent can implement it 1:1 against the existing `platform-shell.ts` baseline:
   token remap, two font families, one new container pattern, the inline confirm
   row (~30 lines of JS), and copy.
4. Encode the scope guardrails (§8) as the registry file, the card-contract comment,
   and the CI grep at the same time as the restyle — they are cheapest before the
   second product exists.

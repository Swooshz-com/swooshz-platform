# ADR 0007: HTTP Transport And CSRF Strategy

## Status

Accepted.

## Context

Swooshz Platform now has provider-agnostic auth contracts, platform session persistence, storage-agnostic session revocation, a protected app-access decision service, and framework-agnostic browser session cookie plus plain-object HTTP handler contracts.

The repository still has no real HTTP server, framework route wiring, CSRF middleware, frontend, KQAG adapter, live database usage, or app launch tokens. The next implementation step needs a clear route and CSRF posture before real browser-cookie endpoints are wired.

## Decision

Keep the current code framework-agnostic for the next phase. Define route contracts now and add a real HTTP adapter only in a later PR.

The first real route wiring should adapt the existing plain-object handlers to the selected server/framework boundary. It must not move platform account, session, app-access, or KQAG-launch decisions into framework route code.

## HTTP Transport And Framework Boundary

Selected direction: continue framework-agnostic handlers and contracts now.

Do not select Express, Fastify, Hono, Next.js, Vite, React, or another server/frontend framework in this ADR.

Reasons:

- The current handlers are already testable with plain objects and no live server.
- Keeping the boundary framework-agnostic minimizes dependency surface while backend contracts are still settling.
- Future Coolify/VPS deployment can support a small Node HTTP adapter or lightweight framework later without changing domain services.
- Avoiding Next.js/Vite/React keeps frontend shell work deferred until backend auth, session, persistence, app access, and launch boundaries are stable.
- Cookie and header handling rules can be documented and tested before selecting framework-specific APIs.

Deferred framework choices:

- Minimal Node HTTP adapter.
- Hono.
- Fastify.
- Express.
- Any future frontend-hosted API framework.

A later ADR or implementation PR must justify the adapter choice against deployment simplicity, TypeScript compatibility, cookie/header support, testability, dependency surface, and frontend coupling.

## CSRF Posture

Swooshz Platform will use browser cookies for platform sessions, so state-changing browser-cookie routes require CSRF protection.

Rules:

- Browser session cookies default to `SameSite=Lax`.
- Production HTTP wiring must set `Secure=true` for browser session cookies.
- State-changing routes using browser cookies must be non-GET and require CSRF protection.
- Future POST, PUT, PATCH, and DELETE routes must require Origin/Referer validation plus a CSRF token strategy.
- The selected CSRF strategy for future state-changing routes is `origin_referer_and_csrf_token`.
- CSRF tokens must not be stored in route code, committed `.env` files, logs, or response bodies where they are not intended.
- Do not weaken CSRF posture for convenience during frontend or framework wiring.

Logout:

- Real logout route wiring must be `POST /api/platform/logout`.
- Logout remains idempotent and privacy-safe, but it is still state-changing because it revokes platform session state and clears a cookie.
- Logout must require the shared CSRF posture when implemented as a real browser-cookie route.

Auth callback:

- OIDC callback protection relies on state and nonce validation from the auth callback contract.
- Generic CSRF middleware alone is not a substitute for OIDC state/nonce validation.
- Raw callback URLs, auth codes, state values, nonce values, provider responses, and provider claims must not be logged or exposed.

Safe GETs:

- `GET /healthz` is unauthenticated and side-effect free.
- `GET /api/platform/session/app-access` reads a browser session cookie and selected workspace/app query parameters. It must not mutate platform records, create launch tokens, or call KQAG.

## Initial Route Contract Map

The initial route contract map is defined in `src/http/route-contracts.ts`.

Initial routes:

- `GET /healthz`
  - No auth.
  - No browser session cookie.
  - No CSRF requirement.
  - No secrets or private data in the response.

- `GET /api/platform/session/app-access`
  - Requires browser session cookie.
  - Requires `workspaceId` and `appKey` query parameters.
  - Calls the protected app-access handler contract.
  - Returns privacy-safe `200`, `401`, `403`, or `500` responses.
  - Does not mutate platform records.
  - Does not create app launch tokens or call KQAG.

- `POST /api/platform/logout`
  - Reads browser session cookie if present.
  - Calls the logout handler contract.
  - Clears the browser session cookie.
  - Returns a uniform privacy-safe logout response.
  - Requires CSRF posture when wired to a real HTTP server.

Deferred routes:

- `GET /api/auth/login`.
- `GET /api/auth/callback`.
- Workspace selection endpoints.
- Invitation acceptance endpoints.
- KQAG app launch endpoint.
- Admin workspace, membership, invitation, app registry, and entitlement APIs.
- Internal dashboards or frontend routes.

## Response And Privacy Conventions

HTTP responses must use safe, consistent bodies:

- Success bodies may include platform-scoped ids needed by frontend or downstream platform code.
- Error bodies must use generic messages and stable safe reason codes.
- Never include stack traces in response bodies.
- Never include raw cookies, raw session tokens, session secrets, provider tokens, auth codes, access tokens, refresh tokens, ID tokens, raw OIDC/provider claims, raw provider responses, database URLs, SQL, private filesystem paths, customer/company/bank data, quote exports, pricing files, embedded logos, or private app payloads.
- `401` is used for missing, revoked, or expired browser sessions.
- `403` is used for authenticated platform sessions that fail app-access authorization.
- `500` is used for generic privacy-safe service failures.

Headers:

- Session cookies must be `HttpOnly`.
- `Path=/` is the default.
- `SameSite=Lax` is the default.
- `Secure` is required in production.
- Logout clears the session cookie with `Max-Age=0` and an expired `Expires` timestamp.

Logging:

- Detailed logging policy is deferred.
- Future logs may include route id, method, path template, status code, request id, timestamp, and high-level error code.
- Future logs must not include raw cookies, tokens, secrets, provider payloads, SQL, DB URLs, or private app/customer data.

## Environment And Config Boundary

Future HTTP wiring may use these configuration names:

- `HTTP_PUBLIC_BASE_URL`.
- `HTTP_ALLOWED_ORIGINS`.
- `HTTP_COOKIE_NAME`.
- `HTTP_COOKIE_SECURE`.
- `HTTP_TRUST_PROXY`.
- `NODE_ENV` or `APP_ENV`.
- `AUTH_REDIRECT_URI`.
- `SESSION_SECRET`.
- `CSRF_SECRET` or a later approved CSRF key name.

This ADR does not add populated `.env` files or real environment values.

Environment examples, if added later, must use synthetic placeholders only.

## Options Considered

### Continue Framework-Agnostic Handlers Now

Pros:

- Preserves current testability.
- Adds no dependencies.
- Keeps HTTP route decisions explicit before framework code exists.
- Reduces risk of accidentally coupling frontend or auth provider choices to route implementation.

Cons:

- Real network behavior is still deferred.
- Framework-specific cookie, proxy, and header details still need later validation.

Conclusion: selected.

### Minimal Node HTTP Adapter First

Pros:

- Very small dependency surface.
- Good deployment fit for simple VPS/Coolify setups.
- Keeps full control over request parsing and response writing.

Cons:

- Requires hand-written routing, middleware, body parsing, and CSRF wiring.
- Easy to miss framework conveniences for security headers, cookie handling, and testing.

Conclusion: deferred.

### Lightweight Framework Later

Pros:

- Hono, Fastify, or Express could provide mature routing and middleware patterns.
- Can simplify cookie/header and route tests once real endpoints are needed.

Cons:

- Adds dependency and convention surface.
- May encourage route-centric business logic if boundaries are not enforced.
- Does not need to be selected before route contracts and CSRF posture are accepted.

Conclusion: deferred.

## Explicit Non-Goals

This ADR does not implement:

- Real HTTP server.
- Express, Fastify, Hono, Next.js, Vite, React, or any route framework.
- Middleware.
- Frontend/login shell.
- Browser UI.
- Real OIDC network calls.
- Provider SDK integration.
- Clerk/Auth0/Supabase Auth coupling.
- CSRF token generation, storage, or middleware.
- App launch token.
- Redirect URL generation.
- KQAG adapter.
- KQAG repo changes.
- Workspace selection UI.
- Membership changes.
- Entitlement changes.
- Audit event writes.
- Schema changes.
- Migrations.
- Live DB usage.
- Billing, credits, or Stripe.

## Consequences

The next implementation PR can wire real HTTP endpoints against `src/http/route-contracts.ts`, `src/http/handlers.ts`, and `src/http/session-cookie.ts`.

Before real browser-cookie state-changing routes ship, the implementation must add and test Origin/Referer validation plus the selected CSRF token strategy. Real route wiring must preserve the existing privacy-safe response and module-boundary rules.

import { publicAssetUrl } from "./public-asset-manifest.js";

type PublicRoute =
  | "home"
  | "solutions"
  | "resources"
  | "about"
  | "contact"
  | "request-access"
  | "login";

interface PublicDocumentOptions {
  title: string;
  route: PublicRoute;
  body: string;
  preloadHero?: boolean;
}

const heroAvifSrcset = [640, 960, 1280, 1672]
  .map((width) => `${publicAssetUrl(`/public-assets/hero-monument-${width}.avif`)} ${width}w`)
  .join(", ");

const heroWebpSrcset = [640, 960, 1280, 1672]
  .map((width) => `${publicAssetUrl(`/public-assets/hero-monument-${width}.webp`)} ${width}w`)
  .join(", ");

const heroPngSrcset = [640, 1280]
  .map((width) => `${publicAssetUrl(`/public-assets/hero-monument-${width}.png`)} ${width}w`)
  .join(", ");

export function renderLandingPage(): string {
  return publicDocument({
    title: "Swooshz Platform",
    route: "home",
    preloadHero: true,
    body: `
      ${publicNav("home")}
      <main id="main-content" class="public-page">
        <section id="welcome" class="prestige-hero home-scene" data-scroll-scene data-public-hero aria-labelledby="home-heading">
          <div class="prestige-hero-copy">
            <p class="public-label">Swooshz Platform / Entry 01</p>
            <h1 id="home-heading">
              <span>One trusted place.</span>
              <span>Your Swooshz tools</span>
              <span class="public-accent">within reach.</span>
            </h1>
            <p class="prestige-hero-lede">
              Enter once, find your approved workspace, and reach the Swooshz
              applications available to your team.
            </p>
            <div class="prestige-hero-actions">
              <a class="public-button" href="/login"><span>Enter the platform</span><b aria-hidden="true">&nearr;</b></a>
              <a class="public-quiet-link" href="#platform-positioning"><span>See the connection</span><b aria-hidden="true">&darr;</b></a>
            </div>
          </div>
          ${heroPicture("prestige-hero-art", true)}
          <div class="hero-index" aria-hidden="true">
            <span>01</span><i></i><b>Trusted account</b>
            <span>02</span><i></i><b>Approved workspace</b>
            <span>03</span><i></i><b>Focused product</b>
          </div>
        </section>

        <section id="platform-positioning" class="viewport-scene positioning-scene home-scene" data-scroll-scene aria-labelledby="positioning-heading">
          <div class="positioning-grid">
            <div class="positioning-copy">
              <p class="public-label">Platform positioning</p>
              <h2 id="positioning-heading">The relationship stays clear.</h2>
              <p>
                Swooshz Platform is the workspace platform for launching trusted business apps. Each
                approved application remains focused on its own work.
              </p>
            </div>
            <div class="positioning-lines" aria-label="Platform relationship">
              <p><span>01</span>One provider-backed account</p>
              <p><span>02</span>Your approved workspace context</p>
              <p><span>03</span>Only applications available to that workspace</p>
            </div>
          </div>
        </section>

        <section id="account-workspace-application" class="viewport-scene dark-scene home-scene" data-scroll-scene aria-labelledby="bridge-heading">
          <div class="bridge-layout">
            <div class="bridge-intro">
              <p class="public-label">Account &rarr; workspace &rarr; application</p>
              <h2 id="bridge-heading">A calm place to arrive. <em class="public-accent">A precise place to continue.</em></h2>
              <p>
                Platform brings account, workspace membership, role context,
                and approved application access together without pulling
                specialised product workflows into the platform itself.
              </p>
            </div>
            <div class="bridge-ledger">
              <article>
                <span>01</span>
                <div><h3>One trusted account</h3><p>Provider-backed entry begins the journey.</p></div>
              </article>
              <article>
                <span>02</span>
                <div><h3>Your approved workspace</h3><p>Membership and role determine the working context.</p></div>
              </article>
              <article>
                <span>03</span>
                <div><h3>Focused Swooshz applications</h3><p>Entitlement checks keep each separate product launch intentional.</p></div>
              </article>
            </div>
          </div>
        </section>

        <section id="quote-auto-generator" class="viewport-scene product-scene home-scene" data-scroll-scene aria-labelledby="product-heading">
          <div class="product-layout">
            <div class="product-copy">
              <p class="public-label">Available product</p>
              <h2 id="product-heading">Swooshz Quote Auto Generator</h2>
              <p>
                Launch the quotation product from an approved workspace after
                Platform confirms access. Product workflows and generated artefacts stay with the product.
              </p>
              <p class="product-boundary">Platform opens the door. The product leads the work.</p>
              <a class="public-button" href="/solutions"><span>Explore the solution</span><b aria-hidden="true">&rarr;</b></a>
            </div>
            <div class="paper-stage" aria-hidden="true">
              <div class="paper-sheet"></div>
              <div class="paper-seam"></div>
              <div class="paper-caption">A separate app launched from Platform through an approved workspace boundary.</div>
            </div>
          </div>
        </section>

        <section id="next-step" class="viewport-scene closing-scene home-scene" data-scroll-scene aria-labelledby="closing-heading">
          <div class="closing-layout">
            <div>
              <p class="public-label">Your next step</p>
              <h2 id="closing-heading">Ready when your workspace is.</h2>
            </div>
            <aside class="closing-aside">
              <p>
                Access is approved through your existing Swooshz or workspace sponsor channel. There is no public signup. SEO / GEO / Seozilla: Unavailable until confirmed. Vendor workflow pending.
              </p>
              <div class="closing-actions">
                <a class="public-button" href="/request-access"><span>Understand access</span><b aria-hidden="true">&nearr;</b></a>
                <a class="public-button-secondary" href="/login">Continue with Google</a>
              </div>
            </aside>
          </div>
        </section>
      </main>
      ${publicFooter()}
    `,
  });
}

export function renderSolutionsPage(): string {
  return publicDocument({
    title: "Swooshz Platform Solutions",
    route: "solutions",
    body: `
      ${publicNav("solutions")}
      <main id="main-content" class="public-page">
        <section class="editorial-hero" aria-labelledby="solutions-heading">
          <div class="editorial-hero-copy">
            <p class="public-label">Swooshz applications</p>
            <h1 id="solutions-heading">Focused products, reached through one trusted place.</h1>
            <p class="lede">
              Platform handles account entry, workspace context, roles, approved
              application access, and launch. Each product remains responsible
              for its specialised work.
            </p>
          </div>
        </section>
        <section class="editorial-section" aria-label="Product availability">
          <article class="product-chapter">
            <span class="product-chapter-number">01</span>
            <div>
              <p class="public-label">Available for approved workspaces</p>
              <h2>Swooshz Quote Auto Generator</h2>
              <p>
                A separate product app launched from Platform for quotation workflows. Platform verifies workspace access and entitlement before launch; the product owns its workflows, generated artefacts, and product history.
              </p>
              <a class="public-button" href="/login"><span>Enter the platform</span><b aria-hidden="true">&nearr;</b></a>
            </div>
          </article>
          <article class="product-chapter">
            <span class="product-chapter-number">02</span>
            <div>
              <p class="public-label">Unavailable / vendor-pending</p>
              <h2>SEO / GEO / Seozilla</h2>
              <p>
                Unavailable until confirmed. Vendor workflow pending. It cannot be launched or purchased through Platform.
              </p>
              <span class="availability-note">Vendor workflow pending</span>
            </div>
          </article>
        </section>
        <section class="editorial-section dark">
          <div class="editorial-split">
            <div class="editorial-heading">
              <p class="public-label">The boundary</p>
              <h2>Shared access. Separate product ownership.</h2>
            </div>
            <div class="editorial-copy">
              <article><h3>Platform owns the entry</h3><p>Access Management and Workspace Entitlements cover accounts, sessions, workspaces, memberships, roles, application access, launch, administration, and audit boundaries. Visible workspace roles remain Owner, Admin, Member, and Pending.</p></article>
              <article><h3>The product owns the workflow</h3><p>Swooshz Quote Auto Generator keeps quotation logic and product runtime data within its own application.</p></article>
            </div>
          </div>
        </section>
      </main>
      ${publicFooter()}
    `,
  });
}

export function renderResourcesPage(): string {
  return publicDocument({
    title: "Swooshz Platform Resources",
    route: "resources",
    body: `
      ${publicNav("resources")}
      <main id="main-content" class="public-page">
        <section class="editorial-hero" aria-labelledby="resources-heading">
          <div class="editorial-hero-copy">
            <p class="public-label">Resources</p>
            <h1 id="resources-heading">Notes for understanding the Platform boundary.</h1>
            <p class="lede">Content pending editorial review. A small collection about approved access, workspace context, and separate product launches.</p>
          </div>
        </section>
        <section class="editorial-section resource-index" aria-labelledby="resource-list-heading">
          <aside class="resource-topics" aria-label="Resource topics">
            <p class="public-label">Topics</p>
            <span>Platform access</span>
            <span>Provider-backed entry</span>
            <span>Workspace readiness</span>
            <span>Product boundaries</span>
          </aside>
          <div class="resource-list">
            <h2 id="resource-list-heading" class="public-label">Editorial index</h2>
            <article class="resource-entry">
              <span>01</span>
              <div>
                <h3><a href="/resources/platform-launch-boundaries">How Swooshz Platform launches workspace apps safely</a></h3>
                <p>Workspace approval, provider-backed access, entitlement checks, and the boundary between Platform and a launched product.</p>
                <a href="/resources/platform-launch-boundaries">Read the article &rarr;</a>
              </div>
            </article>
            <article class="resource-entry">
              <span>02</span>
              <div><h3>Provider-backed access matters</h3><p>Editorial review pending. Publishing details have not been assigned.</p></div>
            </article>
            <article class="resource-entry">
              <span>03</span>
              <div><h3>Preparing workspace access before launch</h3><p>Editorial review pending. No filtering or resource count is implied.</p></div>
            </article>
            <article class="resource-entry">
              <span>04</span>
              <div><h3>Keeping product workflow data outside Platform</h3><p>Editorial review pending. Swooshz Quote Auto Generator remains a separate app launched from Platform; no production claim is included.</p></div>
            </article>
          </div>
        </section>
      </main>
      ${publicFooter()}
    `,
  });
}

export function renderResourceArticlePage(): string {
  return publicDocument({
    title: "How Swooshz Platform Launches Workspace Apps Safely",
    route: "resources",
    body: `
      ${publicNav("resources")}
      <main id="main-content" class="public-page reading-shell">
        <a class="reading-back" href="/resources">&larr; Back to Resources</a>
        <article>
          <header class="reading-hero">
            <p class="public-label">Platform access</p>
            <h1>How Swooshz Platform launches workspace apps safely</h1>
            <p class="lede">
              Article template pending editorial approval. A clear view of the account, workspace, entitlement, and product boundaries that shape an approved launch.
            </p>
          </header>
          <div class="article-layout">
            <div class="article-body">
              <section id="workspace-first">
                <h2>Access starts with the workspace</h2>
                <p>Swooshz Platform is responsible for the access surface around workspace applications. It checks the signed-in account, selected workspace, membership role, and application entitlement before a launch path is available.</p>
              </section>
              <section id="provider-entry">
                <h2>Provider-backed access</h2>
                <p>Access is not self-service. A user arrives through an approved provider-backed account associated with an approved workspace, and Platform evaluates whether the requested application is available.</p>
              </section>
              <aside class="article-callout">
                <strong>Boundary note</strong>
                <p>Swooshz Quote Auto Generator is launched as a separate application. Its quotation workflows and runtime data stay outside Platform.</p>
              </aside>
              <section id="product-launch">
                <h2>A separate product launch</h2>
                <p>Platform coordinates access and launch. Swooshz Quote Auto Generator remains a separate app launched from Platform, and product workflow data stays outside Platform.</p>
              </section>
              <section id="unavailable-products">
                <h2>Unavailable product areas stay unavailable</h2>
                <p>SEO / GEO / Seozilla: Unavailable until confirmed. Vendor workflow pending. The public website does not suggest that it can be launched, purchased, or accessed.</p>
              </section>
            </div>
            <aside class="article-sidebar" aria-labelledby="article-outline-heading">
              <h2 id="article-outline-heading">In this article</h2>
              <ul>
                <li><a href="#workspace-first">Workspace first</a></li>
                <li><a href="#provider-entry">Provider-backed entry</a></li>
                <li><a href="#product-launch">Separate launch</a></li>
                <li><a href="#unavailable-products">Unavailable products</a></li>
              </ul>
            </aside>
          </div>
        </article>
      </main>
      ${publicFooter()}
    `,
  });
}

export function renderAboutPage(): string {
  return publicDocument({
    title: "About Swooshz",
    route: "about",
    body: `
      ${publicNav("about")}
      <main id="main-content" class="public-page">
        <section class="editorial-hero" aria-labelledby="about-heading">
          <div class="editorial-hero-copy">
            <p class="public-label">About Swooshz</p>
            <h1 id="about-heading">Clarity at the point where people and products meet.</h1>
            <p class="lede">Swooshz Platform creates one deliberate place for account entry, workspace access and context, and approved application access.</p>
          </div>
        </section>
        <section class="editorial-section">
          <div class="editorial-split">
            <div class="editorial-heading"><p class="public-label">Brand principles</p><h2>Broad enough to hold the relationship. Quiet enough to let each product lead.</h2></div>
            <div class="editorial-copy">
              <article><h3>Clear ownership</h3><p>Platform explains and enforces its access boundary without absorbing specialised product work.</p></article>
              <article><h3>Approved context</h3><p>Provider-backed accounts, active workspace membership, roles, and entitlements shape what a person can reach.</p></article>
              <article><h3>Focused continuation</h3><p>Approved applications launch separately and remain responsible for their own workflows and runtime data.</p></article>
            </div>
          </div>
        </section>
        <section class="editorial-section dark">
          <div class="editorial-split">
            <div class="editorial-heading"><p class="public-label">A restrained system</p><h2>Precision before noise.</h2></div>
            <div class="editorial-copy"><article><h3>Truthful public language</h3><p>No invented company history, metrics, customers, awards, integrations, or access promises.</p></article><article><h3>Purposeful product boundaries</h3><p>Swooshz Quote Auto Generator remains a separate app launched from Platform. SEO / GEO / Seozilla: Unavailable until confirmed. Vendor workflow pending.</p></article></div>
          </div>
        </section>
      </main>
      ${publicFooter()}
    `,
  });
}

export function renderContactPage(): string {
  return publicDocument({
    title: "Contact Swooshz",
    route: "contact",
    body: `
      ${publicNav("contact")}
      <main id="main-content" class="public-page form-route">
        <section class="form-hero" aria-labelledby="contact-heading">
          <p class="public-label">Access enquiry</p>
          <h1 id="contact-heading">Start with the channel you already trust.</h1>
          <p class="lede">For workspace approval or access questions, use your existing Swooshz or workspace sponsor channel.</p>
        </section>
        <aside class="contact-path" aria-labelledby="contact-path-heading">
          <h2 id="contact-path-heading">Available contact path</h2>
          <p>This page does not submit a message or create a support request. No public enquiry backend is available.</p>
          <p>Do not send secrets, cookies, provider tokens, private customer data, or product records through an unapproved channel.</p>
          <a class="public-button" href="/request-access"><span>Review access steps</span><b aria-hidden="true">&rarr;</b></a>
          <a class="public-button-secondary" href="/login">Continue to access entry</a>
        </aside>
      </main>
      ${publicFooter()}
    `,
  });
}

export function renderRequestAccessPage(): string {
  return publicDocument({
    title: "Request Access - Swooshz Platform",
    route: "request-access",
    body: `
      ${publicNav("request-access")}
      <main id="main-content" class="public-page form-route">
        <section class="form-hero" aria-labelledby="request-access-heading">
          <p class="public-label">Workspace access</p>
          <h1 id="request-access-heading">A connected path into your workspace.</h1>
          <p class="lede">Access begins with an approved workspace and continues through the provider account associated with it.</p>
          <div class="truth-note"><strong>No public signup is available.</strong> This page does not create an account, send a request, or grant application access.</div>
        </section>
        <section aria-label="Access journey">
          <div class="journey-list">
            <article><span>01</span><div><h2>Speak with your sponsor</h2><p>Use your existing Swooshz or workspace sponsor channel to request review.</p></div></article>
            <article><span>02</span><div><h2>Workspace approval is recorded</h2><p>Membership and role establish the workspace context available after sign-in.</p></div></article>
            <article><span>03</span><div><h2>Continue with Google</h2><p>Use the approved provider-backed account associated with your workspace.</p></div></article>
            <article><span>04</span><div><h2>Launch approved applications</h2><p>Workspace entitlements determine which separate Swooshz products can open.</p></div></article>
          </div>
          <div class="prestige-hero-actions">
            <a class="public-button" href="/login"><span>Go to access entry</span><b aria-hidden="true">&nearr;</b></a>
            <a class="public-button-secondary" href="/contact">Contact guidance</a>
          </div>
        </section>
      </main>
      ${publicFooter()}
    `,
  });
}

export function renderLoginPage(): string {
  return publicDocument({
    title: "Swooshz Platform Access",
    route: "login",
    body: `
      <main id="main-content" class="login-route">
        <div class="login-art">
          <a class="login-home-link" href="/"><img src="${publicAssetUrl("/public-assets/swooshz-mark.png")}" width="34" height="34" alt=""><span>Swooshz</span></a>
          ${heroPicture("", true)}
        </div>
        <section class="login-panel" aria-labelledby="login-heading">
          <p class="public-label">Secure Access Portal</p>
          <h1 id="login-heading">Continue to your workspace.</h1>
          <p id="signedOutNotice" class="signed-out" hidden>You are signed out of Swooshz Platform. Your Google account may still be signed in.</p>
          <p class="lede">Access requires an approved provider-backed account. Use the approved Google account for your workspace. No public signup is available.</p>
          <div class="login-actions">
            <a class="public-button" href="/api/platform/auth/start"><span>Continue with Google</span><b aria-hidden="true">&nearr;</b></a>
            <a class="public-button-secondary" href="/app">Already signed in? Continue to app</a>
            <a class="public-quiet-link" href="/request-access"><span>Understand access</span><b aria-hidden="true">&rarr;</b></a>
          </div>
        </section>
      </main>
      <script>
        (() => {
          const notice = document.getElementById("signedOutNotice");
          if (new URLSearchParams(window.location.search).get("signedOut") === "1" && notice) notice.hidden = false;
        })();
      </script>
    `,
  });
}

function publicDocument({ title, route, body, preloadHero = false }: PublicDocumentOptions): string {
  const preload = preloadHero
    ? `<link rel="preload" as="image" href="${publicAssetUrl("/public-assets/hero-monument-1280.avif")}" imagesrcset="${heroAvifSrcset}" imagesizes="(max-width: 720px) 170vw, (max-width: 900px) 116vw, min(82vw, 1240px)" type="image/avif" fetchpriority="high">`
    : "";

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#f5f6f2">
  <title>${title}</title>
  ${preload}
  <link rel="icon" href="${publicAssetUrl("/public-assets/swooshz-mark.png")}" type="image/png">
  <link rel="stylesheet" href="${publicAssetUrl("/public-assets/public-site.css")}">
  <script defer src="${publicAssetUrl("/public-assets/public-site.js")}"></script>
</head>
<body class="public-site" data-public-route="${route}">
  <a class="public-skip-link" href="#main-content">Skip to main content</a>
  ${body}
</body>
</html>`;
}

function heroPicture(className: string, eager: boolean): string {
  return `
    <figure class="${className}" ${className ? "data-public-hero-art" : ""}>
      <picture>
        <source type="image/avif" srcset="${heroAvifSrcset}" sizes="(max-width: 720px) 170vw, (max-width: 900px) 116vw, min(82vw, 1240px)">
        <source type="image/webp" srcset="${heroWebpSrcset}" sizes="(max-width: 720px) 170vw, (max-width: 900px) 116vw, min(82vw, 1240px)">
        <img src="${publicAssetUrl("/public-assets/hero-monument-1280.png")}" srcset="${heroPngSrcset}" sizes="(max-width: 720px) 170vw, (max-width: 900px) 116vw, min(82vw, 1240px)" width="1672" height="941" alt="" ${eager ? 'loading="eager" fetchpriority="high"' : 'loading="lazy"'} decoding="async">
      </picture>
      ${className ? "<figcaption>Entry / context / focus</figcaption>" : ""}
    </figure>
  `;
}

function publicNav(active: Exclude<PublicRoute, "login">): string {
  const current = (route: PublicRoute) => active === route ? ' aria-current="page"' : "";

  return `
    <header class="public-nav">
      <a class="public-brand" href="/" aria-label="Swooshz Platform home">
        <img src="${publicAssetUrl("/public-assets/swooshz-mark.png")}" width="34" height="34" alt="">
        <span>Swooshz</span><small>Platform</small>
      </a>
      <nav class="public-primary-nav" aria-label="Public navigation" data-public-navigation>
        <a href="/"${current("home")}>The idea</a>
        <a class="" href="/solutions"${current("solutions")}>Solutions</a>
        <a class="" href="/resources"${current("resources")}>Resources</a>
        <a class="" href="/about"${current("about")}>About</a>
        <a class="" href="/contact"${current("contact")}>Contact</a>
        <a class="mobile-only" href="/login">Login</a>
        <a class="mobile-only" href="/request-access"${current("request-access")}>Request access</a>
      </nav>
      <div class="public-nav-actions">
        <a class="public-nav-login" href="/login">Login</a>
        <a class="public-button public-nav-cta" href="/request-access"><span>Request access</span><b aria-hidden="true">&nearr;</b></a>
        <button class="public-menu-toggle" type="button" aria-expanded="false" aria-controls="public-navigation" aria-label="Open navigation" data-public-menu-toggle><span></span><span></span></button>
      </div>
    </header>
  `.replace("data-public-navigation", 'id="public-navigation" data-public-navigation');
}

function publicFooter(): string {
  return `
    <footer class="public-footer">
      <a class="public-footer-brand" href="/"><img src="${publicAssetUrl("/public-assets/swooshz-mark.png")}" width="28" height="28" alt=""><span>Swooshz Platform</span></a>
      <nav aria-label="Footer navigation">
        <a class="" href="/solutions">Solutions</a>
        <a class="" href="/resources">Resources</a>
        <a class="" href="/about">About</a>
        <a class="" href="/contact">Contact</a>
        <a href="/request-access">Request access</a>
      </nav>
      <p>Approved access only. No public signup.</p>
    </footer>
  `;
}

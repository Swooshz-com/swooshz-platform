type PublicActiveRoute =
  | "home"
  | "solutions"
  | "resources"
  | "about"
  | "contact"
  | "requestAccess"
  | "login";

type IconName =
  | "account"
  | "app"
  | "arrow"
  | "book"
  | "check"
  | "close"
  | "globe"
  | "layers"
  | "lock"
  | "menu"
  | "spark"
  | "swoosh"
  | "workspace";

const ICONS: Record<IconName, string> = {
  account:
    '<circle cx="12" cy="8" r="3.2"/><path d="M5.5 20c.6-3.3 2.8-5 6.5-5s5.9 1.7 6.5 5"/>',
  app: '<rect x="4" y="4" width="16" height="16" rx="3"/><path d="M8 9h8M8 13h5M8 17h3"/>',
  arrow: '<path d="M5 12h13M13 6l6 6-6 6"/>',
  book: '<path d="M5 5.5A2.5 2.5 0 0 1 7.5 3H19v16H7.5A2.5 2.5 0 0 0 5 21.5z"/><path d="M5 5.5v16M9 7h6M9 11h6"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
  close: '<path d="m6 6 12 12M18 6 6 18"/>',
  globe: '<circle cx="12" cy="12" r="8"/><path d="M4 12h16M12 4c2 2.2 3 4.9 3 8s-1 5.8-3 8c-2-2.2-3-4.9-3-8s1-5.8 3-8Z"/>',
  layers: '<path d="m12 4 8 4-8 4-8-4 8-4Z"/><path d="m4 12 8 4 8-4M4 16l8 4 8-4"/>',
  lock: '<rect x="5" y="10" width="14" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/>',
  menu: '<path d="M4 7h16M4 12h16M4 17h16"/>',
  spark: '<path d="m12 3 1.6 5.4L19 10l-5.4 1.6L12 17l-1.6-5.4L5 10l5.4-1.6L12 3Z"/><path d="m19 16 .7 2.3L22 19l-2.3.7L19 22l-.7-2.3L16 19l2.3-.7L19 16Z"/>',
  swoosh: '<path d="M5 7.5c2.6-2.8 7.2-3.2 10.7-1.1 2.2 1.3 2.4 3.3.2 4.4l-4.1 2.1c-2.1 1.1-2.2 2.5-.2 3.6 1.8 1 4.1.8 6.1-.5-1.2 3.1-4.3 4.6-7.5 3.5-3.1-1-4.6-3.5-2.2-5.3l4.3-3.2c1.2-.9.8-1.9-.6-2.2-2.1-.5-4.7.1-6.7 1.7Z"/>',
  workspace: '<path d="M4 20V8l8-4 8 4v12H4Z"/><path d="M8 20v-5h8v5M8 9h.01M12 9h.01M16 9h.01"/>',
};

const PUBLIC_STYLES = String.raw`
  :root {
    color-scheme: light;
  }

  .public-document-body {
    margin: 0;
    min-width: 320px;
    background: #f7f3ec;
  }

  .public-site {
    --public-canvas: #f7f3ec;
    --public-surface: #fffdf9;
    --public-surface-warm: #f1e9dc;
    --public-ink: #20211f;
    --public-muted: #6e6b63;
    --public-line: #ded6c9;
    --public-accent: #bd5a3e;
    --public-accent-dark: #963f2b;
    --public-olive: #7d8053;
    --public-olive-soft: #e6e5d3;
    --public-shadow: 0 24px 70px rgb(49 39 28 / 11%);
    --public-shadow-soft: 0 12px 34px rgb(49 39 28 / 8%);
    min-height: 100vh;
    overflow: clip;
    background:
      radial-gradient(circle at 93% 9%, rgb(230 183 155 / 20%), transparent 24rem),
      var(--public-canvas);
    color: var(--public-ink);
    font-family: "Avenir Next", "Segoe UI", ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
    line-height: 1.55;
  }

  .public-site *,
  .public-site *::before,
  .public-site *::after {
    box-sizing: border-box;
  }

  .public-site a,
  .public-site button {
    font: inherit;
  }

  .public-site a {
    color: inherit;
  }

  .public-site a:focus-visible,
  .public-site button:focus-visible {
    outline: 3px solid rgb(189 90 62 / 42%);
    outline-offset: 4px;
  }

  .public-site h1,
  .public-site h2,
  .public-site h3,
  .public-site p {
    margin-top: 0;
  }

  .public-site h1,
  .public-site h2,
  .public-site h3 {
    color: var(--public-ink);
    font-weight: 700;
    letter-spacing: -0.045em;
  }

  .public-site p {
    color: var(--public-muted);
  }

  .public-icon {
    display: block;
    width: 1.15rem;
    height: 1.15rem;
    fill: none;
    stroke: currentColor;
    stroke-linecap: round;
    stroke-linejoin: round;
    stroke-width: 1.75;
  }

  .public-header {
    position: sticky;
    top: 0;
    z-index: 10;
    border-bottom: 1px solid rgb(222 214 201 / 78%);
    background: rgb(255 253 249 / 92%);
    backdrop-filter: blur(16px);
  }

  .public-header-inner {
    width: min(1320px, calc(100% - 48px));
    min-height: 76px;
    display: flex;
    align-items: center;
    gap: 2rem;
    margin: 0 auto;
  }

  .public-brand {
    display: inline-flex;
    align-items: center;
    gap: 0.75rem;
    min-width: max-content;
    color: var(--public-ink);
    text-decoration: none;
  }

  .public-brand-mark {
    display: grid;
    width: 2.25rem;
    height: 2.25rem;
    place-items: center;
    border-radius: 0.75rem;
    background: var(--public-accent);
    color: #fffdf9;
    box-shadow: 0 7px 18px rgb(189 90 62 / 22%);
  }

  .public-brand-icon {
    width: 1.55rem;
    height: 1.55rem;
    fill: currentColor;
    stroke: none;
  }

  .public-brand-copy {
    display: grid;
    gap: 0.05rem;
  }

  .public-brand-name {
    font-size: 1.05rem;
    font-weight: 800;
    letter-spacing: -0.035em;
    line-height: 1.1;
  }

  .public-brand-subtitle {
    color: var(--public-muted);
    font-size: 0.62rem;
    font-weight: 700;
    letter-spacing: 0.12em;
    line-height: 1.2;
    text-transform: uppercase;
  }

  .public-nav-links {
    display: flex;
    align-items: center;
    gap: clamp(1rem, 2.3vw, 2.35rem);
    margin: 0 auto;
  }

  .public-nav-link {
    position: relative;
    padding: 0.5rem 0;
    color: var(--public-muted);
    font-size: 0.86rem;
    font-weight: 650;
    text-decoration: none;
    transition: color 180ms ease;
  }

  .public-nav-link::after {
    position: absolute;
    right: 0;
    bottom: 0.1rem;
    left: 0;
    height: 2px;
    border-radius: 999px;
    background: var(--public-accent);
    content: "";
    opacity: 0;
    transform: scaleX(0.35);
    transition: opacity 180ms ease, transform 180ms ease;
  }

  .public-nav-link:hover,
  .public-nav-link.is-active {
    color: var(--public-ink);
  }

  .public-nav-link.is-active::after,
  .public-nav-link:hover::after {
    opacity: 1;
    transform: scaleX(1);
  }

  .public-header-actions {
    display: flex;
    align-items: center;
    gap: 1rem;
  }

  .public-login-link {
    color: var(--public-muted);
    font-size: 0.86rem;
    font-weight: 700;
    text-decoration: none;
    transition: color 180ms ease;
  }

  .public-login-link:hover {
    color: var(--public-ink);
  }

  .public-access-cta,
  .public-button {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.65rem;
    min-height: 3rem;
    padding: 0 1.25rem;
    border: 1px solid transparent;
    border-radius: 999px;
    font-size: 0.88rem;
    font-weight: 750;
    text-decoration: none;
    transition: background 180ms ease, border-color 180ms ease, color 180ms ease, transform 180ms ease, box-shadow 180ms ease;
  }

  .public-access-cta,
  .public-button-primary {
    background: var(--public-ink);
    color: #fffdf9;
    box-shadow: 0 10px 20px rgb(32 33 31 / 12%);
  }

  .public-access-cta:hover,
  .public-button-primary:hover {
    background: var(--public-accent);
    box-shadow: 0 14px 24px rgb(189 90 62 / 18%);
    transform: translateY(-2px);
  }

  .public-access-cta .public-icon,
  .public-button-primary .public-icon {
    transition: transform 180ms ease;
  }

  .public-access-cta:hover .public-icon,
  .public-button-primary:hover .public-icon {
    transform: translateX(3px);
  }

  .public-button-secondary {
    border-color: var(--public-line);
    background: rgb(255 253 249 / 66%);
    color: var(--public-ink);
  }

  .public-button-secondary:hover {
    border-color: var(--public-accent);
    background: var(--public-surface);
    transform: translateY(-2px);
  }

  .public-menu-toggle {
    display: none;
    width: 2.75rem;
    height: 2.75rem;
    margin-left: auto;
    padding: 0;
    border: 1px solid var(--public-line);
    border-radius: 999px;
    background: var(--public-surface);
    color: var(--public-ink);
    cursor: pointer;
  }

  .public-mobile-menu {
    width: min(1320px, calc(100% - 48px));
    margin: 0 auto;
    padding: 0 0 1rem;
  }

  .public-mobile-menu[hidden] {
    display: none;
  }

  .public-mobile-nav {
    display: grid;
    gap: 0.35rem;
    padding: 0.75rem 0 0.5rem;
    border-top: 1px solid var(--public-line);
  }

  .public-mobile-nav .public-nav-link {
    padding: 0.8rem 0;
  }

  .public-mobile-menu .public-button {
    width: 100%;
    margin-top: 0.5rem;
  }

  .public-hero,
  .public-section,
  .public-page-intro,
  .public-footer-inner {
    width: min(1240px, calc(100% - 56px));
    margin: 0 auto;
  }

  .public-hero {
    position: relative;
    display: grid;
    grid-template-columns: minmax(0, 0.88fr) minmax(420px, 1.12fr);
    gap: clamp(3rem, 7vw, 7.5rem);
    align-items: center;
    min-height: 650px;
    padding-top: 5.75rem;
    padding-bottom: 6.5rem;
  }

  .public-hero::before {
    position: absolute;
    top: 7rem;
    left: -6rem;
    width: 20rem;
    height: 20rem;
    border-radius: 50%;
    background: rgb(220 170 139 / 14%);
    content: "";
    filter: blur(2px);
    pointer-events: none;
  }

  .hero-copy {
    position: relative;
    z-index: 1;
  }

  .hero-signal {
    display: inline-flex;
    align-items: center;
    gap: 0.55rem;
    width: 4rem;
    height: 0.35rem;
    margin-bottom: 1.6rem;
    border-radius: 999px;
    background: var(--public-accent);
  }

  .hero-signal::after {
    width: 0.45rem;
    height: 0.45rem;
    margin-left: 4.45rem;
    border-radius: 50%;
    background: var(--public-accent);
    content: "";
  }

  .hero-copy h1 {
    max-width: 650px;
    margin-bottom: 1.6rem;
    font-size: clamp(3.8rem, 6.7vw, 6.8rem);
    line-height: 0.94;
  }

  .hero-lede {
    max-width: 560px;
    margin-bottom: 2rem;
    font-size: clamp(1.05rem, 1.4vw, 1.25rem);
    line-height: 1.7;
  }

  .public-button-row {
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem;
  }

  .hero-proof {
    display: flex;
    flex-wrap: wrap;
    gap: 0.8rem 1.25rem;
    margin-top: 1.7rem;
    color: var(--public-muted);
    font-size: 0.78rem;
    font-weight: 650;
  }

  .hero-proof span {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
  }

  .hero-proof .public-icon {
    width: 0.9rem;
    height: 0.9rem;
    color: var(--public-olive);
  }

  .access-map {
    position: relative;
    z-index: 1;
    display: grid;
    gap: 1.25rem;
    padding: 1.35rem;
    border: 1px solid rgb(222 214 201 / 84%);
    border-radius: 1.8rem;
    background: rgb(255 253 249 / 70%);
    box-shadow: var(--public-shadow);
  }

  .access-map::after {
    position: absolute;
    right: -1.1rem;
    bottom: -1.1rem;
    width: 8rem;
    height: 8rem;
    border-radius: 50%;
    background: rgb(126 129 83 / 18%);
    content: "";
    filter: blur(1px);
    pointer-events: none;
  }

  .access-map-top,
  .product-callout-top,
  .section-heading-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
  }

  .access-map-top {
    padding: 0.25rem 0.4rem 0.7rem;
    color: var(--public-muted);
    font-size: 0.68rem;
    font-weight: 800;
    letter-spacing: 0.12em;
    text-transform: uppercase;
  }

  .map-status {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    letter-spacing: 0;
    text-transform: none;
  }

  .map-status::before,
  .availability-status::before {
    width: 0.45rem;
    height: 0.45rem;
    border-radius: 50%;
    background: var(--public-olive);
    content: "";
  }

  .access-map-stack {
    display: grid;
    gap: 0.75rem;
  }

  .map-card {
    position: relative;
    display: flex;
    align-items: center;
    gap: 1rem;
    min-height: 7rem;
    padding: 1.1rem;
    border: 1px solid var(--public-line);
    border-radius: 1.2rem;
    background: var(--public-surface);
    box-shadow: var(--public-shadow-soft);
    transition: transform 220ms ease, border-color 220ms ease, box-shadow 220ms ease;
  }

  .map-card:hover {
    border-color: var(--public-accent);
    box-shadow: 0 20px 34px rgb(49 39 28 / 13%);
    transform: translateX(0.35rem);
  }

  .map-card-app {
    border-color: var(--public-accent);
  }

  .map-icon {
    display: grid;
    width: 3.15rem;
    height: 3.15rem;
    flex: 0 0 auto;
    place-items: center;
    border-radius: 1rem;
    background: var(--public-surface-warm);
    color: var(--public-accent-dark);
  }

  .map-card-workspace .map-icon {
    background: var(--public-olive-soft);
    color: #5d603a;
  }

  .map-card-app .map-icon {
    background: var(--public-accent);
    color: #fffdf9;
  }

  .map-card strong,
  .map-card small {
    display: block;
  }

  .map-card strong {
    color: var(--public-ink);
    font-size: 1.05rem;
    letter-spacing: -0.025em;
  }

  .map-card small {
    margin-top: 0.25rem;
    color: var(--public-muted);
    font-size: 0.78rem;
  }

  .map-connector {
    position: relative;
    height: 1.2rem;
    margin-left: 1.55rem;
    border-left: 1px dashed rgb(189 90 62 / 62%);
  }

  .map-connector::after {
    position: absolute;
    bottom: -0.25rem;
    left: -0.35rem;
    display: grid;
    width: 0.65rem;
    height: 0.65rem;
    place-items: center;
    border-radius: 50%;
    background: var(--public-accent);
    color: #fffdf9;
    content: "✓";
    font-size: 0.45rem;
    font-weight: 900;
  }

  .public-section {
    padding-top: 6rem;
    padding-bottom: 6rem;
  }

  .public-section-tonal {
    width: 100%;
    max-width: none;
    padding-right: max(28px, calc((100% - 1240px) / 2));
    padding-left: max(28px, calc((100% - 1240px) / 2));
    background: rgb(241 233 220 / 58%);
  }

  .public-section-heading {
    max-width: 650px;
    margin-bottom: 2.5rem;
  }

  .public-kicker {
    margin-bottom: 0.8rem;
    color: var(--public-accent-dark);
    font-size: 0.7rem;
    font-weight: 850;
    letter-spacing: 0.14em;
    text-transform: uppercase;
  }

  .public-section-heading h2,
  .public-page-intro h1 {
    margin-bottom: 0.8rem;
    font-size: clamp(2.4rem, 4.5vw, 4.3rem);
    line-height: 1;
  }

  .public-section-heading p {
    max-width: 620px;
    margin-bottom: 0;
    font-size: 1.05rem;
  }

  .feature-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 1rem;
  }

  .feature-card {
    min-height: 14rem;
    display: grid;
    align-content: start;
    gap: 1rem;
    padding: 1.6rem;
    border-top: 2px solid var(--public-line);
    transition: border-color 180ms ease, transform 180ms ease;
  }

  .feature-card:hover {
    border-top-color: var(--public-accent);
    transform: translateY(-0.25rem);
  }

  .feature-icon {
    display: grid;
    width: 2.7rem;
    height: 2.7rem;
    place-items: center;
    border-radius: 0.9rem;
    background: var(--public-surface);
    color: var(--public-accent-dark);
  }

  .feature-card h3 {
    margin-bottom: 0;
    font-size: 1.35rem;
  }

  .feature-card p {
    margin-bottom: 0;
    font-size: 0.96rem;
  }

  .product-callout {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(280px, 0.8fr);
    gap: 3rem;
    align-items: center;
    padding: clamp(2rem, 5vw, 4rem);
    border-radius: 2rem;
    background: var(--public-ink);
    color: #fffdf9;
    overflow: hidden;
  }

  .product-callout h2,
  .product-callout h3,
  .product-callout p {
    color: inherit;
  }

  .product-callout h2 {
    max-width: 620px;
    margin-bottom: 1rem;
    font-size: clamp(2.3rem, 4vw, 4.2rem);
    line-height: 0.98;
  }

  .product-callout p {
    max-width: 580px;
    margin-bottom: 1.5rem;
    color: rgb(255 253 249 / 72%);
  }

  .product-callout .public-kicker {
    color: #e7b29d;
  }

  .product-callout-art {
    position: relative;
    min-height: 250px;
    display: grid;
    place-items: center;
  }

  .product-orbit {
    width: min(18rem, 100%);
    aspect-ratio: 1;
    display: grid;
    place-items: center;
    border: 1px solid rgb(255 253 249 / 22%);
    border-radius: 50%;
    transform: rotate(-12deg);
  }

  .product-orbit::before,
  .product-orbit::after {
    position: absolute;
    width: 0.8rem;
    height: 0.8rem;
    border-radius: 50%;
    background: var(--public-accent);
    content: "";
  }

  .product-orbit::before {
    top: 0.5rem;
    right: 4rem;
  }

  .product-orbit::after {
    bottom: 2rem;
    left: 1rem;
    background: #adb18b;
  }

  .product-orbit-card {
    display: grid;
    gap: 0.4rem;
    width: 10.5rem;
    min-height: 9rem;
    padding: 1rem;
    border: 1px solid rgb(255 253 249 / 25%);
    border-radius: 1.2rem;
    background: rgb(255 253 249 / 11%);
    transform: rotate(12deg);
  }

  .product-orbit-card strong {
    color: #fffdf9;
    font-size: 1rem;
  }

  .product-orbit-card small {
    color: rgb(255 253 249 / 62%);
    font-size: 0.72rem;
  }

  .product-orbit-card .public-icon {
    color: #e7b29d;
  }

  .availability-row {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    min-height: 2rem;
    padding: 0 0.8rem;
    border: 1px solid rgb(255 253 249 / 17%);
    border-radius: 999px;
    color: #e9ebd6;
    font-size: 0.78rem;
    font-weight: 750;
  }

  .access-steps {
    counter-reset: access-step;
  }

  .access-step-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 1rem;
  }

  .access-step {
    position: relative;
    padding-top: 3rem;
  }

  .access-step::before {
    position: absolute;
    top: 0;
    left: 0;
    display: grid;
    width: 2.25rem;
    height: 2.25rem;
    place-items: center;
    border-radius: 50%;
    background: var(--public-surface-warm);
    color: var(--public-accent-dark);
    content: counter(access-step, decimal-leading-zero);
    counter-increment: access-step;
    font-size: 0.78rem;
    font-weight: 850;
  }

  .access-step h3 {
    margin-bottom: 0.5rem;
    font-size: 1.15rem;
  }

  .access-step p {
    margin-bottom: 0;
    font-size: 0.92rem;
  }

  .public-final-cta {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 2rem;
    padding: 2rem 0 1rem;
    border-top: 1px solid var(--public-line);
  }

  .public-final-cta h2 {
    margin-bottom: 0.5rem;
    font-size: clamp(2rem, 3.5vw, 3.5rem);
  }

  .public-final-cta p {
    margin-bottom: 0;
  }

  .public-footer {
    padding: 4.5rem 0 1.5rem;
    background: var(--public-ink);
    color: #fffdf9;
  }

  .public-footer-inner {
    display: grid;
    grid-template-columns: minmax(0, 1.3fr) minmax(160px, 0.7fr) minmax(220px, 0.9fr);
    gap: 3rem;
  }

  .public-footer .public-brand-name,
  .public-footer .public-brand-subtitle,
  .public-footer p,
  .public-footer a {
    color: inherit;
  }

  .public-footer .public-brand-subtitle,
  .public-footer p,
  .public-footer a {
    color: rgb(255 253 249 / 64%);
  }

  .public-footer p {
    max-width: 330px;
    margin: 1rem 0 0;
    font-size: 0.9rem;
  }

  .public-footer h2 {
    margin-bottom: 1rem;
    color: #fffdf9;
    font-size: 0.8rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
  }

  .public-footer nav {
    display: grid;
    gap: 0.7rem;
  }

  .public-footer a {
    font-size: 0.9rem;
    text-decoration: none;
    transition: color 180ms ease;
  }

  .public-footer a:hover {
    color: #fffdf9;
  }

  .public-footer-note {
    padding-left: 1.25rem;
    border-left: 1px solid rgb(255 253 249 / 20%);
  }

  .public-footer-bottom {
    width: min(1240px, calc(100% - 56px));
    margin: 3.5rem auto 0;
    padding-top: 1rem;
    border-top: 1px solid rgb(255 253 249 / 14%);
    color: rgb(255 253 249 / 44%);
    font-size: 0.78rem;
  }

  .public-page-intro {
    display: grid;
    gap: 1rem;
    padding-top: 6.5rem;
    padding-bottom: 4rem;
  }

  .public-page-intro h1 {
    max-width: 880px;
    margin-bottom: 0;
    font-size: clamp(3.2rem, 6vw, 6.3rem);
  }

  .public-page-intro > p:last-child {
    max-width: 720px;
    margin-bottom: 0;
    font-size: 1.1rem;
    line-height: 1.7;
  }

  .solutions-hero-art {
    display: grid;
    gap: 0.85rem;
    padding: 1.4rem;
    border-radius: 1.7rem;
    background: var(--public-ink);
    color: #fffdf9;
    box-shadow: var(--public-shadow);
  }

  .solutions-hero-art > strong {
    color: rgb(255 253 249 / 66%);
    font-size: 0.7rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
  }

  .solution-stack {
    display: grid;
    gap: 0.75rem;
  }

  .solution-stack-card {
    display: flex;
    align-items: center;
    gap: 1rem;
    min-height: 5.2rem;
    padding: 1rem;
    border: 1px solid rgb(255 253 249 / 18%);
    border-radius: 1rem;
    background: rgb(255 253 249 / 9%);
  }

  .solution-stack-card:first-child {
    border-color: #e5b29c;
    background: rgb(189 90 62 / 18%);
  }

  .solution-stack-card strong,
  .solution-stack-card small {
    display: block;
  }

  .solution-stack-card strong {
    color: #fffdf9;
    font-size: 1rem;
  }

  .solution-stack-card small {
    margin-top: 0.2rem;
    color: rgb(255 253 249 / 62%);
    font-size: 0.78rem;
  }

  .solution-stack-card .public-icon {
    color: #e5b29c;
  }

  .capability-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 1rem;
  }

  .capability-card {
    display: grid;
    align-content: start;
    gap: 1rem;
    min-height: 18rem;
    padding: 1.6rem;
    border: 1px solid var(--public-line);
    border-radius: 1.4rem;
    background: var(--public-surface);
    box-shadow: var(--public-shadow-soft);
  }

  .capability-card h2 {
    margin-bottom: 0;
    font-size: 1.35rem;
  }

  .capability-card p {
    margin-bottom: 0;
    font-size: 0.95rem;
  }

  .role-list {
    display: flex;
    flex-wrap: wrap;
    gap: 0.45rem;
    margin-top: auto;
  }

  .role-list span {
    padding: 0.35rem 0.55rem;
    border-radius: 999px;
    background: var(--public-surface-warm);
    color: var(--public-accent-dark);
    font-size: 0.7rem;
    font-weight: 800;
  }

  .unavailable-card {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr) auto;
    align-items: center;
    gap: 1rem;
    padding: 1.4rem 1.6rem;
    border: 1px dashed var(--public-line);
    border-radius: 1.3rem;
    background: rgb(255 253 249 / 48%);
  }

  .unavailable-card h2,
  .unavailable-card p {
    margin-bottom: 0;
  }

  .unavailable-card h2 {
    font-size: 1.1rem;
  }

  .unavailable-card p {
    font-size: 0.88rem;
  }

  .status-pill,
  .resource-card-status {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-height: 2rem;
    padding: 0 0.75rem;
    border: 1px solid var(--public-line);
    border-radius: 999px;
    color: var(--public-muted);
    font-size: 0.7rem;
    font-weight: 800;
    white-space: nowrap;
  }

  .resources-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 1rem;
    padding-bottom: 6rem;
  }

  .resource-card {
    display: grid;
    align-content: start;
    min-height: 22rem;
    border: 1px solid var(--public-line);
    border-radius: 1.4rem;
    background: var(--public-surface);
    overflow: hidden;
    box-shadow: var(--public-shadow-soft);
  }

  .resource-card-featured {
    grid-column: span 2;
  }

  .resource-card-visual {
    position: relative;
    min-height: 10rem;
    display: grid;
    place-items: center;
    background:
      radial-gradient(circle at 30% 30%, rgb(189 90 62 / 25%) 0 0.35rem, transparent 0.4rem),
      linear-gradient(135deg, #f0e0d3, #e7ebdd);
  }

  .resource-card-visual::before,
  .resource-card-visual::after {
    position: absolute;
    border: 1px solid rgb(189 90 62 / 35%);
    border-radius: 50%;
    content: "";
  }

  .resource-card-visual::before {
    width: 9rem;
    height: 9rem;
  }

  .resource-card-visual::after {
    width: 5rem;
    height: 5rem;
    border-color: rgb(125 128 83 / 48%);
  }

  .resource-card-visual span {
    position: relative;
    z-index: 1;
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.5rem 0.75rem;
    border: 1px solid rgb(255 253 249 / 70%);
    border-radius: 999px;
    background: rgb(255 253 249 / 78%);
    color: var(--public-ink);
    font-size: 0.7rem;
    font-weight: 800;
  }

  .resource-card-body {
    display: grid;
    align-content: start;
    gap: 0.7rem;
    padding: 1.45rem;
  }

  .resource-card-kicker {
    color: var(--public-accent-dark);
    font-size: 0.68rem;
    font-weight: 850;
    letter-spacing: 0.12em;
    text-transform: uppercase;
  }

  .resource-card h2 {
    margin-bottom: 0;
    font-size: 1.35rem;
    line-height: 1.1;
  }

  .resource-card p {
    margin-bottom: 0;
    font-size: 0.92rem;
  }

  .resource-card-link {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    margin-top: auto;
    padding-top: 0.8rem;
    color: var(--public-accent-dark);
    font-size: 0.82rem;
    font-weight: 800;
    text-decoration: none;
  }

  .resource-card-link .public-icon {
    width: 0.9rem;
    height: 0.9rem;
    transition: transform 180ms ease;
  }

  .resource-card-link:hover .public-icon {
    transform: translateX(3px);
  }

  .resource-card-inert {
    background: rgb(255 253 249 / 48%);
    box-shadow: none;
  }

  .resource-card-inert .resource-card-visual {
    background: linear-gradient(135deg, #ede8df, #e9eadf);
    filter: saturate(0.7);
  }

  .article-shell {
    width: min(1120px, calc(100% - 56px));
    padding-top: 4.5rem;
    padding-bottom: 6rem;
  }

  .article-breadcrumb {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-bottom: 2rem;
    color: var(--public-muted);
    font-size: 0.82rem;
  }

  .article-breadcrumb a {
    color: var(--public-accent-dark);
    font-weight: 750;
    text-decoration: none;
  }

  .article-hero {
    width: min(820px, 100%);
    margin-bottom: 3rem;
  }

  .article-hero h1 {
    margin-bottom: 1rem;
    font-size: clamp(3rem, 5.5vw, 5.6rem);
    line-height: 0.98;
  }

  .article-hero > p:last-child {
    max-width: 690px;
    margin-bottom: 0;
    font-size: 1.08rem;
    line-height: 1.75;
  }

  .article-visual {
    min-height: 280px;
    display: grid;
    place-items: center;
    margin-bottom: 3rem;
    padding: 2rem;
    border: 1px solid var(--public-line);
    border-radius: 1.6rem;
    background:
      radial-gradient(circle at 50% 30%, rgb(189 90 62 / 15%), transparent 13rem),
      var(--public-surface-warm);
  }

  .article-flow {
    width: min(760px, 100%);
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 0.65rem;
    align-items: center;
  }

  .article-flow-step {
    position: relative;
    display: grid;
    min-height: 6rem;
    place-items: center;
    align-content: center;
    gap: 0.45rem;
    padding: 0.8rem;
    border: 1px solid var(--public-line);
    border-radius: 1rem;
    background: var(--public-surface);
    text-align: center;
  }

  .article-flow-step strong {
    font-size: 0.8rem;
  }

  .article-flow-step small {
    color: var(--public-muted);
    font-size: 0.68rem;
  }

  .article-flow-step:not(:last-child)::after {
    position: absolute;
    top: 50%;
    right: -0.9rem;
    width: 1.1rem;
    border-top: 1px dashed var(--public-accent);
    content: "";
  }

  .article-layout {
    display: grid;
    grid-template-columns: 190px minmax(0, 700px);
    gap: 3.5rem;
    align-items: start;
    justify-content: center;
  }

  .article-toc {
    position: sticky;
    top: 6.5rem;
    display: grid;
    gap: 0.65rem;
    padding-top: 0.3rem;
  }

  .article-toc strong {
    margin-bottom: 0.35rem;
    font-size: 0.72rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
  }

  .article-toc a {
    color: var(--public-muted);
    font-size: 0.8rem;
    text-decoration: none;
  }

  .article-toc a:hover {
    color: var(--public-accent-dark);
  }

  .article-body {
    display: grid;
    gap: 2.7rem;
  }

  .article-body section {
    scroll-margin-top: 7rem;
  }

  .article-body h2 {
    margin-bottom: 0.75rem;
    font-size: clamp(1.8rem, 3vw, 2.6rem);
    line-height: 1.05;
  }

  .article-body p {
    margin-bottom: 0;
    color: var(--public-ink);
    font-size: 1.04rem;
    line-height: 1.85;
  }

  .article-callout {
    display: grid;
    gap: 0.65rem;
    padding: 1.5rem;
    border-left: 3px solid var(--public-accent);
    border-radius: 0 1rem 1rem 0;
    background: var(--public-surface-warm);
  }

  .article-callout strong {
    color: var(--public-accent-dark);
  }

  .public-split-layout {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(280px, 0.72fr);
    gap: 1rem;
    padding-bottom: 6rem;
  }

  .public-panel {
    display: grid;
    align-content: start;
    gap: 1.2rem;
    padding: clamp(1.6rem, 4vw, 3.5rem);
    border: 1px solid var(--public-line);
    border-radius: 1.6rem;
    background: var(--public-surface);
    box-shadow: var(--public-shadow-soft);
  }

  .public-panel-dark {
    background: var(--public-ink);
    color: #fffdf9;
  }

  .public-panel-dark h2,
  .public-panel-dark p,
  .public-panel-dark .public-kicker {
    color: inherit;
  }

  .public-panel-dark p {
    color: rgb(255 253 249 / 70%);
  }

  .public-panel h2 {
    margin-bottom: 0;
    font-size: clamp(2rem, 3.6vw, 3.3rem);
    line-height: 1;
  }

  .public-panel p {
    margin-bottom: 0;
  }

  .guidance-list {
    display: grid;
    gap: 0.9rem;
  }

  .guidance-item {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr);
    gap: 0.8rem;
    padding-top: 0.9rem;
    border-top: 1px solid var(--public-line);
  }

  .guidance-item .public-icon {
    color: var(--public-accent);
  }

  .access-requirement-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 0.85rem;
    padding-bottom: 2rem;
  }

  .access-requirement {
    display: grid;
    align-content: start;
    gap: 0.6rem;
    min-height: 13rem;
    padding: 1.25rem;
    border: 1px solid var(--public-line);
    border-radius: 1.2rem;
    background: var(--public-surface);
  }

  .access-requirement-number {
    color: var(--public-accent);
    font-size: 0.75rem;
    font-weight: 850;
  }

  .access-requirement h2 {
    margin-bottom: 0;
    font-size: 1.2rem;
  }

  .access-requirement p {
    margin-bottom: 0;
    font-size: 0.88rem;
  }

  .access-notice {
    display: grid;
    gap: 0.55rem;
    margin-bottom: 2rem;
    padding: 1.3rem 1.5rem;
    border-left: 3px solid var(--public-accent);
    border-radius: 0 1rem 1rem 0;
    background: var(--public-surface-warm);
  }

  .access-notice h2,
  .access-notice p {
    margin-bottom: 0;
  }

  .access-notice h2 {
    font-size: 1.1rem;
  }

  .access-notice p {
    font-size: 0.92rem;
  }

  .centered-actions {
    justify-content: center;
  }

  .login-page {
    width: min(1120px, calc(100% - 56px));
    display: grid;
    grid-template-columns: minmax(0, 0.95fr) minmax(320px, 0.78fr);
    gap: 1rem;
    align-items: stretch;
    margin: 0 auto;
    padding: 5rem 0 6rem;
  }

  .login-panel {
    display: grid;
    align-content: center;
    gap: 1.25rem;
    min-height: 38rem;
    padding: clamp(2rem, 5vw, 4rem);
    border-radius: 1.8rem;
    background: var(--public-ink);
    color: #fffdf9;
    box-shadow: var(--public-shadow);
  }

  .login-panel h1,
  .login-panel p {
    color: inherit;
  }

  .login-panel h1 {
    max-width: 520px;
    margin-bottom: 0;
    font-size: clamp(3.4rem, 6vw, 5.8rem);
    line-height: 0.96;
  }

  .login-panel > p:not(.signed-out) {
    color: rgb(255 253 249 / 70%);
  }

  .login-brand {
    display: inline-flex;
    align-items: center;
    gap: 0.75rem;
    color: #fffdf9;
    font-size: 1.15rem;
    font-weight: 800;
  }

  .login-brand .public-brand-mark {
    width: 2rem;
    height: 2rem;
    background: var(--public-accent);
  }

  .provider-button {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.7rem;
    width: 100%;
    min-height: 3.25rem;
    padding: 0 1.25rem;
    border: 0;
    border-radius: 0.85rem;
    background: #fffdf9;
    color: var(--public-ink);
    font-weight: 800;
    text-decoration: none;
    transition: background 180ms ease, transform 180ms ease;
  }

  .provider-button:hover {
    background: #f2e7d9;
    transform: translateY(-2px);
  }

  .provider-button .public-icon {
    color: var(--public-accent-dark);
  }

  .signed-out {
    padding: 0.85rem 1rem;
    border: 1px solid rgb(231 178 157 / 55%);
    border-radius: 0.9rem;
    background: rgb(189 90 62 / 18%);
    color: #ffe8dc !important;
    font-size: 0.85rem;
  }

  .login-helper {
    margin-bottom: 0;
    font-size: 0.78rem;
  }

  .login-secondary-link {
    color: rgb(255 253 249 / 74%);
    font-size: 0.84rem;
    font-weight: 700;
    text-decoration: none;
  }

  .login-secondary-link:hover {
    color: #fffdf9;
  }

  .login-side {
    display: grid;
    align-content: center;
    gap: 1rem;
    padding: 2rem;
    border: 1px solid var(--public-line);
    border-radius: 1.8rem;
    background: var(--public-surface);
  }

  .login-side h2 {
    margin-bottom: 0;
    font-size: 1.7rem;
  }

  .login-side p {
    margin-bottom: 0;
    font-size: 0.95rem;
  }

  .login-side-list {
    display: grid;
    gap: 0.8rem;
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .login-side-list li {
    display: flex;
    align-items: flex-start;
    gap: 0.65rem;
    color: var(--public-muted);
    font-size: 0.88rem;
  }

  .login-side-list .public-icon {
    flex: 0 0 auto;
    margin-top: 0.15rem;
    color: var(--public-olive);
  }

  .auth-error-page {
    min-height: 32rem;
    display: grid;
    place-items: center;
    padding: 5rem 1.5rem;
  }

  .auth-error-panel {
    width: min(590px, 100%);
    display: grid;
    gap: 1rem;
    padding: clamp(2rem, 5vw, 3.5rem);
    border: 1px solid var(--public-line);
    border-radius: 1.6rem;
    background: var(--public-surface);
    box-shadow: var(--public-shadow-soft);
  }

  .auth-error-panel h1 {
    margin-bottom: 0;
    font-size: clamp(2.6rem, 5vw, 4.5rem);
    line-height: 0.98;
  }

  .auth-error-panel p {
    margin-bottom: 0;
  }

  .auth-error-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem;
    margin-top: 0.75rem;
  }

  @media (max-width: 980px) {
    .public-header-inner {
      gap: 1rem;
    }

    .public-nav-links {
      gap: 1rem;
    }

    .public-login-link {
      display: none;
    }

    .public-hero,
    .login-page {
      grid-template-columns: 1fr;
    }

    .public-hero {
      gap: 3rem;
      padding-top: 4.5rem;
    }

    .access-map {
      width: min(700px, 100%);
    }

    .login-panel {
      min-height: auto;
    }

    .login-side {
      min-height: 16rem;
    }

    .feature-grid,
    .capability-grid,
    .access-step-grid,
    .access-requirement-grid {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }

    .resources-grid {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }

    .resource-card-featured {
      grid-column: span 2;
    }

    .public-footer-inner {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }

    .public-footer-brand {
      grid-column: 1 / -1;
    }
  }

  @media (max-width: 700px) {
    .public-header-inner,
    .public-mobile-menu,
    .public-hero,
    .public-section,
    .public-page-intro,
    .article-shell,
    .login-page,
    .public-footer-bottom {
      width: min(100% - 32px, 1240px);
    }

    .public-header-inner {
      min-height: 68px;
    }

    .public-nav-links,
    .public-header-actions {
      display: none;
    }

    .public-menu-toggle {
      display: grid;
      place-items: center;
    }

    .public-hero {
      min-height: auto;
      padding-top: 4rem;
      padding-bottom: 4.5rem;
    }

    .hero-copy h1 {
      font-size: clamp(3.25rem, 15vw, 5rem);
    }

    .public-button-row,
    .public-button-row .public-button {
      width: 100%;
    }

    .public-button-row .public-button {
      justify-content: center;
    }

    .access-map {
      padding: 0.85rem;
      border-radius: 1.3rem;
    }

    .map-card {
      min-height: 6.2rem;
      padding: 0.9rem;
    }

    .map-card strong {
      font-size: 0.92rem;
    }

    .public-section,
    .public-page-intro,
    .article-shell {
      padding-top: 4rem;
      padding-bottom: 4rem;
    }

    .public-section-tonal {
      padding-right: 16px;
      padding-left: 16px;
    }

    .feature-grid,
    .capability-grid,
    .access-step-grid,
    .access-requirement-grid,
    .resources-grid,
    .public-split-layout {
      grid-template-columns: 1fr;
    }

    .resource-card-featured {
      grid-column: auto;
    }

    .unavailable-card {
      grid-template-columns: auto minmax(0, 1fr);
    }

    .unavailable-card .status-pill {
      grid-column: 2;
      justify-self: start;
    }

    .product-callout {
      grid-template-columns: 1fr;
      gap: 2rem;
      border-radius: 1.4rem;
    }

    .product-callout-art {
      min-height: 12rem;
    }

    .public-final-cta {
      align-items: flex-start;
      flex-direction: column;
      padding-top: 2rem;
    }

    .public-footer {
      padding-top: 3.5rem;
    }

    .public-footer-inner {
      grid-template-columns: 1fr 1fr;
      gap: 2rem;
    }

    .public-footer-note {
      grid-column: 1 / -1;
      padding-top: 1rem;
      padding-left: 0;
      border-top: 1px solid rgb(255 253 249 / 20%);
      border-left: 0;
    }

    .article-flow {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }

    .article-flow-step:not(:last-child)::after {
      display: none;
    }

    .article-layout {
      grid-template-columns: 1fr;
      gap: 2rem;
    }

    .article-toc {
      position: static;
      padding: 1rem;
      border: 1px solid var(--public-line);
      border-radius: 1rem;
      background: var(--public-surface);
    }

    .login-page {
      padding-top: 3rem;
      padding-bottom: 4rem;
    }

    .login-panel,
    .login-side {
      padding: 1.5rem;
      border-radius: 1.3rem;
    }

    .auth-error-actions,
    .auth-error-actions .public-button {
      width: 100%;
    }
  }

  @media (prefers-reduced-motion: reduce) {
    .public-site *,
    .public-site *::before,
    .public-site *::after {
      scroll-behavior: auto !important;
      animation-duration: 0.01ms !important;
      animation-iteration-count: 1 !important;
      transition-duration: 0.01ms !important;
    }
  }
`;

const PUBLIC_NAVIGATION_SCRIPT = `<script>
  (() => {
    const toggle = document.querySelector(".public-menu-toggle");
    const menu = document.getElementById("public-mobile-menu");
    if (!toggle || !menu) return;

    const setMenuState = (open) => {
      toggle.setAttribute("aria-expanded", String(open));
      toggle.setAttribute("aria-label", open ? "Close navigation menu" : "Open navigation menu");
      menu.hidden = !open;
    };

    toggle.addEventListener("click", () => {
      setMenuState(toggle.getAttribute("aria-expanded") !== "true");
    });

    menu.addEventListener("click", (event) => {
      if (event.target instanceof HTMLAnchorElement) setMenuState(false);
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && toggle.getAttribute("aria-expanded") === "true") {
        setMenuState(false);
        toggle.focus();
      }
    });
  })();
</script>`;

function icon(name: IconName, className = "public-icon"): string {
  return `<svg class="${className}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">${ICONS[name]}</svg>`;
}

function navLink(
  href: string,
  label: string,
  active: PublicActiveRoute,
  route: PublicActiveRoute,
): string {
  const isActive = active === route;
  return `<a class="public-nav-link${isActive ? " is-active" : ""}" href="${href}"${isActive ? ' aria-current="page"' : ""}>${label}</a>`;
}

function publicNav(active: PublicActiveRoute): string {
  const links = [
    navLink("/", "Overview", active, "home"),
    navLink("/solutions", "Solutions", active, "solutions"),
    navLink("/resources", "Resources", active, "resources"),
    navLink("/about", "About", active, "about"),
  ].join("");

  return `
    <header class="public-header">
      <div class="public-header-inner">
        <a class="public-brand" href="/" aria-label="Swooshz Platform home">
          <span class="public-brand-mark">${icon("swoosh", "public-brand-icon")}</span>
          <span class="public-brand-copy">
            <span class="public-brand-name">Swooshz</span>
            <span class="public-brand-subtitle">AI solutions platform</span>
          </span>
        </a>
        <nav class="public-nav-links" aria-label="Public navigation">${links}</nav>
        <div class="public-header-actions">
          <a class="public-login-link" href="/login">Login</a>
          <a class="public-access-cta" href="/login">Access workspace ${icon("arrow")}</a>
        </div>
        <button class="public-menu-toggle" type="button" aria-expanded="false" aria-controls="public-mobile-menu" aria-label="Open navigation menu">
          ${icon("menu")}
        </button>
      </div>
      <div id="public-mobile-menu" class="public-mobile-menu" hidden>
        <nav class="public-mobile-nav" aria-label="Mobile public navigation">
          ${links}
          <a class="public-button public-button-primary" href="/login">Access workspace ${icon("arrow")}</a>
        </nav>
      </div>
    </header>
  `;
}

function publicFooter(): string {
  return `
    <footer class="public-footer">
      <div class="public-footer-inner">
        <div class="public-footer-brand">
          <a class="public-brand" href="/" aria-label="Swooshz Platform home">
            <span class="public-brand-mark">${icon("swoosh", "public-brand-icon")}</span>
            <span class="public-brand-copy">
              <span class="public-brand-name">Swooshz</span>
              <span class="public-brand-subtitle">AI solutions platform</span>
            </span>
          </a>
          <p>Practical AI solutions for the work businesses already do, with one trusted way to access approved tools.</p>
        </div>
        <div>
          <h2>Explore</h2>
          <nav aria-label="Footer exploration navigation">
            <a href="/solutions">Solutions</a>
            <a href="/resources">Resources</a>
            <a href="/about">About Swooshz</a>
          </nav>
        </div>
        <div class="public-footer-note">
          <h2>Access</h2>
          <nav aria-label="Footer access navigation">
            <a href="/login">Access your workspace</a>
            <a href="/request-access">Review access requirements</a>
            <a href="/contact">Contact guidance</a>
          </nav>
          <p>Workspace approval is required. Product workflows stay inside their dedicated applications.</p>
        </div>
      </div>
      <div class="public-footer-bottom">&copy; Swooshz. Public information for approved workspace access.</div>
    </footer>
  `;
}

function publicDocument({
  title,
  body,
  script = PUBLIC_NAVIGATION_SCRIPT,
}: {
  title: string;
  body: string;
  script?: string;
}): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title>
  <link rel="icon" href="about:blank">
  <style>${PUBLIC_STYLES}</style>
</head>
<body class="public-document-body">
  <div class="public-site">${body}</div>
  ${script}
</body>
</html>`;
}

export function renderLandingPage(): string {
  return publicDocument({
    title: "Swooshz | AI solutions platform",
    body: `
      ${publicNav("home")}
      <main>
        <section class="public-hero">
          <div class="hero-copy">
            <span class="hero-signal" aria-hidden="true"></span>
            <h1>One trusted place for your Swooshz tools.</h1>
            <p class="hero-lede">
              Swooshz is an AI solutions platform for practical business work. Enter your approved workspace once, then access the applications available to your team.
            </p>
            <div class="public-button-row">
              <a class="public-button public-button-primary" href="/login">Access your workspace ${icon("arrow")}</a>
              <a class="public-button public-button-secondary" href="/solutions">Explore solutions ${icon("arrow")}</a>
            </div>
            <div class="hero-proof" aria-label="Platform access principles">
              <span>${icon("check")} Workspace-approved access</span>
              <span>${icon("lock")} Dedicated product applications</span>
            </div>
          </div>
          <div class="access-map" aria-label="One account connects to a workspace and approved applications">
            <div class="access-map-top">
              <span>How access flows</span>
              <span class="map-status">Protected entry</span>
            </div>
            <div class="access-map-stack">
              <div class="map-card">
                <span class="map-icon">${icon("account")}</span>
                <div><strong>One account</strong><small>Provider-backed sign in</small></div>
              </div>
              <div class="map-connector" aria-hidden="true"></div>
              <div class="map-card map-card-workspace">
                <span class="map-icon">${icon("workspace")}</span>
                <div><strong>Your workspace</strong><small>Membership and access checked</small></div>
              </div>
              <div class="map-connector" aria-hidden="true"></div>
              <div class="map-card map-card-app">
                <span class="map-icon">${icon("app")}</span>
                <div><strong>Swooshz Quote Auto Generator</strong><small>Available application</small></div>
              </div>
            </div>
          </div>
        </section>

        <section class="public-section public-section-tonal">
          <div class="public-section-heading">
            <p class="public-kicker">A clearer way in</p>
            <h2>AI solutions with a place to begin.</h2>
            <p>Platform keeps access, workspace membership, and application availability clear while each product keeps its own workflow.</p>
          </div>
          <div class="public-section">
            <div class="feature-grid">
              <article class="feature-card">
                <span class="feature-icon">${icon("lock")}</span>
                <h3>Trusted access</h3>
                <p>Sign in with the approved provider account connected to your workspace.</p>
              </article>
              <article class="feature-card">
                <span class="feature-icon">${icon("layers")}</span>
                <h3>Workspace clarity</h3>
                <p>See the workspace, role, and application access that has been approved for you.</p>
              </article>
              <article class="feature-card">
                <span class="feature-icon">${icon("app")}</span>
                <h3>Dedicated applications</h3>
                <p>Launch a product where its own workflow and private product data belong.</p>
              </article>
            </div>
          </div>
        </section>

        <section class="public-section">
          <div class="product-callout">
            <div>
              <p class="public-kicker">Available now</p>
              <h2>Swooshz Quote Auto Generator</h2>
              <p>
                Our first available AI solution is designed for exhibition and interior design teams first, with room to expand over time. It is a separate app launched from Platform after workspace access is approved.
              </p>
              <span class="availability-row">${icon("check")} Available for approved workspaces</span>
            </div>
            <div class="product-callout-art" aria-hidden="true">
              <div class="product-orbit">
                <div class="product-orbit-card">
                  ${icon("spark")}
                  <strong>Quote workflow</strong>
                  <small>Dedicated product space</small>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section class="public-section public-section-tonal">
          <div class="public-section-heading">
            <p class="public-kicker">The wider ecosystem</p>
            <h2>Useful tools, honest availability.</h2>
            <p>SEO / GEO / Seozilla is a separate whitelabel AI solution. Its vendor workflow is pending and it is not available yet.</p>
          </div>
          <div class="unavailable-card">
            <span class="feature-icon">${icon("globe")}</span>
            <div><h2>SEO / GEO / Seozilla</h2><p>Separate whitelabel solution. Vendor workflow pending.</p></div>
            <span class="status-pill">Not available yet</span>
          </div>
        </section>

        <section class="public-section access-steps">
          <div class="public-section-heading">
            <p class="public-kicker">How access works</p>
            <h2>Four simple steps from approval to launch.</h2>
          </div>
          <div class="access-step-grid">
            <article class="access-step"><h3>Workspace approval</h3><p>Your organization or workspace sponsor approves access.</p></article>
            <article class="access-step"><h3>Provider account</h3><p>You use the approved Google or provider-backed account.</p></article>
            <article class="access-step"><h3>Membership and access</h3><p>Platform checks your workspace role and available applications.</p></article>
            <article class="access-step"><h3>Secure launch</h3><p>You open the dedicated product application from your workspace.</p></article>
          </div>
        </section>

        <section class="public-section">
          <div class="public-final-cta">
            <div><h2>Ready to find your way in?</h2><p>Access is available to approved Swooshz workspaces.</p></div>
            <a class="public-button public-button-primary" href="/login">Access your workspace ${icon("arrow")}</a>
          </div>
        </section>
      </main>
      ${publicFooter()}
    `,
  });
}

export function renderSolutionsPage(): string {
  return publicDocument({
    title: "Swooshz Solutions | AI solutions platform",
    body: `
      ${publicNav("solutions")}
      <main>
        <section class="public-page-intro">
          <p class="public-kicker">Solutions</p>
          <h1>AI solutions for the work ahead.</h1>
          <p>
            Swooshz builds practical AI solutions and gives approved teams one trusted way to access them. Start with a focused product, then let each application own its workflow.
          </p>
        </section>
        <section class="public-section">
          <div class="public-split-layout">
            <div class="public-panel public-panel-dark">
              <p class="public-kicker">Current solution</p>
              <h2>Swooshz Quote Auto Generator</h2>
              <p>
                Designed for exhibition and interior design teams first, Swooshz Quote Auto Generator is the first available product in the ecosystem. It is a separate product app launched from Platform after approved access checks pass.
              </p>
              <div class="public-button-row"><a class="public-button public-button-primary" href="/login">Access your workspace ${icon("arrow")}</a></div>
            </div>
            <div class="solutions-hero-art" aria-label="Product and platform relationship">
              <strong>One platform. Dedicated applications.</strong>
              <div class="solution-stack">
                <div class="solution-stack-card"><span class="feature-icon">${icon("app")}</span><div><strong>AutoQuote</strong><small>Available application</small></div></div>
                <div class="solution-stack-card"><span class="feature-icon">${icon("globe")}</span><div><strong>Seozilla</strong><small>Whitelabel, vendor workflow pending</small></div></div>
              </div>
            </div>
          </div>
        </section>
        <section class="public-section public-section-tonal">
          <div class="public-section-heading"><p class="public-kicker">Platform role</p><h2>Access, workspace, and application clarity.</h2><p>Platform owns the trusted access layer around the products. It does not absorb product workflow data or pretend that unavailable solutions are live.</p></div>
          <div class="capability-grid">
            <article class="capability-card"><span class="feature-icon">${icon("lock")}</span><h2>Access Management</h2><p>Provider identities, sessions, workspace memberships, roles, and launch eligibility stay in one clear access layer.</p><div class="role-list"><span>Owner</span><span>Admin</span><span>Member</span><span>Pending</span></div></article>
            <article class="capability-card"><span class="feature-icon">${icon("layers")}</span><h2>Workspace Entitlements</h2><p>Application availability is controlled at the workspace boundary and fails closed when access is not available.</p></article>
            <article class="capability-card"><span class="feature-icon">${icon("app")}</span><h2>Dedicated Applications</h2><p>Each solution keeps its own workflow, records, and product experience in its own application.</p></article>
          </div>
        </section>
        <section class="public-section"><div class="unavailable-card"><span class="feature-icon">${icon("globe")}</span><div><h2>SEO / GEO / Seozilla</h2><p>Separate whitelabel AI solution. Vendor workflow pending; unavailable until confirmed and not available yet.</p></div><span class="status-pill">Vendor workflow pending</span></div></section>
      </main>
      ${publicFooter()}
    `,
  });
}

export function renderResourcesPage(): string {
  return publicDocument({
    title: "Swooshz Resources",
    body: `
      ${publicNav("resources")}
      <main>
        <section class="public-page-intro">
          <p class="public-kicker">Resources</p>
          <h1>Insights &amp; Resources</h1>
          <p>Practical guides to approved workspaces, Platform access, and the boundary between a trusted access layer and dedicated AI applications.</p>
        </section>
        <section class="public-section public-section-tonal">
          <div class="public-section-heading"><p class="public-kicker">Browse by subject</p><h2>Clear language for real access decisions.</h2><p>Start with the guide below. Future topics will be published only when they are ready to stand on their own.</p></div>
          <div class="topic-rail" aria-label="Resource topics"><span>All topics</span><span>Platform access</span><span>Provider-backed entry</span><span>Product boundaries</span></div>
        </section>
        <section class="public-section"><div class="public-panel public-panel-dark resource-focus"><p class="public-kicker">Product in focus</p><h2>Swooshz Quote Auto Generator</h2><p>The available product is a separate app launched from Platform for approved workspaces, keeping its quote workflow inside its own dedicated experience.</p></div></section>
        <section class="public-section">
          <div class="resources-grid">
            <article class="resource-card resource-card-featured">
              <div class="resource-card-visual" aria-hidden="true"><span>${icon("layers")} Launch boundary</span></div>
              <div class="resource-card-body"><span class="resource-card-kicker">Platform access</span><h2>How Swooshz Platform launches workspace apps safely</h2><p>A clear guide to workspace approval, provider-backed access, entitlement checks, and the separate app boundary.</p><a class="resource-card-link" href="/resources/platform-launch-boundaries">Read the guide ${icon("arrow")}</a></div>
            </article>
            <article class="resource-card resource-card-inert"><div class="resource-card-visual" aria-hidden="true"><span>${icon("lock")} Access model</span></div><div class="resource-card-body"><span class="resource-card-kicker">Access</span><h2>Workspace access checklist</h2><p>A practical overview of the questions to answer before a team member signs in.</p><span class="resource-card-status">In preparation</span></div></article>
            <article class="resource-card resource-card-inert"><div class="resource-card-visual" aria-hidden="true"><span>${icon("layers")} Ownership</span></div><div class="resource-card-body"><span class="resource-card-kicker">Product boundary</span><h2>What belongs in Platform</h2><p>How access services stay distinct from the workflows inside each dedicated application.</p><span class="resource-card-status">In preparation</span></div></article>
            <article class="resource-card resource-card-inert"><div class="resource-card-visual" aria-hidden="true"><span>${icon("app")} Application launch</span></div><div class="resource-card-body"><span class="resource-card-kicker">Applications</span><h2>From workspace approval to a dedicated app</h2><p>What changes when a product is available to your workspace and ready to launch.</p><span class="resource-card-status">In preparation</span></div></article>
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
    body: `
      ${publicNav("resources")}
      <main>
        <article class="article-shell">
          <div class="article-breadcrumb"><a href="/resources">Resources</a><span>/</span><span>Platform access</span></div>
          <header class="article-hero"><p class="public-kicker">Platform access</p><h1>How Swooshz Platform launches workspace apps safely</h1><p>A clear guide to what happens between sign-in and an approved application, limited to the Platform behavior available today.</p></header>
          <div class="article-visual" aria-hidden="true"><div class="article-flow"><div class="article-flow-step">${icon("account")}<strong>One account</strong><small>Provider-backed entry</small></div><div class="article-flow-step">${icon("workspace")}<strong>Workspace</strong><small>Membership checked</small></div><div class="article-flow-step">${icon("lock")}<strong>Access</strong><small>Entitlement checked</small></div><div class="article-flow-step">${icon("app")}<strong>Dedicated app</strong><small>Launch separately</small></div></div></div>
          <div class="article-layout">
            <nav class="article-toc" aria-label="In this guide"><strong>In this guide</strong><a href="#workspace">Workspace approval</a><a href="#provider">Provider-backed access</a><a href="#boundary">The app boundary</a><a href="#unavailable">Unavailable areas</a></nav>
            <div class="article-body">
              <section id="workspace"><h2>Access starts with the workspace</h2><p>Swooshz Platform is the access surface around approved workspace applications. It considers the signed-in account, selected workspace, membership role, and application availability before a launch path is available.</p></section>
              <section id="provider"><h2>Provider-backed access</h2><p>Public access is not self-service. Users arrive through an approved provider-backed account that belongs to an approved workspace, then Platform evaluates whether the requested application can be launched.</p></section>
              <aside class="article-callout" id="boundary"><strong>The application stays in its own space.</strong><p>Swooshz Quote Auto Generator is a separate app launched from Platform. Its product workflow data stays outside Platform; generated documents and private product state remain with the product.</p></aside>
              <section><h2>Launch follows a clear check</h2><p>Platform owns the access decision and handoff. It does not embed product workflows, invent product records, or move a dedicated application's data into the public access layer.</p></section>
              <section id="unavailable"><h2>Unavailable areas stay honest</h2><p>SEO / GEO / Seozilla remains unavailable. Its whitelabel vendor workflow is pending and is not presented as launched, integrated, or purchasable.</p></section>
            </div>
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
    body: `
      ${publicNav("about")}
      <main>
        <section class="public-page-intro"><p class="public-kicker">About Swooshz</p><h1>Practical AI solutions with a trusted way in.</h1><p>Swooshz is an AI solutions platform building focused tools for real business work, starting with exhibition and interior design teams and expanding over time.</p><div class="public-button-row"><a class="public-button public-button-primary" href="/request-access">Review access requirements ${icon("arrow")}</a><a class="public-button public-button-secondary" href="/contact">Contact guidance</a></div></section>
        <section class="public-section public-section-tonal"><div class="public-section-heading"><p class="public-kicker">Why Platform exists</p><h2>One trusted access layer, specialised applications.</h2><p>Platform gives customers a clear place to sign in, enter their workspace, see approved applications, and launch the right product without blending separate workflows together.</p></div><div class="feature-grid"><article class="feature-card"><span class="feature-icon">${icon("spark")}</span><h3>Build useful AI</h3><p>Solutions begin with a concrete business need rather than a generic technology promise.</p></article><article class="feature-card"><span class="feature-icon">${icon("lock")}</span><h3>Make access clear</h3><p>Provider-backed accounts, memberships, roles, and application access stay visible and deliberate.</p></article><article class="feature-card"><span class="feature-icon">${icon("layers")}</span><h3>Keep ownership honest</h3><p>Each product owns its own workflow, records, and dedicated application experience.</p></article></div></section>
        <section class="public-section"><div class="public-section-heading"><p class="public-kicker">Product boundaries</p><h2>Each part has a clear job.</h2></div><div class="capability-grid"><article class="capability-card"><span class="feature-icon">${icon("app")}</span><h2>Swooshz Quote Auto Generator</h2><p>Swooshz Quote Auto Generator is a separate app launched from Platform for approved workspaces. Its quote workflow data stays in its own product.</p></article><article class="capability-card"><span class="feature-icon">${icon("globe")}</span><h2>SEO / GEO / Seozilla</h2><p>Separate whitelabel AI solution. Vendor workflow pending and unavailable until confirmed.</p></article><article class="capability-card"><span class="feature-icon">${icon("workspace")}</span><h2>Platform</h2><p>Platform owns provider-backed access, users, workspaces, memberships, roles, entitlements, launch decisions, and access presentation.</p></article></div></section>
      </main>
      ${publicFooter()}
    `,
  });
}

export function renderContactPage(): string {
  return publicDocument({
    title: "Contact Swooshz",
    body: `
      ${publicNav("contact")}
      <main>
        <section class="public-page-intro"><p class="public-kicker">Access enquiry</p><h1>Contact Swooshz.</h1><p>Use your existing Swooshz or workspace sponsor channel for access questions, workspace approval, and provider-backed account setup.</p></section>
        <section class="public-section"><div class="public-split-layout"><div class="public-panel public-panel-dark"><p class="public-kicker">A safe next step</p><h2>Start with the person who manages your workspace.</h2><p>If your team already uses Swooshz, your workspace sponsor or administrator can confirm the right account and application access.</p><div class="public-button-row"><a class="public-button public-button-primary" href="/request-access">Review access requirements ${icon("arrow")}</a><a class="public-button public-button-secondary" href="/login">Access workspace</a></div></div><aside class="public-panel"><h2>Contact guidance</h2><div class="guidance-list"><div class="guidance-item">${icon("account")}<p>Use your workspace sponsor or administrator for approval questions.</p></div><div class="guidance-item">${icon("lock")}<p>Do not send secrets, cookies, provider tokens, private customer data, or product records through a public enquiry channel.</p></div><div class="guidance-item">${icon("arrow")}<p>This page is informational only. It does not submit messages, create accounts, or connect a backend intake flow.</p></div></div></aside></div></section>
      </main>
      ${publicFooter()}
    `,
  });
}

export function renderRequestAccessPage(): string {
  return publicDocument({
    title: "Request Access | Swooshz Platform",
    body: `
      ${publicNav("requestAccess")}
      <main>
        <section class="public-page-intro"><p class="public-kicker">Workspace access</p><h1>Request Access.</h1><p>Access to Swooshz Platform begins with workspace approval, an approved provider-backed account, and application access assigned to your membership.</p></section>
        <section class="public-section public-section-tonal"><div class="access-requirement-grid"><article class="access-requirement"><span class="access-requirement-number">01</span><h2>Workspace approval</h2><p>Your organization or workspace sponsor approves access.</p></article><article class="access-requirement"><span class="access-requirement-number">02</span><h2>Provider-backed account</h2><p>Use the approved Google or provider-backed account assigned to your workspace.</p></article><article class="access-requirement"><span class="access-requirement-number">03</span><h2>Membership and role</h2><p>Your workspace membership determines the access you receive.</p></article><article class="access-requirement"><span class="access-requirement-number">04</span><h2>Application availability</h2><p>Platform checks which dedicated applications are available to your workspace.</p></article></div><div class="access-notice"><h2>No public signup is available</h2><p>This page does not create an account, send a request, or grant workspace access. Use your existing Swooshz or workspace sponsor channel to ask for an access review.</p></div><div class="public-button-row centered-actions"><a class="public-button public-button-primary" href="/login">Go to access entry ${icon("arrow")}</a><a class="public-button public-button-secondary" href="/contact">Contact guidance</a></div></section>
      </main>
      ${publicFooter()}
    `,
  });
}

export function renderLoginPage(): string {
  const signedOutScript = `<script>
    (() => {
      const params = new URLSearchParams(window.location.search);
      const notice = document.getElementById("signedOutNotice");
      if (params.get("signedOut") === "1" && notice) notice.hidden = false;
    })();
  </script>`;

  return publicDocument({
    title: "Swooshz Platform Access",
    script: `${PUBLIC_NAVIGATION_SCRIPT}${signedOutScript}`,
    body: `
      ${publicNav("login")}
      <main class="login-page">
        <section class="login-panel">
          <div class="login-brand"><span class="public-brand-mark">${icon("swoosh", "public-brand-icon")}</span><span>Swooshz Platform</span></div>
          <h1>Enter your Swooshz workspace.</h1>
          <p>Access requires an approved provider-backed account for your workspace. No public signup is available.</p>
          <p id="signedOutNotice" class="signed-out" hidden>You are signed out of Swooshz Platform. Your Google account may still be signed in.</p>
          <a class="provider-button" href="/api/platform/auth/start">${icon("account")} Continue with Google</a>
          <p class="login-helper">Use the approved Google account for your workspace.</p>
          <a class="login-secondary-link" href="/app">Already signed in? Continue to app</a>
        </section>
        <aside class="login-side"><p class="public-kicker">Before you sign in</p><h2>Access is workspace-approved.</h2><p>Your sponsor or administrator must approve your workspace access before a product application can open.</p><ul class="login-side-list"><li>${icon("check")} Provider-backed account verified at sign in</li><li>${icon("check")} Workspace membership and role checked</li><li>${icon("check")} Application access stays with its dedicated product</li></ul><a class="public-button public-button-secondary" href="/request-access">Review access requirements ${icon("arrow")}</a></aside>
      </main>
      ${publicFooter()}
    `,
  });
}

export function renderAuthErrorPage(): string {
  return publicDocument({
    title: "Swooshz Platform Access Not Approved",
    body: `
      ${publicNav("login")}
      <main class="auth-error-page">
        <section class="auth-error-panel"><p class="public-kicker">Access review</p><h1>Access not approved.</h1><p>This account is not approved for Swooshz Platform. Use an approved account or contact your workspace admin.</p><div class="auth-error-actions"><a class="public-button public-button-primary" href="/api/platform/auth/start">Try another Google account ${icon("arrow")}</a><a class="public-button public-button-secondary" href="/">Back to sign in</a></div></section>
      </main>
      ${publicFooter()}
    `,
  });
}

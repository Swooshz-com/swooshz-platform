import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

import {
  renderAboutPage,
  renderAdminShellPage,
  renderAppShellPage,
  renderContactPage,
  renderLandingPage,
  renderLoginPage,
  renderResourceArticlePage,
  renderResourcesPage,
  renderRequestAccessPage,
  renderSolutionsPage,
  readPublicSiteAsset,
} from "../dist/index.js";

const publicPages = [
  renderLandingPage,
  renderSolutionsPage,
  renderResourcesPage,
  renderResourceArticlePage,
  renderAboutPage,
  renderContactPage,
  renderRequestAccessPage,
  renderLoginPage,
];

test("public Prestige pages expose named navigation and visible non-empty CTA labels", () => {
  for (const renderPage of publicPages) {
    const html = renderPage();
    assert.match(html, /<main id="main-content"/);
    assert.match(html, /<a class="public-skip-link" href="#main-content">Skip to main content<\/a>/);

    for (const match of html.matchAll(/<a class="public-(?:button|button-secondary)"[^>]*>([\s\S]*?)<\/a>/g)) {
      const visibleLabel = match[1].replace(/<[^>]+>/g, "").replace(/&(?:nearr|rarr|darr|larr);/g, "").trim();
      assert.notEqual(visibleLabel, "");
    }
  }

  const landing = renderLandingPage();
  assert.match(landing, /aria-label="Public navigation"/);
  assert.match(landing, /aria-label="Open navigation"/);
  assert.match(landing, /aria-controls="public-navigation"/);
});

test("hero uses responsive optimized formats with one homepage-only preload", async () => {
  const landing = renderLandingPage();
  const nonHome = renderSolutionsPage() + renderLoginPage();

  assert.equal((landing.match(/rel="preload" as="image"/g) ?? []).length, 1);
  assert.doesNotMatch(nonHome, /rel="preload" as="image"/);
  assert.match(landing, /type="image\/avif" srcset=/);
  assert.match(landing, /type="image\/webp" srcset=/);
  assert.match(landing, /width="1672" height="941"/);
  assert.match(landing, /sizes="\(max-width: 720px\) 170vw/);

  for (const width of [640, 960, 1280, 1672]) {
    for (const format of ["avif", "webp"]) {
      const path = `src/http/public-assets/hero-monument-${width}.${format}`;
      assert.match(landing, new RegExp(`hero-monument-${width}\\.${format}`));
      assert.ok((await stat(path)).size > 0);
    }
  }

  assert.ok((await stat("src/http/public-assets/hero-monument-1672.avif")).size < 100_000);
});

test("public assets are allowlisted, typed, immutable, and copied by the production build", async () => {
  const stylesheet = await readPublicSiteAsset("/public-assets/public-site.css");
  const script = await readPublicSiteAsset("/public-assets/public-site.js");
  const missing = await readPublicSiteAsset("/public-assets/not-allowlisted.txt");

  assert.equal(stylesheet?.headers["content-type"], "text/css; charset=utf-8");
  assert.equal(script?.headers["content-type"], "text/javascript; charset=utf-8");
  assert.equal(stylesheet?.headers["x-content-type-options"], "nosniff");
  assert.equal(stylesheet?.headers["cache-control"], "public, max-age=31536000, immutable");
  assert.equal(missing, null);
  assert.ok((await stat("dist/http/public-assets/public-site.css")).size > 0);
});

test("public assets and interactions are absent from app and admin HTML", () => {
  for (const html of [renderAppShellPage(), renderAdminShellPage()]) {
    assert.doesNotMatch(html, /public-site\.(?:css|js)/);
    assert.doesNotMatch(html, /data-public-route|data-public-menu-toggle|data-scroll-scene/);
  }
});

test("mobile menu excludes closed links, moves focus, closes on Escape, and clears on desktop resize", async () => {
  const harness = await createPublicSiteHarness({ mobile: true });

  assert.equal(harness.menu.getAttribute("aria-expanded"), "false");
  assert.equal(harness.navigation.getAttribute("aria-hidden"), "true");
  assert.equal(harness.navigation.hasAttribute("inert"), true);

  harness.menu.emit("click", {});
  assert.equal(harness.menu.getAttribute("aria-expanded"), "true");
  assert.equal(harness.navigation.getAttribute("aria-hidden"), "false");
  assert.equal(harness.navigation.hasAttribute("inert"), false);
  assert.equal(harness.document.activeElement, harness.firstLink);
  assert.equal(harness.body.classList.contains("public-menu-open"), true);

  harness.document.emit("keydown", {
    key: "Escape",
    preventDefault() { this.defaultPrevented = true; },
  });
  assert.equal(harness.menu.getAttribute("aria-expanded"), "false");
  assert.equal(harness.document.activeElement, harness.menu);
  assert.equal(harness.body.classList.contains("public-menu-open"), false);

  harness.menu.emit("click", {});
  harness.media.mobile.setMatches(false);
  assert.equal(harness.menu.getAttribute("aria-expanded"), "false");
  assert.equal(harness.navigation.getAttribute("aria-hidden"), "false");
  assert.equal(harness.navigation.hasAttribute("inert"), false);
  assert.equal(harness.body.classList.contains("public-menu-open"), false);
});

test("scroll settling enables only for eligible desktop scenes and bypasses reduced motion, touch, focus, anchors, selection, zoom, and tall content", async () => {
  const desktop = await createPublicSiteHarness({ mobile: false });
  assert.equal(desktop.root.dataset.scrollAssist, "enabled");
  assert.equal(desktop.root.dataset.scrollStrategy, "native-proximity");

  const reduced = await createPublicSiteHarness({ mobile: false, reducedMotion: true });
  assert.equal(reduced.root.dataset.scrollAssistReason, "reduced-motion");
  assert.equal(reduced.root.style.values.get("--hero-progress"), "0");

  const touch = await createPublicSiteHarness({ mobile: true });
  assert.equal(touch.root.dataset.scrollAssistReason, "input-or-width");

  const anchored = await createPublicSiteHarness({ mobile: false, hash: "#quote-auto-generator" });
  assert.equal(anchored.root.dataset.scrollAssistReason, "deep-link");

  const zoomed = await createPublicSiteHarness({ mobile: false, zoom: 1.2 });
  assert.equal(zoomed.root.dataset.scrollAssistReason, "zoom");

  const tall = await createPublicSiteHarness({ mobile: false, sceneHeight: 900 });
  assert.equal(tall.root.dataset.scrollAssistReason, "tall-scene");
  assert.equal(tall.scenes[0].hasAttribute("data-scroll-tall"), true);

  desktop.firstLink.focus();
  desktop.document.emit("focusin", { target: desktop.firstLink });
  assert.equal(desktop.root.dataset.scrollAssistReason, "focus");

  const selection = await createPublicSiteHarness({ mobile: false, selectionCollapsed: false });
  assert.equal(selection.root.dataset.scrollAssistReason, "selection");
});

test("native proximity settling does not intercept wheel input or create repeated programmatic scroll loops", async () => {
  const script = await readFile("src/http/public-assets/public-site.js", "utf8");
  const styles = await readFile("src/http/public-assets/public-site.css", "utf8");

  assert.match(styles, /scroll-snap-type:\s*y proximity/);
  assert.match(styles, /scroll-snap-stop:\s*always/);
  assert.doesNotMatch(script, /addEventListener\(["']wheel/);
  assert.doesNotMatch(script, /scrollTo\(|scrollIntoView\(/);
});

class FakeClassList {
  constructor(initial = []) { this.values = new Set(initial); }
  contains(value) { return this.values.has(value); }
  add(value) { this.values.add(value); }
  remove(value) { this.values.delete(value); }
  toggle(value, force) {
    const enabled = force === undefined ? !this.values.has(value) : force;
    if (enabled) this.values.add(value); else this.values.delete(value);
    return enabled;
  }
}

class FakeStyle {
  values = new Map();
  setProperty(name, value) { this.values.set(name, String(value)); }
}

class FakeTarget {
  listeners = new Map();
  addEventListener(type, listener) {
    const listeners = this.listeners.get(type) ?? [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }
  removeEventListener(type, listener) {
    this.listeners.set(type, (this.listeners.get(type) ?? []).filter((value) => value !== listener));
  }
  emit(type, event = {}) {
    event.target ??= this;
    for (const listener of this.listeners.get(type) ?? []) listener(event);
  }
}

class FakeElement extends FakeTarget {
  constructor(document, classes = []) {
    super();
    this.ownerDocument = document;
    this.classList = new FakeClassList(classes);
    this.style = new FakeStyle();
    this.dataset = {};
    this.attributes = new Map();
    this.children = [];
    this.scrollHeight = 0;
  }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.get(name) ?? null; }
  hasAttribute(name) { return this.attributes.has(name); }
  removeAttribute(name) { this.attributes.delete(name); }
  toggleAttribute(name, force) {
    const enabled = force === undefined ? !this.attributes.has(name) : force;
    if (enabled) this.attributes.set(name, ""); else this.attributes.delete(name);
    return enabled;
  }
  querySelector(selector) { return selector === "a" ? this.children[0] ?? null : null; }
  querySelectorAll(selector) { return selector === "a" ? this.children : []; }
  contains(target) { return target === this || this.children.includes(target); }
  focus() { this.ownerDocument.activeElement = this; }
  getBoundingClientRect() { return { width: 800, height: 80, top: 0, left: 0 }; }
}

class FakeButton extends FakeElement {}

class FakeMedia extends FakeTarget {
  constructor(matches) { super(); this.matches = matches; }
  setMatches(matches) { this.matches = matches; this.emit("change", { matches }); }
}

async function createPublicSiteHarness({
  mobile,
  reducedMotion = false,
  hash = "",
  zoom = 1,
  sceneHeight = 800,
  selectionCollapsed = true,
}) {
  const document = new FakeTarget();
  const root = new FakeElement(document);
  const body = new FakeElement(document, ["public-site"]);
  const menu = new FakeButton(document);
  const navigation = new FakeElement(document);
  const firstLink = new FakeElement(document);
  const hero = new FakeElement(document);
  const heroArtwork = new FakeElement(document);
  const header = new FakeElement(document);
  const scenes = Array.from({ length: 5 }, () => {
    const scene = new FakeElement(document);
    scene.scrollHeight = sceneHeight;
    return scene;
  });
  navigation.children.push(firstLink);
  body.dataset.publicRoute = "home";
  menu.setAttribute("aria-expanded", "false");
  document.body = body;
  document.documentElement = root;
  document.activeElement = body;
  document.hidden = false;
  document.querySelector = (selector) => ({
    "[data-public-menu-toggle]": menu,
    "[data-public-navigation]": navigation,
    "[data-public-hero]": hero,
    "[data-public-hero-art]": heroArtwork,
    ".public-nav": header,
  })[selector] ?? null;
  document.querySelectorAll = (selector) => selector === "[data-scroll-scene]" ? scenes : [];

  const media = {
    reduced: new FakeMedia(reducedMotion),
    mobile: new FakeMedia(mobile),
    desktop: new FakeMedia(!mobile),
    short: new FakeMedia(false),
  };
  const visualViewport = new FakeTarget();
  visualViewport.scale = zoom;
  const window = new FakeTarget();
  Object.assign(window, {
    innerHeight: 900,
    scrollY: 0,
    visualViewport,
    location: { hash, search: "" },
    matchMedia(query) {
      if (query.includes("prefers-reduced-motion")) return media.reduced;
      if (query.includes("max-width")) return media.mobile;
      if (query.includes("min-width")) return media.desktop;
      if (query.includes("max-height")) return media.short;
      throw new Error(`Unexpected media query: ${query}`);
    },
    getSelection: () => ({ isCollapsed: selectionCollapsed }),
    setTimeout(callback) { callback(); return 1; },
    clearTimeout() {},
  });
  hero.getBoundingClientRect = () => ({ width: 800, height: 820, top: 0, left: 0 });
  heroArtwork.getBoundingClientRect = () => ({ width: 800, height: 700, top: 0, left: 0 });

  const source = await readFile("src/http/public-assets/public-site.js", "utf8");
  const context = {
    document,
    window,
    Element: FakeElement,
    HTMLElement: FakeElement,
    HTMLButtonElement: FakeButton,
    URLSearchParams,
    getComputedStyle: () => ({ fontSize: "16px" }),
    requestAnimationFrame(callback) { callback(); return 1; },
  };
  vm.runInNewContext(source, context);

  return { body, document, firstLink, media, menu, navigation, root, scenes, window };
}

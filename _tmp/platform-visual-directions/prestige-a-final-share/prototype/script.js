const menuButton = document.querySelector('.menu-toggle');
const nav = document.querySelector('.primary-nav');
const hero = document.querySelector('.hero');
const visual = document.querySelector('.hero-visual');
const root = document.documentElement;
const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
const mobileNavigation = window.matchMedia('(max-width: 900px)');
const finePointer = window.matchMedia('(hover: hover) and (pointer: fine)');

root.classList.toggle('motion-enabled', !reduceMotion.matches);
if (reduceMotion.matches) root.classList.add('is-ready');
else requestAnimationFrame(() => window.setTimeout(() => root.classList.add('is-ready'), 60));

function isMenuOpen() { return menuButton?.getAttribute('aria-expanded') === 'true'; }
function setNavigationAccess(open) {
  if (!menuButton || !nav) return;
  const hidden = mobileNavigation.matches && !open;
  menuButton.setAttribute('aria-expanded', String(open));
  menuButton.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
  nav.classList.toggle('is-open', open);
  nav.toggleAttribute('inert', hidden);
  nav.setAttribute('aria-hidden', String(hidden));
  document.body.classList.toggle('menu-open', open);
}
function closeMenu({ restoreFocus = false } = {}) {
  if (!menuButton || !nav) return;
  setNavigationAccess(false);
  if (restoreFocus && mobileNavigation.matches) menuButton.focus();
}
function openMenu() {
  if (!menuButton || !nav || !mobileNavigation.matches) return;
  setNavigationAccess(true);
  requestAnimationFrame(() => nav.querySelector('a')?.focus());
}
function syncNavigation() {
  if (!menuButton || !nav) return;
  if (!mobileNavigation.matches) {
    nav.classList.remove('is-open');
    nav.removeAttribute('inert');
    nav.setAttribute('aria-hidden', 'false');
    menuButton.setAttribute('aria-expanded', 'false');
    menuButton.setAttribute('aria-label', 'Open navigation');
    document.body.classList.remove('menu-open');
    return;
  }
  setNavigationAccess(isMenuOpen());
}
menuButton?.addEventListener('click', () => { if (isMenuOpen()) closeMenu({ restoreFocus: true }); else openMenu(); });
nav?.querySelectorAll('a').forEach(link => link.addEventListener('click', () => closeMenu()));
document.addEventListener('keydown', event => { if (event.key === 'Escape' && isMenuOpen()) { event.preventDefault(); closeMenu({ restoreFocus: true }); } });
document.addEventListener('pointerdown', event => { if (!isMenuOpen() || nav?.contains(event.target) || menuButton?.contains(event.target)) return; closeMenu({ restoreFocus: true }); });
mobileNavigation.addEventListener?.('change', syncNavigation);
window.addEventListener('orientationchange', () => { closeMenu(); window.setTimeout(syncNavigation, 80); });
syncNavigation();

let scrollFrame = 0;
function updateScroll() {
  scrollFrame = 0;
  if (!hero || reduceMotion.matches) { root.style.setProperty('--hero-progress', '0'); return; }
  const rect = hero.getBoundingClientRect();
  const distance = Math.max(1, rect.height - window.innerHeight * 0.35);
  const progress = Math.min(1, Math.max(0, -rect.top / distance));
  root.style.setProperty('--hero-progress', progress.toFixed(4));
}
function requestScrollUpdate() { if (!scrollFrame) scrollFrame = requestAnimationFrame(updateScroll); }
window.addEventListener('scroll', requestScrollUpdate, { passive: true });
window.addEventListener('resize', requestScrollUpdate);
updateScroll();

function resetPointer() { root.style.setProperty('--pointer-x', '0'); root.style.setProperty('--pointer-y', '0'); }
visual?.addEventListener('pointermove', event => {
  if (!finePointer.matches || reduceMotion.matches) { resetPointer(); return; }
  const rect = visual.getBoundingClientRect();
  const x = ((event.clientX - rect.left) / rect.width - 0.5) * 2;
  const y = ((event.clientY - rect.top) / rect.height - 0.5) * 2;
  root.style.setProperty('--pointer-x', x.toFixed(3));
  root.style.setProperty('--pointer-y', y.toFixed(3));
});
visual?.addEventListener('pointerleave', resetPointer);
visual?.addEventListener('pointercancel', resetPointer);
window.addEventListener('blur', resetPointer);
window.addEventListener('pagehide', resetPointer);
document.addEventListener('visibilitychange', () => { resetPointer(); if (!document.hidden) updateScroll(); });
window.addEventListener('pageshow', () => { syncNavigation(); resetPointer(); updateScroll(); });
reduceMotion.addEventListener?.('change', () => { root.classList.toggle('motion-enabled', !reduceMotion.matches); root.classList.add('is-ready'); resetPointer(); updateScroll(); });

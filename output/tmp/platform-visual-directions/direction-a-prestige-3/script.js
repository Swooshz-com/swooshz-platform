const menuButton = document.querySelector('.menu-toggle');
const nav = document.querySelector('.primary-nav');
const header = document.querySelector('.site-header');
const heroObject = document.querySelector('.hero-object');
const theatre = document.querySelector('.theatre');
const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

requestAnimationFrame(() => requestAnimationFrame(() => document.body.classList.add('is-ready')));

function setMenu(open) {
  if (!menuButton || !nav) return;
  menuButton.setAttribute('aria-expanded', String(open));
  nav.classList.toggle('is-open', open);
}
menuButton?.addEventListener('click', () => setMenu(menuButton.getAttribute('aria-expanded') !== 'true'));
nav?.querySelectorAll('a').forEach((link) => link.addEventListener('click', () => setMenu(false)));
document.addEventListener('keydown', (event) => { if (event.key === 'Escape') setMenu(false); });

const finePointer = window.matchMedia('(hover: hover) and (pointer: fine)');
if (heroObject && finePointer.matches && !reduceMotion.matches) {
  heroObject.addEventListener('pointermove', (event) => {
    const rect = heroObject.getBoundingClientRect();
    const x = ((event.clientX - rect.left) / rect.width - .5) * 2;
    const y = ((event.clientY - rect.top) / rect.height - .5) * 2;
    document.documentElement.style.setProperty('--pointer-x', x.toFixed(3));
    document.documentElement.style.setProperty('--pointer-y', y.toFixed(3));
  });
  heroObject.addEventListener('pointerleave', () => {
    document.documentElement.style.setProperty('--pointer-x', '0');
    document.documentElement.style.setProperty('--pointer-y', '0');
  });
}

let frame = 0;
function updateTheatre() {
  frame = 0;
  if (!theatre || reduceMotion.matches) {
    document.documentElement.style.setProperty('--theatre-progress', '1');
    header?.classList.add('is-dark');
    return;
  }
  const rect = theatre.getBoundingClientRect();
  const distance = Math.max(1, rect.height - window.innerHeight);
  const progress = Math.min(1, Math.max(0, -rect.top / distance));
  document.documentElement.style.setProperty('--theatre-progress', progress.toFixed(4));
  header?.classList.toggle('is-dark', progress > .45 && rect.bottom > 78);
}
function requestUpdate() { if (!frame) frame = requestAnimationFrame(updateTheatre); }
window.addEventListener('scroll', requestUpdate, { passive: true });
window.addEventListener('resize', requestUpdate);
reduceMotion.addEventListener?.('change', updateTheatre);
updateTheatre();

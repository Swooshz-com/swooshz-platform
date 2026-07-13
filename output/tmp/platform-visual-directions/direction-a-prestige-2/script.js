const menuButton = document.querySelector('.menu-toggle');
const nav = document.querySelector('.primary-nav');
const stage = document.querySelector('.material-stage');
const handoff = document.querySelector('.handoff');
const marker = document.querySelector('.sequence-marker b');
const steps = [...document.querySelectorAll('.sequence-step')];
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
if (stage && finePointer.matches && !reduceMotion.matches) {
  stage.addEventListener('pointermove', (event) => {
    const rect = stage.getBoundingClientRect();
    const x = ((event.clientX - rect.left) / rect.width - 0.5) * 2;
    const y = ((event.clientY - rect.top) / rect.height - 0.5) * 2;
    document.documentElement.style.setProperty('--tilt-x', `${(x * 1.15).toFixed(2)}deg`);
    document.documentElement.style.setProperty('--tilt-y', `${(-y * 0.85).toFixed(2)}deg`);
    document.documentElement.style.setProperty('--shift-x', `${(x * 5).toFixed(2)}px`);
    document.documentElement.style.setProperty('--shift-y', `${(y * 4).toFixed(2)}px`);
  });
  stage.addEventListener('pointerleave', () => {
    ['--tilt-x','--tilt-y'].forEach((name) => document.documentElement.style.setProperty(name, '0deg'));
    ['--shift-x','--shift-y'].forEach((name) => document.documentElement.style.setProperty(name, '0px'));
  });
}

function activateStep(step) {
  const index = Number(step.dataset.layer || 0);
  steps.forEach((item) => item.classList.toggle('is-active', item === step));
  document.documentElement.style.setProperty('--sequence-index', String(index));
  if (marker) marker.textContent = step.dataset.label || '';
}

const observer = new IntersectionObserver((entries) => {
  const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
  if (visible) activateStep(visible.target);
}, { rootMargin: '-28% 0px -42% 0px', threshold: [0.08, 0.35, 0.7] });
steps.forEach((step) => observer.observe(step));

let scrollFrame = 0;
function updateHandoff() {
  scrollFrame = 0;
  if (!handoff || reduceMotion.matches) {
    document.documentElement.style.setProperty('--handoff-progress', '1');
    return;
  }
  const rect = handoff.getBoundingClientRect();
  const progress = Math.min(1, Math.max(0, (window.innerHeight - rect.top) / (window.innerHeight + rect.height * .3)));
  document.documentElement.style.setProperty('--handoff-progress', progress.toFixed(4));
}
window.addEventListener('scroll', () => { if (!scrollFrame) scrollFrame = requestAnimationFrame(updateHandoff); }, { passive: true });
window.addEventListener('resize', updateHandoff);
updateHandoff();

reduceMotion.addEventListener?.('change', updateHandoff);

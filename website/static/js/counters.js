import { prefersReducedMotion, supportsObserver } from "./reduced-motion.js";

const DURATION_BASE = 1500; // PRD §10: duration = 1500 + i*80
const DURATION_STEP = 80;
const DELAY_BASE = 480;     // PRD §10: delay = 480 + i*90
const DELAY_STEP = 90;

function easeOutCubic(t) {
  return 1 - Math.pow(1 - t, 3);
}

function format(value, decimals) {
  return decimals > 0 ? value.toFixed(decimals) : String(Math.round(value));
}

function run(el, index) {
  const target = Number.parseFloat(el.dataset.countTo || "0");
  const decimals = Number.parseInt(el.dataset.decimals || "0", 10);
  const suffix = el.dataset.suffix || "";
  if (!Number.isFinite(target)) return;

  if (prefersReducedMotion()) {
    el.textContent = `${format(target, decimals)}${suffix}`;
    return;
  }

  const duration = DURATION_BASE + index * DURATION_STEP;
  const delay = DELAY_BASE + index * DELAY_STEP;
  let start = null;

  const step = (timestamp) => {
    if (start === null) start = timestamp;
    const progress = Math.min((timestamp - start) / duration, 1);
    const value = target * easeOutCubic(progress);
    el.textContent = `${format(value, decimals)}${suffix}`;
    if (progress < 1) window.requestAnimationFrame(step);
  };

  el.textContent = `${format(0, decimals)}${suffix}`;
  window.setTimeout(() => window.requestAnimationFrame(step), delay);
}

/** Animated metrics. Each element counts once, when it first becomes visible. */
export function initCounters() {
  const counters = Array.from(document.querySelectorAll("[data-count-to]"));
  if (!counters.length) return;

  if (!supportsObserver()) {
    counters.forEach((el, index) => run(el, index));
    return;
  }

  const seen = new Set();
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting || seen.has(entry.target)) return;
      seen.add(entry.target);
      run(entry.target, counters.indexOf(entry.target));
      observer.unobserve(entry.target);
    });
  }, { threshold: 0.4 });

  counters.forEach((el) => observer.observe(el));
}
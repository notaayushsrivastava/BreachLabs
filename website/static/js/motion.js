import { prefersReducedMotion, supportsObserver } from "./reduced-motion.js";

function staggerDelay(el) {
  const siblings = el.parentElement ? Array.from(el.parentElement.children) : [];
  const index = siblings.indexOf(el);
  return Math.min(Math.max(index, 0), 7) * 70;
}

/**
 * Single-viewport entry reveals plus staggered groups and the section rail.
 * Everything animates with transform/opacity/filter only.
 */
export function initReveal() {
  const targets = document.querySelectorAll(".reveal, .stagger");

  if (prefersReducedMotion() || !supportsObserver()) {
    targets.forEach((el) => el.classList.add("is-visible"));
    return;
  }

  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting) return;
      const el = entry.target;
      if (el.classList.contains("stagger")) {
        el.classList.add("is-visible");
      } else {
        el.style.setProperty("--d", `${staggerDelay(el)}ms`);
        el.classList.add("is-visible");
      }
      observer.unobserve(el);
    });
  }, { threshold: 0.14, rootMargin: "0px 0px -8% 0px" });

  targets.forEach((el) => observer.observe(el));
}

/** Thin scroll position rule at the top of the document. */
export function initScrollProgress() {
  const bar = document.getElementById("scroll-progress");
  if (!bar) return;
  let raf = 0;
  const sync = () => {
    raf = 0;
    const doc = document.documentElement;
    const max = doc.scrollHeight - doc.clientHeight;
    bar.style.width = `${max > 0 ? (doc.scrollTop / max) * 100 : 0}%`;
  };
  window.addEventListener("scroll", () => {
    if (!raf) raf = window.requestAnimationFrame(sync);
  }, { passive: true });
  window.addEventListener("resize", sync, { passive: true });
  sync();
}

/**
 * Progressive fill for `.rail`: marks the item nearest the reading position
 * and grows the track fill to that item's offset.
 */
export function initRail() {
  document.querySelectorAll("[data-rail]").forEach((rail) => {
    const items = Array.from(rail.querySelectorAll(".rail-item"));
    const fill = rail.querySelector("[data-rail-fill]");
    if (!items.length || !fill) return;

    if (prefersReducedMotion() || !supportsObserver()) {
      items.forEach((item) => item.setAttribute("data-active", "true"));
      fill.style.height = "100%";
      return;
    }

    const mark = (active) => {
      items.forEach((item) => item.setAttribute("data-active", String(item === active)));
      const offset = active.offsetTop + active.offsetHeight * 0.5;
      fill.style.height = `${offset}px`;
    };

    mark(items[0]);

    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) mark(entry.target);
      });
    }, { threshold: 0.55, rootMargin: "-18% 0px -38% 0px" });

    items.forEach((item) => observer.observe(item));
  });
}
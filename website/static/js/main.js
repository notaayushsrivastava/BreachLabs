/**
 * Shared entry point for all pages.
 * Imports activate each page's own module, which self-initializes on its own
 * DOMContentLoaded. This file focuses on the things every route needs:
 * nav behaviour, scroll progress, reveal timing, and the route-independent skeleton.
 */
import { initNav } from "./nav.js";
import { initReveal, initScrollProgress, initRail } from "./motion.js";
import { initCounters } from "./counters.js";
import { initWorkflow } from "./workflow.js";

export function init() {
  initNav();
  initScrollProgress();
  initReveal();
  initRail();
  initCounters();
  initWorkflow();
}

if (typeof window !== "undefined") {
  window.document.addEventListener("DOMContentLoaded", () => {
    try { init(); } catch (e) { console.error(e); }
  });
}
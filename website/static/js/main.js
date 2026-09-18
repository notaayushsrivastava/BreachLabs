import { initNav } from "./nav.js";
import { initReveal, initScrollProgress } from "./motion.js";
import { initCounters } from "./counters.js";
import { initWorkflow } from "./workflow.js";
import { initArchitecture } from "./architecture.js";
import { prefersReducedMotion } from "./reduced-motion.js";

export function init() {
  try { initNav(); } catch (e) { console.error(e); }
  try { initReveal(); } catch (e) { console.error(e); }
  try { initScrollProgress(); } catch (e) { console.error(e); }
  try { initCounters(); } catch (e) { console.error(e); }
  try { initWorkflow(); } catch (e) { console.error(e); }
  try { initArchitecture(); } catch (e) { console.error(e); }
  const y = document.getElementById("year");
  if (y) y.textContent = String(new Date().getFullYear());
  document.documentElement.dataset.motion =
    prefersReducedMotion() ? "reduced" : "full";
}
document.addEventListener("DOMContentLoaded", init);

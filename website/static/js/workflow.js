import { prefersReducedMotion, supportsObserver } from "./reduced-motion.js";

/**
 * Highlights the loop stage currently in view inside any `[data-stages]` list.
 * Purely presentational: the stage copy is always present in the DOM.
 */
export function initWorkflow() {
  const roots = document.querySelectorAll("[data-stages]");
  if (!roots.length) return;

  roots.forEach((root) => {
    const stages = Array.from(root.querySelectorAll("[data-stage]"));

    if (prefersReducedMotion() || !supportsObserver()) {
      stages.forEach((stage) => stage.setAttribute("data-on", "true"));
      return;
    }

    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) entry.target.setAttribute("data-on", "true");
      });
    }, { threshold: 0.6 });

    stages.forEach((stage) => observer.observe(stage));
  });
}
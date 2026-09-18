/** Central reduced-motion guard used by every animation module. */
export function prefersReducedMotion() {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/** True when the browser can drive IntersectionObserver. */
export function supportsObserver() {
  return "IntersectionObserver" in window;
}
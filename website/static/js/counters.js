export function initCounters() {
  document.querySelectorAll("[data-count-to]").forEach((el) => {
    el.textContent = el.dataset.countTo;
  });
}

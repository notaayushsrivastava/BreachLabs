export function initNav() {
  const btn = document.querySelector("[data-nav-toggle]");
  const sheet = document.getElementById("mobile-sheet");
  if (!btn || !sheet) return;
  const close = () => {
    sheet.classList.remove("is-open");
    btn.setAttribute("aria-expanded", "false");
  };
  btn.addEventListener("click", () => {
    const open = sheet.classList.toggle("is-open");
    btn.setAttribute("aria-expanded", String(open));
    if (open) {
      const first = sheet.querySelector("a");
      if (first) first.focus();
    }
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { close(); btn.focus(); }
  });
  sheet.addEventListener("click", (e) => {
    if (e.target === sheet) close();
  });
}

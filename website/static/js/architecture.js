export function initArchitecture() {
  document.querySelectorAll(".arch-node").forEach((n) => {
    n.addEventListener("click", () => {
      document.querySelectorAll(".arch-node").forEach((m) => m.removeAttribute("data-active"));
      n.setAttribute("data-active", "true");
    });
  });
}

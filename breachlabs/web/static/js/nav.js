/**
 * Nav behaviour: mobile sheet, floating header reveal, scrolled glass state.
 * The header stays hidden on the home hero until the hero is scrolled past,
 * so the hero keeps the PRD §10 three-region composition at rest.
 */
export function initNav() {
  const header = document.querySelector("[data-site-header]");
  const toggle = document.querySelector("[data-nav-toggle]");
  const sheet = document.getElementById("mobile-sheet");
  const hero = document.querySelector(".page");

  if (header && hero) {
    let raf = 0;
    const sync = () => {
      raf = 0;
      const past = window.scrollY > window.innerHeight * 0.72;
      header.classList.toggle("is-revealed", past);
      header.classList.toggle("is-scrolled", window.scrollY > window.innerHeight * 0.9);
    };
    const onScroll = () => {
      if (!raf) raf = window.requestAnimationFrame(sync);
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    sync();
  } else if (header) {
    // Sub-pages have no hero: the header is present throughout and gains
    // its glass treatment once the page moves.
    let raf = 0;
    const sync = () => {
      raf = 0;
      header.classList.add("is-revealed");
      header.classList.toggle("is-scrolled", window.scrollY > 8);
    };
    window.addEventListener("scroll", () => {
      if (!raf) raf = window.requestAnimationFrame(sync);
    }, { passive: true });
    sync();
  }

  if (!toggle || !sheet) return;

  const setOpen = (open) => {
    sheet.classList.toggle("is-open", open);
    toggle.setAttribute("aria-expanded", String(open));
    sheet.setAttribute("aria-hidden", String(!open));
    if (open) {
      const first = sheet.querySelector("a");
      if (first) first.focus();
    }
  };

  setOpen(false);

  toggle.addEventListener("click", () => {
    setOpen(toggle.getAttribute("aria-expanded") !== "true");
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && sheet.classList.contains("is-open")) {
      setOpen(false);
      toggle.focus();
    }
  });

  sheet.querySelectorAll("a").forEach((link) => {
    link.addEventListener("click", () => setOpen(false));
  });

  window.addEventListener("resize", () => {
    if (window.innerWidth > 720) setOpen(false);
  }, { passive: true });

  // Dropdown interactions for touch / click
  document.querySelectorAll("[data-dropdown]").forEach((container) => {
    const trigger = container.querySelector(".nav-dropdown-trigger, .hero-dropdown-trigger");
    if (!trigger) return;

    trigger.addEventListener("click", (e) => {
      e.stopPropagation();
      const isExpanded = trigger.getAttribute("aria-expanded") === "true";
      trigger.setAttribute("aria-expanded", String(!isExpanded));
      container.classList.toggle("is-open", !isExpanded);
    });
  });

  document.addEventListener("click", () => {
    document.querySelectorAll("[data-dropdown]").forEach((container) => {
      container.classList.remove("is-open");
      const trigger = container.querySelector(".nav-dropdown-trigger, .hero-dropdown-trigger");
      if (trigger) trigger.setAttribute("aria-expanded", "false");
    });
  });
}
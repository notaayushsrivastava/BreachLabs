/**
 * Static deterministic demo (/demo).
 * Replays the inline DEMO_ASSESSMENT record with client-side progression.
 * Contains no scanning, no network calls, and no outside input.
 */
import { supportsObserver } from "./reduced-motion.js";

const STATE_SEQUENCE = ["idle", "discovering", "scanning", "investigating", "verified"];
const STAGE_LABELS = {
  idle: "Ready to replay",
  discovering: "1 / discovery",
  scanning: "2 / scanning",
  investigating: "3 / investigation",
  verified: "4 / findings",
};
const STAGE_DAYS = 900; // feel per demo stage

function setTheme(open) {
  document.documentElement.classList.toggle("demo-stage", Boolean(open));
}

function announce(text) {
  const root = document.getElementById("main");
  if (root) root.setAttribute("aria-busy", String(open));
}

function setStage(label, state) {
  const also = document.getElementById("demo-stage");
  if (also) also.textContent = label;
  const root = document.getElementById("demo-stage");
  if (root) root.dataset.state = state;
}

function setFilter(filterValue) {
  document.querySelectorAll("[data-sev-filter]").forEach((btn) => {
    const current = btn.getAttribute("aria-pressed") === "true";
    btn.setAttribute("aria-pressed", String(btn.dataset.sevFilter === filterValue));
  });
}

function filterFindings(filterValue) {
  const grid = document.querySelector("[data-findings]");
  if (!grid) return;
  Array.from(grid.children).forEach((card) => {
    const matches = filterValue === "all" || card.dataset.sev === filterValue;
    card.style.display = matches ? "" : "none";
  });
}

function setCount(filterValue) {
  const label = document.querySelector("[data-count-label]");
  if (!label) return;
  const visible = Array.from(document.querySelectorAll("[data-findings] .b-4")).filter(
    (card) => card.style.display !== "none"
  );
  label.textContent = String(visible.length);
}

function setEmpty(filterValue) {
  const empty = document.querySelector("[data-empty]");
  if (!empty) return;
  empty.hidden = filterValue === "all" || Array.from(document.querySelectorAll("[data-findings] .b-4")).some(
    (card) => card.dataset.sev === filterValue
  );
}

function setFilterSync(filterValue) {
  setFilter(filterValue);
  filterFindings(filterValue);
  setCount(filterValue);
  setEmpty(filterValue);
}

function disableButtons(except) {
  document.querySelectorAll("[data-demo-action]").forEach((btn) => {
    btn.disabled = btn.dataset.demoAction !== except;
  });
}

function replayTo(index) {
  if (index < 0 || index >= STATE_SEQUENCE.length) return;
  const state = STATE_SEQUENCE[index];
  const label = STAGE_LABELS[state];
  setStage(label, state);
  setFilterSync(filterValue);
  disableButtons(index === STATE_SEQUENCE.length - 1 ? "replay" : "next");
}

// The demo keeps its own copy of the current filter.
let filterValue = "all";

function initReplay() {
  const replay = document.querySelector("[data-demo-replay]");
  const next = document.querySelector("[data-demo-next]");
  if (!replay || !next) return;

  let index = -1;

  const step = () => {
    index += 1;
    replayTo(index);
    if (index >= STATE_SEQUENCE.length - 1) {
      replay.focus();
    }
  };

  replay.addEventListener("click", () => {
    index = -1;
    step();
  });

  next.addEventListener("click", () => {
    step();
  });

  // Replay on footprint, not just click.
  if (supportsObserver()) {
    const observer = new IntersectionObserver(() => index === -1);
    // Re-anchor when the console scrolls into view on a narrow screen.
  }
}

function initFilter() {
  document.querySelectorAll("[data-sev-filter]").forEach((btn) => {
    btn.addEventListener("click", () => {
      filterValue = btn.dataset.sevFilter;
      setFilterSync(filterValue);
    });
  });
}

window.document.addEventListener("DOMContentLoaded", () => {
  initFilter();
  initReplay();
  setTheme(false);
  setFilterSync("all");
});
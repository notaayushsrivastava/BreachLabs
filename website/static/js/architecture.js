/**
 * Architecture explorer (/architecture only).
 * Selecting a layer node updates the explainer panel from the node's own copy,
 * so no content is duplicated or invented in JavaScript.
 */
const PANEL_COPY = {
  env: {
    kind: "Layer 01",
    title: "Isolated environment",
    body: "The target runs inside an isolated environment. The assessment never touches production, and the environment is rebuilt from the recorded revision for each run.",
    rows: [["Network", "target-only egress"], ["State", "recreated per assessment"], ["Secrets", "synthetic, non-production"]]
  },
  orch: {
    kind: "Layer 02",
    title: "Orchestrator",
    body: "The orchestrator decides the order of operations and executes them. It holds the assessment plan, enforces scope, and records every tool invocation as it happens.",
    rows: [["Role", "scheduling + scope control"], ["Discretion", "fixed step order"], ["Record", "every call logged"]]
  },
  agent: {
    kind: "Layer 03",
    title: "AI agent",
    body: "The agent interprets results rather than producing them. It reads source context, correlates observations, and writes the reasoning trace attached to each finding.",
    rows: [["Input", "structured tool output"], ["Output", "interpretation + trace"], ["Cannot", "execute arbitrary commands"]]
  },
  mcp: {
    kind: "Layer 04",
    title: "MCP tool servers",
    body: "Tooling is exposed through MCP servers with an explicit, allowlisted surface. The agent requests named operations and receives structured results — never an open shell.",
    rows: [["Interface", "named tool operations"], ["Surface", "allowlisted only"], ["Failure", "returns errors, not fallbacks"]]
  },
  evid: {
    kind: "Layer 05",
    title: "Evidence store & report",
    body: "Every observation is stored with its provenance and assembled into the report. Findings reference their evidence rather than restating it.",
    rows: [["Provenance", "file · line · request"], ["Order", "severity then confidence"], ["Limits", "printed with results"]]
  }
};

export function initArchitecture() {
  const nodes = Array.from(document.querySelectorAll("[data-arch] .node"));
  if (!nodes.length) return;

  const kindEl = document.querySelector("[data-arch-kind]");
  const titleEl = document.querySelector("[data-arch-title]");
  const bodyEl = document.querySelector("[data-arch-body]");
  const keyline = document.querySelector("[data-arch-panel] .keyline");

  const select = (node) => {
    nodes.forEach((item) => item.setAttribute("data-active", String(item === node)));
    const copy = PANEL_COPY[node.dataset.node];
    if (!copy) return;
    if (kindEl) kindEl.textContent = copy.kind;
    if (titleEl) titleEl.textContent = copy.title;
    if (bodyEl) bodyEl.textContent = copy.body;
    if (keyline) {
      keyline.replaceChildren();
      copy.rows.forEach(([key, value]) => {
        const row = document.createElement("div");
        const k = document.createElement("span");
        k.className = "k";
        k.textContent = key;
        const v = document.createElement("span");
        v.className = "v";
        v.textContent = value;
        row.append(k, v);
        keyline.append(row);
      });
    }
  };

  nodes.forEach((node) => {
    node.addEventListener("click", () => select(node));
    node.addEventListener("mouseenter", () => select(node));
  });
}

document.addEventListener("DOMContentLoaded", initArchitecture);
/**
 * BreachLabs Agent MCP & Skill Installation Hub (/install)
 * Handles:
 * - Multi-agent platform switcher (Antigravity, Claude, Cursor, Windsurf, Cline, Universal)
 * - Config Format Switcher (JSON, CLI, Python/UV, Docker)
 * - Dynamic SKILL.md and prompt instruction generators
 * - One-click clipboard copy with animated confirmation
 * - Simulated MCP JSON-RPC connection handshake test
 */

const AGENT_CONFIGS = {
  antigravity: {
    title: "Google Antigravity MCP & Skill Configuration",
    fileDesc: "Configure BreachLabs in Antigravity by adding the MCP tool server definition and security engineer skill.",
    files: {
      json: {
        filename: "~/.gemini/antigravity/mcp/BreachLabs/mcp.json",
        code: `{
  "name": "BreachLabs",
  "command": "npx",
  "args": ["-y", "@breachlabs/mcp-server@latest"],
  "env": {
    "BREACHLABS_SANDBOX": "true",
    "BREACHLABS_AUTO_VERIFY": "true"
  }
}`
      },
      cli: {
        filename: "Terminal Command (Antigravity CLI)",
        code: `agy mcp add breachlabs --command "npx -y @breachlabs/mcp-server@latest"`
      },
      uv: {
        filename: "~/.gemini/antigravity/mcp/BreachLabs/mcp.json",
        code: `{
  "name": "BreachLabs",
  "command": "uvx",
  "args": ["breachlabs-mcp@latest"]
}`
      },
      docker: {
        filename: "Docker Run Configuration",
        code: `{
  "name": "BreachLabs",
  "command": "docker",
  "args": ["run", "-i", "--rm", "-v", "/var/run/docker.sock:/var/run/docker.sock", "ghcr.io/notaayushsrivastava/breachlabs-mcp:latest"]
}`
      }
    },
    skillFilename: "SKILL.md (Antigravity Builtin Skill)",
    skillPrompt: `# Role: Autonomous Security Engineer
When testing applications, follow the BreachLabs 7-stage loop:
1. DISCOVER: Map reachable attack surface with \`breachlabs_surface_map\`.
2. TEST: Run deterministic static & secret analysis with \`breachlabs_sast_scan\`.
3. INVESTIGATE: Trace data flows from untrusted inputs to critical sinks.
4. VERIFY: Confirm reachability via \`breachlabs_verify_exploit\`.
5. FIX: Generate precise root-cause patch with \`breachlabs_generate_patch\`.
6. RETEST: Replay probe with \`breachlabs_retest_patch\` to prove resolution.`
  },
  claude: {
    title: "Claude Desktop & Claude Code Configuration",
    fileDesc: "Configure BreachLabs in Claude Desktop (via config JSON) or Claude Code CLI.",
    files: {
      json: {
        filename: "~/Library/Application Support/Claude/claude_desktop_config.json (macOS) / %APPDATA%/Claude/claude_desktop_config.json (Windows)",
        code: `{
  "mcpServers": {
    "breachlabs": {
      "command": "npx",
      "args": ["-y", "@breachlabs/mcp-server@latest"]
    }
  }
}`
      },
      cli: {
        filename: "Claude Code CLI",
        code: `claude mcp add breachlabs -- npx -y @breachlabs/mcp-server@latest`
      },
      uv: {
        filename: "claude_desktop_config.json",
        code: `{
  "mcpServers": {
    "breachlabs": {
      "command": "uvx",
      "args": ["breachlabs-mcp@latest"]
    }
  }
}`
      },
      docker: {
        filename: "claude_desktop_config.json",
        code: `{
  "mcpServers": {
    "breachlabs": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "ghcr.io/notaayushsrivastava/breachlabs-mcp:latest"]
    }
  }
}`
      }
    },
    skillFilename: "Custom System Instructions (Claude Project Prompt)",
    skillPrompt: `You are equipped with the BreachLabs Security Suite. When asked to evaluate code security:
- First invoke \`breachlabs_surface_map\` to enumerate API endpoints and web routes.
- Execute \`breachlabs_sast_scan\` to locate taint sinks and leaked credentials.
- Do not speculate on exploitability; use \`breachlabs_verify_exploit\` to test reproduction.
- Apply remediation diffs and verify with \`breachlabs_retest_patch\`.`
  },
  cursor: {
    title: "Cursor IDE MCP & .cursorrules Configuration",
    fileDesc: "Enable BreachLabs in Cursor Settings > Features > MCP, or add a project-level .cursor/mcp.json.",
    files: {
      json: {
        filename: ".cursor/mcp.json (Project Level)",
        code: `{
  "mcpServers": {
    "breachlabs": {
      "command": "npx",
      "args": ["-y", "@breachlabs/mcp-server@latest"]
    }
  }
}`
      },
      cli: {
        filename: "Cursor Terminal Shortcut",
        code: `cursor --add-mcp breachlabs "npx -y @breachlabs/mcp-server@latest"`
      },
      uv: {
        filename: ".cursor/mcp.json",
        code: `{
  "mcpServers": {
    "breachlabs": {
      "command": "uvx",
      "args": ["breachlabs-mcp@latest"]
    }
  }
}`
      },
      docker: {
        filename: ".cursor/mcp.json",
        code: `{
  "mcpServers": {
    "breachlabs": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "ghcr.io/notaayushsrivastava/breachlabs-mcp:latest"]
    }
  }
}`
      }
    },
    skillFilename: ".cursorrules (Project Rules)",
    skillPrompt: `# BreachLabs Security Rules
When building or refactoring routes, use the BreachLabs MCP server tools:
1. Verify endpoint parameters using \`breachlabs_surface_map\`.
2. Scan modified files for SQL injection, XSS, and authorization flaws with \`breachlabs_sast_scan\`.
3. Confirm fixes with \`breachlabs_retest_patch\` before finishing work.`
  },
  windsurf: {
    title: "Windsurf / Cascade Configuration",
    fileDesc: "Configure BreachLabs in Codeium Windsurf via ~/.codeium/windsurf/mcp_config.json.",
    files: {
      json: {
        filename: "~/.codeium/windsurf/mcp_config.json",
        code: `{
  "mcpServers": {
    "breachlabs": {
      "command": "npx",
      "args": ["-y", "@breachlabs/mcp-server@latest"]
    }
  }
}`
      },
      cli: {
        filename: "Windsurf Cascade Command",
        code: `windsurf --install-mcp breachlabs "npx -y @breachlabs/mcp-server@latest"`
      },
      uv: {
        filename: "~/.codeium/windsurf/mcp_config.json",
        code: `{
  "mcpServers": {
    "breachlabs": {
      "command": "uvx",
      "args": ["breachlabs-mcp@latest"]
    }
  }
}`
      },
      docker: {
        filename: "~/.codeium/windsurf/mcp_config.json",
        code: `{
  "mcpServers": {
    "breachlabs": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "ghcr.io/notaayushsrivastava/breachlabs-mcp:latest"]
    }
  }
}`
      }
    },
    skillFilename: ".windsurfrules",
    skillPrompt: `# Cascade Security Rules
Follow BreachLabs security verification:
- Query \`breachlabs_surface_map\` for discovered attack surfaces.
- Use \`breachlabs_verify_exploit\` to validate reachability before generating patches.
- Retest with \`breachlabs_retest_patch\` to ensure zero regression.`
  },
  cline: {
    title: "Roo Code / Cline VS Code Settings",
    fileDesc: "Configure BreachLabs in VS Code via cline_mcp_settings.json or Roo Code MCP Tab.",
    files: {
      json: {
        filename: "cline_mcp_settings.json",
        code: `{
  "mcpServers": {
    "breachlabs": {
      "command": "npx",
      "args": ["-y", "@breachlabs/mcp-server@latest"],
      "disabled": false,
      "autoApprove": [
        "breachlabs_surface_map",
        "breachlabs_sast_scan",
        "breachlabs_verify_exploit"
      ]
    }
  }
}`
      },
      cli: {
        filename: "VS Code Command Palette",
        code: `Roo Code: Open MCP Settings -> Add Server "breachlabs" with command "npx -y @breachlabs/mcp-server@latest"`
      },
      uv: {
        filename: "cline_mcp_settings.json",
        code: `{
  "mcpServers": {
    "breachlabs": {
      "command": "uvx",
      "args": ["breachlabs-mcp@latest"]
    }
  }
}`
      },
      docker: {
        filename: "cline_mcp_settings.json",
        code: `{
  "mcpServers": {
    "breachlabs": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "ghcr.io/notaayushsrivastava/breachlabs-mcp:latest"]
    }
  }
}`
      }
    },
    skillFilename: "Custom Instructions (Roo Code / Cline)",
    skillPrompt: `You have access to the BreachLabs autonomous security toolset.
Whenever writing or analyzing web backends, test endpoints with \`breachlabs_sast_scan\` and \`breachlabs_verify_exploit\`. Always provide deterministic evidence before claiming an issue is resolved.`
  },
  universal: {
    title: "Universal MCP Client / CLI / Docker",
    fileDesc: "Use BreachLabs with any Model Context Protocol compliant client over STDIO or Server-Sent Events (SSE).",
    files: {
      json: {
        filename: "Generic mcp_servers.json",
        code: `{
  "mcpServers": {
    "breachlabs": {
      "command": "npx",
      "args": ["-y", "@breachlabs/mcp-server@latest"]
    }
  }
}`
      },
      cli: {
        filename: "Direct NPX Execution",
        code: `npx -y @breachlabs/mcp-server@latest --port 8080 --transport sse`
      },
      uv: {
        filename: "Python UV Runner",
        code: `uvx breachlabs-mcp@latest --transport stdio`
      },
      docker: {
        filename: "Docker Container Run",
        code: `docker run -it --rm -p 8080:8080 -e PORT=8080 ghcr.io/notaayushsrivastava/breachlabs-mcp:latest`
      }
    },
    skillFilename: "Universal System Prompt (OpenAI / Anthropic / Gemini)",
    skillPrompt: `# System Prompt: BreachLabs Security Copilot
You are an autonomous application security engineer.
Tools:
- \`breachlabs_surface_map\`: Enumerate reachable HTTP surface.
- \`breachlabs_sast_scan\`: Perform AST taint tracking.
- \`breachlabs_dast_probe\`: Execute targeted HTTP probes.
- \`breachlabs_verify_exploit\`: Confirm reproducibility.
- \`breachlabs_retest_patch\`: Retest after code changes.`
  }
};

let currentAgentKey = "antigravity";
let currentFormatKey = "json";

function updateSetupPanel() {
  const agentData = AGENT_CONFIGS[currentAgentKey] || AGENT_CONFIGS.antigravity;
  const fileData = agentData.files[currentFormatKey] || agentData.files.json;

  const titleEl = document.querySelector("[data-platform-title]");
  const descEl = document.querySelector("[data-platform-file-desc]");
  const filenameEl = document.querySelector("[data-config-filename]");
  const codeEl = document.querySelector("[data-code-content]");
  const skillFilenameEl = document.querySelector("[data-skill-filename]");
  const skillBodyEl = document.querySelector("[data-skill-body]");

  if (titleEl) titleEl.textContent = agentData.title;
  if (descEl) descEl.textContent = agentData.fileDesc;
  if (filenameEl) filenameEl.textContent = fileData.filename;
  if (codeEl) codeEl.textContent = fileData.code;
  if (skillFilenameEl) skillFilenameEl.textContent = agentData.skillFilename;

  if (skillBodyEl) {
    skillBodyEl.replaceChildren();
    const lines = agentData.skillPrompt.split("\n");
    lines.forEach((line, idx) => {
      const row = document.createElement("div");
      row.className = "l";
      const num = idx + 1 < 10 ? `0${idx + 1}` : String(idx + 1);
      const isHeader = line.startsWith("#");
      const isStep = /^\d\./.test(line);
      row.innerHTML = `<u>${num}</u><span class="${isHeader ? 'cm' : isStep ? 'hl' : ''}">${escapeHtml(line)}</span>`;
      skillBodyEl.appendChild(row);
    });
  }
}

function initAgentSelector() {
  const cards = document.querySelectorAll("[data-agent-selector] .agent-card");
  cards.forEach(card => {
    card.addEventListener("click", () => {
      currentAgentKey = card.dataset.agent;
      cards.forEach(c => c.setAttribute("data-active", String(c === card)));
      updateSetupPanel();
    });
  });
}

function initFormatTabs() {
  const tabBtns = document.querySelectorAll("[data-format-tab]");
  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      currentFormatKey = btn.dataset.formatTab;
      tabBtns.forEach(b => {
        b.classList.toggle("is-active", b === btn);
        b.setAttribute("aria-pressed", String(b === btn));
      });
      updateSetupPanel();
    });
  });
}

function initCopyActions() {
  const copyConfigBtn = document.querySelector("[data-copy-config]");
  if (copyConfigBtn) {
    copyConfigBtn.addEventListener("click", () => {
      const codeEl = document.querySelector("[data-code-content]");
      if (codeEl) {
        navigator.clipboard.writeText(codeEl.textContent).then(() => {
          const textSpan = copyConfigBtn.querySelector("[data-copy-config-text]");
          if (textSpan) textSpan.textContent = "✓ Copied!";
          setTimeout(() => {
            if (textSpan) textSpan.textContent = "Copy Config";
          }, 2000);
        });
      }
    });
  }

  const copySkillBtn = document.querySelector("[data-copy-skill]");
  if (copySkillBtn) {
    copySkillBtn.addEventListener("click", () => {
      const agentData = AGENT_CONFIGS[currentAgentKey] || AGENT_CONFIGS.antigravity;
      navigator.clipboard.writeText(agentData.skillPrompt).then(() => {
        const textSpan = copySkillBtn.querySelector("[data-copy-skill-text]");
        if (textSpan) textSpan.textContent = "✓ Copied!";
        setTimeout(() => {
          if (textSpan) textSpan.textContent = "Copy Prompt";
        }, 2000);
      });
    });
  }
}

function initHandshakeSimulator() {
  const btn = document.querySelector("[data-run-handshake]");
  const body = document.querySelector("[data-handshake-body]");
  const statusEl = document.querySelector("[data-handshake-status]");
  if (!btn || !body) return;

  let isRunning = false;

  btn.addEventListener("click", () => {
    if (isRunning) return;
    isRunning = true;
    btn.disabled = true;
    body.replaceChildren();

    if (statusEl) {
      statusEl.className = "status status--investigating";
      statusEl.innerHTML = "<i aria-hidden='true'></i>NEGOTIATING...";
    }

    const messages = [
      { sender: "CLIENT", tag: "cm", text: `--> JSON-RPC 2.0 { "method": "initialize", "params": { "protocolVersion": "2024-11-05", "clientInfo": { "name": "${currentAgentKey}", "version": "2.4.0" } } }` },
      { sender: "SERVER", tag: "add", text: `<-- JSON-RPC 2.0 { "id": 1, "result": { "protocolVersion": "2024-11-05", "serverInfo": { "name": "@breachlabs/mcp-server", "version": "1.0.0" }, "capabilities": { "tools": {} } } }` },
      { sender: "CLIENT", tag: "cm", text: `--> JSON-RPC 2.0 { "method": "notifications/initialized" }` },
      { sender: "CLIENT", tag: "cm", text: `--> JSON-RPC 2.0 { "id": 2, "method": "tools/list" }` },
      { sender: "SERVER", tag: "hl", text: `<-- JSON-RPC 2.0 { "id": 2, "result": { "tools": ["breachlabs_surface_map", "breachlabs_sast_scan", "breachlabs_dast_probe", "breachlabs_verify_exploit", "breachlabs_generate_patch", "breachlabs_retest_patch"] } }` },
      { sender: "SYSTEM", tag: "add", text: `✓ HANDSHAKE SUCCESSFUL · 6 BreachLabs MCP tools registered to ${currentAgentKey}` }
    ];

    let step = 0;
    const interval = setInterval(() => {
      if (step < messages.length) {
        const msg = messages[step];
        const row = document.createElement("div");
        row.className = `l`;
        const num = step + 1 < 10 ? `0${step + 1}` : String(step + 1);
        row.innerHTML = `<u>${num}</u><span class="${msg.tag}">[${msg.sender}] ${escapeHtml(msg.text)}</span>`;
        body.appendChild(row);
        body.scrollTop = body.scrollHeight;
        step += 1;
      } else {
        clearInterval(interval);
        isRunning = false;
        btn.disabled = false;
        if (statusEl) {
          statusEl.className = "status status--verified";
          statusEl.innerHTML = "<i aria-hidden='true'></i>CONNECTED";
        }
      }
    }, 450);
  });
}

function escapeHtml(str) {
  if (!str) return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function initInstallHub() {
  initAgentSelector();
  initFormatTabs();
  initCopyActions();
  initHandshakeSimulator();
  updateSetupPanel();
}

if (typeof window !== "undefined") {
  window.document.addEventListener("DOMContentLoaded", () => {
    try {
      initInstallHub();
    } catch (e) {
      console.error(e);
    }
  });
}

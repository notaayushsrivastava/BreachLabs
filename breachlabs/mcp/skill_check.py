"""Skill and MCP installation verification helpers.

Enables reciprocal verification between the BreachLabs MCP server and
the AI Agent Skill, ensuring both components are installed and guiding
the user with actionable installation instructions if either is missing.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def get_skill_search_paths(repo_path: str | None = None) -> list[Path]:
    """Return prioritized candidate paths where the BreachLabs skill may reside."""
    home = Path.home()
    candidates: list[Path] = []

    # 1. Active repository / workspace
    if repo_path:
        r_path = Path(repo_path)
        candidates.extend([
            r_path / "skills" / "breachlabs" / "SKILL.md",
            r_path / "skills" / "breachlabs",
            r_path / ".skills" / "breachlabs" / "SKILL.md",
            r_path / "SKILL.md",
        ])

    # 2. Current working directory
    cwd = Path.cwd()
    candidates.extend([
        cwd / "skills" / "breachlabs" / "SKILL.md",
        cwd / "skills" / "breachlabs",
        cwd / ".skills" / "breachlabs" / "SKILL.md",
    ])

    # 3. Global agent skill directories (Antigravity, Cursor, Windsurf, Claude, Universal)
    candidates.extend([
        home / ".gemini" / "antigravity" / "skills" / "breachlabs" / "SKILL.md",
        home / ".gemini" / "antigravity" / "skills" / "breachlabs",
        home / ".gemini" / "config" / "plugins" / "breachlabs" / "SKILL.md",
        home / ".skills" / "breachlabs" / "SKILL.md",
        home / ".skills" / "breachlabs",
        home / ".cursor" / "skills" / "breachlabs" / "SKILL.md",
        home / ".codeium" / "windsurf" / "skills" / "breachlabs" / "SKILL.md",
        home / ".claude" / "skills" / "breachlabs" / "SKILL.md",
    ])

    return candidates


def check_skill_installation(repo_path: str | None = None) -> dict[str, Any]:
    """Verify if the BreachLabs Skill is installed.

    Returns structured status with installation guidance.
    """
    candidates = get_skill_search_paths(repo_path)
    found_path: str | None = None

    for p in candidates:
        if p.exists():
            found_path = str(p.resolve())
            break

    skill_installed = found_path is not None
    mcp_running = True  # We are executing within the active MCP server runtime

    if skill_installed:
        message = f"BreachLabs Skill is installed at '{found_path}'."
        prompt = None
    else:
        message = (
            "BreachLabs Skill is NOT detected in standard agent skill locations. "
            "Please install the universal skill via npx to give your agent the full security workflow."
        )
        prompt = (
            "⚠️ Notice: The BreachLabs Skill is not installed in your agent environment.\n"
            "To install the skill, run:\n"
            "  $ npx -y skills add breachlabs\n"
            "Or copy the universal SKILL.md from http://127.0.0.1:8000/install"
        )

    return {
        "skill_installed": skill_installed,
        "installed_path": found_path,
        "mcp_installed": mcp_running,
        "mcp_running": mcp_running,
        "status": "ready" if skill_installed else "skill_missing",
        "message": message,
        "prompt": prompt,
        "install_commands": {
            "skill": "npx -y skills add breachlabs",
            "mcp_start": "python run_breachlabs.py",
            "mcp_url": "http://127.0.0.1:8000/mcp",
            "install_hub": "http://127.0.0.1:8000/install",
        },
    }


def format_installation_prompt(
    skill_missing: bool = False,
    mcp_missing: bool = False,
) -> str:
    """Format a clear user-facing prompt when either or both components are missing."""
    if skill_missing and mcp_missing:
        return (
            "⚠️ BreachLabs requires both the MCP Server and the Agent Skill to operate.\n\n"
            "1. Install and Start the MCP Server:\n"
            "   Run: python run_breachlabs.py (or breachlabs serve)\n"
            "   Configure your agent with URL: http://127.0.0.1:8000/mcp\n\n"
            "2. Install the Agent Skill:\n"
            "   Run: npx -y skills add breachlabs\n\n"
            "Visit http://127.0.0.1:8000/install for guided one-click configuration."
        )
    if mcp_missing:
        return (
            "⚠️ BreachLabs MCP Server is not detected or running.\n\n"
            "To start the MCP Server:\n"
            "   Run: python run_breachlabs.py (or breachlabs serve)\n"
            "   Configure your agent with URL: http://127.0.0.1:8000/mcp\n"
            "Visit http://127.0.0.1:8000/install for quick configuration."
        )
    if skill_missing:
        return (
            "⚠️ BreachLabs Agent Skill is not installed.\n\n"
            "To install the universal security engineering skill:\n"
            "   Run: npx -y skills add breachlabs\n"
            "Or visit http://127.0.0.1:8000/install for manual SKILL.md setup."
        )
    return "✓ Both BreachLabs MCP Server and Agent Skill are installed and ready."

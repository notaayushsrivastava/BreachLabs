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
    """Return prioritized candidate paths where BreachLabs skills may reside."""
    home = Path.home()
    candidates: list[Path] = []

    skill_subdirs = [
        "breachlabs",
        "breachlabs-security-guidelines",
    ]

    # 1. Active repository / workspace
    if repo_path:
        r_path = Path(repo_path)
        for s in skill_subdirs:
            candidates.extend([
                r_path / "skills" / s / "SKILL.md",
                r_path / "skills" / s,
                r_path / ".skills" / s / "SKILL.md",
            ])
        candidates.append(r_path / "SKILL.md")

    # 2. Current working directory
    cwd = Path.cwd()
    for s in skill_subdirs:
        candidates.extend([
            cwd / "skills" / s / "SKILL.md",
            cwd / "skills" / s,
            cwd / ".skills" / s / "SKILL.md",
        ])

    # 3. Global agent skill directories (Antigravity, Cursor, Windsurf, Claude, Universal)
    for s in skill_subdirs:
        candidates.extend([
            home / ".gemini" / "antigravity" / "skills" / s / "SKILL.md",
            home / ".gemini" / "antigravity" / "skills" / s,
            home / ".gemini" / "config" / "plugins" / s / "SKILL.md",
            home / ".skills" / s / "SKILL.md",
            home / ".skills" / s,
            home / ".cursor" / "skills" / s / "SKILL.md",
            home / ".codeium" / "windsurf" / "skills" / s / "SKILL.md",
            home / ".claude" / "skills" / s / "SKILL.md",
        ])

    return candidates


def check_skill_installation(repo_path: str | None = None) -> dict[str, Any]:
    """Verify if BreachLabs Skills are installed.

    Returns structured status with installation guidance for both bundled skills:
    1. breachlabs (Autonomous Security Engineer)
    2. breachlabs-security-guidelines (Secure Application Guidelines)
    """
    candidates = get_skill_search_paths(repo_path)
    found_paths: list[str] = []

    for p in candidates:
        if p.exists():
            resolved = str(p.resolve())
            if resolved not in found_paths:
                found_paths.append(resolved)

    skill_installed = len(found_paths) > 0
    mcp_running = True  # We are executing within the active MCP server runtime

    if skill_installed:
        message = f"BreachLabs Skill bundle is installed ({len(found_paths)} skill file/path(s) found)."
        prompt = None
    else:
        message = (
            "BreachLabs Skills are NOT detected in standard agent skill locations. "
            "Please install the universal skill bundle via npx to give your agent the full security workflow."
        )
        prompt = (
            "⚠️ Notice: The BreachLabs Skill bundle is not installed in your agent environment.\n"
            "To install both skills (breachlabs & breachlabs-security-guidelines), run:\n"
            "  $ npx -y skills add notaayushsrivastava/BreachLabs\n"
            "Or copy the universal SKILL.md from http://127.0.0.1:8000/install"
        )

    return {
        "skill_installed": skill_installed,
        "installed_paths": found_paths,
        "installed_path": found_paths[0] if found_paths else None,
        "bundled_skills": [
            "breachlabs",
            "breachlabs-security-guidelines",
        ],
        "mcp_installed": mcp_running,
        "mcp_running": mcp_running,
        "status": "ready" if skill_installed else "skill_missing",
        "message": message,
        "prompt": prompt,
        "install_commands": {
            "skill": "npx -y skills add notaayushsrivastava/BreachLabs",
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
            "   Run: npx -y skills add notaayushsrivastava/BreachLabs\n\n"
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
            "   Run: npx -y skills add notaayushsrivastava/BreachLabs\n"
            "Or visit http://127.0.0.1:8000/install for manual SKILL.md setup."
        )
    return "✓ Both BreachLabs MCP Server and Agent Skill are installed and ready."

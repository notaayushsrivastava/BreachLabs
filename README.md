# BreachLabs

> **Build. Break. Verify. Fix.**

BreachLabs is an autonomous AI application-security engineer designed to assess software immediately after it is built.

It combines an AI security agent with controlled MCP tools, deterministic security scanners, browser automation, and isolated execution environments. The goal is not to replace professional penetration testers. The goal is to make security validation an immediate part of the software-building loop.

## The Core Loop

~~~
BUILD → DISCOVER → TEST → INVESTIGATE → VERIFY → FIX → RETEST
~~~

BreachLabs can:

- Inspect a repository and understand its application surface.
- Validate that an application can run.
- Discover routes, forms, APIs, and authentication flows.
- Run static security analysis.
- Check dependencies and secrets.
- Run dynamic web application security checks.
- Explore application workflows with browser automation.
- Correlate scanner output with source and runtime evidence.
- Use an AI agent to investigate suspicious findings.
- Verify selected findings in an isolated environment.
- Produce evidence-backed security reports.
- Eventually feed findings back into an AI development workflow for fixing and retesting.

## Architecture

~~~
Application / Repository
          ↓
   Isolated Environment
          ↓
   Security Orchestrator
          ↓
      AI Agent
          ↓
      MCP Tools
     ↙    ↓     ↘
  SAST   DAST   Browser
     \    ↓     /
       Evidence
          ↓
    Verification
          ↓
      Report
~~~

The AI agent is the investigator and orchestrator. Deterministic security tools provide measurable signals, while MCP provides a controlled interface through which the agent can use those capabilities.

## Safety

BreachLabs is designed for authorized defensive security testing.

The target application should run in an isolated disposable environment whenever possible. The agent should use allowlisted security tools rather than unrestricted command execution. Application content is treated as untrusted data and cannot override the agent's security policy.

A clean automated assessment is **not** a guarantee that an application is secure.

## Hackathon

BreachLabs is being developed for **VINHACK 2026** during the 30-hour schedule spanning 18–19 September.

The development plan is documented in PRD.md, including:

- phased implementation,
- exact hackathon review gates,
- agent architecture,
- MCP architecture,
- sandboxing,
- security tooling,
- testing,
- dashboard requirements,
- demo strategy,
- risks,
- and post-hackathon roadmap.

## Hackathon MVP

The primary MVP target is:

~~~
Repository
  ↓
Sandbox
  ↓
Build + Health Check
  ↓
Recon
  ↓
SAST + SCA + Secrets + DAST
  ↓
AI Investigation
  ↓
Browser Investigation
  ↓
Verification
  ↓
Evidence-backed Report
~~~

A controlled vulnerable demo application is used to make the live demonstration deterministic.

## Status

🚧 **Hackathon development**

The repository is intentionally starting from the product and architecture specification before implementation.

## Disclaimer

BreachLabs is a defensive application-security research project. Only assess applications and environments for which you have explicit authorization.

---

**BreachLabs**

*Give every application its own security engineer.*

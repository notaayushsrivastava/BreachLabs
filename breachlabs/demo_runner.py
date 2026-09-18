"""One-command BreachLabs demo.

Runs a full sandboxed assessment of the deliberately vulnerable demo target,
streams live progress to stdout, and prints the complete Markdown report at
the end (``run_demo.sh`` captures all of it into ``Report.md``).

Usage:
    python -m breachlabs.demo_runner [--port 5005]
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time

from breachlabs.core.agent import SecurityAgent
from breachlabs.core.types import Assessment, AssessmentStatus
from breachlabs.report.generator import generate_markdown
from breachlabs.sandbox.manager import LocalSandbox

DEMO_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo")


def _watch_events(assessment: Assessment, stop: threading.Event) -> None:
    """Print each new assessment event as it happens (live stream)."""
    seen = 0
    while not stop.is_set() or seen < len(assessment.events):
        while seen < len(assessment.events):
            event = assessment.events[seen]
            seen += 1
            tool = f" [{event.tool}]" if event.tool else ""
            print(f"[{event.phase.value.upper():>15}]{tool} {event.message}", flush=True)
        time.sleep(0.5)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the BreachLabs demo assessment.")
    parser.add_argument("--port", type=int, default=5005, help="Sandboxed target port")
    args = parser.parse_args()

    print("=== BreachLabs demo assessment ===", flush=True)
    print(f"Target: {DEMO_DIR} (isolated sandbox, port {args.port})", flush=True)

    sandbox = LocalSandbox(DEMO_DIR, port=args.port)
    print("[*] Creating isolated environment...", flush=True)
    sandbox.create()
    print("[*] Starting target application (auto-detected app.py)...", flush=True)
    sandbox.start()  # entrypoint auto-detected: breachlabs/demo/app.py
    health = sandbox.check_health(timeout=90.0)
    if not health.get("healthy"):
        print(f"[!] Target failed health check: {health}", flush=True)
        print("--- sandbox logs ---", flush=True)
        print(sandbox.logs(), flush=True)
        sandbox.destroy()
        return 1
    print(f"[+] Target healthy at {sandbox.base_url}", flush=True)

    assessment = Assessment(repository="demo/vulnerable_app", commit="demo")
    agent = SecurityAgent()
    stop = threading.Event()
    watcher = threading.Thread(target=_watch_events, args=(assessment, stop), daemon=True)
    watcher.start()
    try:
        agent.run(assessment, sandbox)
    finally:
        stop.set()
        watcher.join(timeout=5)
        print("[*] Destroying isolated environment...", flush=True)
        sandbox.destroy()

    print("", flush=True)
    print(f"Assessment status: {assessment.status.value}", flush=True)
    print(f"Findings: {len(assessment.findings)}", flush=True)

    investigated = sum(1 for f in assessment.findings if f.remediation)

    def _vres(f):
        v = f.verification
        return v.result.value if (v.attempted and v.result is not None) else ""

    verified = sum(1 for f in assessment.findings if _vres(f) == "confirmed")
    inconclusive = sum(1 for f in assessment.findings if _vres(f) == "inconclusive")
    print(
        f"Investigated: {investigated} | Verified: {verified} | "
        f"Inconclusive: {inconclusive}",
        flush=True,
    )
    print("", flush=True)

    for finding in assessment.findings:
        print(
            f"  - {finding.id} [{finding.severity.value}/{finding.confidence.value}] "
            f"{finding.title} (sources: {', '.join(finding.sources) or 'n/a'})",
            flush=True,
        )
        print(
            f"      status={finding.status.value} "
            f"evidence={len(finding.evidence)} "
            f"verification={_vres(finding) or 'not attempted'}",
            flush=True,
        )
        probe_evidence = [e for e in finding.evidence if e.source == "verification"]
        for ev in probe_evidence[:1]:
            print(f"      probe: {ev.description}", flush=True)
        if finding.remediation:
            print(f"      fix: {finding.remediation[:140]}", flush=True)

    print("", flush=True)
    print("=" * 72, flush=True)
    print("FULL REPORT", flush=True)
    print("=" * 72, flush=True)
    print(generate_markdown(assessment), flush=True)
    return 0 if assessment.status is AssessmentStatus.COMPLETED else 1


if __name__ == "__main__":
    sys.exit(main())

"""Fix-and-retest loop (PRD.md section 16).

ASSESS -> FIND -> FIX -> REBUILD -> RETEST -> COMPARE.

Operates ONLY on the disposable sandbox copy - production code is never
modified. A fix is a line-based patch applied to the sandboxed repo copy;
the target is rebuilt and the original verification probe is re-run.
"""

from __future__ import annotations

import os
import shutil
from typing import Any

from breachlabs.core.types import Finding
from breachlabs.core.verify import VerificationProbeResult, verify_finding

PatchLine = tuple[int, str | None]  # (1-based line number, new content or None=delete)


def apply_patch(file_path: str, patch_lines: list[PatchLine]) -> bool:
    """Apply a line-based patch. (n, None) deletes line n; (n, text) replaces it.

    1-based line numbers. Creates a .bak backup before the first write.
    Returns True if any change was applied.
    """
    if not os.path.isfile(file_path):
        return False
    with open(file_path, encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()

    changed = False
    for line_no, new_content in sorted(patch_lines, key=lambda p: p[0], reverse=True):
        if line_no < 1 or line_no > len(lines):
            continue  # graceful skip for out-of-range lines
        old = lines[line_no - 1]
        if new_content is None:
            del lines[line_no - 1]
            changed = True
        else:
            if not new_content.endswith("\n"):
                new_content += "\n"
            lines[line_no - 1] = new_content
            if old != new_content:
                changed = True

    if changed:
        backup = file_path + ".bak"
        if not os.path.exists(backup):
            shutil.copy2(file_path, backup)
        with open(file_path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
    return changed


def retest_finding(finding: Finding, context: Any) -> VerificationProbeResult | None:
    """Re-run the same category probe after a fix was applied.

    Returns the fresh probe result. `succeeded=True` still means the
    vulnerability is present; `succeeded=False` means the probe no longer
    confirms it (resolved or inconclusive).
    """
    return verify_finding(finding, context)


def run_fix_retest_loop(
    assessment: Any,
    finding: Finding,
    repo_copy: str | None,
    context: Any,
    patch_lines: list[PatchLine] | None = None,
) -> dict[str, Any]:
    """Full cycle: patch sandbox copy -> retest -> compare statuses.

    Requires a prebuilt patch for now (auto-generation lands in Phase 3
    with LLM integration). Never touches anything outside repo_copy.
    """
    result: dict[str, Any] = {
        "finding_id": finding.id,
        "patch_applied": False,
        "retest_result": None,
        "before_status": finding.status.value,
        "after_status": finding.status.value,
        "notes": "",
    }

    if not repo_copy or not finding.location.file:
        result["notes"] = "No sandbox repo copy or source location; cannot patch."
        return result

    target_file = os.path.join(repo_copy, finding.location.file)
    patch_applied = False
    if patch_lines:
        patch_applied = apply_patch(target_file, patch_lines)
        result["patch_applied"] = patch_applied
        if patch_applied:
            assessment.add_event(
                f"Fix applied to {finding.location.file} for {finding.id}",
                tool="fix_retest",
            )
        else:
            result["notes"] = "Patch produced no changes (lines out of range?)."
            return result
    else:
        result["notes"] = "No patch supplied; retest without changes."

    probe = retest_finding(finding, context)
    result["retest_result"] = probe.model_dump() if probe else None

    if probe is None:
        result["notes"] = (result["notes"] + " " if result["notes"] else "") + (
            "No runtime probe exists for this category; retest skipped."
        )
        return result

    if probe.succeeded:
        # Vulnerability still present after the fix
        result["after_status"] = finding.status.value
        result["notes"] = (result["notes"] + " " if result["notes"] else "") + (
            "Retest still confirms the vulnerability."
        )
    else:
        # Probe no longer reproduces: record resolution without mislabeling
        # the finding as a "confirmed vulnerability" (verification already
        # established that). The fix is what got verified here.
        finding.verification = finding.verification.model_copy(
            update={
                "attempted": True,
                "details": (
                    f"Fix verified: {probe.probe} no longer reproduces after "
                    f"patching {finding.location.file}."
                ),
            }
        )
        result["after_status"] = finding.status.value
        result["notes"] = (result["notes"] + " " if result["notes"] else "") + (
            "Retest passed: finding resolved in the sandbox copy."
        )
        assessment.add_event(
            f"Retest confirmed {finding.id} resolved after fix",
            tool="fix_retest",
        )
    return result

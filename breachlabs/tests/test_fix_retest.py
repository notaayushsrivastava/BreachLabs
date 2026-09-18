"""Tests for the fix-and-retest loop (Phase 2 - PRD section 16)."""

from breachlabs.core.fix_retest import apply_patch, run_fix_retest_loop
from breachlabs.core.types import Assessment, Finding, Location, Severity


def _finding(file="app.py", line=3):
    return Finding(
        title="Debug mode enabled",
        category="configuration",
        severity=Severity.MEDIUM,
        location=Location(file=file, line=line),
        description="app.run(debug=True)",
    )


class TestApplyPatch:
    def test_replaces_line(self, tmp_path):
        target = tmp_path / "app.py"
        target.write_text("a = 1\nb = 2\nc = 3\n")
        assert apply_patch(str(target), [(2, "b = 22")]) is True
        content = target.read_text()
        assert "b = 22" in content
        assert "b = 2\n" not in content
        assert "a = 1" in content and "c = 3" in content

    def test_deletes_line(self, tmp_path):
        target = tmp_path / "app.py"
        target.write_text("a = 1\ndebug = True\nc = 3\n")
        assert apply_patch(str(target), [(2, None)]) is True
        content = target.read_text()
        assert "debug = True" not in content
        assert "a = 1" in content and "c = 3" in content

    def test_invalid_line_number_skipped(self, tmp_path):
        target = tmp_path / "app.py"
        target.write_text("a = 1\n")
        assert apply_patch(str(target), [(99, "x = 1"), (0, "y = 2")]) is False
        assert target.read_text() == "a = 1\n"

    def test_backup_created(self, tmp_path):
        target = tmp_path / "app.py"
        target.write_text("debug = True\n")
        apply_patch(str(target), [(1, "debug = False")])
        assert (tmp_path / "app.py.bak").exists()

    def test_missing_file_returns_false(self, tmp_path):
        assert apply_patch(str(tmp_path / "ghost.py"), [(1, "x")]) is False

    def test_no_change_returns_false(self, tmp_path):
        target = tmp_path / "app.py"
        target.write_text("a = 1\n")
        assert apply_patch(str(target), [(1, "a = 1")]) is False


class TestFixRetestLoop:
    def test_no_repo_copy_reports_failure(self):
        assessment = Assessment(repository="r", commit="c")
        finding = _finding()
        context = type("Ctx", (), {"target_base_url": None})()
        result = run_fix_retest_loop(assessment, finding, None, context)
        assert result["patch_applied"] is False
        assert "cannot patch" in result["notes"].lower()

    def test_no_patch_retests_unchanged(self, tmp_path):
        # Without a patch and with no reachable target, the loop reports
        # a skipped retest rather than claiming resolution.
        (tmp_path / "app.py").write_text("app.run(debug=True)\n")
        assessment = Assessment(repository="r", commit="c")
        finding = _finding()
        context = type("Ctx", (), {"target_base_url": None})()
        result = run_fix_retest_loop(
            assessment, finding, str(tmp_path), context, patch_lines=None
        )
        assert result["retest_result"] is None
        assert "skipped" in result["notes"].lower()

    def test_patch_applied_event_logged(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1\napp.run(debug=True)\nz = 3\n")
        assessment = Assessment(repository="r", commit="c")
        finding = _finding(line=2)
        context = type("Ctx", (), {"target_base_url": None})()
        run_fix_retest_loop(
            assessment, finding, str(tmp_path), context,
            patch_lines=[(2, "app.run(debug=False)")],
        )
        assert any(e.tool == "fix_retest" for e in assessment.events)

    def test_patch_changes_file_content(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1\napp.run(debug=True)\nz = 3\n")
        assessment = Assessment(repository="r", commit="c")
        finding = _finding(line=2)
        context = type("Ctx", (), {"target_base_url": None})()
        run_fix_retest_loop(
            assessment, finding, str(tmp_path), context,
            patch_lines=[(2, "app.run(debug=False)")],
        )
        content = (tmp_path / "app.py").read_text()
        assert "debug=False" in content
        assert "debug=True" not in content

    def test_result_schema(self, tmp_path):
        (tmp_path / "app.py").write_text("app.run(debug=True)\n")
        assessment = Assessment(repository="r", commit="c")
        finding = _finding(line=1)
        context = type("Ctx", (), {"target_base_url": None})()
        result = run_fix_retest_loop(
            assessment, finding, str(tmp_path), context,
            patch_lines=[(1, "app.run(debug=False)")],
        )
        for key in ("finding_id", "patch_applied", "retest_result",
                    "before_status", "after_status", "notes"):
            assert key in result
        assert result["finding_id"] == finding.id
        assert result["patch_applied"] is True

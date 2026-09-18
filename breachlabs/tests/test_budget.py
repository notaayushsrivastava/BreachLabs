"""Tests for the budget tracker (Phase 3 - PRD.md sections 7.1, 20)."""

import pytest

from breachlabs.core.budget import Budget, BudgetExceeded


class TestBudget:
    def test_fresh_budget_not_exhausted(self):
        assert Budget().exhausted() is False

    def test_tool_call_budget_exhaustion(self):
        budget = Budget(tool_calls=2)
        budget.check_tool_call()
        budget.check_tool_call()
        with pytest.raises(BudgetExceeded):
            budget.check_tool_call()

    def test_browser_action_budget_exhaustion(self):
        budget = Budget(browser_actions=1)
        budget.check_browser_action()
        with pytest.raises(BudgetExceeded):
            budget.check_browser_action()

    def test_investigation_loop_budget_exhaustion(self):
        budget = Budget(investigation_loops=1)
        budget.check_investigation_loop()
        with pytest.raises(BudgetExceeded):
            budget.check_investigation_loop()

    def test_timeout_exhaustion(self):
        budget = Budget(timeout_seconds=0)
        with pytest.raises(BudgetExceeded):
            budget.check_tool_call()

    def test_summary_shape(self):
        summary = Budget().summary()
        assert "tool_calls" in summary
        assert "browser_actions" in summary
        assert "investigation_loops" in summary
        assert "elapsed_seconds" in summary

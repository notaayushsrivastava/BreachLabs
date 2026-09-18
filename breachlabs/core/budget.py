"""Agent budget enforcement (PRD.md sections 7.1 and 20).

MVP defaults per PRD:
    assessment timeout: 10 minutes
    tool-call budget:   30
    browser action budget: 40
    investigation loops: 5

Every phase consults the tracker; exhausting any budget stops the phase
cleanly with an explanatory event instead of an unbounded run.
"""

from __future__ import annotations

import time


class BudgetExceeded(Exception):
    """Raised when a budget dimension is exhausted."""


class Budget:
    """Tracks consumption of the agent's resource budgets."""

    def __init__(
        self,
        timeout_seconds: float = 600.0,
        tool_calls: int = 30,
        browser_actions: int = 40,
        investigation_loops: int = 5,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_tool_calls = tool_calls
        self.max_browser_actions = browser_actions
        self.max_investigation_loops = investigation_loops

        self.started_at = time.monotonic()
        self.tool_calls_used = 0
        self.browser_actions_used = 0
        self.investigation_loops_used = 0

    # -- consumption ---------------------------------------------------------

    def check_tool_call(self) -> None:
        """Raise BudgetExceeded if the tool-call or time budget is spent."""
        self._check_time()
        if self.tool_calls_used >= self.max_tool_calls:
            raise BudgetExceeded(
                f"Tool-call budget exhausted ({self.tool_calls_used}/"
                f"{self.max_tool_calls})."
            )
        self.tool_calls_used += 1

    def check_browser_action(self) -> None:
        """Raise BudgetExceeded if the browser-action budget is spent."""
        self._check_time()
        if self.browser_actions_used >= self.max_browser_actions:
            raise BudgetExceeded(
                f"Browser action budget exhausted ({self.browser_actions_used}/"
                f"{self.max_browser_actions})."
            )
        self.browser_actions_used += 1

    def check_investigation_loop(self) -> None:
        if self.investigation_loops_used >= self.max_investigation_loops:
            raise BudgetExceeded(
                f"Investigation loop budget exhausted "
                f"({self.investigation_loops_used}/{self.max_investigation_loops})."
            )
        self.investigation_loops_used += 1

    # -- status --------------------------------------------------------------

    def elapsed(self) -> float:
        return time.monotonic() - self.started_at

    def time_remaining(self) -> float:
        return max(0.0, self.timeout_seconds - self.elapsed())

    def exhausted(self) -> bool:
        return (
            self.time_remaining() <= 0
            or self.tool_calls_used >= self.max_tool_calls
            or self.browser_actions_used >= self.max_browser_actions
            or self.investigation_loops_used >= self.max_investigation_loops
        )

    def summary(self) -> dict[str, object]:
        return {
            "elapsed_seconds": round(self.elapsed(), 1),
            "tool_calls": f"{self.tool_calls_used}/{self.max_tool_calls}",
            "browser_actions": f"{self.browser_actions_used}/{self.max_browser_actions}",
            "investigation_loops": (
                f"{self.investigation_loops_used}/{self.max_investigation_loops}"
            ),
        }

    def _check_time(self) -> None:
        if self.time_remaining() <= 0:
            raise BudgetExceeded(
                f"Assessment timeout exceeded ({self.elapsed():.0f}s/"
                f"{self.timeout_seconds:.0f}s)."
            )

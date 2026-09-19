"""Sandbox: isolated, disposable execution environment for target apps.

MVP implementation: local process sandbox (subprocess + temp workspace copy).
Docker-backed isolation can replace LocalSandbox behind the same interface.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # noqa: S404 - controlled launcher, not agent-exposed
import tempfile
import time
from typing import Any


class SandboxError(Exception):
    pass


class LocalSandbox:
    """A disposable workspace: repo copy + launched application process."""

    def __init__(self, repo_source: str, port: int = 5000) -> None:
        self.repo_source = os.path.abspath(repo_source)
        self.port = port
        self.workspace: str | None = None
        self.process: subprocess.Popen | None = None
        self.base_url: str | None = None
        self.environment_id = f"sbx-{os.getpid()}-{int(time.time())}"

    def create(self) -> str:
        """Copy the repository into a temp workspace (Phase B step 1-2)."""
        if not os.path.isdir(self.repo_source):
            raise SandboxError(f"Repository source not found: {self.repo_source}")
        self.workspace = tempfile.mkdtemp(prefix="breachlabs-")
        dest = os.path.join(self.workspace, "repo")
        shutil.copytree(
            self.repo_source, dest,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules", ".venv"),
        )
        self.repo_copy = dest
        return dest

    def start(self, launch_command: list[str] | None = None) -> str:
        """Install deps (if requirements.txt) and launch the app (Phase B steps 3-4)."""
        if not self.workspace:
            raise SandboxError("Sandbox not created. Call create() first.")
        repo = self.repo_copy
        venv_python = self._ensure_python_env(repo)
        cmd = launch_command or self._detect_launch(repo, venv_python)
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        env = dict(os.environ)
        # The demo wrapper (app.py) reads the port from the environment so the
        # sandboxed target always binds the port the health check polls.
        env.setdefault("BREACHLABS_TARGET_PORT", str(self.port))
        self.process = subprocess.Popen(
            cmd,
            cwd=repo,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            creationflags=creationflags,
            env=env,
        )
        self.base_url = f"http://127.0.0.1:{self.port}"
        return self.base_url

    def _ensure_python_env(self, repo: str) -> str:
        """Use current python interpreter if dependencies are available, or create sandbox venv."""
        import sys

        # Fast path: current interpreter already has Flask / standard dependencies
        try:
            import flask  # noqa: F401

            return sys.executable
        except ImportError:
            pass

        requirements = os.path.join(repo, "requirements.txt")
        if not os.path.isfile(requirements):
            return sys.executable
        venv_dir = os.path.join(self.workspace, "venv")  # type: ignore[union-attr]
        try:
            import venv as venv_module

            builder = venv_module.EnvBuilder(with_pip=True)
            builder.create(venv_dir)
        except Exception as exc:  # pragma: no cover - platform dependent
            raise SandboxError(f"Failed to create venv: {exc}") from exc
        python = (
            os.path.join(venv_dir, "Scripts", "python.exe")
            if os.name == "nt"
            else os.path.join(venv_dir, "bin", "python")
        )
        subprocess.run(
            [python, "-m", "pip", "install", "-q", "-r", requirements],
            check=False, capture_output=True, text=True, timeout=600,
        )
        return python

    def _detect_launch(self, repo: str, python: str) -> list[str]:
        app_py = os.path.join(repo, "app.py")
        if os.path.isfile(app_py):
            return [python, "app.py"]
        main_py = os.path.join(repo, "main.py")
        if os.path.isfile(main_py):
            return [python, "main.py"]
        raise SandboxError("No launchable entrypoint found (app.py or main.py).")

    def check_health(self, timeout: float = 30.0, interval: float = 1.0) -> dict[str, Any]:
        """Poll the app until it responds (Phase B step 5)."""
        import httpx

        if not self.base_url:
            raise SandboxError("Application not started.")
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.process is not None and self.process.poll() is not None:
                return {"healthy": False, "reason": "Application process exited early."}
            try:
                response = httpx.get(self.base_url, timeout=5.0)
                if response.status_code < 500:
                    return {"healthy": True, "status_code": response.status_code}
            except Exception:  # noqa: S110 - poll until deadline
                pass
            time.sleep(interval)
        return {"healthy": False, "reason": "Health check timed out."}

    def logs(self) -> str:
        """Best-effort capture of application stdout (startup errors, Phase B step 6)."""
        if self.process and self.process.stdout:
            try:
                return "\n".join(self.process.stdout.readlines()[-200:])
            except Exception:
                return ""
        return ""

    def destroy(self) -> None:
        """Terminate the process and remove the workspace (PRD 5.3 — environment destroyed)."""
        if self.process and self.process.poll() is None:
            try:
                # On Windows, terminate() is TerminateProcess (hard kill) and
                # never touches the parent console — safe in shared terminals.
                self.process.terminate()
                self.process.wait(timeout=10)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
        self.process = None
        if self.workspace and os.path.isdir(self.workspace):
            shutil.rmtree(self.workspace, ignore_errors=True)
        self.workspace = None
        self.base_url = None

    def __enter__(self) -> LocalSandbox:
        self.create()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.destroy()

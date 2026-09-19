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
        """Install dependencies and launch the application process across supported runtimes."""
        if not self.workspace:
            raise SandboxError("Sandbox not created. Call create() first.")
        repo = self.repo_copy
        venv_python = self._ensure_python_env(repo)
        cmd = launch_command or self._detect_launch(repo, venv_python)
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        env = dict(os.environ)
        port_str = str(self.port)
        env.setdefault("PORT", port_str)
        env.setdefault("BREACHLABS_TARGET_PORT", port_str)
        env.setdefault("FLASK_RUN_PORT", port_str)
        env.setdefault("UVICORN_PORT", port_str)
        env.setdefault("HOST", "127.0.0.1")
        env.setdefault("NODE_ENV", "development")

        resolved_cmd = list(cmd)
        use_shell = False
        if resolved_cmd and os.name == "nt":
            bin_path = shutil.which(resolved_cmd[0])
            if bin_path:
                resolved_cmd[0] = bin_path
            use_shell = bool(resolved_cmd[0].lower().endswith((".cmd", ".bat")))

        try:
            self.process = subprocess.Popen(
                resolved_cmd,
                cwd=repo,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                creationflags=creationflags,
                env=env,
                shell=use_shell,
            )
        except FileNotFoundError as exc:
            raise SandboxError(
                f"Executable '{cmd[0]}' not found on system PATH. Please ensure the runtime is installed: {exc}"
            ) from exc
        except OSError as exc:
            raise SandboxError(f"Failed to start sandbox process with command {cmd}: {exc}") from exc

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
        try:
            subprocess.run(
                [python, "-m", "pip", "install", "-q", "-r", requirements],
                check=False, capture_output=True, text=True, timeout=600,
            )
        except (FileNotFoundError, OSError):
            pass
        return python

    def _detect_launch(self, repo: str, python: str) -> list[str]:
        """Auto-detect application entry point across Python, Node.js, Go, Rust, Ruby, and PHP."""
        import json

        # 1. Python entry points
        for py_entry in ("app.py", "main.py", "server.py", "run.py", "wsgi.py"):
            if os.path.isfile(os.path.join(repo, py_entry)):
                return [python, py_entry]

        # Django
        if os.path.isfile(os.path.join(repo, "manage.py")):
            return [python, "manage.py", "runserver", f"127.0.0.1:{self.port}", "--noreload"]

        # 2. Node.js / JavaScript / TypeScript
        pkg_json = os.path.join(repo, "package.json")
        if os.path.isfile(pkg_json):
            try:
                with open(pkg_json, encoding="utf-8", errors="replace") as fh:
                    pkg_data = json.load(fh)
                scripts = pkg_data.get("scripts", {})
                if "start" in scripts:
                    return ["npm", "start"]
                if "dev" in scripts:
                    return ["npm", "run", "dev"]
                main_file = pkg_data.get("main")
                if main_file and os.path.isfile(os.path.join(repo, main_file)):
                    return ["node", main_file]
            except Exception:
                pass

        for node_entry in ("index.js", "server.js", "app.js", "main.js", "src/index.js", "src/server.js", "src/app.js"):
            if os.path.isfile(os.path.join(repo, node_entry)):
                return ["node", node_entry]

        # 3. Go
        if os.path.isfile(os.path.join(repo, "main.go")):
            return ["go", "run", "main.go"]
        if os.path.isfile(os.path.join(repo, "go.mod")):
            return ["go", "run", "."]

        # 4. Rust
        if os.path.isfile(os.path.join(repo, "Cargo.toml")):
            return ["cargo", "run"]

        # 5. PHP
        if os.path.isfile(os.path.join(repo, "index.php")):
            return ["php", "-S", f"127.0.0.1:{self.port}", "index.php"]

        # 6. Ruby
        if os.path.isfile(os.path.join(repo, "config.ru")):
            return ["rackup", "-p", str(self.port), "-o", "127.0.0.1"]
        if os.path.isfile(os.path.join(repo, "app.rb")):
            return ["ruby", "app.rb", "-p", str(self.port)]

        raise SandboxError("No launchable entrypoint found (checked Python, Node.js, Go, Rust, PHP, Ruby).")

    def check_health(self, timeout: float = 30.0, interval: float = 1.0) -> dict[str, Any]:
        """Poll the app until it responds (Phase B step 5)."""
        import httpx

        if not self.base_url:
            raise SandboxError("Application not started.")
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.process is not None and self.process.poll() is not None:
                code = self.process.returncode
                stdout_err = ""
                if self.process.stdout:
                    try:
                        stdout_err = self.process.stdout.read()
                    except Exception:
                        pass
                err_msg = f"Application process exited early (exit code {code})"
                if stdout_err.strip():
                    err_msg += f": {stdout_err.strip()[:300]}"
                return {"healthy": False, "reason": err_msg, "exit_code": code}
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
        if self.process and self.process.stdout and self.process.poll() is not None:
            try:
                return self.process.stdout.read()
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

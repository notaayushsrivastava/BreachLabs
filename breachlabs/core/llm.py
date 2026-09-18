"""Provider-agnostic LLM client for agentic triage (PRD.md section 28).

Provider is selected via environment variables:

    BREACHLABS_LLM_PROVIDER = nvidia | openai | anthropic | none
    BREACHLABS_LLM_API_KEY  = provider API key
    BREACHLABS_LLM_MODEL    = provider-specific model id

Default provider is NVIDIA NIM (free tier, OpenAI-compatible):

    base URL: https://integrate.api.nvidia.com/v1
    default model: meta/llama-3.1-8b-instruct
    API key from: https://build.nvidia.com/settings

Design rules:
- ``BREACHLABS_LLM_API_KEY`` unset -> client is unavailable; the caller
  falls back to the deterministic Phase 2 pipeline. The LLM is an
  enhancer, never a dependency (PRD.md section 26.5).
- Every prompt is sanitized through ``redact_secrets`` before sending:
  hardcoded secrets discovered during the assessment must never reach the
  model (PRD.md section 9.2).
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"
DEFAULT_NVIDIA_MODEL = "meta/llama-3.1-8b-instruct"
REQUEST_TIMEOUT = 60.0


class LLMError(Exception):
    """Raised when the LLM client fails (network, parse, auth)."""


def _redact_patterns(text: str) -> str:
    """Mask secret-like literals before any content leaves the process."""
    patterns = (
        r"(?i)(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*\S+",
        r"sk-[A-Za-z0-9]{16,}",
        r"ghp_[A-Za-z0-9]{20,}",
    )
    for pattern in patterns:
        text = re.sub(pattern, "[REDACTED]", text)
    return text


def redact_finding(finding: Any) -> dict[str, Any]:
    """Return a JSON-safe finding dict with secret-like values masked."""
    data = {
        "id": finding.id,
        "title": finding.title,
        "category": finding.category,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "status": finding.status.value,
        "location": finding.location.model_dump(),
        "description": _redact_patterns(finding.description or ""),
        "sources": list(finding.sources),
    }
    return json.loads(json.dumps(data, default=str))


class LLMClient:
    """Thin chat-completions wrapper over an OpenAI-compatible endpoint."""

    def __init__(
        self,
        provider: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
    ) -> None:
        self.provider = (provider or os.environ.get(
            "BREACHLABS_LLM_PROVIDER", "nvidia"
        )).strip().lower()
        self.api_key = api_key or os.environ.get("BREACHLABS_LLM_API_KEY", "")
        if self.provider == "nvidia":
            self.model = model or os.environ.get(
                "BREACHLABS_LLM_MODEL", DEFAULT_NVIDIA_MODEL
            )
            self.base_url = NVIDIA_BASE_URL
        elif self.provider == "openai":
            self.model = model or os.environ.get(
                "BREACHLABS_LLM_MODEL", "gpt-4o-mini"
            )
            self.base_url = "https://api.openai.com/v1"
        else:  # "none" or unknown -> unavailable
            self.provider = "none"
            self.model = ""
            self.base_url = ""

    @property
    def available(self) -> bool:
        return bool(
            self.provider != "none" and self.api_key and self.base_url
        )

    def complete(
        self,
        system: str,
        user: str,
        json_mode: bool = False,
    ) -> str:
        """Run one chat completion. Raises LLMError on any failure."""
        if not self.available:
            raise LLMError("LLM client is not configured.")

        import httpx

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": _redact_patterns(user)},
        ]
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": 1024,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        url = f"{self.base_url.rstrip('/')}/chat/completions"
        try:
            response = httpx.post(
                url,
                headers=headers,
                json=payload,
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            body = response.json()
        except Exception as exc:
            raise LLMError(f"LLM request failed: {exc}") from exc

        try:
            content = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"Unexpected LLM response shape: {body}") from exc
        if not isinstance(content, str):
            raise LLMError("LLM returned non-string content.")
        return content

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        """Chat completion parsed as a JSON object. Raises LLMError on failure."""
        raw = self.complete(system, user, json_mode=True)
        # Models sometimes wrap JSON in markdown fences; strip them.
        fenced = re.search(r"```(?:json)?\s*(.*?)\s*```", raw, re.DOTALL)
        candidate = fenced.group(1) if fenced else raw
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError as exc:
            raise LLMError(f"LLM returned invalid JSON: {candidate[:200]}") from exc
        if not isinstance(parsed, dict):
            raise LLMError("LLM JSON was not an object.")
        return parsed

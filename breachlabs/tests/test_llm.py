"""Tests for the provider-agnostic LLM client (Phase 3 - PRD section 28).

The client must degrade to unavailable without a key (deterministic
fallback), redact secrets before any prompt leaves the process, and parse
JSON completions. Networked NIM calls are NOT tested here (they need a key
and a sandbox; smoke-test them manually).
"""

import json

import pytest

from breachlabs.core.llm import (
    DEFAULT_NVIDIA_MODEL,
    NVIDIA_BASE_URL,
    LLMClient,
    LLMError,
    redact_finding,
)
from breachlabs.core.types import Finding, Location, Severity


class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self._status = status

    def raise_for_status(self):
        if self._status >= 400:
            import httpx

            raise httpx.HTTPStatusError("bad", request=None, response=None)

    def json(self):
        return self._payload


def _finding():
    return Finding(
        title="Hardcoded admin password",
        category="secrets",
        severity=Severity.CRITICAL,
        location=Location(file="app.py", line=29),
        description='ADMIN_PASSWORD = "super-admin-password-123"',
        remediation="",
        impact="",
    )


class TestAvailability:
    def test_unavailable_without_key(self, monkeypatch):
        monkeypatch.delenv("BREACHLABS_LLM_API_KEY", raising=False)
        client = LLMClient(provider="nvidia", api_key="")
        assert client.available is False

    def test_available_with_key(self):
        client = LLMClient(provider="nvidia", api_key="nv-test", model="m")
        assert client.available is True
        assert client.base_url == NVIDIA_BASE_URL

    def test_unknown_provider_is_none(self):
        client = LLMClient(provider="mystery", api_key="k")
        assert client.provider == "none"
        assert client.available is False

    def test_default_model_is_free_nim(self):
        client = LLMClient(provider="nvidia", api_key="k")
        assert client.model == DEFAULT_NVIDIA_MODEL
        assert client.model == "meta/llama-3.1-8b-instruct"


class TestRedaction:
    def test_finding_redacted(self):
        redacted = redact_finding(_finding())
        dumped = json.dumps(redacted)
        assert "super-admin-password-123" not in dumped
        assert redacted["title"] == "Hardcoded admin password"

    def test_json_safe(self):
        redacted = redact_finding(_finding())
        json.dumps(redacted)  # must not raise


class TestCompletions:
    def test_complete_posts_and_returns(self, monkeypatch):
        calls = {}

        def fake_post(url, headers=None, json=None, timeout=None):
            calls["url"] = url
            calls["model"] = json["model"]
            assert "nvidia.com" in url
            assert headers["Authorization"] == "Bearer nv-test"
            return FakeResponse({
                "choices": [{"message": {"content": "hello analyst"}}]
            })

        import httpx

        monkeypatch.setattr(httpx, "post", fake_post)
        client = LLMClient(provider="nvidia", api_key="nv-test")
        assert client.complete("sys", "user") == "hello analyst"
        assert calls["model"] == DEFAULT_NVIDIA_MODEL

    def test_complete_raises_on_network_error(self, monkeypatch):
        def fake_post(url, headers=None, json=None, timeout=None):
            raise ConnectionError("down")

        import httpx

        monkeypatch.setattr(httpx, "post", fake_post)
        client = LLMClient(provider="nvidia", api_key="k")
        with pytest.raises(LLMError):
            client.complete("sys", "user")

    def test_complete_json_parses_object(self, monkeypatch):
        def fake_post(url, headers=None, json=None, timeout=None):
            return FakeResponse({
                "choices": [{"message": {"content": '{"patch": [1]}'}}]
            })

        import httpx

        monkeypatch.setattr(httpx, "post", fake_post)
        client = LLMClient(provider="nvidia", api_key="k")
        assert client.complete_json("sys", "user") == {"patch": [1]}

    def test_complete_json_rejects_garbage(self, monkeypatch):
        def fake_post(url, headers=None, json=None, timeout=None):
            return FakeResponse({
                "choices": [{"message": {"content": "not json at all"}}]
            })

        import httpx

        monkeypatch.setattr(httpx, "post", fake_post)
        client = LLMClient(provider="nvidia", api_key="k")
        with pytest.raises(LLMError):
            client.complete_json("sys", "user")

    def test_unavailable_client_raises(self):
        client = LLMClient(provider="none")
        with pytest.raises(LLMError):
            client.complete("sys", "user")

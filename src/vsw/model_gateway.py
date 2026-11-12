"""ModelGateway: mock, OpenRouter, and compatible-endpoint adapters."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import httpx


class ProviderUnavailable(RuntimeError):
    pass


@dataclass
class ModelResponse:
    text: str
    model: str
    usage: dict[str, object] = field(default_factory=dict)
    cost_usd: float = 0.0
    note: str = ""


class MockModelGateway:
    """Deterministic gateway. No network, no credentials."""

    name = "mock"

    def __init__(self, responses: dict[str, str] | None = None):
        self.responses = responses or {
            "plan": "1. implement the bounded change\n2. review independently\n3. run tests",
            "review": "APPROVED\nNo issues found.",
        }
        self.calls: list[str] = []

    def complete(self, prompt: str, role: str = "plan") -> ModelResponse:
        self.calls.append(role)
        text = self.responses.get(role, self.responses["plan"])
        return ModelResponse(
            text=text,
            model="mock/deterministic",
            usage={"prompt_chars": len(prompt), "output_chars": len(text)},
            cost_usd=0.0,
            note="mock: no remote inference",
        )


class OpenAICompatibleGateway:
    """Minimal chat-completions client for OpenRouter and compatible endpoints."""

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key_env: str,
        timeout_s: float = 60.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key_env = api_key_env
        self.timeout_s = timeout_s

    @property
    def name(self) -> str:
        return self.base_url

    def complete(self, prompt: str, role: str = "plan") -> ModelResponse:
        api_key = os.environ.get(self.api_key_env)
        if not api_key:
            raise ProviderUnavailable(f"{self.api_key_env} is not set; route is unavailable")
        response = httpx.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0,
            },
            timeout=self.timeout_s,
        )
        response.raise_for_status()
        payload = response.json()
        text = payload["choices"][0]["message"]["content"]
        usage = payload.get("usage") or {}
        if "total_cost" in payload:
            cost = float(payload["total_cost"])
        else:
            cost = 0.0
        return ModelResponse(
            text=text,
            model=payload.get("model", self.model),
            usage=usage,
            cost_usd=cost,
        )


def openrouter_gateway(model: str) -> OpenAICompatibleGateway:
    return OpenAICompatibleGateway(
        base_url="https://openrouter.ai/api/v1",
        model=model,
        api_key_env="OPENROUTER_API_KEY",
    )

"""ModelGateway transport, route config, and secret-handling tests."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml

from vsw.config import Limits
from vsw.model_gateway import (
    ModelConfig,
    ModelRoute,
    OpenAICompatibleGateway,
    OpenRouterGateway,
    ProviderConfig,
    ProviderUnavailable,
    gateway_for_route,
    load_model_config,
)

ROOT = Path(__file__).resolve().parents[1]
LIMITS = Limits()


def _config_data() -> dict[str, Any]:
    return {
        "providers": {
            "opencode-go": {
                "base_url": "https://opencode.ai/inference/go/openai/v1",
                "api_key_env": "OPENCODE_API_KEY",
                "session_header": "x-opencode-session",
                "user_agent": "vsw/test",
            },
            "openrouter": {
                "base_url": "https://openrouter.ai/api/v1",
                "api_key_env": "OPENROUTER_API_KEY",
                "app_url": "https://example.invalid/vsw",
                "app_title": "vsw",
            },
        },
        "routes": {
            "plan": {
                "provider": "opencode-go",
                "model": "deepseek-v4.1-flash",
                "effort": "high",
                "max_tokens": 128,
                "enabled": False,
            },
            "sol": {
                "provider": "openrouter",
                "model": "openai/gpt-6-sol",
                "effort": "max",
                "max_tokens": 128,
                "enabled": False,
            },
        },
    }


def _write_config(tmp_path: Path, data: dict[str, Any]) -> Path:
    path = tmp_path / "models.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def _gateway(model: str = "glm-5.3-flash", **kwargs: Any) -> OpenAICompatibleGateway:
    options: dict[str, Any] = {
        "timeout_s": 5,
        "max_tokens": 64,
        "reasoning_effort": "high",
        "user_agent": "vsw/test",
    }
    options.update(kwargs)
    return OpenAICompatibleGateway(
        "https://go.example/v1", model, "GO_KEY", **options
    )


def test_gateway_sends_reasoning_and_records_go_usage(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GO_KEY", "test-key")
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["headers"] = dict(request.headers)
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "model": "glm-5.3-flash",
                "choices": [
                    {"message": {"content": "pong"}, "finish_reason": "stop"}
                ],
                "usage": {
                    "prompt_tokens": 19,
                    "completion_tokens": 3,
                    "cost": 0,
                    "opencode": {"billing_source": "go", "allowance": 0.0000435},
                },
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        gateway = _gateway(
            session_header="x-opencode-session", max_output_chars=5, client=client
        )
        response = gateway.complete("Reply with pong")

    assert seen["headers"]["authorization"] == "Bearer test-key"
    assert seen["headers"]["user-agent"] == "vsw/test"
    assert seen["headers"]["x-opencode-session"].startswith("vsw-")
    assert seen["body"]["model"] == "glm-5.3-flash"
    assert seen["body"]["reasoning"] == {"effort": "high"}
    assert "temperature" not in seen["body"]
    assert response.text == "pong"
    assert response.finish_reason == "stop"
    assert response.cost_usd == 0.0
    assert response.cost_measured is True
    assert response.billing_source == "go"
    assert response.allowance_usd == pytest.approx(0.0000435)


def test_gateway_records_openrouter_cost(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-key")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["http-referer"] == "https://example.invalid/vsw"
        assert request.headers["x-openrouter-title"] == "vsw"
        return httpx.Response(
            200,
            json={
                "model": "openai/gpt-6-sol",
                "choices": [{"message": {"content": "pong"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 13, "completion_tokens": 5, "cost": 0.000076},
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        gateway = OpenRouterGateway(
            "openai/gpt-6-sol",
            reasoning_effort="max",
            app_url="https://example.invalid/vsw",
            app_title="vsw",
            client=client,
        )
        response = gateway.complete("Reply with pong")

    assert response.cost_usd == pytest.approx(0.000076)
    assert response.cost_measured is True
    assert response.billing_source == ""
    assert response.allowance_usd is None


def test_gateway_redacts_key_from_provider_errors(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GO_KEY", "secret-key-123")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad key secret-key-123")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        gateway = _gateway(client=client)
        with pytest.raises(ProviderUnavailable) as exc:
            gateway.complete("hello")

    assert "secret-key-123" not in str(exc.value)
    assert "<redacted>" in str(exc.value)


def test_gateway_requires_its_own_key(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("GO_KEY", raising=False)
    with pytest.raises(ProviderUnavailable, match="GO_KEY"):
        _gateway().complete("hello")


def test_gateway_rejects_oversized_prompt(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GO_KEY", "test-key")
    with pytest.raises(ProviderUnavailable, match="limit is 3"):
        _gateway(max_prompt_chars=3).complete("four")


def test_gateway_truncates_output(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GO_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "abcdefgh"}, "finish_reason": "stop"}],
                "usage": {"cost": 0},
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        gateway = _gateway(max_output_chars=4, client=client)
        response = gateway.complete("hello")

    assert response.text.startswith("abcd")
    assert "truncated" in response.text
    assert response.note == "output truncated"


def test_gateway_rejects_non_json(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GO_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not json")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        gateway = _gateway(client=client)
        with pytest.raises(ProviderUnavailable, match="non-JSON"):
            gateway.complete("hello")


def test_gateway_rejects_missing_choices(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GO_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [], "error": "upstream failed"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        gateway = _gateway(client=client)
        with pytest.raises(ProviderUnavailable, match="no choices"):
            gateway.complete("hello")


def test_load_model_config_round_trip(tmp_path: Path):
    config = load_model_config(_write_config(tmp_path, _config_data()))
    assert set(config.providers) == {"opencode-go", "openrouter"}
    assert config.providers["opencode-go"].session_header == "x-opencode-session"
    assert config.providers["openrouter"].app_title == "vsw"
    assert config.routes["plan"].model == "deepseek-v4.1-flash"
    assert config.routes["sol"].effort == "max"
    assert all(route.enabled is False for route in config.routes.values())


@pytest.mark.parametrize(
    ("path", "value", "match"),
    [
        (("routes", "plan", "provider"), "missing", "unknown provider"),
        (("routes", "plan", "effort"), "turbo", "effort must be one of"),
        (("routes", "plan", "max_tokens"), 0, "max_tokens must be positive"),
        (("routes", "plan", "enabled"), "no", "enabled must be bool"),
        (("routes", "sol", "model"), "gpt-6-sol", "vendor/model"),
        (("routes", "plan", "model"), "deepseek v4", "exact provider/model"),
        (("providers", "opencode-go", "base_url"), "ftp://x", "must start with"),
        (("providers", "opencode-go", "api_key_env"), "", "api_key_env must be set"),
    ],
)
def test_load_model_config_rejects_invalid_values(
    tmp_path: Path, path: tuple[str, ...], value: object, match: str
):
    data = copy.deepcopy(_config_data())
    target: dict[str, Any] = data
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ProviderUnavailable, match=match):
        load_model_config(_write_config(tmp_path, data))


def _route_config(enabled: bool) -> ModelConfig:
    return ModelConfig(
        providers={
            "opencode-go": ProviderConfig(
                name="opencode-go",
                base_url="https://go.example/v1",
                api_key_env="GO_KEY",
                session_header="x-opencode-session",
            )
        },
        routes={
            "plan": ModelRoute(
                name="plan",
                provider="opencode-go",
                model="deepseek-v4.1-flash",
                effort="high",
                max_tokens=128,
                enabled=enabled,
            )
        },
    )


def test_disabled_route_is_refused_by_default():
    with pytest.raises(ProviderUnavailable, match="route plan is disabled"):
        gateway_for_route(_route_config(False), "plan", limits=LIMITS)


def test_check_may_use_a_disabled_route_without_enabling_it():
    gateway = gateway_for_route(
        _route_config(False), "plan", limits=LIMITS, allow_disabled=True
    )
    assert gateway.base_url == "https://go.example/v1"
    assert gateway.model == "deepseek-v4.1-flash"
    assert _route_config(False).routes["plan"].enabled is False


def test_unknown_route_is_refused():
    with pytest.raises(ProviderUnavailable, match="unknown model route"):
        gateway_for_route(_route_config(True), "nope", limits=LIMITS)


def test_repository_routes_are_exact_and_disabled():
    expected = {
        "plan": ("opencode-go", "deepseek-v4.1-flash", "high"),
        "plan-openrouter": ("openrouter", "deepseek/deepseek-v4.1-flash-1017", "high"),
        "triage": ("opencode-go", "glm-5.3-flash", "high"),
        "triage-openrouter": ("openrouter", "z-ai/glm-5.3-flash", "high"),
        "kimi": ("opencode-go", "kimi-k3.1-pro", "max"),
        "gemini": ("openrouter", "google/gemini-4-argon", "high"),
        "hy4": ("opencode-go", "hy4", "high"),
    }
    config = load_model_config(ROOT / "configs" / "models.yaml")
    assert set(config.routes) == set(expected)
    for name, (provider, model, effort) in expected.items():
        route = config.routes[name]
        assert (route.provider, route.model, route.effort) == (provider, model, effort)
        assert route.enabled is False, f"{name} must stay disabled until evaluated"
    assert config.providers["opencode-go"].api_key_env == "OPENCODE_API_KEY"
    assert config.providers["openrouter"].api_key_env == "OPENROUTER_API_KEY"

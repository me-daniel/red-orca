"""ModelGateway: mock, OpenRouter, and compatible-endpoint adapters.

Build delegation stays on the Claude/Codex CLIs (`CodingAgentGateway`). This
gateway is the runtime transport for assessment roles. Routes are configured in
`configs/models.yaml`, carry an exact model ID and effort, and stay disabled
until a live check and the fixture comparison justify enabling them.
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import httpx
import yaml

from .config import Limits

ALLOWED_EFFORTS = {"none", "minimal", "low", "medium", "high", "max"}
MAX_ERROR_CHARS = 500
USER_AGENT = "vsw/0.1"


class ProviderUnavailable(RuntimeError):
    pass


def _number(value: object) -> float | None:
    """Return a numeric value, excluding booleans and non-numbers."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


@dataclass
class ModelResponse:
    text: str
    model: str
    usage: dict[str, object] = field(default_factory=dict)
    cost_usd: float = 0.0
    cost_measured: bool = False
    billing_source: str = ""
    allowance_usd: float | None = None
    note: str = ""
    finish_reason: str = ""
    latency_s: float = 0.0


class ModelGateway(Protocol):
    name: str

    def complete(self, prompt: str, role: str = "plan") -> ModelResponse: ...


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
            cost_measured=False,
            note="mock: no remote inference",
            finish_reason="stop",
        )


class OpenAICompatibleGateway:
    """Minimal chat-completions client for OpenRouter and compatible endpoints."""

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key_env: str,
        *,
        timeout_s: float = 60.0,
        max_tokens: int = 4096,
        max_prompt_chars: int = 24000,
        max_output_chars: int = 20000,
        reasoning_effort: str | None = None,
        app_url: str = "",
        app_title: str = "",
        session_header: str = "",
        user_agent: str = USER_AGENT,
        client: httpx.Client | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key_env = api_key_env
        self.timeout_s = timeout_s
        self.max_tokens = max_tokens
        self.max_prompt_chars = max_prompt_chars
        self.max_output_chars = max_output_chars
        self.reasoning_effort = reasoning_effort
        self.app_url = app_url
        self.app_title = app_title
        self.session_header = session_header
        self.session_id = f"vsw-{uuid.uuid4().hex}"
        self.user_agent = user_agent
        self._client = client

    @property
    def name(self) -> str:
        return f"{self.base_url}/{self.model}"

    def complete(self, prompt: str, role: str = "plan") -> ModelResponse:
        api_key = os.environ.get(self.api_key_env)
        if not api_key:
            raise ProviderUnavailable(
                f"{self.api_key_env} is not set; {self.model} is unavailable"
            )
        if len(prompt) > self.max_prompt_chars:
            raise ProviderUnavailable(
                f"prompt is {len(prompt)} chars; limit is {self.max_prompt_chars}"
            )
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": self.max_tokens,
        }
        # Do not force temperature. Some reasoning models (for example Kimi)
        # reject anything but their required value.
        if self.reasoning_effort and self.reasoning_effort != "none":
            body["reasoning"] = {"effort": self.reasoning_effort}
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": self.user_agent,
        }
        if self.session_header:
            headers[self.session_header] = self.session_id
        if self.app_url:
            headers["HTTP-Referer"] = self.app_url
        if self.app_title:
            headers["X-OpenRouter-Title"] = self.app_title

        client = self._client or httpx.Client(timeout=self.timeout_s, trust_env=False)
        started = time.monotonic()
        try:
            response = client.post(
                f"{self.base_url}/chat/completions", headers=headers, json=body
            )
            latency_s = round(time.monotonic() - started, 3)
            if response.status_code >= 400:
                detail = response.text[:MAX_ERROR_CHARS].replace(api_key, "<redacted>")
                raise ProviderUnavailable(
                    f"{self.base_url} returned {response.status_code}: {detail.strip()}"
                )
            try:
                payload = response.json()
            except ValueError:
                raise ProviderUnavailable(
                    f"{self.base_url} returned a non-JSON response"
                ) from None
        except httpx.HTTPError as exc:
            raise ProviderUnavailable(
                f"{self.base_url} request failed: {type(exc).__name__}"
            ) from None
        finally:
            if self._client is None:
                client.close()

        if not isinstance(payload, dict):
            raise ProviderUnavailable(f"{self.base_url} returned an unexpected payload")
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            error = payload.get("error")
            raise ProviderUnavailable(f"{self.base_url} returned no choices: {error}")
        choice: dict[str, Any] = choices[0] if isinstance(choices[0], dict) else {}
        raw_message = choice.get("message")
        message: dict[str, Any] = raw_message if isinstance(raw_message, dict) else {}
        text = message.get("content")
        if text is None:
            text = ""
        if not isinstance(text, str):
            raise ProviderUnavailable(f"{self.base_url} returned non-text content")

        note = ""
        if len(text) > self.max_output_chars:
            text = text[: self.max_output_chars] + "\n…[output truncated]\n"
            note = "output truncated"

        usage = payload.get("usage")
        usage = usage if isinstance(usage, dict) else {}
        cost = _number(usage.get("cost"))
        opencode_meta = usage.get("opencode")
        opencode_meta = opencode_meta if isinstance(opencode_meta, dict) else {}
        billing_source = str(opencode_meta.get("billing_source") or "")
        allowance = _number(opencode_meta.get("allowance"))
        return ModelResponse(
            text=text,
            model=str(payload.get("model") or self.model),
            usage=usage,
            cost_usd=cost if cost is not None else 0.0,
            cost_measured=cost is not None,
            billing_source=billing_source,
            allowance_usd=allowance,
            note=note,
            finish_reason=str(choice.get("finish_reason") or ""),
            latency_s=latency_s,
        )


class OpenRouterGateway(OpenAICompatibleGateway):
    """OpenRouter chat-completions transport with app attribution headers."""

    def __init__(
        self,
        model: str,
        *,
        base_url: str = "https://openrouter.ai/api/v1",
        api_key_env: str = "OPENROUTER_API_KEY",
        **kwargs: Any,
    ):
        super().__init__(base_url, model, api_key_env, **kwargs)


def openrouter_gateway(model: str, **kwargs: Any) -> OpenRouterGateway:
    return OpenRouterGateway(model, **kwargs)


def compatible_gateway(
    base_url: str, model: str, api_key_env: str, **kwargs: Any
) -> OpenAICompatibleGateway:
    return OpenAICompatibleGateway(base_url, model, api_key_env, **kwargs)


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    base_url: str
    api_key_env: str
    app_url: str = ""
    app_title: str = ""
    session_header: str = ""
    user_agent: str = USER_AGENT


@dataclass(frozen=True)
class ModelRoute:
    name: str
    provider: str
    model: str
    effort: str
    max_tokens: int
    enabled: bool
    purpose: str = ""


@dataclass(frozen=True)
class ModelConfig:
    providers: dict[str, ProviderConfig]
    routes: dict[str, ModelRoute]


def default_model_config_path(root: Path) -> Path:
    return root / "configs" / "models.yaml"


def _require(data: dict[str, Any], key: str, kind: type, where: str) -> Any:
    value = data.get(key)
    if not isinstance(value, kind):
        raise ProviderUnavailable(f"{where}: {key} must be {kind.__name__}")
    return value


def load_model_config(path: Path) -> ModelConfig:
    """Load and validate the runtime model routes. Raises ProviderUnavailable."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ProviderUnavailable(f"model config not found: {path}") from None
    except (OSError, yaml.YAMLError) as exc:
        raise ProviderUnavailable(f"cannot read model config {path}: {exc}") from None
    if not isinstance(raw, dict):
        raise ProviderUnavailable(f"{path} must contain a mapping")

    providers: dict[str, ProviderConfig] = {}
    raw_providers = raw.get("providers")
    if not isinstance(raw_providers, dict) or not raw_providers:
        raise ProviderUnavailable(f"{path}: providers must be a non-empty mapping")
    for name, item in raw_providers.items():
        if not isinstance(item, dict):
            raise ProviderUnavailable(f"{path}: provider {name} must be a mapping")
        base_url = str(_require(item, "base_url", str, f"provider {name}")).rstrip("/")
        if not base_url.startswith(("https://", "http://")):
            raise ProviderUnavailable(
                f"{path}: provider {name} base_url must start with https:// or http://"
            )
        api_key_env = str(_require(item, "api_key_env", str, f"provider {name}")).strip()
        if not api_key_env:
            raise ProviderUnavailable(f"{path}: provider {name} api_key_env must be set")
        providers[str(name)] = ProviderConfig(
            name=str(name),
            base_url=base_url,
            api_key_env=api_key_env,
            app_url=str(item.get("app_url") or ""),
            app_title=str(item.get("app_title") or ""),
            session_header=str(item.get("session_header") or ""),
            user_agent=str(item.get("user_agent") or USER_AGENT),
        )

    routes: dict[str, ModelRoute] = {}
    raw_routes = raw.get("routes")
    if not isinstance(raw_routes, dict) or not raw_routes:
        raise ProviderUnavailable(f"{path}: routes must be a non-empty mapping")
    for name, item in raw_routes.items():
        where = f"route {name}"
        if not isinstance(item, dict):
            raise ProviderUnavailable(f"{path}: {where} must be a mapping")
        provider = str(_require(item, "provider", str, where))
        if provider not in providers:
            raise ProviderUnavailable(f"{path}: {where} names unknown provider {provider}")
        model = str(_require(item, "model", str, where)).strip()
        if not model or any(ch.isspace() for ch in model):
            raise ProviderUnavailable(
                f"{path}: {where} model must be an exact provider/model ID"
            )
        # OpenRouter route IDs are namespaced (`vendor/model`); compatible
        # endpoints such as OpenCode Go use flat IDs (`glm-5.3-flash`).
        if provider == "openrouter" and ("/" not in model or model.startswith("/")):
            raise ProviderUnavailable(
                f"{path}: {where} OpenRouter model must be an exact vendor/model ID"
            )
        effort = str(_require(item, "effort", str, where)).strip().lower()
        if effort not in ALLOWED_EFFORTS:
            raise ProviderUnavailable(
                f"{path}: {where} effort must be one of {sorted(ALLOWED_EFFORTS)}"
            )
        max_tokens = _require(item, "max_tokens", int, where)
        if max_tokens <= 0:
            raise ProviderUnavailable(f"{path}: {where} max_tokens must be positive")
        enabled = _require(item, "enabled", bool, where)
        routes[str(name)] = ModelRoute(
            name=str(name),
            provider=provider,
            model=model,
            effort=effort,
            max_tokens=max_tokens,
            enabled=enabled,
            purpose=str(item.get("purpose") or ""),
        )
    return ModelConfig(providers=providers, routes=routes)


def gateway_for_route(
    config: ModelConfig,
    route_name: str,
    *,
    limits: Limits,
    allow_disabled: bool = False,
    client: httpx.Client | None = None,
) -> OpenAICompatibleGateway:
    """Build the transport for one configured route.

    A disabled route is refused unless the caller is the explicit check command.
    """
    route = config.routes.get(route_name)
    if route is None:
        raise ProviderUnavailable(f"unknown model route: {route_name}")
    if not route.enabled and not allow_disabled:
        raise ProviderUnavailable(
            f"route {route_name} is disabled; run `vsw models check {route_name}` "
            "and enable it in configs/models.yaml after evaluation"
        )
    provider = config.providers[route.provider]
    kwargs: dict[str, Any] = {
        "timeout_s": float(limits.per_call_timeout_seconds),
        "max_tokens": route.max_tokens,
        "max_prompt_chars": int(limits.max_prompt_chars),
        "max_output_chars": int(limits.max_output_chars),
        "app_url": provider.app_url,
        "app_title": provider.app_title,
        "session_header": provider.session_header,
        "user_agent": provider.user_agent,
        "client": client,
    }
    if provider.name == "openrouter":
        return OpenRouterGateway(
            route.model,
            base_url=provider.base_url,
            api_key_env=provider.api_key_env,
            reasoning_effort=route.effort,
            **kwargs,
        )
    return OpenAICompatibleGateway(
        provider.base_url,
        route.model,
        provider.api_key_env,
        reasoning_effort=route.effort,
        **kwargs,
    )

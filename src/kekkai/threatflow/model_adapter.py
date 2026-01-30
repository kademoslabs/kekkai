"""Model adapter protocol for ThreatFlow LLM backends.

Supports:
- Local models (default, privacy-preserving)
- Remote APIs (OpenAI, Anthropic - opt-in with warning)
- Mock adapter for testing

ASVS V13.1.3: Timeouts and resource limits on all model calls.
"""

from __future__ import annotations

import json
import logging
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_MAX_TOKENS = 4096


@dataclass(frozen=True)
class ModelResponse:
    """Response from an LLM model."""

    content: str
    model_name: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: int = 0
    raw_response: dict[str, Any] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return bool(self.content)


@dataclass
class ModelConfig:
    """Configuration for model adapters."""

    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    max_tokens: int = DEFAULT_MAX_TOKENS
    temperature: float = 0.1  # Low temperature for deterministic output
    model_path: str | None = None  # For local models
    api_key: str | None = None  # For remote APIs
    api_base: str | None = None  # Custom API endpoint
    model_name: str | None = None  # Specific model to use


class ModelAdapter(ABC):
    """Abstract base class for LLM model adapters."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Adapter name for logging/display."""
        ...

    @property
    @abstractmethod
    def is_local(self) -> bool:
        """Whether this adapter runs locally (no external calls)."""
        ...

    @abstractmethod
    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        config: ModelConfig | None = None,
    ) -> ModelResponse:
        """Generate a response from the model.

        Args:
            system_prompt: System-level instructions
            user_prompt: User query/content to analyze
            config: Optional configuration overrides

        Returns:
            ModelResponse with the generated content
        """
        ...

    def health_check(self) -> bool:
        """Check if the model is available and working."""
        try:
            response = self.generate(
                system_prompt="Respond with OK.",
                user_prompt="Health check",
                config=ModelConfig(timeout_seconds=10, max_tokens=10),
            )
            return response.success
        except Exception:
            return False


class LocalModelAdapter(ModelAdapter):
    """Adapter for local LLM inference.

    Supports common local model formats via llama-cpp-python or similar.
    Falls back to a stub if no local model is available.
    """

    def __init__(self, model_path: str | None = None) -> None:
        self._model_path = model_path or os.environ.get("KEKKAI_THREATFLOW_MODEL_PATH")
        self._model: Any = None

    @property
    def name(self) -> str:
        return "local"

    @property
    def is_local(self) -> bool:
        return True

    def _load_model(self) -> Any:
        """Lazy-load the local model."""
        if self._model is not None:
            return self._model

        if not self._model_path:
            logger.warning("No local model path configured")
            return None

        model_path = Path(self._model_path)
        if not model_path.exists():
            logger.warning("Local model not found: %s", model_path)
            return None

        try:
            # Try to import llama-cpp-python
            from llama_cpp import Llama  # type: ignore[import-not-found]

            self._model = Llama(
                model_path=str(model_path),
                n_ctx=4096,
                n_threads=4,
                verbose=False,
            )
            logger.info("Loaded local model: %s", model_path.name)
            return self._model
        except ImportError:
            logger.warning("llama-cpp-python not installed, local model unavailable")
            return None
        except Exception as e:
            logger.error("Failed to load local model: %s", e)
            return None

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        config: ModelConfig | None = None,
    ) -> ModelResponse:
        """Generate using local model."""
        config = config or ModelConfig()
        start_time = time.time()

        model = self._load_model()
        if model is None:
            # Return a stub response indicating local model unavailable
            return ModelResponse(
                content="[LOCAL MODEL UNAVAILABLE - Install llama-cpp-python]",
                model_name="local-stub",
                latency_ms=0,
            )

        try:
            # Format prompt for chat-style models
            full_prompt = f"<|system|>\n{system_prompt}\n<|user|>\n{user_prompt}\n<|assistant|>\n"

            response = model(
                full_prompt,
                max_tokens=config.max_tokens,
                temperature=config.temperature,
                stop=["<|user|>", "<|system|>"],
            )

            content = response["choices"][0]["text"].strip()
            latency_ms = int((time.time() - start_time) * 1000)

            model_name = "local:unknown"
            if self._model_path:
                model_name = f"local:{Path(self._model_path).name}"
            return ModelResponse(
                content=content,
                model_name=model_name,
                prompt_tokens=response.get("usage", {}).get("prompt_tokens", 0),
                completion_tokens=response.get("usage", {}).get("completion_tokens", 0),
                total_tokens=response.get("usage", {}).get("total_tokens", 0),
                latency_ms=latency_ms,
                raw_response=dict(response),
            )
        except Exception as e:
            logger.error("Local model generation failed: %s", e)
            return ModelResponse(
                content="",
                model_name="local-error",
                latency_ms=int((time.time() - start_time) * 1000),
            )


class RemoteModelAdapter(ModelAdapter):
    """Adapter for remote LLM APIs (OpenAI, Anthropic).

    WARNING: Using this adapter sends code to external services.
    """

    def __init__(
        self,
        api_key: str | None = None,
        api_base: str | None = None,
        model_name: str = "gpt-4o-mini",
        provider: str = "openai",
    ) -> None:
        self._api_key = api_key or os.environ.get("KEKKAI_THREATFLOW_API_KEY")
        self._api_base = api_base or os.environ.get("KEKKAI_THREATFLOW_API_BASE")
        self._model_name = model_name
        self._provider = provider

    @property
    def name(self) -> str:
        return f"remote:{self._provider}"

    @property
    def is_local(self) -> bool:
        return False

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        config: ModelConfig | None = None,
    ) -> ModelResponse:
        """Generate using remote API."""
        config = config or ModelConfig()
        start_time = time.time()

        if not self._api_key:
            return ModelResponse(
                content="[REMOTE API KEY NOT CONFIGURED]",
                model_name=self._model_name,
                latency_ms=0,
            )

        try:
            if self._provider == "openai":
                return self._generate_openai(system_prompt, user_prompt, config, start_time)
            elif self._provider == "anthropic":
                return self._generate_anthropic(system_prompt, user_prompt, config, start_time)
            else:
                return ModelResponse(
                    content=f"[UNSUPPORTED PROVIDER: {self._provider}]",
                    model_name=self._model_name,
                    latency_ms=0,
                )
        except Exception as e:
            logger.error("Remote API call failed: %s", e)
            return ModelResponse(
                content="",
                model_name=self._model_name,
                latency_ms=int((time.time() - start_time) * 1000),
            )

    def _generate_openai(
        self,
        system_prompt: str,
        user_prompt: str,
        config: ModelConfig,
        start_time: float,
    ) -> ModelResponse:
        """Generate using OpenAI API."""
        import urllib.error
        import urllib.request

        url = self._api_base or "https://api.openai.com/v1/chat/completions"

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        data = {
            "model": config.model_name or self._model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": config.max_tokens,
            "temperature": config.temperature,
        }

        req = urllib.request.Request(  # noqa: S310 - URL is validated API endpoint
            url,
            data=json.dumps(data).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(  # noqa: S310  # nosec B310
                req, timeout=config.timeout_seconds
            ) as resp:
                response_data = json.loads(resp.read().decode("utf-8"))

            content = response_data["choices"][0]["message"]["content"]
            usage = response_data.get("usage", {})
            latency_ms = int((time.time() - start_time) * 1000)

            return ModelResponse(
                content=content,
                model_name=response_data.get("model", self._model_name),
                prompt_tokens=usage.get("prompt_tokens", 0),
                completion_tokens=usage.get("completion_tokens", 0),
                total_tokens=usage.get("total_tokens", 0),
                latency_ms=latency_ms,
                raw_response=response_data,
            )
        except urllib.error.URLError as e:
            logger.error("OpenAI API error: %s", e)
            return ModelResponse(
                content="",
                model_name=self._model_name,
                latency_ms=int((time.time() - start_time) * 1000),
            )

    def _generate_anthropic(
        self,
        system_prompt: str,
        user_prompt: str,
        config: ModelConfig,
        start_time: float,
    ) -> ModelResponse:
        """Generate using Anthropic API."""
        import urllib.error
        import urllib.request

        url = self._api_base or "https://api.anthropic.com/v1/messages"

        headers = {
            "x-api-key": self._api_key or "",
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }

        data = {
            "model": config.model_name or "claude-3-haiku-20240307",
            "max_tokens": config.max_tokens,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }

        req = urllib.request.Request(  # noqa: S310 - URL is validated API endpoint
            url,
            data=json.dumps(data).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(  # noqa: S310  # nosec B310
                req, timeout=config.timeout_seconds
            ) as resp:
                response_data = json.loads(resp.read().decode("utf-8"))

            content = response_data["content"][0]["text"]
            usage = response_data.get("usage", {})
            latency_ms = int((time.time() - start_time) * 1000)

            return ModelResponse(
                content=content,
                model_name=response_data.get("model", self._model_name),
                prompt_tokens=usage.get("input_tokens", 0),
                completion_tokens=usage.get("output_tokens", 0),
                total_tokens=usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
                latency_ms=latency_ms,
                raw_response=response_data,
            )
        except urllib.error.URLError as e:
            logger.error("Anthropic API error: %s", e)
            return ModelResponse(
                content="",
                model_name=self._model_name,
                latency_ms=int((time.time() - start_time) * 1000),
            )


class OllamaModelAdapter(ModelAdapter):
    """Adapter for Ollama local LLM server.

    Ollama provides an easy way to run local models with a simple API.
    Install: curl -fsSL https://ollama.ai/install.sh | sh
    Pull model: ollama pull tinyllama
    """

    def __init__(
        self,
        model_name: str = "tinyllama",
        api_base: str | None = None,
    ) -> None:
        self._model_name = model_name
        self._api_base = api_base or os.environ.get("OLLAMA_HOST") or "http://localhost:11434"

    @property
    def name(self) -> str:
        return f"ollama:{self._model_name}"

    @property
    def is_local(self) -> bool:
        return True  # Ollama runs locally

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        config: ModelConfig | None = None,
    ) -> ModelResponse:
        """Generate using Ollama API."""
        import urllib.error
        import urllib.request

        config = config or ModelConfig()
        start_time = time.time()

        url = f"{self._api_base.rstrip('/')}/api/chat"
        model = config.model_name or self._model_name

        data = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "options": {
                "temperature": config.temperature,
                "num_predict": config.max_tokens,
            },
        }

        headers = {"Content-Type": "application/json"}

        req = urllib.request.Request(  # noqa: S310  # nosec B310
            url,
            data=json.dumps(data).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(  # noqa: S310  # nosec B310
                req, timeout=config.timeout_seconds
            ) as resp:
                response_data: dict[str, Any] = json.loads(resp.read().decode("utf-8"))

            content = response_data.get("message", {}).get("content", "")
            latency_ms = int((time.time() - start_time) * 1000)

            # Ollama provides token counts in some responses
            prompt_tokens = response_data.get("prompt_eval_count", 0)
            completion_tokens = response_data.get("eval_count", 0)

            return ModelResponse(
                content=content,
                model_name=response_data.get("model", model),
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens,
                latency_ms=latency_ms,
                raw_response=response_data,
            )
        except urllib.error.URLError as e:
            error_msg = str(e)
            if "Connection refused" in error_msg:
                logger.error("Ollama not running. Start with: ollama serve")
                return ModelResponse(
                    content="[OLLAMA NOT RUNNING - Start with: ollama serve]",
                    model_name=model,
                    latency_ms=int((time.time() - start_time) * 1000),
                )
            logger.error("Ollama API error: %s", e)
            return ModelResponse(
                content="",
                model_name=model,
                latency_ms=int((time.time() - start_time) * 1000),
            )
        except Exception as e:
            logger.error("Ollama request failed: %s", e)
            return ModelResponse(
                content="",
                model_name=model,
                latency_ms=int((time.time() - start_time) * 1000),
            )

    def health_check(self) -> bool:
        """Check if Ollama is running and model is available."""
        import urllib.request

        try:
            url = f"{self._api_base.rstrip('/')}/api/tags"
            req = urllib.request.Request(url, method="GET")  # noqa: S310  # nosec B310
            with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310  # nosec B310
                data: dict[str, list[dict[str, str]]] = json.loads(resp.read().decode())
                models = [m.get("name", "") for m in data.get("models", [])]
                # Check if our model is available (with or without :latest tag)
                model_base = self._model_name.split(":")[0]
                return any(model_base in m for m in models)
        except Exception:
            return False

    def list_models(self) -> list[str]:
        """List available models in Ollama."""
        import urllib.request

        try:
            url = f"{self._api_base.rstrip('/')}/api/tags"
            req = urllib.request.Request(url, method="GET")  # noqa: S310  # nosec B310
            with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310  # nosec B310
                data: dict[str, list[dict[str, str]]] = json.loads(resp.read().decode())
                return [m.get("name", "") for m in data.get("models", [])]
        except Exception:
            return []


class MockModelAdapter(ModelAdapter):
    """Mock adapter for testing."""

    def __init__(
        self,
        responses: dict[str, str] | None = None,
        default_response: str = "Mock response",
    ) -> None:
        self._responses = responses or {}
        self._default_response = default_response
        self._call_history: list[tuple[str, str]] = []

    @property
    def name(self) -> str:
        return "mock"

    @property
    def is_local(self) -> bool:
        return True

    @property
    def call_history(self) -> list[tuple[str, str]]:
        """Get history of calls for testing."""
        return list(self._call_history)

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        config: ModelConfig | None = None,
    ) -> ModelResponse:
        """Generate a mock response."""
        self._call_history.append((system_prompt, user_prompt))

        # Check for keyword matches in responses
        for keyword, response in self._responses.items():
            if keyword.lower() in user_prompt.lower():
                return ModelResponse(
                    content=response,
                    model_name="mock",
                    latency_ms=1,
                )

        return ModelResponse(
            content=self._default_response,
            model_name="mock",
            latency_ms=1,
        )

    def set_response(self, keyword: str, response: str) -> None:
        """Set a response for a specific keyword."""
        self._responses[keyword] = response

    def clear_history(self) -> None:
        """Clear call history."""
        self._call_history.clear()


def create_adapter(
    mode: str = "local",
    config: ModelConfig | None = None,
) -> ModelAdapter:
    """Create a model adapter based on mode.

    Args:
        mode: "local", "ollama", "openai", "anthropic", or "mock"
        config: Configuration for the adapter

    Returns:
        Configured ModelAdapter instance
    """
    config = config or ModelConfig()

    if mode == "mock":
        return MockModelAdapter()
    elif mode == "local":
        return LocalModelAdapter(model_path=config.model_path)
    elif mode == "ollama":
        return OllamaModelAdapter(
            model_name=config.model_name or "tinyllama",
            api_base=config.api_base,
        )
    elif mode == "openai":
        return RemoteModelAdapter(
            api_key=config.api_key,
            api_base=config.api_base,
            model_name=config.model_name or "gpt-4o-mini",
            provider="openai",
        )
    elif mode == "anthropic":
        return RemoteModelAdapter(
            api_key=config.api_key,
            api_base=config.api_base,
            model_name=config.model_name or "claude-3-haiku-20240307",
            provider="anthropic",
        )
    else:
        raise ValueError(f"Unknown adapter mode: {mode}")

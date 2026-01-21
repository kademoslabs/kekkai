"""Unit tests for ThreatFlow model adapter."""

from __future__ import annotations

import pytest

from kekkai.threatflow.model_adapter import (
    LocalModelAdapter,
    MockModelAdapter,
    ModelAdapter,
    ModelConfig,
    ModelResponse,
    RemoteModelAdapter,
    create_adapter,
)


class TestModelResponse:
    """Tests for ModelResponse dataclass."""

    def test_success_with_content(self) -> None:
        """Test success property with content."""
        response = ModelResponse(content="Hello", model_name="test")
        assert response.success

    def test_success_without_content(self) -> None:
        """Test success property without content."""
        response = ModelResponse(content="", model_name="test")
        assert not response.success

    def test_response_metadata(self) -> None:
        """Test response metadata fields."""
        response = ModelResponse(
            content="Hello",
            model_name="test-model",
            prompt_tokens=10,
            completion_tokens=5,
            total_tokens=15,
            latency_ms=100,
        )
        assert response.model_name == "test-model"
        assert response.prompt_tokens == 10
        assert response.completion_tokens == 5
        assert response.total_tokens == 15
        assert response.latency_ms == 100


class TestModelConfig:
    """Tests for ModelConfig dataclass."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = ModelConfig()
        assert config.timeout_seconds == 120
        assert config.max_tokens == 4096
        assert config.temperature == 0.1

    def test_custom_config(self) -> None:
        """Test custom configuration."""
        config = ModelConfig(
            timeout_seconds=60,
            max_tokens=1000,
            temperature=0.5,
        )
        assert config.timeout_seconds == 60
        assert config.max_tokens == 1000
        assert config.temperature == 0.5


class TestMockModelAdapter:
    """Tests for MockModelAdapter."""

    def test_is_local(self) -> None:
        """Test that mock adapter is marked as local."""
        adapter = MockModelAdapter()
        assert adapter.is_local
        assert adapter.name == "mock"

    def test_default_response(self) -> None:
        """Test default response generation."""
        adapter = MockModelAdapter(default_response="Test response")
        response = adapter.generate(
            system_prompt="You are helpful",
            user_prompt="Hello",
        )
        assert response.content == "Test response"
        assert response.success

    def test_keyword_responses(self) -> None:
        """Test keyword-based response selection."""
        adapter = MockModelAdapter(
            responses={
                "dataflow": "User -> API -> Database",
                "threats": "T001: SQL Injection",
            }
        )

        df_response = adapter.generate("system", "Analyze dataflow")
        assert "User -> API" in df_response.content

        threat_response = adapter.generate("system", "List threats")
        assert "T001" in threat_response.content

    def test_call_history(self) -> None:
        """Test that calls are recorded."""
        adapter = MockModelAdapter()
        adapter.generate("system1", "user1")
        adapter.generate("system2", "user2")

        assert len(adapter.call_history) == 2
        assert adapter.call_history[0] == ("system1", "user1")
        assert adapter.call_history[1] == ("system2", "user2")

    def test_clear_history(self) -> None:
        """Test clearing call history."""
        adapter = MockModelAdapter()
        adapter.generate("system", "user")
        adapter.clear_history()
        assert len(adapter.call_history) == 0

    def test_set_response(self) -> None:
        """Test setting responses dynamically."""
        adapter = MockModelAdapter()
        adapter.set_response("custom", "Custom response")
        response = adapter.generate("system", "custom query")
        assert response.content == "Custom response"


class TestLocalModelAdapter:
    """Tests for LocalModelAdapter."""

    def test_is_local(self) -> None:
        """Test that local adapter is marked as local."""
        adapter = LocalModelAdapter()
        assert adapter.is_local
        assert adapter.name == "local"

    def test_no_model_returns_stub(self) -> None:
        """Test that missing model returns stub response."""
        adapter = LocalModelAdapter(model_path=None)
        response = adapter.generate("system", "user")
        assert "UNAVAILABLE" in response.content
        assert response.model_name == "local-stub"


class TestRemoteModelAdapter:
    """Tests for RemoteModelAdapter."""

    def test_is_not_local(self) -> None:
        """Test that remote adapter is not marked as local."""
        adapter = RemoteModelAdapter()
        assert not adapter.is_local
        assert "remote" in adapter.name

    def test_no_api_key_returns_error(self) -> None:
        """Test that missing API key returns error response."""
        adapter = RemoteModelAdapter(api_key=None)
        response = adapter.generate("system", "user")
        assert "NOT CONFIGURED" in response.content

    def test_openai_provider(self) -> None:
        """Test OpenAI provider configuration."""
        adapter = RemoteModelAdapter(provider="openai", model_name="gpt-4")
        assert "openai" in adapter.name

    def test_anthropic_provider(self) -> None:
        """Test Anthropic provider configuration."""
        adapter = RemoteModelAdapter(provider="anthropic")
        assert "anthropic" in adapter.name


class TestCreateAdapter:
    """Tests for create_adapter factory function."""

    def test_create_mock_adapter(self) -> None:
        """Test creating mock adapter."""
        adapter = create_adapter("mock")
        assert isinstance(adapter, MockModelAdapter)

    def test_create_local_adapter(self) -> None:
        """Test creating local adapter."""
        adapter = create_adapter("local")
        assert isinstance(adapter, LocalModelAdapter)

    def test_create_openai_adapter(self) -> None:
        """Test creating OpenAI adapter."""
        adapter = create_adapter("openai")
        assert isinstance(adapter, RemoteModelAdapter)

    def test_create_anthropic_adapter(self) -> None:
        """Test creating Anthropic adapter."""
        adapter = create_adapter("anthropic")
        assert isinstance(adapter, RemoteModelAdapter)

    def test_create_unknown_raises(self) -> None:
        """Test that unknown mode raises ValueError."""
        with pytest.raises(ValueError, match="Unknown"):
            create_adapter("unknown_mode")

    def test_create_with_config(self) -> None:
        """Test creating adapter with config."""
        config = ModelConfig(model_path="/path/to/model")
        adapter = create_adapter("local", config)
        assert isinstance(adapter, LocalModelAdapter)


class TestModelAdapterProtocol:
    """Tests for ModelAdapter protocol compliance."""

    def test_mock_implements_protocol(self) -> None:
        """Test that MockModelAdapter implements ModelAdapter."""
        adapter: ModelAdapter = MockModelAdapter()
        assert hasattr(adapter, "name")
        assert hasattr(adapter, "is_local")
        assert hasattr(adapter, "generate")

    def test_local_implements_protocol(self) -> None:
        """Test that LocalModelAdapter implements ModelAdapter."""
        adapter: ModelAdapter = LocalModelAdapter()
        assert hasattr(adapter, "name")
        assert hasattr(adapter, "is_local")
        assert hasattr(adapter, "generate")

    def test_remote_implements_protocol(self) -> None:
        """Test that RemoteModelAdapter implements ModelAdapter."""
        adapter: ModelAdapter = RemoteModelAdapter()
        assert hasattr(adapter, "name")
        assert hasattr(adapter, "is_local")
        assert hasattr(adapter, "generate")

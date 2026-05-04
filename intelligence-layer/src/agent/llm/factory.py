"""Dependency injection: get_llm_client(role) — swap provider via .env only."""
from typing import Literal

from ...config import Settings
from .interface import LLMClient
from .openai_compat import OpenAICompatibleClient


def get_llm_client(role: Literal["primary", "fast"], settings: Settings) -> LLMClient:
    if role == "primary":
        provider = settings.llm_primary_provider
        api_key = settings.llm_primary_api_key
        base_url = settings.llm_primary_base_url
        model = settings.llm_primary_model
        temperature = settings.llm_primary_temperature
        max_tokens = settings.llm_primary_max_tokens
    else:
        provider = settings.llm_fast_provider
        api_key = settings.llm_fast_api_key
        base_url = settings.llm_fast_base_url
        model = settings.llm_fast_model
        temperature = settings.llm_fast_temperature
        max_tokens = settings.llm_fast_max_tokens

    if provider == "openai_compat":
        return OpenAICompatibleClient(
            api_key=api_key,
            base_url=base_url,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=settings.llm_timeout_seconds,
        )

    raise ValueError(f"Unknown LLM provider: {provider!r}. Supported: openai_compat")

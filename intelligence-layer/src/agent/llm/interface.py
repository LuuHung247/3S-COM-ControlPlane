"""LLMClient abstract base class. All providers must implement this interface."""
from abc import ABC, abstractmethod
from typing import Any


class LLMClient(ABC):
    @abstractmethod
    async def chat(
        self,
        messages: list[dict[str, str]],
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict | None = None,
    ) -> dict[str, Any]:
        """
        Send a chat request. Returns a dict with at minimum:
          {"content": str, "tool_calls": list[dict] | None}
        tool_calls entries: {"name": str, "arguments": dict}
        """

    @abstractmethod
    async def chat_json(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Force JSON output conforming to schema (function-calling or json_mode).
        Returns the parsed dict.
        """

    @property
    @abstractmethod
    def model(self) -> str:
        """Return the model identifier string."""

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

    @abstractmethod
    async def chat_react(
        self,
        messages: list[dict[str, str]],
        tools: list[dict[str, Any]],
        tool_handlers: dict[str, Any],
        final_schema: dict[str, Any],
        max_iterations: int = 5,
    ) -> dict[str, Any]:
        """
        Multi-round tool-calling loop. The model emits tool_calls; the framework
        executes each via tool_handlers[name](**args), appends results, and
        re-prompts the model. Loops until the model emits a final answer
        conforming to `final_schema` (forced via tool_choice on the last round)
        or max_iterations is reached.

        tool_handlers: dict mapping tool name → async callable. Each handler
        receives the parsed arguments dict and returns a string (or any
        JSON-serializable value) that becomes the tool result.

        Returns the parsed final_schema dict.
        """

    @property
    @abstractmethod
    def model(self) -> str:
        """Return the model identifier string."""

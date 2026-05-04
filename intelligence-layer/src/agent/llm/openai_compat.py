"""OpenAI-compatible client: works with Cerebras, Z.ai, Groq, vLLM, Ollama, OpenRouter."""
import json
from typing import Any

import httpx

from .interface import LLMClient


class OpenAICompatibleClient(LLMClient):
    def __init__(
        self,
        api_key: str,
        base_url: str,
        model: str,
        temperature: float = 0.1,
        max_tokens: int = 2048,
        timeout: int = 10,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._timeout = timeout

    @property
    def model(self) -> str:
        return self._model

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

    async def chat(
        self,
        messages: list[dict[str, str]],
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "temperature": self._temperature,
            "max_tokens": self._max_tokens,
        }
        if tools:
            payload["tools"] = tools
        if tool_choice is not None:
            payload["tool_choice"] = tool_choice

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{self._base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()

        choice = data["choices"][0]
        msg = choice["message"]
        tool_calls = None
        if msg.get("tool_calls"):
            tool_calls = [
                {
                    "name": tc["function"]["name"],
                    "arguments": json.loads(tc["function"]["arguments"]),
                    "id": tc.get("id", ""),
                }
                for tc in msg["tool_calls"]
            ]
        return {
            "content": msg.get("content") or "",
            "tool_calls": tool_calls,
            "usage": data.get("usage", {}),
        }

    async def chat_json(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any],
    ) -> dict[str, Any]:
        """Force structured JSON output via function calling."""
        tool = {
            "type": "function",
            "function": {
                "name": "structured_output",
                "description": "Return the structured output",
                "parameters": schema,
            },
        }
        result = await self.chat(
            messages=messages,
            tools=[tool],
            tool_choice={"type": "function", "function": {"name": "structured_output"}},
        )
        if result["tool_calls"]:
            return result["tool_calls"][0]["arguments"]
        # Fallback: try parsing content as JSON
        try:
            return json.loads(result["content"])
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError(f"LLM did not return valid JSON: {result['content']!r}") from exc

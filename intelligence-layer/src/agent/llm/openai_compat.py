"""OpenAI-compatible client: works with Cerebras, Z.ai, Groq, vLLM, Ollama, OpenRouter."""
import json
import time
from typing import Any

import httpx

from .interface import LLMClient
from ...observability.langfuse_tracer import get_global_tracer, get_active_trace


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

        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    f"{self._base_url}/chat/completions",
                    headers=self._headers(),
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            # Record failed LLM call to Langfuse before re-raising
            self._record_generation(
                input_messages=messages,
                output=None,
                usage={},
                latency_ms=(time.monotonic() - t0) * 1000,
                error=str(exc)[:200],
            )
            raise

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
        usage = data.get("usage", {})

        # Record successful LLM generation to Langfuse (cost + tokens auto-tracked)
        self._record_generation(
            input_messages=messages,
            output=msg.get("content") or tool_calls,
            usage=usage,
            latency_ms=(time.monotonic() - t0) * 1000,
        )

        return {
            "content": msg.get("content") or "",
            "tool_calls": tool_calls,
            "usage": usage,
        }

    def _record_generation(
        self,
        input_messages: list[dict[str, str]],
        output: Any,
        usage: dict,
        latency_ms: float,
        error: str = "",
    ) -> None:
        """Emit a Langfuse generation event for this LLM call. Links to current trace
        via the active span (set by graph.py per-node context manager)."""
        tracer = get_global_tracer()
        if tracer is None or not tracer.enabled:
            return
        try:
            current_trace = get_active_trace()
            if current_trace is None:
                # Fallback: standalone generation (no parent — appears at root level)
                client = tracer._client
                if client is None:
                    return
                gen = client.generation(
                    name="llm.chat",
                    model=self._model,
                    input=input_messages,
                    metadata={
                        "temperature": self._temperature,
                        "max_tokens": self._max_tokens,
                        "latency_ms": round(latency_ms, 1),
                    },
                )
            else:
                # Nested under active trace — proper parent-child linkage
                gen = current_trace.generation(
                    name="llm.chat",
                    model=self._model,
                    input=input_messages,
                    metadata={
                        "temperature": self._temperature,
                        "max_tokens": self._max_tokens,
                        "latency_ms": round(latency_ms, 1),
                    },
                )

            update_kwargs: dict = {"output": output}
            if usage:
                update_kwargs["usage"] = {
                    "input": usage.get("prompt_tokens", 0),
                    "output": usage.get("completion_tokens", 0),
                    "total": usage.get("total_tokens", 0),
                    "unit": "TOKENS",
                }
            if error:
                update_kwargs["level"] = "ERROR"
                update_kwargs["status_message"] = error
            gen.update(**update_kwargs)
            gen.end()
        except Exception:
            pass  # Tracing must never break the agent

    async def chat_json(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any],
    ) -> dict[str, Any]:
        """Force structured JSON output. Tries function-calling first; on Cerebras
        tool-call parser failure (HTTP 400 generation_error), falls back to plain
        JSON-mode + schema described in system prompt."""
        tool = {
            "type": "function",
            "function": {
                "name": "structured_output",
                "description": "Return the structured output",
                "parameters": schema,
            },
        }
        try:
            result = await self.chat(
                messages=messages,
                tools=[tool],
                tool_choice={"type": "function", "function": {"name": "structured_output"}},
            )
            if result["tool_calls"]:
                return result["tool_calls"][0]["arguments"]
            # Tool was offered but model returned plain content — try parsing
            try:
                return json.loads(result["content"])
            except (json.JSONDecodeError, TypeError):
                pass
        except httpx.HTTPStatusError as exc:
            # Cerebras occasionally returns 400 generation_error on complex schemas.
            # Fall through to JSON-mode fallback rather than failing the decision.
            if exc.response.status_code != 400:
                raise

        # Fallback path: JSON mode without tools, schema described in instructions.
        # Try with response_format json_object first; if empty, retry with simplified
        # schema (strip optional V2 fields that Cerebras parser sometimes refuses).
        schema_hint = json.dumps(schema, indent=2)
        fallback_msgs = list(messages) + [
            {
                "role": "system",
                "content": (
                    "Output ONLY a single JSON object matching this schema. "
                    "No prose, no markdown fences. Begin with `{` and end with `}`.\n\n"
                    "SCHEMA:\n" + schema_hint
                ),
            }
        ]

        for attempt in range(2):
            payload: dict[str, Any] = {
                "model": self._model,
                "messages": fallback_msgs,
                "temperature": self._temperature + (0.1 if attempt > 0 else 0.0),
                "max_tokens": self._max_tokens,
                "response_format": {"type": "json_object"},
            }
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    resp = await client.post(
                        f"{self._base_url}/chat/completions",
                        headers=self._headers(),
                        json=payload,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                content = data["choices"][0]["message"].get("content") or ""
                if content.strip():
                    return json.loads(content)
            except (httpx.HTTPStatusError, json.JSONDecodeError, KeyError):
                if attempt == 0:
                    continue
                raise

        raise ValueError(f"LLM did not return valid JSON after fallback retries")

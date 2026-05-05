"""Langfuse tracing wrapper for the intelligence-layer agent.

Single integration point. Falls back to no-op gracefully if Langfuse SDK is unavailable
or LANGFUSE_ENABLED=false.

Trace structure per alert:
  trace: agent.process (root, tagged with sid, src_ip)
    ├─ span: load_context
    ├─ span: classify (with nested generation event for fast LLM)
    ├─ span: gather_context
    │    └─ span: investigation (parallel sub-fetches)
    ├─ span: cache_lookup
    ├─ span: reason (with nested generation events for primary LLM, possibly N self-consistency)
    ├─ span: validate
    └─ span: enforce
"""
from __future__ import annotations

import contextlib
import contextvars
from typing import Any, Iterator

import structlog


# Active parent observation (trace or span) — used by LLM client to nest generations
_active_observation: contextvars.ContextVar[Any | None] = contextvars.ContextVar(
    "_active_observation", default=None
)


def get_active_trace() -> Any | None:
    """Return the currently active Langfuse trace/span, or None."""
    return _active_observation.get()

log = structlog.get_logger()

try:
    from langfuse import Langfuse
    _LANGFUSE_AVAILABLE = True
except ImportError:
    Langfuse = None  # type: ignore
    _LANGFUSE_AVAILABLE = False


class _NoopSpan:
    """Returned when Langfuse is disabled. Mimics the API but does nothing."""
    id: str = ""

    def update(self, **kwargs: Any) -> None: ...
    def end(self, **kwargs: Any) -> None: ...
    def score(self, **kwargs: Any) -> None: ...


class _NoopTrace(_NoopSpan):
    def span(self, **kwargs: Any) -> "_NoopSpan": return _NoopSpan()
    def generation(self, **kwargs: Any) -> "_NoopSpan": return _NoopSpan()
    def event(self, **kwargs: Any) -> "_NoopSpan": return _NoopSpan()


class LangfuseTracer:
    """Thin wrapper around the Langfuse client. Designed to be safely no-op."""

    def __init__(
        self,
        host: str = "",
        public_key: str = "",
        secret_key: str = "",
        enabled: bool = True,
    ) -> None:
        self._enabled = enabled and _LANGFUSE_AVAILABLE and bool(public_key and secret_key)
        self._client: Any | None = None
        if self._enabled:
            try:
                self._client = Langfuse(
                    host=host or None,
                    public_key=public_key,
                    secret_key=secret_key,
                    flush_at=1,           # ship spans eagerly for low-latency dev
                    flush_interval=2.0,
                )
                log.info("langfuse_tracer_enabled", host=host)
            except Exception as exc:
                log.warning("langfuse_init_failed", error=str(exc))
                self._enabled = False
                self._client = None
        else:
            log.info("langfuse_tracer_disabled",
                     reason="missing_keys" if not (public_key and secret_key) else "disabled")

    @property
    def enabled(self) -> bool:
        return self._enabled

    def trace(
        self,
        name: str,
        *,
        user_id: str = "",
        session_id: str = "",
        metadata: dict | None = None,
        tags: list[str] | None = None,
        input: Any | None = None,
    ) -> Any:
        """Start a new trace. Returns a trace object (or no-op stub).
        Sets it as the active observation for any LLM calls in current async context.
        """
        if not self._enabled or self._client is None:
            return _NoopTrace()
        try:
            t = self._client.trace(
                name=name,
                user_id=user_id or None,
                session_id=session_id or None,
                metadata=metadata or {},
                tags=tags or [],
                input=input,
            )
            _active_observation.set(t)
            return t
        except Exception as exc:
            log.warning("langfuse_trace_failed", error=str(exc))
            return _NoopTrace()

    @contextlib.contextmanager
    def span(
        self,
        parent: Any,
        name: str,
        *,
        input: Any | None = None,
        metadata: dict | None = None,
    ) -> Iterator[Any]:
        """Context manager for a child span under a trace or another span.
        Sets the span as active observation while the context is open so LLM
        generations inside nest under it.
        """
        if not self._enabled or parent is None:
            yield _NoopSpan()
            return
        span = None
        token = None
        try:
            span = parent.span(name=name, input=input, metadata=metadata or {})
            token = _active_observation.set(span)
            yield span
        except Exception as exc:
            if span is not None:
                try:
                    span.update(level="ERROR", status_message=str(exc)[:200])
                except Exception:
                    pass
            raise
        finally:
            if token is not None:
                try:
                    _active_observation.reset(token)
                except Exception:
                    pass
            if span is not None:
                try:
                    span.end()
                except Exception:
                    pass

    def generation(
        self,
        parent: Any,
        name: str,
        *,
        model: str,
        input: Any,
        output: Any | None = None,
        usage: dict | None = None,
        metadata: dict | None = None,
        level: str = "DEFAULT",
    ) -> None:
        """Record a single LLM generation event under a trace/span. Fire-and-forget."""
        if not self._enabled or parent is None:
            return
        try:
            gen = parent.generation(
                name=name,
                model=model,
                input=input,
                metadata=metadata or {},
            )
            update_kwargs: dict = {}
            if output is not None:
                update_kwargs["output"] = output
            if usage:
                update_kwargs["usage"] = usage
            if level != "DEFAULT":
                update_kwargs["level"] = level
            if update_kwargs:
                gen.update(**update_kwargs)
            gen.end()
        except Exception as exc:
            log.warning("langfuse_generation_failed", error=str(exc))

    def score_trace(self, trace_id: str, name: str, value: float, comment: str = "") -> None:
        """Attach a score to a previously emitted trace (used by retrospective labeler)."""
        if not self._enabled or self._client is None or not trace_id:
            return
        try:
            self._client.score(
                trace_id=trace_id,
                name=name,
                value=value,
                comment=comment or None,
            )
        except Exception as exc:
            log.warning("langfuse_score_failed", error=str(exc))

    def flush(self) -> None:
        if self._enabled and self._client is not None:
            try:
                self._client.flush()
            except Exception:
                pass

    def shutdown(self) -> None:
        if self._enabled and self._client is not None:
            try:
                self._client.shutdown()
            except Exception:
                pass


# Module-level instance for use by LLM client without circular imports
_global_tracer: LangfuseTracer | None = None


def set_global_tracer(tracer: LangfuseTracer) -> None:
    global _global_tracer
    _global_tracer = tracer


def get_global_tracer() -> LangfuseTracer | None:
    return _global_tracer

"""Embedder — produces 384-dim vectors for past-decision semantic search.

Uses fastembed (ONNX runtime, ~80MB model). Local, no network calls.
Model: BAAI/bge-small-en-v1.5 — 384-dim, fast, good for short-text retrieval.

Lifecycle:
- Lazy-loaded singleton — first .embed() warms the ONNX session
- Thread-safe via fastembed internals
- Embedding for past_decisions runs in background after Postgres write
"""
from __future__ import annotations

import asyncio
from functools import lru_cache
from typing import Iterable

import structlog

log = structlog.get_logger()

EMBED_DIM: int = 384
_MODEL_NAME: str = "BAAI/bge-small-en-v1.5"


class _EmbedderSingleton:
    _instance = None
    _model = None

    @classmethod
    def get(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _ensure_loaded(self):
        if self._model is None:
            try:
                from fastembed import TextEmbedding
                self._model = TextEmbedding(model_name=_MODEL_NAME)
                log.info("embedder_loaded", model=_MODEL_NAME, dim=EMBED_DIM)
            except Exception as exc:
                log.warning("embedder_load_failed", error=str(exc))
                self._model = False  # mark as broken

    def embed_one(self, text: str) -> list[float] | None:
        self._ensure_loaded()
        if self._model is False or self._model is None:
            return None
        try:
            vec = next(iter(self._model.embed([text])))
            return vec.tolist() if hasattr(vec, "tolist") else list(vec)
        except Exception as exc:
            log.warning("embed_one_failed", error=str(exc))
            return None

    def embed_many(self, texts: Iterable[str]) -> list[list[float] | None]:
        self._ensure_loaded()
        if self._model is False or self._model is None:
            return [None] * len(list(texts))
        try:
            return [v.tolist() if hasattr(v, "tolist") else list(v) for v in self._model.embed(list(texts))]
        except Exception as exc:
            log.warning("embed_many_failed", error=str(exc))
            return [None] * len(list(texts))


# ─────────────────────────────────────────────────────────────────────────────
# Public async API
# ─────────────────────────────────────────────────────────────────────────────
async def embed_text(text: str) -> list[float] | None:
    """Run embedding in thread pool to avoid blocking the event loop."""
    if not text or not text.strip():
        return None
    embedder = _EmbedderSingleton.get()
    return await asyncio.to_thread(embedder.embed_one, text)


def build_decision_text(
    sid: int,
    src_zone: str | None,
    dst_zone: str | None,
    signature: str = "",
    primary_hypothesis: str = "",
    reasoning_first_step: str = "",
    mitre_technique: str = "",
) -> str:
    """Compose a short doc representing a decision for semantic indexing.

    Keep it concise (< 300 chars) so embedding stays focused on threat shape,
    not noise like timestamps or rule IDs.
    """
    parts = [f"SID {sid}"]
    if mitre_technique:
        parts.append(f"MITRE {mitre_technique}")
    if src_zone or dst_zone:
        parts.append(f"flow {src_zone or '?'} to {dst_zone or '?'}")
    if signature:
        parts.append(f"sig: {signature[:120]}")
    if primary_hypothesis:
        parts.append(f"hypothesis: {primary_hypothesis[:120]}")
    if reasoning_first_step:
        parts.append(f"why: {reasoning_first_step[:160]}")
    return " | ".join(parts)

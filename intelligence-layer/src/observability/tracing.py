"""OpenTelemetry + LangSmith tracing setup (no-op when keys not configured)."""
import os


def configure_tracing(langsmith_api_key: str = "", langsmith_project: str = "") -> None:
    if langsmith_api_key:
        os.environ.setdefault("LANGCHAIN_API_KEY", langsmith_api_key)
        os.environ.setdefault("LANGCHAIN_PROJECT", langsmith_project)
        os.environ.setdefault("LANGCHAIN_TRACING_V2", "true")

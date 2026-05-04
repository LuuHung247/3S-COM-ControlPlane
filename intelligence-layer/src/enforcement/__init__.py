from .interface import EnforcementBackend
from .ids_agent_proxy import IDSAgentProxyBackend


def get_backend(settings) -> EnforcementBackend:
    return IDSAgentProxyBackend(settings.ids_agent_url, timeout=settings.llm_timeout_seconds)


__all__ = ["EnforcementBackend", "IDSAgentProxyBackend", "get_backend"]

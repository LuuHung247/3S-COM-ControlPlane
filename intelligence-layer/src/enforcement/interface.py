"""Abstract enforcement backend."""
from abc import ABC, abstractmethod

from ..models.decision import PolicyIntent
from ..models.enforcement import EnforcementResult


class EnforcementBackend(ABC):
    @abstractmethod
    async def enforce(self, intent: PolicyIntent) -> EnforcementResult:
        """Push the policy intent to the dataplane. Returns EnforcementResult."""

    @abstractmethod
    async def revoke(self, rule_id: str) -> EnforcementResult:
        """Remove a previously pushed rule."""

    @abstractmethod
    async def ping(self) -> bool:
        """Return True if backend is reachable."""

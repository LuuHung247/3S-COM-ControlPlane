from pydantic import BaseModel


class EnforcementResult(BaseModel):
    success: bool
    rule_id: str = ""
    backend: str = ""
    response: dict = {}
    error: str = ""

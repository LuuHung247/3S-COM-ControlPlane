from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # LLM Primary
    llm_primary_provider: str = "openai_compat"
    llm_primary_api_key: str = ""
    llm_primary_base_url: str = "https://api.cerebras.ai/v1"
    llm_primary_model: str = "zai-glm-4.7"
    llm_primary_temperature: float = 0.1
    llm_primary_max_tokens: int = 2048

    # LLM Fast
    llm_fast_provider: str = "openai_compat"
    llm_fast_api_key: str = ""
    llm_fast_base_url: str = "https://api.cerebras.ai/v1"
    llm_fast_model: str = "llama3.1-8b"
    llm_fast_temperature: float = 0.0
    llm_fast_max_tokens: int = 512

    llm_timeout_seconds: int = 10

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Postgres
    postgres_url: str = "postgresql+asyncpg://ztuser:ztpass@localhost:5432/zerotrust"

    # ChromaDB
    chroma_host: str = "localhost"
    chroma_port: int = 8000
    chroma_collection_mitre: str = "mitre_attack"
    chroma_collection_decisions: str = "past_decisions"

    # IDS Agent
    ids_agent_url: str = "http://ids-agent:8766"

    # Pipeline filters
    filter_severity_min: int = 2
    filter_dedup_window_seconds: int = 30
    filter_rate_limit_per_minute: int = 30
    filter_whitelist_ips: str = "10.10.6.238,192.168.122.20,192.168.122.21"

    # Safety guardrails
    agent_dry_run: bool = True
    agent_confidence_auto_enforce: float = 0.85
    agent_confidence_notify: float = 0.70
    agent_confidence_hold: float = 0.50
    agent_self_consistency_runs: int = 3
    agent_self_consistency_min_agree: int = 2

    # Blast radius
    safety_max_rules_per_minute: int = 5
    safety_max_total_agent_rules: int = 50
    safety_max_rules_per_ip: int = 3
    safety_per_ip_window_seconds: int = 300
    safety_ttl_min_seconds: int = 60
    safety_ttl_max_seconds: int = 3600

    # Circuit breaker
    safety_circuit_fail_threshold: int = 3
    safety_circuit_halt_seconds: int = 300

    # Observability
    langsmith_api_key: str = ""
    langsmith_project: str = "zerotrust-agent"
    log_level: str = "INFO"

    @property
    def filter_whitelist_ip_list(self) -> list[str]:
        return [ip.strip() for ip in self.filter_whitelist_ips.split(",") if ip.strip()]


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings

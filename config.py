from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # LLM & Embedding
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    embedding_provider: str = "openai"
    embedding_model: str = "text-embedding-3-small"
    shadow_exec_model: str = "gpt-4o-mini"

    # Ed25519 signing — raw 32-byte key, base64-encoded
    memguard_ed25519_private_key: Optional[str] = None

    # ChromaDB
    chroma_host: str = "localhost"
    chroma_port: int = 8000
    chroma_collection: str = "agent_memory"

    # Gateway
    gateway_host: str = "0.0.0.0"
    gateway_port: int = 8080

    # Periodic scanner
    scan_interval_minutes: int = 5
    scan_sample_size: int = 20

    # Audit
    audit_log_file: str = "logs/memguard_audit.jsonl"


settings = Settings()

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-backed settings for the firewall service."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_ENV: str = "development"
    API_KEY: str = ""
    AUDIT_LOG_FILE: str = "firewall_audit.log"
    CORS_ORIGINS: str = "http://localhost:8000,http://127.0.0.1:8000"

    # Policy thresholds
    RISK_THRESHOLD_WARN: int = 30
    RISK_THRESHOLD_BLOCK: int = 60

    # Category weights and caps
    WEIGHT_INSTRUCTION_OVERRIDE: int = 40
    CAP_INSTRUCTION_OVERRIDE: int = 60
    WEIGHT_ROLE_MANIPULATION: int = 30
    CAP_ROLE_MANIPULATION: int = 30
    WEIGHT_SYSTEM_PROMPT_EXTRACTION: int = 40
    CAP_SYSTEM_PROMPT_EXTRACTION: int = 40
    WEIGHT_OBFUSCATION_ENCODING: int = 15
    CAP_OBFUSCATION_ENCODING: int = 30

    # Normalization and egress security
    MAX_DECODING_DEPTH: int = 3
    ALLOWED_HOSTS: str = "example.com,trusted.example.com"
    CANARY_SECRETS: str = ""
    MAX_REQUEST_BYTES: int = 1_000_000
    MAX_TEXT_LENGTH: int = 100_000


settings = Settings()

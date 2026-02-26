"""Configuration for YAGMCP server via environment variables."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Server configuration loaded from environment variables."""

    # Ollama LLM backend
    # Override via OLLAMA_URL environment variable or .env file
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5-coder:7b"
    # Per-call read timeout (seconds) for Ollama requests.
    # Large models (20B+) with big context payloads can take >180s on first load.
    # Increase this if you see "unable to reach language model" with large models.
    ollama_timeout: int = 300

    # Ghidra repos directory (shared volume with ghidra-server)
    repos_dir: str = "/repos"

    # Project cache
    max_cached_programs: int = 5

    # Server
    ghidra_assist_port: int = 8889
    log_level: str = "INFO"

    # Timezone
    tz: str = "America/New_York"

    model_config = {"env_prefix": "", "case_sensitive": False}


settings = Settings()

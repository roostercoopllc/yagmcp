"""Configuration for YAGMCP server via environment variables."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Server configuration loaded from environment variables."""

    # Ollama LLM backend
    ollama_url: str = "http://192.168.0.79:11434"
    ollama_model: str = "qwen2.5-coder:7b"

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

"""Configuration for YAGMCP server via environment variables."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Server configuration loaded from environment variables."""

    # OpenAI-compatible LLM backend (vLLM on the DGX Spark pair).
    # Override via LLM_BASE_URL / LLM_MODEL / LLM_API_KEY environment variables
    # or a .env file. The "/v1" suffix is optional — llm_client normalizes it.
    llm_base_url: str = "http://192.168.0.25:8001/v1"
    llm_model: str = "RedHatAI/Llama-4-Maverick-17B-128E-Instruct-quantized.w4a16"
    # Empty = no Authorization header, which is correct when vLLM runs
    # without --api-key.
    llm_api_key: str = ""
    # Per-call read timeout (seconds). Large models with big decompilation
    # payloads can take >180s, and a tensor-parallel model adds a network hop.
    llm_timeout_seconds: int = 300
    # Cap on generated tokens. vLLM otherwise defaults to the whole remaining
    # context window, which on a 32K model means very long generations.
    llm_max_tokens: int = 2048

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

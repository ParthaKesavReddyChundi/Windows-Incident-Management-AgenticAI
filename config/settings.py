"""
Central application settings.

All configuration is read from environment variables (and optionally a .env file).
Values are validated by pydantic-settings. The project root is derived
from this file's location so the application works regardless of where
the project folder is placed.
"""
from __future__ import annotations

from pathlib import Path
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# The project root is two levels up from config/settings.py
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Application settings loaded from environment / .env file."""

    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ────────────────────────────────────────────────────────────
    app_env: str = "development"
    app_host: str = "127.0.0.1"
    app_port: int = 8000
    app_log_level: str = "INFO"

    # ── CORS ───────────────────────────────────────────────────────────────────
    cors_origins: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

    # ── Telemetry ──────────────────────────────────────────────────────────────
    telemetry_interval_seconds: float = 5.0
    telemetry_queue_max_size: int = 200

    # ── Anomaly Detection ──────────────────────────────────────────────────────
    anomaly_threshold: float = 0.5
    model_path: Path = PROJECT_ROOT / "models" / "autoencoder.pt"

    # ── Ollama ─────────────────────────────────────────────────────────────────
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.2:3b"

    # ── RAG ────────────────────────────────────────────────────────────────────
    vector_store_path: Path = PROJECT_ROOT / "vector_store"
    rag_sources_path: Path = PROJECT_ROOT / "rag" / "sources"
    rag_collection_name: str = "windows_knowledge"
    rag_top_k: int = 5
    embedding_model: str = "all-MiniLM-L6-v2"

    # ── Database ───────────────────────────────────────────────────────────────
    database_url: str = f"sqlite+aiosqlite:///{PROJECT_ROOT / 'database' / 'incidents.db'}"

    # ── Paths (derived from project root — never hardcoded) ───────────────────
    @property
    def logs_dir(self) -> Path:
        return PROJECT_ROOT / "logs"

    @property
    def reports_dir(self) -> Path:
        return PROJECT_ROOT / "reports"

    @property
    def data_raw_dir(self) -> Path:
        return PROJECT_ROOT / "data" / "raw"

    @property
    def data_processed_dir(self) -> Path:
        return PROJECT_ROOT / "data" / "processed"

    @property
    def data_simulated_dir(self) -> Path:
        return PROJECT_ROOT / "data" / "simulated"

    @property
    def models_dir(self) -> Path:
        return PROJECT_ROOT / "models"

    @field_validator("app_log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid:
            raise ValueError(f"log_level must be one of {valid}")
        return upper


# ── Singleton ──────────────────────────────────────────────────────────────────
settings = Settings()

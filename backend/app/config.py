from __future__ import annotations

import os
from dataclasses import dataclass


def _csv(value: str | None) -> list[str]:
    return [item.strip().rstrip("/") for item in (value or "").split(",") if item.strip()]


def _positive_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    database_url: str
    allowed_origins: list[str]
    jwt_secret: str
    environment: str
    log_level: str
    max_frame_bytes: int
    heartbeat_expiry_seconds: int

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"


def load_settings() -> Settings:
    environment = os.getenv("ENVIRONMENT", "development").strip() or "development"
    default_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://aalimbaba.github.io",
    ]
    return Settings(
        database_url=os.getenv("DATABASE_URL") or os.getenv("GLASSWALL_DB_URL") or "sqlite:///./glasswall-dev.db",
        allowed_origins=_csv(os.getenv("ALLOWED_ORIGINS")) or default_origins,
        jwt_secret=os.getenv("JWT_SECRET", ""),
        environment=environment,
        log_level=(os.getenv("LOG_LEVEL", "INFO").strip() or "INFO").upper(),
        max_frame_bytes=_positive_int("MAX_FRAME_BYTES", 2_000_000),
        heartbeat_expiry_seconds=_positive_int("HEARTBEAT_EXPIRY_SECONDS", 60),
    )

"""Runtime configuration, read once from the environment."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    secret: str
    token_ttl: int
    rate_limit: int
    rate_window: int

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            secret=os.environ.get("KEYSTONE_SECRET", "dev-secret-change-me"),
            token_ttl=int(os.environ.get("KEYSTONE_TOKEN_TTL", "3600")),
            rate_limit=int(os.environ.get("KEYSTONE_RATE_LIMIT", "60")),
            rate_window=int(os.environ.get("KEYSTONE_RATE_WINDOW", "60")),
        )


settings = Settings.from_env()

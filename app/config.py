import os
from functools import lru_cache
from pydantic import BaseModel, Field


class Settings(BaseModel):
    """Central place for runtime configuration pulled from env vars."""

    db_host: str = Field(default="localhost")
    db_port: int = Field(default=3306)
    db_user: str = Field(default="root")
    db_password: str = Field(default="rootpassword")
    db_name: str = Field(default="enc_poc")

    vault_addr: str = Field(default="http://localhost:8200")
    vault_token: str = Field(default="root")
    vault_transit_key: str = Field(default="pii-master")

    class Config:
        frozen = True


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Read environment variables once and memoize the result."""
    return Settings(
        db_host=os.getenv("DB_HOST", "localhost"),
        db_port=int(os.getenv("DB_PORT", "3306")),
        db_user=os.getenv("DB_USER", "root"),
        db_password=os.getenv("DB_PASSWORD", "rootpassword"),
        db_name=os.getenv("DB_NAME", "enc_poc"),
        vault_addr=os.getenv("VAULT_ADDR", "http://localhost:8200"),
        vault_token=os.getenv("VAULT_TOKEN", "root"),
        vault_transit_key=os.getenv("VAULT_TRANSIT_KEY", "pii-master"),
    )

"""
Configuration is read from the environment exactly once, at process start,
into a frozen dataclass. Every other module imports `Config` and the
running instance, never `os.environ`. This is the "explicit environment
wiring" rule: no smart defaults, no late-binding lookups, no surprises
six months from now when an env var quietly stops being read.
"""
import os
from dataclasses import dataclass
from abstract_security import *
from abstract_database import *
class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Config:
    db_dsn: str
    secret_key: str
    session_cookie_name: str
    session_lifetime_seconds: int
    registration_open: bool
    password_min_length: int
    argon2_time_cost: int
    argon2_memory_cost_kib: int
    argon2_parallelism: int


def _required(name):
    val = get_env_value(name)
    if not val:
        raise ConfigError("missing required env var: " + name)
    return val


def _int(name, default):
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        raise ConfigError("env var " + name + " must be an integer, got: " + raw)


def _bool(name, default):
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def load_config():
    """Build Config from the current environment. Call once."""
    db_dsn= _required("AUTH_DB_DSN")
    connectionManager(dbUrl=db_dsn)
    return Config(
        db_dsn=db_dsn,
        secret_key=_required("AUTH_SECRET_KEY"),
        session_cookie_name=os.environ.get("AUTH_SESSION_COOKIE", "auth_session"),
        session_lifetime_seconds=_int("AUTH_SESSION_LIFETIME", 60 * 60 * 12),
        registration_open=_bool("AUTH_REGISTRATION_OPEN", False),
        password_min_length=_int("AUTH_PASSWORD_MIN_LENGTH", 10),
        argon2_time_cost=_int("AUTH_ARGON2_TIME_COST", 3),
        argon2_memory_cost_kib=_int("AUTH_ARGON2_MEMORY_KIB", 64 * 1024),
        argon2_parallelism=_int("AUTH_ARGON2_PARALLELISM", 1),
    )

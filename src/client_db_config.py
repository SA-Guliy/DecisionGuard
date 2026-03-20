from __future__ import annotations

import os
from urllib.parse import quote_plus


def _env(name: str, default: str = "") -> str:
    return str(os.getenv(name, default) or "").strip()


def client_db_name() -> str:
    return _env("CLIENT_DB_NAME", _env("PG_EXPECTED_DB", "client_db"))


def client_db_host() -> str:
    return _env("CLIENT_DB_HOST", "")


def client_db_port() -> str:
    return _env("CLIENT_DB_PORT", "5432")


def client_db_service(role: str) -> str:
    role_norm = str(role or "").strip().lower()
    if role_norm == "loader":
        return _env("CLIENT_DB_LOADER_SERVICE", "client_loader")
    if role_norm == "admin":
        return _env("CLIENT_DB_ADMIN_SERVICE", "client_admin")
    return _env("CLIENT_DB_APP_SERVICE", "client_app")


def client_db_user(role: str) -> str:
    role_norm = str(role or "").strip().lower()
    if role_norm == "loader":
        return _env("CLIENT_DB_LOADER_USER", _env("CLIENT_DB_USER", client_db_service("loader")))
    if role_norm == "admin":
        return _env("CLIENT_DB_ADMIN_USER", _env("CLIENT_DB_USER", client_db_service("admin")))
    return _env("CLIENT_DB_APP_USER", _env("CLIENT_DB_USER", client_db_service("app")))


def client_db_password(role: str) -> str:
    role_norm = str(role or "").strip().lower()
    if role_norm == "loader":
        return _env("CLIENT_DB_LOADER_PASS", _env("CLIENT_DB_PASS", ""))
    if role_norm == "admin":
        return _env("CLIENT_DB_ADMIN_PASS", _env("CLIENT_DB_PASS", ""))
    return _env("CLIENT_DB_APP_PASS", _env("CLIENT_DB_PASS", ""))


def expected_db() -> str:
    return client_db_name()


def expected_user(role: str) -> str:
    return client_db_user(role)


def using_direct_db_credentials() -> bool:
    return bool(client_db_host())


def _direct_pg_url(role: str) -> str:
    host = client_db_host()
    if not host:
        raise RuntimeError("CLIENT_DB_HOST is empty")
    user = client_db_user(role)
    if not user:
        raise RuntimeError(f"Missing DB user for role '{role}'")
    password = client_db_password(role)
    db_name = client_db_name()
    port = client_db_port()
    user_enc = quote_plus(user)
    pwd_enc = quote_plus(password) if password else ""
    auth = f"{user_enc}:{pwd_enc}@" if pwd_enc else f"{user_enc}@"
    return f"postgresql://{auth}{host}:{port}/{db_name}"


def resolve_pg_url(*, role: str, fallback_service: str = "", explicit_dsn: str = "") -> str:
    if explicit_dsn:
        return explicit_dsn
    if role == "loader":
        env_dsn = _env("PG_DSN_LOADER")
        if env_dsn:
            return env_dsn
    if role == "admin":
        env_dsn = _env("PG_DSN_ADMIN")
        if env_dsn:
            return env_dsn
    env_dsn = _env("PG_DSN")
    if env_dsn and role == "app":
        return env_dsn
    database_url = _env("DATABASE_URL")
    if database_url and role == "app":
        return database_url
    if using_direct_db_credentials():
        return _direct_pg_url(role)
    service = fallback_service or client_db_service(role)
    return f"postgresql:///?service={service}"


def runtime_db_env(role: str) -> dict[str, str]:
    role_norm = str(role or "").strip().lower()
    if using_direct_db_credentials():
        env: dict[str, str] = {
            "PGSERVICE": "",
            "PG_EXPECTED_DB": expected_db(),
        }
        if role_norm == "loader":
            env["PG_DSN_LOADER"] = resolve_pg_url(role="loader")
            env["PG_DSN"] = ""
        elif role_norm == "admin":
            env["PG_DSN_ADMIN"] = resolve_pg_url(role="admin")
            env["PG_DSN"] = ""
        else:
            env["PG_DSN"] = resolve_pg_url(role="app")
        return env
    if role_norm == "loader":
        return {"PGSERVICE": client_db_service("loader"), "PG_DSN": "", "PG_EXPECTED_DB": expected_db()}
    if role_norm == "admin":
        return {"PGSERVICE": client_db_service("admin"), "PG_DSN": "", "PG_EXPECTED_DB": expected_db()}
    return {"PGSERVICE": client_db_service("app"), "PG_DSN": "", "PG_EXPECTED_DB": expected_db()}


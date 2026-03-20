#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import sys
import traceback
from pathlib import Path

from sqlalchemy import create_engine, text

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.client_db_config import client_db_service, expected_db, resolve_pg_url

_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")


def _safe_ident(value: str) -> str:
    if not _IDENT.match(value):
        raise SystemExit("unsafe identifier in admin ACL script")
    return value


def _log(path: Path, msg: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(msg + "\n")


def _is_local_addr(addr: str | None) -> bool:
    if addr is None:
        return True  # unix socket
    return addr in {"127.0.0.1", "::1"}


def _owner_roles(conn) -> list[str]:
    rows = conn.execute(
        text(
            """
            SELECT DISTINCT r.rolname
            FROM pg_namespace n
            JOIN pg_roles r ON n.nspowner = r.oid
            WHERE n.nspname IN ('raw', 'step1')
            ORDER BY 1
            """
        )
    ).fetchall()
    return [_safe_ident(r[0]) for r in rows]


def main() -> None:
    parser = argparse.ArgumentParser(description="Admin-only: normalize default ACLs to project policy")
    parser.add_argument("--pgservice", default=client_db_service("admin"))
    parser.add_argument("--expected-db", default=expected_db())
    parser.add_argument("--allowed-admin-users", default=f"postgres,{client_db_service('admin')}")
    parser.add_argument("--allow-nonlocal", action="store_true")
    parser.add_argument("--log-file", default="data/logs/admin_fix_default_acls.log")
    args = parser.parse_args()

    log_file = Path(args.log_file)
    engine = create_engine(resolve_pg_url(role="admin", fallback_service=args.pgservice))
    allowed_users = {u.strip() for u in args.allowed_admin_users.split(",") if u.strip()}
    app_role = _safe_ident(os.getenv("CLIENT_DB_APP_USER", "client_app"))
    loader_role = _safe_ident(os.getenv("CLIENT_DB_LOADER_USER", "client_loader"))
    agent_ro_role = _safe_ident(os.getenv("CLIENT_DB_AGENT_RO_USER", "client_agent_ro"))

    try:
        with engine.begin() as conn:
            info = conn.execute(
                text(
                    """
                    SELECT current_database() AS db,
                           inet_server_addr()::text AS addr,
                           inet_server_port() AS port,
                           session_user::text AS session_user,
                           current_user::text AS current_user,
                           current_role::text AS current_role
                    """
                )
            ).mappings().first()
            if info is None:
                raise SystemExit("admin acl fix failed: preflight unavailable")

            db = str(info["db"])
            addr = info["addr"]
            cur_user = str(info["current_user"])
            if db != args.expected_db:
                raise SystemExit("admin acl fix failed: unexpected database")
            if not args.allow_nonlocal and not _is_local_addr(addr):
                raise SystemExit("admin acl fix failed: non-local connection blocked")
            if cur_user not in allowed_users:
                raise SystemExit("admin acl fix failed: current_user not allowed")

            print(
                f"preflight ok: db={db} addr={addr or 'socket'} port={info['port']} "
                f"session_user={info['session_user']} current_user={cur_user} current_role={info['current_role']}"
            )

            owner_roles = _owner_roles(conn)
            _log(log_file, f"owner_roles={owner_roles}")

            for owner in owner_roles:
                # Remove agent_ro defaults completely for raw/step1.
                conn.execute(text(f"ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA raw REVOKE ALL ON TABLES FROM {agent_ro_role}"))
                conn.execute(text(f"ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA step1 REVOKE ALL ON TABLES FROM {agent_ro_role}"))
                conn.execute(text(f"ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA raw REVOKE ALL ON SEQUENCES FROM {agent_ro_role}"))
                conn.execute(text(f"ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA step1 REVOKE ALL ON SEQUENCES FROM {agent_ro_role}"))
                conn.execute(text(f"ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA raw REVOKE ALL ON FUNCTIONS FROM {agent_ro_role}"))
                conn.execute(text(f"ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA step1 REVOKE ALL ON FUNCTIONS FROM {agent_ro_role}"))

                # Re-assert runtime defaults.
                conn.execute(text(f"ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA raw GRANT SELECT ON TABLES TO {app_role}"))
                conn.execute(text(f"ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA step1 GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {app_role}"))
                conn.execute(text(f"ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA raw GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {loader_role}"))
                conn.execute(text(f"ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA raw GRANT USAGE, SELECT ON SEQUENCES TO {app_role}"))
                conn.execute(text(f"ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA step1 GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO {app_role}"))
                conn.execute(text(f"ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA raw GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO {loader_role}"))

        print("ok: default ACL policy normalized")
    except SystemExit:
        raise
    except Exception:
        _log(log_file, traceback.format_exc())
        raise SystemExit(f"admin acl fix failed. See {log_file}")


if __name__ == "__main__":
    main()

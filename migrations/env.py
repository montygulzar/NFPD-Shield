"""Alembic environment for NFPD Shield.

The URL is resolved in this order:

1. ``-x url=...`` passed on the Alembic command line.
2. ``DATABASE_URL`` from the process environment (the normal path).
3. ``sqlalchemy.url`` set programmatically (used by ``ShieldBot.run_migrations``).

An async driver URL is converted to its sync equivalent for migrations, because
Alembic's DDL runs synchronously. That keeps a single DATABASE_URL in the
environment file.
"""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shield.db.models import Base  # noqa: E402
from shield.db.urls import to_sync_url  # noqa: E402

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata

def resolve_url() -> str:
    cli = context.get_x_argument(as_dictionary=True).get("url")
    url = cli or os.environ.get("DATABASE_URL") or config.get_main_option("sqlalchemy.url")
    if not url:
        raise SystemExit(
            "No database URL. Set DATABASE_URL in the environment, or pass "
            "-x url=postgresql+asyncpg://user:pass@host:5432/dbname"
        )
    return to_sync_url(url)


def run_migrations_offline() -> None:
    context.configure(
        url=resolve_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = resolve_url()
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

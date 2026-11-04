"""Database URL handling, shared by the application and Alembic.

Shield accepts one ``DATABASE_URL`` and needs it in two shapes:

* the **async** driver (asyncpg) for everything the bot does at runtime, and
* a **sync** driver (psycopg2) for Alembic, whose DDL path is synchronous.

Keeping both conversions here means the application and the migration
environment can never disagree about what a given DSN means. The module imports
nothing but the standard library, so it is safe to use from ``shield/config.py``
and from ``migrations/env.py`` alike.
"""

from __future__ import annotations

from urllib.parse import quote

#: PostgreSQL URLs with no driver named. Accepted and upgraded, because every
#: other tool on a shared host writes this form.
BARE_PG_SCHEMES = frozenset({"postgresql", "postgres"})

#: Async drivers Shield runs on.
ASYNC_PG_SCHEMES = frozenset({"postgresql+asyncpg", "postgres+asyncpg"})

#: Scheme -> synchronous driver for Alembic.
#:
#: The driverless entries are load-bearing: SQLAlchemy's default dialect for a
#: bare ``postgresql://`` URL is psycopg **v3**, which Shield does not install,
#: so leaving it unmapped fails with ``No module named 'psycopg'``. Pinning it
#: to psycopg2 keeps the one installed sync driver in use.
SYNC_DRIVERS: dict[str, str] = {
    "postgresql+asyncpg": "postgresql+psycopg2",
    "postgres+asyncpg": "postgresql+psycopg2",
    "postgresql": "postgresql+psycopg2",
    "postgres": "postgresql+psycopg2",
    "sqlite+aiosqlite": "sqlite",
}


def split_scheme(url: str) -> tuple[str, str]:
    """``("postgresql+asyncpg", "user@host/db")``, or ``("", url)`` if unparseable."""
    scheme, separator, remainder = url.partition("://")
    if not separator:
        return "", url
    return scheme.lower(), remainder


def to_async_url(url: str) -> str:
    """Upgrade a driverless PostgreSQL URL to asyncpg; leave anything else alone.

    The whole data layer is async, so the driver is not a choice the operator
    needs to express - only the host, credentials and database are.
    """
    scheme, remainder = split_scheme(url)
    if scheme in BARE_PG_SCHEMES:
        return f"postgresql+asyncpg://{remainder}"
    return url


def to_sync_url(url: str) -> str:
    """Rewrite a URL to its synchronous equivalent for Alembic."""
    scheme, remainder = split_scheme(url)
    sync_driver = SYNC_DRIVERS.get(scheme)
    if sync_driver is None:
        return url
    converted = f"{sync_driver}://{remainder}"
    # asyncpg spells it ?ssl=require; psycopg2 wants ?sslmode=require.
    return converted.replace("?ssl=", "?sslmode=").replace("&ssl=", "&sslmode=")


def build_url(
    *, user: str, password: str, host: str, database: str, port: str | int = 5432
) -> str:
    """Assemble an asyncpg URL from discrete parts, percent-encoding credentials.

    An unescaped ``@`` or ``/`` in a password silently produces a URL that points
    somewhere else entirely, so encoding is not optional.
    """
    return (
        f"postgresql+asyncpg://{quote(user, safe='')}:{quote(password, safe='')}"
        f"@{host}:{port}/{quote(database, safe='')}"
    )

"""Database URL conversion shared by the application and Alembic.

These conversions are the reason one ``DATABASE_URL`` can serve both the async
runtime and Alembic's synchronous DDL path. Getting the sync mapping wrong is
not a cosmetic failure: a bare ``postgresql://`` URL resolves to psycopg v3,
which Shield does not install, so migrations abort at container start.
"""

from __future__ import annotations

import pytest

from shield.db.urls import (
    ASYNC_PG_SCHEMES,
    BARE_PG_SCHEMES,
    build_url,
    split_scheme,
    to_async_url,
    to_sync_url,
)


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("postgresql://u:p@nfpd-postgres:5432/db", "postgresql+asyncpg://u:p@nfpd-postgres:5432/db"),
        ("postgres://u:p@h/db", "postgresql+asyncpg://u:p@h/db"),
        ("POSTGRESQL://u:p@h/db", "postgresql+asyncpg://u:p@h/db"),
    ],
)
def test_driverless_urls_are_upgraded_to_asyncpg(given: str, expected: str):
    assert to_async_url(given) == expected


@pytest.mark.parametrize(
    "given",
    [
        "postgresql+asyncpg://u:p@h/db",
        "postgresql+psycopg2://u:p@h/db",
        "sqlite+aiosqlite:///:memory:",
        "not-a-url",
        "",
    ],
)
def test_other_urls_are_left_alone(given: str):
    assert to_async_url(given) == given


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("postgresql+asyncpg://u:p@h/db", "postgresql+psycopg2://u:p@h/db"),
        ("postgres+asyncpg://u:p@h/db", "postgresql+psycopg2://u:p@h/db"),
        # The case that broke the container entrypoint: without this mapping
        # SQLAlchemy picks psycopg v3 and Alembic fails to import it.
        ("postgresql://u:p@h/db", "postgresql+psycopg2://u:p@h/db"),
        ("postgres://u:p@h/db", "postgresql+psycopg2://u:p@h/db"),
        ("sqlite+aiosqlite:///x.db", "sqlite:///x.db"),
    ],
)
def test_sync_conversion(given: str, expected: str):
    assert to_sync_url(given) == expected


def test_sync_conversion_translates_the_tls_parameter():
    """asyncpg spells it ssl=; psycopg2 only understands sslmode=."""
    assert to_sync_url("postgresql://u:p@h/db?ssl=require") == (
        "postgresql+psycopg2://u:p@h/db?sslmode=require"
    )
    assert to_sync_url("postgresql+asyncpg://u:p@h/db?a=1&ssl=verify-full") == (
        "postgresql+psycopg2://u:p@h/db?a=1&sslmode=verify-full"
    )


def test_async_and_bare_schemes_do_not_overlap():
    """A longest-match bug here would silently route asyncpg URLs wrongly."""
    assert not (ASYNC_PG_SCHEMES & BARE_PG_SCHEMES)
    assert to_sync_url("postgresql+asyncpg://u@h/db").startswith("postgresql+psycopg2://")


@pytest.mark.parametrize("given", ["mysql://u@h/db", "redis://h:6379/0", "no-scheme"])
def test_unknown_schemes_pass_through_sync_conversion(given: str):
    assert to_sync_url(given) == given


def test_split_scheme():
    assert split_scheme("postgresql+asyncpg://rest/of/it") == ("postgresql+asyncpg", "rest/of/it")
    assert split_scheme("bare") == ("", "bare")


def test_build_url_percent_encodes_credentials():
    url = build_url(
        user="nfpd shield", password="p@ss/w0rd:x", host="nfpd-postgres", database="nfpd_shield"
    )
    assert url == (
        "postgresql+asyncpg://nfpd%20shield:p%40ss%2Fw0rd%3Ax@nfpd-postgres:5432/nfpd_shield"
    )


def test_build_url_round_trips_through_the_sync_conversion():
    url = build_url(user="u", password="p", host="nfpd-postgres", database="db", port=5433)
    assert to_sync_url(url) == "postgresql+psycopg2://u:p@nfpd-postgres:5433/db"

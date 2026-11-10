"""Drop schema that no code ever used.

``audit_cursors`` was created for audit-log replay tracking that was never
wired up (consumed entries are tracked in memory), and
``guild_settings.min_account_age_hours`` was never read. Unused schema is a
trap for the next reader, so both go.

Revision ID: 0002_drop_unused
Revises: 0001_initial
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

import shield.db.models

revision: str = "0002_drop_unused"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_table("audit_cursors")
    op.drop_column("guild_settings", "min_account_age_hours")


def downgrade() -> None:
    op.add_column(
        "guild_settings",
        sa.Column("min_account_age_hours", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_table(
        "audit_cursors",
        sa.Column("guild_id", sa.BigInteger(), autoincrement=False, nullable=False),
        sa.Column("audit_action", sa.String(length=64), nullable=False),
        sa.Column("last_entry_id", sa.BigInteger(), nullable=False),
        sa.Column(
            "updated_at",
            shield.db.models.UTCDateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("guild_id", "audit_action"),
    )

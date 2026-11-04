"""Configuration validation: boot must fail loudly and specifically."""

from __future__ import annotations

import pytest

from shield.config import ConfigError, load_config, load_dotenv
from shield.constants import ShieldMode
from tests.conftest import FAKE_DISCORD_TOKEN

GOOD = {
    "DISCORD_TOKEN": FAKE_DISCORD_TOKEN,
    "APPLICATION_ID": "123456789012345678",
    "OWNERID": "123456789012345679",
    "DATABASE_URL": "postgresql+asyncpg://u:p@127.0.0.1:5432/db",
}


def load(**overrides: str):  # noqa: ANN201
    env = dict(GOOD)
    env.update(overrides)
    return load_config(env, allow_dotenv=False)


def errors_for(**overrides: str) -> list[str]:
    env = dict(GOOD)
    for key, value in overrides.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    with pytest.raises(ConfigError) as info:
        load_config(env, allow_dotenv=False)
    return info.value.errors


def test_valid_config_defaults_to_alert_only():
    config = load()
    assert config.default_mode is ShieldMode.ALERT_ONLY
    assert config.owner_id == 123456789012345679
    assert config.is_operator(config.owner_id)
    assert config.run_migrations_on_boot is True


def test_ownerid_aliases_are_accepted():
    env = dict(GOOD)
    del env["OWNERID"]
    env["OWNER_ID"] = "123456789012345679"
    assert load_config(env, allow_dotenv=False).owner_id == 123456789012345679
    del env["OWNER_ID"]
    env["SHIELD_OWNER_ID"] = "123456789012345679"
    assert load_config(env, allow_dotenv=False).owner_id == 123456789012345679


def test_missing_required_values_are_all_reported_at_once():
    found = errors_for(DISCORD_TOKEN=None, APPLICATION_ID=None, OWNERID=None, DATABASE_URL=None)
    assert len(found) == 4
    assert any("DISCORD_TOKEN is required" in e for e in found)
    assert any("OWNERID is required" in e for e in found)


def test_placeholder_token_is_rejected():
    assert any("placeholder" in e for e in errors_for(DISCORD_TOKEN="REPLACE_ME_WITH_BOT_TOKEN"))


def test_token_with_bot_prefix_is_rejected():
    assert any("'Bot ' prefix" in e for e in errors_for(DISCORD_TOKEN="Bot " + GOOD["DISCORD_TOKEN"]))


def test_malformed_token_is_rejected():
    assert any("does not look like" in e for e in errors_for(DISCORD_TOKEN="not-a-token"))


@pytest.mark.parametrize("value", ["<@123456789012345678>", "abc", "'123456789012345678'", "123"])
def test_invalid_snowflakes_are_rejected(value: str):
    assert any("APPLICATION_ID" in e for e in errors_for(APPLICATION_ID=value))


def test_sync_driver_is_rejected_with_actionable_message():
    found = errors_for(DATABASE_URL="postgresql://u:p@127.0.0.1:5432/db")
    assert any("asyncpg" in e for e in found)


def test_remote_database_requires_tls():
    found = errors_for(DATABASE_URL="postgresql+asyncpg://u:p@db.example.com:5432/db")
    assert any("without TLS" in e for e in found)


def test_remote_database_with_ssl_is_accepted():
    config = load(DATABASE_URL="postgresql+asyncpg://u:p@db.example.com:5432/db?ssl=require")
    assert config.database.requires_tls and config.database.tls_configured


def test_database_url_missing_dbname_is_rejected():
    assert any("database name" in e for e in errors_for(DATABASE_URL="postgresql+asyncpg://u:p@127.0.0.1:5432/"))


def test_contradictory_default_mode_lockdown():
    assert any("contradictory" in e for e in errors_for(DEFAULT_MODE="lockdown"))


def test_enforce_without_member_intent_is_contradictory():
    found = errors_for(DEFAULT_MODE="enforce", ENABLE_GUILD_MEMBERS="false")
    assert any("ENABLE_GUILD_MEMBERS=false is incompatible" in e for e in found)


def test_audit_delay_must_be_smaller_than_window():
    found = errors_for(AUDIT_CORRELATION_DELAY="30", AUDIT_CORRELATION_WINDOW="10")
    assert any("must be smaller than" in e for e in found)


def test_event_retention_cannot_exceed_incident_retention():
    found = errors_for(RETENTION_EVENT_DAYS="400", RETENTION_INCIDENT_DAYS="30")
    assert any("must not outlive" in e for e in found)


def test_shard_ids_require_shard_count():
    assert any("SHARD_COUNT is not" in e for e in errors_for(SHARD_IDS="0,1"))


def test_shard_id_out_of_range():
    found = errors_for(SHARD_COUNT="2", SHARD_IDS="0,5")
    assert any("outside the range" in e for e in found)


def test_bad_encryption_key_is_rejected():
    assert any("Fernet" in e or "base64" in e for e in errors_for(SNAPSHOT_ENCRYPTION_KEY="short"))


def test_valid_encryption_key_is_accepted():
    from cryptography.fernet import Fernet

    key = Fernet.generate_key().decode()
    assert load(SNAPSHOT_ENCRYPTION_KEY=key).snapshot_encryption_key == key


def test_bad_boolean_is_rejected():
    assert any("not a boolean" in e for e in errors_for(GLOBAL_DRY_RUN="maybe"))


def test_instance_id_charset_is_enforced():
    assert any("INSTANCE_ID" in e for e in errors_for(INSTANCE_ID="bad id!"))


def test_redacted_config_contains_no_secrets():
    config = load(SNAPSHOT_ENCRYPTION_KEY="")
    redacted = config.redacted()
    rendered = str(redacted)
    assert GOOD["DISCORD_TOKEN"] not in rendered
    assert redacted["discord_token"] == "***redacted***"
    assert ":p@" not in redacted["database_url"]
    assert "***" in redacted["database_url"]


def test_safe_url_masks_password():
    config = load()
    assert "***" in config.database.safe_url()
    assert ":p@" not in config.database.safe_url()


def test_dotenv_parser_is_systemd_compatible(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_text(
        "\n".join(
            [
                "# a comment",
                "",
                "SIMPLE=value",
                'QUOTED="quoted value"',
                "export EXPORTED=exported",
                "NOT_EXPANDED=$HOME/literal",
                "EMPTY=",
            ]
        ),
        encoding="utf-8",
    )
    values = load_dotenv(path)
    assert values["SIMPLE"] == "value"
    assert values["QUOTED"] == "quoted value"
    assert values["EXPORTED"] == "exported"
    assert values["NOT_EXPANDED"] == "$HOME/literal"  # no shell expansion
    assert values["EMPTY"] == ""

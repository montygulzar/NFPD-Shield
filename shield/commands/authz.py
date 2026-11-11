"""Server-side authorization for slash commands.

Discord's command-permission UI is advisory: a guild administrator can edit it,
and an interaction can be forged in no supported way but *can* arrive from a
user whose Discord-side permissions changed since the command tree was synced.
Shield therefore re-checks authority on the server for **every** invocation and
writes the result to ``command_audit``.

Authority ladder (highest first):

``OWNER``
    The Discord guild owner. Final authority for that guild.
``DELEGATE``
    A user (or holder of a role) explicitly granted the ``manage_shield`` trust
    scope by the owner. Can tune Shield but cannot flip protection on/off,
    cannot apply a restore and cannot pause protection.
``OPERATOR``
    The global bot operator from ``OWNERID``. Diagnostics and support scope
    only - it is **not** exempt from any guild's protections and cannot change
    a guild's protection state.
``NONE``
    Everyone else, including guild administrators and Manage Guild holders.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any

import discord

from shield.constants import TrustScope
from shield.db.repositories import UnitOfWork
from shield.observability.correlation import new_correlation_id
from shield.observability.logging import get_logger

log = get_logger("authz")


class Authority(enum.IntEnum):
    NONE = 0
    OPERATOR = 1
    DELEGATE = 2
    OWNER = 3


@dataclass(frozen=True, slots=True)
class AuthResult:
    authority: Authority
    allowed: bool
    reason: str

    @property
    def label(self) -> str:
        return self.authority.name.lower()


#: What each command family requires.
REQUIRE_OWNER = Authority.OWNER
REQUIRE_DELEGATE = Authority.DELEGATE
REQUIRE_OPERATOR = Authority.OPERATOR


def _is_guild_owner(interaction: discord.Interaction) -> bool:
    guild = interaction.guild
    return guild is not None and int(getattr(guild, "owner_id", 0) or 0) == int(
        interaction.user.id
    )


async def resolve_authority(interaction: discord.Interaction) -> Authority:
    """Determine the caller's authority for *this* guild."""
    guild = interaction.guild
    user = interaction.user
    if guild is None or user is None:
        return Authority.NONE

    if int(getattr(guild, "owner_id", 0) or 0) == int(user.id):
        return Authority.OWNER

    bot = interaction.client
    # Delegate: explicit manage_shield trust scope, user or role.
    try:
        async with bot.db.begin() as session:
            uow = UnitOfWork(session)
            entries = await uow.trust.list_for_guild(guild.id)
    except Exception:  # noqa: BLE001 - database outage
        entries = []
    role_ids = {int(r.id) for r in getattr(user, "roles", ()) or ()}
    for entry in entries:
        scopes = {str(s) for s in (entry.scopes or ())}
        if TrustScope.MANAGE_SHIELD.value not in scopes:
            continue
        if entry.entity_type == "user" and int(entry.entity_id) == int(user.id):
            return Authority.DELEGATE
        if entry.entity_type == "role" and int(entry.entity_id) in role_ids:
            return Authority.DELEGATE

    config = getattr(bot, "shield_config", None)
    if config is not None and config.is_operator(int(user.id)):
        # With OPERATOR_FULL_AUTHORITY the operator acts with owner authority in
        # every guild. Off (the default) they keep diagnostics-only scope.
        if getattr(config, "operator_full_authority", False):
            return Authority.OWNER
        return Authority.OPERATOR
    return Authority.NONE


async def authorize(
    interaction: discord.Interaction,
    required: Authority,
    *,
    command: str,
    parameters: dict[str, Any] | None = None,
) -> AuthResult:
    """Check authority, record the attempt, and return the verdict.

    Also enforces guild-only usage. Every privileged attempt - allowed or
    denied - lands in ``command_audit`` with the caller, the parameters and the
    reason, which is the audit trail for operator access.
    """
    correlation_id = new_correlation_id("cmd")
    guild = interaction.guild
    if guild is None:
        result = AuthResult(Authority.NONE, False, "Shield commands are guild-only.")
        await _record(interaction, command, result, parameters, correlation_id, guild_id=None)
        return result

    config = getattr(interaction.client, "shield_config", None)
    if config is not None and not config.guild_approved(guild.id):
        result = AuthResult(
            Authority.NONE, False, "This server is not approved to use NFPD Shield."
        )
        await _record(interaction, command, result, parameters, correlation_id, guild_id=guild.id)
        return result

    authority = await resolve_authority(interaction)
    allowed = authority >= required

    # Operators may never change a guild's protection posture.
    if allowed and authority is Authority.OPERATOR and required > Authority.OPERATOR:
        allowed = False

    if allowed and authority is Authority.OWNER and not _is_guild_owner(interaction):
        reason = "authorized as bot operator (OPERATOR_FULL_AUTHORITY)"
    elif allowed:
        reason = f"authorized as {authority.name.lower()}"
    elif authority is Authority.OPERATOR:
        reason = (
            "The global bot operator has diagnostics scope only. "
            "The guild owner must run this command."
        )
    elif required is Authority.OWNER:
        reason = (
            "Only the Discord **guild owner** may change Shield's protection state. "
            "Administrator and Manage Guild deliberately grant no Shield authority, "
            "because those are exactly the permissions an attacker abuses."
        )
    else:
        reason = (
            "You need the `manage_shield` trust scope. Ask the guild owner to run "
            "`/shield whitelist add` with scope `manage_shield`."
        )

    result = AuthResult(authority, allowed, reason)
    await _record(interaction, command, result, parameters, correlation_id, guild_id=guild.id)
    if not allowed:
        log.warning(
            "command denied",
            extra={
                "guild_id": guild.id,
                "user_id": int(interaction.user.id),
                "command": command,
                "authority": authority.name,
                "required": required.name,
                "correlation_id": correlation_id,
            },
        )
    return result


async def _record(
    interaction: discord.Interaction,
    command: str,
    result: AuthResult,
    parameters: dict[str, Any] | None,
    correlation_id: str,
    *,
    guild_id: int | None,
) -> None:
    bot = interaction.client
    db = getattr(bot, "db", None)
    if db is None:
        return
    try:
        async with db.begin() as session:
            uow = UnitOfWork(session)
            await uow.command_audit.record(
                user_id=int(interaction.user.id),
                command=command,
                allowed=result.allowed,
                guild_id=guild_id,
                authority=result.label,
                reason=result.reason,
                parameters=_safe_params(parameters),
                correlation_id=correlation_id,
            )
    except Exception:  # noqa: BLE001 - never block a command on the audit write
        log.warning(
            "could not write command audit row",
            extra={"command": command, "guild_id": guild_id},
        )


def _safe_params(parameters: dict[str, Any] | None) -> dict[str, Any]:
    """Keep command parameters loggable: no secrets, bounded size."""
    if not parameters:
        return {}
    out: dict[str, Any] = {}
    for key, value in list(parameters.items())[:25]:
        if isinstance(value, (int, float, bool)) or value is None:
            out[key] = value
        else:
            out[key] = str(value)[:200]
    return out


async def deny(interaction: discord.Interaction, result: AuthResult) -> None:
    """Send the standard denial reply."""
    message = f"**Not authorized.** {result.reason}"
    if interaction.response.is_done():
        await interaction.followup.send(message, ephemeral=True)
    else:
        await interaction.response.send_message(message, ephemeral=True)


async def respond(interaction: discord.Interaction, content: str = "", **kwargs: Any) -> None:
    """Reply ephemerally whether or not the interaction was deferred."""
    kwargs.setdefault("ephemeral", True)
    payload: dict[str, Any] = dict(kwargs)
    if content:
        payload["content"] = content[:1990]
    if interaction.response.is_done():
        await interaction.followup.send(**payload)
    else:
        await interaction.response.send_message(**payload)


async def require(
    interaction: discord.Interaction,
    required: Authority,
    *,
    command: str,
    parameters: dict[str, Any] | None = None,
) -> bool:
    """Authorize or send the denial. Returns True when the caller may proceed."""
    result = await authorize(interaction, required, command=command, parameters=parameters)
    if not result.allowed:
        await deny(interaction, result)
        return False
    return True

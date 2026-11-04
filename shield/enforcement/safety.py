"""Hierarchy and collateral-damage safety checks.

These functions are pure (they take simple role/member *views*), so the exact
rules that decide "what may Shield touch" are unit-testable without a Discord
connection. The real cogs adapt discord.py objects into these views.

Discord rules encoded here:

* A bot can only modify a role **strictly below** its own highest role.
* A bot can never modify the guild owner, regardless of permissions.
* ``@everyone`` (position 0, id == guild id) cannot be removed from anyone.
* Managed roles (bot/integration/booster roles) cannot be removed by a bot.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from shield.constants import DANGEROUS_PERMISSIONS


@dataclass(frozen=True, slots=True)
class RoleView:
    """ORM/discord-free snapshot of a role."""

    id: int
    name: str
    position: int
    permissions: frozenset[str] = field(default_factory=frozenset)
    managed: bool = False
    is_default: bool = False

    @property
    def dangerous_permissions(self) -> tuple[str, ...]:
        return tuple(p for p in DANGEROUS_PERMISSIONS if p in self.permissions)

    @property
    def is_dangerous(self) -> bool:
        return bool(self.dangerous_permissions)


@dataclass(frozen=True, slots=True)
class MemberView:
    id: int
    roles: tuple[RoleView, ...] = ()
    is_bot: bool = False

    @property
    def top_position(self) -> int:
        return max((r.position for r in self.roles), default=0)


@dataclass(frozen=True, slots=True)
class StripPlan:
    """Which roles Shield will remove, which it will keep, and why."""

    removable: tuple[RoleView, ...]
    blocked: tuple[tuple[RoleView, str], ...]
    preserved_safe: tuple[RoleView, ...]
    #: True when at least one dangerous role could not be removed, i.e. the
    #: actor remains dangerous and containment has NOT been achieved.
    residual_risk: bool
    reason: str

    @property
    def removable_ids(self) -> tuple[int, ...]:
        return tuple(r.id for r in self.removable)

    def as_dict(self) -> dict[str, object]:
        return {
            "removable": [{"id": r.id, "name": r.name, "position": r.position} for r in self.removable],
            "blocked": [
                {"id": r.id, "name": r.name, "position": r.position, "why": why}
                for r, why in self.blocked
            ],
            "preserved_safe": [{"id": r.id, "name": r.name} for r in self.preserved_safe],
            "residual_risk": self.residual_risk,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class Enforceability:
    """Can Shield act on this target at all?"""

    possible: bool
    reason: str
    #: Suggested protective action when direct enforcement is impossible.
    recommend_lockdown: bool = False


def plan_role_strip(
    *,
    actor: MemberView,
    bot_top_position: int,
    guild_owner_id: int | None,
    bot_user_id: int | None,
    guild_id: int | None = None,
) -> StripPlan:
    """Compute the minimal, hierarchy-safe set of roles to remove.

    Only **dangerous** roles strictly below the bot's highest role are removed.
    Safe roles (colour roles, ping roles, member roles) are preserved - the
    default sanction is deliberately not "remove all roles".
    """
    if guild_owner_id is not None and actor.id == guild_owner_id:
        return StripPlan(
            (),
            tuple((r, "actor is the guild owner; Discord forbids modifying them") for r in actor.roles),
            tuple(r for r in actor.roles if not r.is_dangerous),
            residual_risk=True,
            reason="actor is the Discord guild owner: no role may be removed",
        )
    if bot_user_id is not None and actor.id == bot_user_id:
        return StripPlan(
            (),
            tuple((r, "refusing to strip Shield's own roles") for r in actor.roles),
            actor.roles,
            residual_risk=False,
            reason="target is Shield itself; self-protection prevents any change",
        )

    removable: list[RoleView] = []
    blocked: list[tuple[RoleView, str]] = []
    preserved: list[RoleView] = []

    for role in actor.roles:
        if role.is_default or (guild_id is not None and role.id == guild_id):
            preserved.append(role)
            continue
        if not role.is_dangerous:
            preserved.append(role)
            continue
        if role.managed:
            blocked.append((role, "managed/integration role: Discord forbids removal"))
            continue
        if role.position >= bot_top_position:
            blocked.append(
                (
                    role,
                    f"role position {role.position} is at or above Shield's highest role "
                    f"({bot_top_position}); Discord forbids the change",
                )
            )
            continue
        removable.append(role)

    residual = bool(blocked)
    if removable and not residual:
        reason = (
            f"removing {len(removable)} dangerous role(s) strictly below Shield's "
            f"highest role; {len(preserved)} safe role(s) preserved"
        )
    elif removable and residual:
        reason = (
            f"removing {len(removable)} dangerous role(s), but {len(blocked)} dangerous "
            "role(s) are out of reach: containment is PARTIAL"
        )
    elif residual:
        reason = (
            "every dangerous role held by the actor is out of Shield's reach "
            "(managed or above Shield in the hierarchy): containment NOT achieved"
        )
    else:
        reason = "actor holds no dangerous, removable roles"

    return StripPlan(
        tuple(removable), tuple(blocked), tuple(preserved), residual_risk=residual, reason=reason
    )


def check_enforceability(
    *,
    actor: MemberView | None,
    bot_top_position: int,
    bot_permissions: frozenset[str],
    guild_owner_id: int | None,
    bot_user_id: int | None,
    required_permission: str = "manage_roles",
    guild_id: int | None = None,
) -> Enforceability:
    """Decide whether an enforcement attempt is possible and honest.

    Returns ``possible=False`` with an explicit reason whenever Shield would be
    unable to contain the actor, so the caller can escalate to protective mode
    instead of claiming a successful containment.
    """
    if actor is None:
        return Enforceability(
            False,
            "actor is not attributed; Shield will alert instead of sanctioning a guess",
        )
    if guild_owner_id is not None and actor.id == guild_owner_id:
        return Enforceability(
            False,
            "actor is the Discord guild owner: Shield never sanctions the owner",
            recommend_lockdown=True,
        )
    if bot_user_id is not None and actor.id == bot_user_id:
        return Enforceability(False, "target is Shield itself; ignoring")
    if "administrator" not in bot_permissions and required_permission not in bot_permissions:
        return Enforceability(
            False,
            f"Shield is missing the {required_permission.replace('_', ' ').title()} "
            "permission in this guild",
            recommend_lockdown=True,
        )
    plan = plan_role_strip(
        actor=actor,
        bot_top_position=bot_top_position,
        guild_owner_id=guild_owner_id,
        bot_user_id=bot_user_id,
        guild_id=guild_id,
    )
    if not plan.removable and plan.residual_risk:
        return Enforceability(
            False,
            plan.reason,
            recommend_lockdown=True,
        )
    if not plan.removable:
        return Enforceability(
            False, "actor holds no dangerous, removable roles; nothing to strip"
        )
    return Enforceability(True, plan.reason)


def role_views_from_member(member, guild_id: int | None = None) -> MemberView:  # noqa: ANN001
    """Adapt a ``discord.Member`` into a :class:`MemberView`."""
    roles: list[RoleView] = []
    for role in getattr(member, "roles", ()):
        perms = getattr(role, "permissions", None)
        granted = frozenset(
            name for name, value in (perms or ()) if value
        ) if perms is not None else frozenset()
        roles.append(
            RoleView(
                id=int(role.id),
                name=str(getattr(role, "name", "")),
                position=int(getattr(role, "position", 0)),
                permissions=granted,
                managed=bool(getattr(role, "managed", False)),
                is_default=bool(getattr(role, "is_default", lambda: False)())
                if callable(getattr(role, "is_default", None))
                else bool(getattr(role, "is_default", False)),
            )
        )
    return MemberView(
        id=int(member.id), roles=tuple(roles), is_bot=bool(getattr(member, "bot", False))
    )


def permissions_set(permissions) -> frozenset[str]:  # noqa: ANN001
    """Adapt ``discord.Permissions`` into a set of granted permission names."""
    if permissions is None:
        return frozenset()
    try:
        return frozenset(name for name, value in permissions if value)
    except TypeError:
        return frozenset()


def dangerous_grants(before: frozenset[str], after: frozenset[str]) -> tuple[str, ...]:
    """Dangerous permissions newly granted between two permission sets."""
    from shield.constants import CRITICAL_PERMISSIONS

    gained = after - before
    return tuple(p for p in CRITICAL_PERMISSIONS if p in gained)

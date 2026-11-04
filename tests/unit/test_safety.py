"""Role hierarchy and collateral-damage rules."""

from __future__ import annotations

from shield.enforcement.safety import (
    Enforceability,
    MemberView,
    RoleView,
    check_enforceability,
    dangerous_grants,
    plan_role_strip,
)

GUILD = 1
OWNER = 11
BOT = 22
ACTOR = 33

EVERYONE = RoleView(id=GUILD, name="@everyone", position=0, is_default=True)
COLOUR = RoleView(id=2, name="Blue", position=3)
PING = RoleView(id=3, name="Announcements", position=4)
ADMIN = RoleView(id=4, name="Admin", position=10, permissions=frozenset({"administrator"}))
MOD = RoleView(id=5, name="Mod", position=8, permissions=frozenset({"ban_members", "kick_members"}))
ABOVE_BOT = RoleView(id=6, name="Super", position=99, permissions=frozenset({"administrator"}))
MANAGED = RoleView(
    id=7, name="Integration", position=6, permissions=frozenset({"manage_webhooks"}), managed=True
)

BOT_TOP = 50


def test_only_dangerous_roles_are_removed():
    actor = MemberView(id=ACTOR, roles=(EVERYONE, COLOUR, PING, ADMIN, MOD))
    plan = plan_role_strip(
        actor=actor, bot_top_position=BOT_TOP, guild_owner_id=OWNER, bot_user_id=BOT, guild_id=GUILD
    )
    assert set(plan.removable_ids) == {ADMIN.id, MOD.id}
    assert {r.name for r in plan.preserved_safe} == {"@everyone", "Blue", "Announcements"}
    assert not plan.residual_risk


def test_roles_at_or_above_the_bot_are_untouchable():
    actor = MemberView(id=ACTOR, roles=(EVERYONE, ABOVE_BOT))
    plan = plan_role_strip(
        actor=actor, bot_top_position=BOT_TOP, guild_owner_id=OWNER, bot_user_id=BOT, guild_id=GUILD
    )
    assert plan.removable_ids == ()
    assert plan.residual_risk
    assert "NOT achieved" in plan.reason
    assert "above Shield" in plan.blocked[0][1]


def test_equal_position_is_also_untouchable():
    equal = RoleView(id=8, name="Equal", position=BOT_TOP, permissions=frozenset({"administrator"}))
    plan = plan_role_strip(
        actor=MemberView(id=ACTOR, roles=(equal,)),
        bot_top_position=BOT_TOP,
        guild_owner_id=OWNER,
        bot_user_id=BOT,
    )
    assert plan.removable_ids == () and plan.residual_risk


def test_managed_roles_cannot_be_removed():
    plan = plan_role_strip(
        actor=MemberView(id=ACTOR, roles=(EVERYONE, MANAGED)),
        bot_top_position=BOT_TOP,
        guild_owner_id=OWNER,
        bot_user_id=BOT,
        guild_id=GUILD,
    )
    assert plan.removable_ids == ()
    assert "managed" in plan.blocked[0][1]


def test_partial_containment_is_reported():
    actor = MemberView(id=ACTOR, roles=(ADMIN, ABOVE_BOT))
    plan = plan_role_strip(
        actor=actor, bot_top_position=BOT_TOP, guild_owner_id=OWNER, bot_user_id=BOT
    )
    assert set(plan.removable_ids) == {ADMIN.id}
    assert plan.residual_risk and "PARTIAL" in plan.reason


def test_guild_owner_is_never_stripped():
    plan = plan_role_strip(
        actor=MemberView(id=OWNER, roles=(ADMIN,)),
        bot_top_position=BOT_TOP,
        guild_owner_id=OWNER,
        bot_user_id=BOT,
    )
    assert plan.removable_ids == ()
    assert "guild owner" in plan.reason
    assert plan.residual_risk


def test_shield_never_strips_itself():
    plan = plan_role_strip(
        actor=MemberView(id=BOT, roles=(ADMIN,)),
        bot_top_position=BOT_TOP,
        guild_owner_id=OWNER,
        bot_user_id=BOT,
    )
    assert plan.removable_ids == () and not plan.residual_risk
    assert "self-protection" in plan.reason


def test_everyone_role_is_preserved_by_id_even_without_flag():
    sneaky = RoleView(id=GUILD, name="@everyone", position=0, permissions=frozenset({"administrator"}))
    plan = plan_role_strip(
        actor=MemberView(id=ACTOR, roles=(sneaky,)),
        bot_top_position=BOT_TOP,
        guild_owner_id=OWNER,
        bot_user_id=BOT,
        guild_id=GUILD,
    )
    assert plan.removable_ids == ()


def test_enforceability_requires_manage_roles():
    verdict = check_enforceability(
        actor=MemberView(id=ACTOR, roles=(ADMIN,)),
        bot_top_position=BOT_TOP,
        bot_permissions=frozenset({"send_messages"}),
        guild_owner_id=OWNER,
        bot_user_id=BOT,
    )
    assert not verdict.possible and "Manage Roles" in verdict.reason
    assert verdict.recommend_lockdown


def test_administrator_satisfies_any_required_permission():
    verdict = check_enforceability(
        actor=MemberView(id=ACTOR, roles=(ADMIN,)),
        bot_top_position=BOT_TOP,
        bot_permissions=frozenset({"administrator"}),
        guild_owner_id=OWNER,
        bot_user_id=BOT,
    )
    assert verdict.possible


def test_enforceability_blocks_on_owner_and_recommends_lockdown():
    verdict = check_enforceability(
        actor=MemberView(id=OWNER, roles=(ADMIN,)),
        bot_top_position=BOT_TOP,
        bot_permissions=frozenset({"manage_roles"}),
        guild_owner_id=OWNER,
        bot_user_id=BOT,
    )
    assert not verdict.possible and verdict.recommend_lockdown


def test_enforceability_without_actor():
    verdict = check_enforceability(
        actor=None,
        bot_top_position=BOT_TOP,
        bot_permissions=frozenset({"manage_roles"}),
        guild_owner_id=OWNER,
        bot_user_id=BOT,
    )
    assert not verdict.possible and "not attributed" in verdict.reason


def test_enforceability_when_nothing_to_strip():
    verdict = check_enforceability(
        actor=MemberView(id=ACTOR, roles=(COLOUR,)),
        bot_top_position=BOT_TOP,
        bot_permissions=frozenset({"manage_roles"}),
        guild_owner_id=OWNER,
        bot_user_id=BOT,
    )
    assert isinstance(verdict, Enforceability) and not verdict.possible
    assert "nothing to strip" in verdict.reason


def test_dangerous_grants_detects_only_new_critical_permissions():
    assert dangerous_grants(frozenset(), frozenset({"administrator", "connect"})) == ("administrator",)
    assert dangerous_grants(frozenset({"administrator"}), frozenset({"administrator"})) == ()
    assert set(
        dangerous_grants(frozenset({"connect"}), frozenset({"connect", "ban_members", "manage_guild"}))
    ) == {"manage_guild", "ban_members"}


def test_role_view_classification():
    assert ADMIN.is_dangerous and "administrator" in ADMIN.dangerous_permissions
    assert not COLOUR.is_dangerous

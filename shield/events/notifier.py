"""Discord channel notifications.

Every incident produces one message in the guild's configured log channel (and
the alert channel, when different). Notifications are rate limited per guild so
a flood cannot turn Shield into the spammer, and the message always states:

* what was detected and on what evidence,
* who the actor is and how confidently they were identified,
* what Shield did or would have done, including anything it could NOT do,
* the correlation ID, so the operator can find the incident and the logs.
"""

from __future__ import annotations

from typing import Any

from shield.constants import EnforcementStatus, ResponseAction, Severity
from shield.enforcement.ratelimit import RateLimiter, call_with_retry
from shield.observability.logging import get_logger
from shield.observability.metrics import METRICS

log = get_logger("notify")

SEVERITY_COLORS = {
    Severity.LOW: 0x3BA55D,
    Severity.MEDIUM: 0xFAA61A,
    Severity.HIGH: 0xED4245,
    Severity.CRITICAL: 0x992D22,
}

CONFIDENCE_LABEL = {
    "confirmed": "confirmed from the audit log",
    "likely": "LIKELY only - not confirmed, no sanction applied",
    "unknown": "UNKNOWN - actor could not be identified",
}


class Notifier:
    def __init__(self, *, limiter: RateLimiter) -> None:
        self.limiter = limiter

    async def send_incident(
        self,
        guild,  # noqa: ANN001
        *,
        incident_id: int | None,
        action: str,
        severity: Severity,
        reason: str,
        decision_code: str,
        response: ResponseAction,
        dry_run: bool,
        actor_id: int | None,
        confidence: str,
        target_label: str | None,
        correlation_id: str,
        evidence: dict[str, Any],
        enforcement: dict[str, Any] | None = None,
        log_channel_id: int | None = None,
        alert_channel_id: int | None = None,
    ) -> bool:
        """Post an incident report. Returns True if at least one message was sent."""
        if not self.limiter.allow("notify", guild.id):
            log.warning(
                "notification suppressed by rate limit",
                extra={"guild_id": guild.id, "correlation_id": correlation_id},
            )
            return False

        embed = self._build_embed(
            guild=guild,
            incident_id=incident_id,
            action=action,
            severity=severity,
            reason=reason,
            decision_code=decision_code,
            response=response,
            dry_run=dry_run,
            actor_id=actor_id,
            confidence=confidence,
            target_label=target_label,
            correlation_id=correlation_id,
            evidence=evidence,
            enforcement=enforcement,
        )

        sent = False
        targets = {cid for cid in (log_channel_id, alert_channel_id) if cid}
        if not targets:
            log.info(
                "no log channel configured; incident not posted to Discord",
                extra={"guild_id": guild.id, "correlation_id": correlation_id},
            )
            return False
        for channel_id in targets:
            channel = guild.get_channel(int(channel_id)) if hasattr(guild, "get_channel") else None
            if channel is None or not hasattr(channel, "send"):
                log.warning(
                    "configured log channel is unavailable",
                    extra={"guild_id": guild.id, "channel_id": channel_id},
                )
                continue
            try:
                await call_with_retry(
                    lambda c=channel: c.send(embed=embed), description="send incident embed"
                )
                sent = True
                METRICS.incr("notifications_sent_total")
            except Exception as exc:  # noqa: BLE001
                METRICS.incr("notification_errors_total")
                log.warning(
                    "failed to post incident",
                    extra={
                        "guild_id": guild.id,
                        "channel_id": channel_id,
                        "error": f"{type(exc).__name__}: {exc}",
                    },
                )
        return sent

    async def send_text(
        self, guild, channel_id: int | None, message: str  # noqa: ANN001
    ) -> bool:
        if not channel_id or not self.limiter.allow("notify", guild.id):
            return False
        channel = guild.get_channel(int(channel_id)) if hasattr(guild, "get_channel") else None
        if channel is None or not hasattr(channel, "send"):
            return False
        try:
            await call_with_retry(
                lambda: channel.send(message[:1900]), description="send shield notice"
            )
            return True
        except Exception:  # noqa: BLE001
            return False

    # -- embed ---------------------------------------------------------
    def _build_embed(self, **kw: Any):  # noqa: ANN202
        import discord

        severity: Severity = kw["severity"]
        dry_run: bool = kw["dry_run"]
        response: ResponseAction = kw["response"]
        enforcement: dict[str, Any] | None = kw["enforcement"]
        code: str = kw["decision_code"]

        prefix = "DRY RUN" if dry_run else "INCIDENT"
        if code == "alert_only_mode":
            prefix = "ALERT ONLY"
        elif code == "owner_alert_only":
            prefix = "OWNER ACTION"
        elif code == "unconfirmed_actor":
            prefix = "UNATTRIBUTED"
        elif code == "enforcement_blocked":
            prefix = "CONTAINMENT FAILED"

        title = f"[{prefix}] {kw['action'].replace('_', ' ').title()}"
        embed = discord.Embed(
            title=title[:256],
            description=str(kw["reason"])[:2000],
            colour=SEVERITY_COLORS.get(severity, 0x5865F2),
        )
        incident_id = kw["incident_id"]
        embed.add_field(
            name="Incident",
            value=f"`#{incident_id}`" if incident_id else "`not persisted (database unavailable)`",
            inline=True,
        )
        embed.add_field(name="Severity", value=severity.value, inline=True)
        actor_id = kw["actor_id"]
        embed.add_field(
            name="Actor",
            value=(f"<@{actor_id}> (`{actor_id}`)" if actor_id else "unidentified"),
            inline=True,
        )
        embed.add_field(
            name="Attribution",
            value=CONFIDENCE_LABEL.get(kw["confidence"], kw["confidence"]),
            inline=False,
        )
        if kw.get("target_label"):
            embed.add_field(name="Target", value=str(kw["target_label"])[:1000], inline=False)

        evidence = kw.get("evidence") or {}
        evidence_lines = [
            f"events in window: **{evidence.get('window_count', '?')}** "
            f"(threshold {evidence.get('threshold', '?')} / "
            f"{evidence.get('window_seconds', '?')}s)"
        ]
        if evidence.get("window_distinct"):
            evidence_lines.append(f"distinct targets: **{evidence['window_distinct']}**")
        if evidence.get("escalation_level"):
            evidence_lines.append(f"escalation level: **{evidence['escalation_level']}**")
        if evidence.get("trust_basis") and evidence["trust_basis"] != "none":
            evidence_lines.append(f"trust basis: `{evidence['trust_basis']}`")
        embed.add_field(name="Evidence", value="\n".join(evidence_lines)[:1000], inline=False)

        if dry_run:
            action_text = f"Would have applied **{response.value}** (dry run: nothing changed)."
        elif enforcement:
            status = enforcement.get("status", "unknown")
            action_text = f"**{response.value}** -> `{status}`\n{enforcement.get('summary', '')}"
            if enforcement.get("residual_risk"):
                action_text += (
                    "\n**Containment incomplete** - manual intervention required."
                )
        else:
            action_text = f"**{response.value}** (no enforcement record)"
        embed.add_field(name="Response", value=action_text[:1000], inline=False)

        if enforcement and enforcement.get("steps"):
            lines = []
            for step in enforcement["steps"][:5]:
                marker = "+" if step.get("status") == EnforcementStatus.SUCCEEDED.value else "!"
                lines.append(f"{marker} `{step.get('action')}` {step.get('detail', '')}")
            embed.add_field(name="Steps", value="\n".join(lines)[:1000], inline=False)

        embed.set_footer(text=f"correlation {kw['correlation_id']}"[:2048])
        return embed

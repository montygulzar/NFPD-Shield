"""Message gateway listeners: spam, duplicate spam, mention floods, webhooks.

Intent requirements
-------------------
* ``on_message`` needs the ``Guild Messages`` intent for metadata.
* Duplicate-content detection and reliable ``@everyone``/``@here`` matching need
  the privileged **Message Content** intent. When it is disabled, Shield still
  counts message *rate* and *mention targets* (both available without content),
  and reports the degradation through ``/shield health``.

Privacy
-------
Message text is never stored. Duplicate detection uses a truncated SHA-256 of
the normalised text, held in memory only.
"""

from __future__ import annotations

from datetime import datetime, timezone

import discord
from discord.ext import commands

from shield.constants import ActionKey, EventSource
from shield.events.normalize import NormalizedEvent, hash_content
from shield.observability.logging import get_logger

log = get_logger("events.message")


class MessageEventsCog(commands.Cog):
    def __init__(self, bot) -> None:  # noqa: ANN001
        self.bot = bot

    @property
    def pipeline(self):  # noqa: ANN201
        return self.bot.pipeline

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        guild = message.guild
        if guild is None:
            return  # DMs are out of scope
        author = message.author
        if author is None:
            return
        if getattr(author, "id", None) == getattr(self.bot.user, "id", None):
            return  # never police ourselves

        now = datetime.now(tz=timezone.utc)
        channel_id = int(getattr(message.channel, "id", 0) or 0)

        if message.webhook_id:
            # Webhook traffic has no member to sanction. It is reported so an
            # operator can investigate a compromised webhook.
            await self._handle_webhook_message(message, guild, now)
            return

        content = message.content or ""
        content_available = bool(content) or not self.bot.shield_config.enable_message_content

        mention_ids = tuple(
            {int(u.id) for u in getattr(message, "mentions", []) or []}
            | {int(r.id) for r in getattr(message, "role_mentions", []) or []}
        )
        mentions_everyone = bool(getattr(message, "mention_everyone", False))

        base_payload = {
            "message_id": int(message.id),
            "mention_count": len(mention_ids),
            "mentions_everyone": mentions_everyone,
            "content_intent": self.bot.shield_config.enable_message_content,
        }

        # 1. Message rate (works without Message Content).
        spam_event = NormalizedEvent(
            guild_id=guild.id,
            action_key=ActionKey.MESSAGE_SPAM,
            source=EventSource.GATEWAY,
            occurred_at=now,
            actor_id=int(author.id),
            actor_confidence=_direct_confidence(),
            target_type="message",
            target_id=int(message.id),
            channel_id=channel_id,
            payload=base_payload | {"target_name": str(author)},
        )
        await self.pipeline.handle(spam_event, guild)

        # 2. Duplicate content (requires Message Content).
        if content and len(content.strip()) >= 3:
            dup_event = NormalizedEvent(
                guild_id=guild.id,
                action_key=ActionKey.DUPLICATE_SPAM,
                source=EventSource.GATEWAY,
                occurred_at=now,
                actor_id=int(author.id),
                actor_confidence=_direct_confidence(),
                target_type="message",
                target_id=int(message.id),
                channel_id=channel_id,
                content_hash=hash_content(content),
                payload=base_payload | {"target_name": str(author), "length": len(content)},
            )
            await self.pipeline.handle(dup_event, guild)
        elif not content_available:
            log.debug(
                "duplicate spam detection skipped: Message Content intent disabled",
                extra={"guild_id": guild.id},
            )

        # 3. Mentions.
        if mention_ids or mentions_everyone:
            mention_event = NormalizedEvent(
                guild_id=guild.id,
                action_key=ActionKey.MASS_MENTION,
                source=EventSource.GATEWAY,
                occurred_at=now,
                actor_id=int(author.id),
                actor_confidence=_direct_confidence(),
                target_type="message",
                target_id=int(message.id),
                channel_id=channel_id,
                mention_ids=mention_ids,
                mentions_everyone=mentions_everyone,
                payload=base_payload | {"target_name": str(author)},
            )
            await self.pipeline.handle(mention_event, guild)

    async def _handle_webhook_message(
        self, message: discord.Message, guild: discord.Guild, now: datetime
    ) -> None:
        """Report suspicious webhook messages.

        Observability limit: Shield sees a webhook message only in channels it
        can read, and the audit log does not record webhook *executions*. There
        is therefore no member to attribute and no sanction to apply - this is
        an alerting-only signal.
        """
        mention_count = len(getattr(message, "mentions", []) or [])
        suspicious = bool(getattr(message, "mention_everyone", False)) or mention_count >= 5
        if not suspicious:
            return
        event = NormalizedEvent(
            guild_id=guild.id,
            action_key=ActionKey.WEBHOOK_UPDATE,
            source=EventSource.GATEWAY,
            occurred_at=now,
            target_type="webhook",
            target_id=int(message.webhook_id or 0) or None,
            channel_id=int(getattr(message.channel, "id", 0) or 0),
            payload={
                "target_name": f"webhook {message.webhook_id}",
                "suspicious_webhook_message": True,
                "mention_everyone": bool(getattr(message, "mention_everyone", False)),
                "mention_count": mention_count,
                "note": (
                    "webhook executions are not recorded in the audit log, so no actor "
                    "can be attributed and no sanction is applied"
                ),
            },
        )
        await self.pipeline.handle(event, guild)


def _direct_confidence():  # noqa: ANN202
    from shield.constants import Confidence

    # The gateway tells us the author directly - no audit correlation needed.
    return Confidence.CONFIRMED


async def setup(bot) -> None:  # noqa: ANN001
    await bot.add_cog(MessageEventsCog(bot))

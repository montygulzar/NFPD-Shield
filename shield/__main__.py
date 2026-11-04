"""Entry point: ``python -m shield`` / ``nfpd-shield``.

Boot sequence:

1. Load and validate the environment (fails loudly, listing every problem).
2. Configure structured logging with redaction.
3. Connect to PostgreSQL, apply migrations, register slash commands.
4. Run until SIGTERM/SIGINT, then shut down cleanly so systemd restarts are
   graceful.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys

from shield.config import ConfigError, load_config
from shield.observability.logging import configure_logging


def _install_signal_handlers(loop: asyncio.AbstractEventLoop, bot) -> None:  # noqa: ANN001
    async def _shutdown(signame: str) -> None:
        logging.getLogger("shield").warning("received %s, shutting down", signame)
        await bot.close()

    for signame in ("SIGTERM", "SIGINT"):
        sig = getattr(signal, signame, None)
        if sig is None:
            continue
        try:
            loop.add_signal_handler(
                sig, lambda s=signame: asyncio.create_task(_shutdown(s))
            )
        except NotImplementedError:  # pragma: no cover - non-POSIX
            pass


async def _run() -> int:
    try:
        config = load_config()
    except ConfigError as exc:
        # Printed to stderr because logging is not configured yet.
        print(str(exc), file=sys.stderr)
        return 78  # EX_CONFIG

    log = configure_logging(config.logging)
    log.info("NFPD Shield booting", extra={"instance_id": config.instance_id})

    from shield.bot import ShieldBot

    bot = ShieldBot(config)
    _install_signal_handlers(asyncio.get_running_loop(), bot)

    try:
        await bot.start(config.discord_token)
    except Exception as exc:  # noqa: BLE001
        name = type(exc).__name__
        if name in {"LoginFailure", "PrivilegedIntentsRequired"}:
            if name == "LoginFailure":
                log.critical(
                    "Discord rejected the bot token. Check DISCORD_TOKEN, and rotate it "
                    "in the Developer Portal if it may have leaked."
                )
            else:
                log.critical(
                    "Discord rejected the requested privileged intents. Enable SERVER "
                    "MEMBERS INTENT and/or MESSAGE CONTENT INTENT for this application "
                    "in the Developer Portal (Bot -> Privileged Gateway Intents), or set "
                    "ENABLE_GUILD_MEMBERS/ENABLE_MESSAGE_CONTENT to false."
                )
            return 78
        log.critical("fatal error during startup: %s: %s", name, exc, exc_info=True)
        return 1
    finally:
        if not bot.is_closed():
            await bot.close()
    return 0


def main() -> int:
    try:
        return asyncio.run(_run())
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

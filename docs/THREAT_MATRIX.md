# Threat matrix

Legend for **Attribution**: *direct* = the gateway names the actor; *audit* =
requires `View Audit Log` and is eventually consistent; *none* = no actor
exists or none is discoverable.

Residual risk is stated bluntly. Where Shield cannot contain something, it says
so at runtime too.

| # | Threat | Actor | Detection | Attribution | Default response | Residual risk |
|---|---|---|---|---|---|---|
| T1 | Mass channel deletion (nuke) | compromised admin, rogue mod, malicious bot | `on_guild_channel_delete`, 1 event / 15s per actor | audit | strip dangerous roles below the bot; snapshot-based restore available | Channels already deleted are gone; message history is unrecoverable. Without `View Audit Log`, alert only. |
| T2 | Mass bans | rogue moderator | `on_member_ban`, 2 / 15s per actor | gateway + audit | strip dangerous roles | Bans already issued are not auto-reverted (unbanning in bulk is itself destructive); the operator unbans after review. |
| T3 | Mass kicks | rogue moderator | `on_member_remove` correlated against `kick` audit entries | audit **only** | strip dangerous roles | A voluntary leave is indistinguishable without the audit log, so without it Shield emits nothing rather than guessing. |
| T4 | Channel creation flood (spam/grief) | compromised admin, bot | `on_guild_channel_create`, 4 / 20s per actor | audit | strip dangerous roles | Shield does not delete the created channels — deleting is the attacker's goal, not the defender's. |
| T5 | Role deletion | compromised admin | `on_guild_role_delete`, 1 / 15s | audit | strip dangerous roles; restore recreates the role | Recreated roles come back **empty**: member assignments are deliberately not restored. |
| T6 | Role creation flood | compromised admin | `on_guild_role_create`, 4 / 20s | audit | strip dangerous roles | As T4. |
| T7 | Privilege escalation via role edit | compromised admin | `on_guild_role_update` diff for newly granted Administrator / Manage Roles / Manage Channels / Ban / Kick / Manage Webhooks / Manage Guild | audit | strip dangerous roles | Single-event policy: legitimate permission work trips it. Allowlist your role-management tooling. |
| T8 | Privilege escalation via role grant | compromised admin | `on_member_update` role diff | audit | strip dangerous roles from the **granter** | The granted member keeps the role until an operator removes it; Shield targets the actor, not the beneficiary. |
| T9 | Dangerous channel overwrite | compromised admin | `on_guild_channel_update` overwrite diff | audit | strip dangerous roles | Only reported when the diff grants a dangerous permission, so subtle read-access changes are not covered. |
| T10 | Unauthorised bot addition | compromised admin | `on_member_join` where `member.bot` | audit (`bot_add` names the authorising member) | **alert only** | Shield cannot distinguish an authorised integration install from a malicious one. Deliberately alert-only; raise it per guild once you maintain an allowlist. |
| T11 | Webhook creation / deletion / modification | compromised admin, malicious bot | `on_webhooks_update` + audit classification | audit | **alert only** | The gateway event names only the channel. Without the audit log Shield can only say "webhooks changed in #channel". |
| T12 | Webhook message abuse (mass ping via a stolen webhook URL) | anyone holding the URL | `on_message` where `webhook_id` is set and the message pings `@everyone` or ≥5 users | **none** — webhook executions are not audited | alert only | No member to sanction. Remediation is manual: delete the webhook and rotate the consumer. Shield never stores webhook tokens, so it cannot leak one. |
| T13 | Mass mention / ping flood | raider, compromised member | 5 unique mentions / 10s, or any `@everyone`/`@here` from a non-allowlisted member | direct | timeout + bounded message delete | Reliable `@everyone` matching benefits from Message Content. Announcement roles should be allowlisted with the `messages` scope. |
| T14 | Message spam | raider, compromised member, spam bot | 6 messages / 8s per user | direct | timeout + bounded delete (max 25) | Busy channels need `exempt_channel_ids`. Deletion is bounded, so a long flood is not fully cleaned automatically. |
| T15 | Duplicate-content spam (scam links) | spam bot | 4 identical messages / 15s per user | direct | timeout + bounded delete | Requires the Message Content intent; unavailable without it. Content is hashed, never stored. |
| T16 | Join flood / raid | botnet | 8 joins / 20s per guild, new accounts weighted | **none** (a join has no actor) | reversible raid mode: verification level, invite pause, slowmode | Shield **never** bans or kicks joiners. Determined raiders with aged accounts still get in; raid mode slows, it does not block. |
| T17 | Guild identity / security changes (name, icon, verification, content filter, MFA, system channels) | compromised admin | `on_guild_update` field diff | audit, partial | **alert only**; `/shield restore` can revert name, verification level and content filter | Discord's `guild_update` audit coverage is coarse, so attribution may be missing. Icons and banners are not restorable from a snapshot (only their URLs were recorded). |
| T18 | Vanity URL hijack | compromised admin | `on_guild_update` `vanity_url_code` diff | audit, partial | **alert only** | Only observable on guilds with the `VANITY_URL` feature. A released vanity code can be claimed by anyone immediately. |
| T19 | Attacker above the bot in the hierarchy | the guild owner's alt, a founder-role holder | detected normally | audit | incident marked `enforcement_blocked`, severity **critical**, operator told to use `/shield lockdown enable` | **Shield cannot contain this.** It is a Discord hierarchy rule. Keep Shield's role high; `/shield health` lists every out-of-reach dangerous role. |
| T20 | The guild owner is the attacker | owner, or an attacker who has taken the owner account | detected normally | audit | alert only, never a sanction | Nothing a bot can do: Discord forbids modifying the owner. Mitigation is 2FA on the owner account and server ownership transfer discipline. |
| T21 | Compromised Shield bot token | attacker with the token | not self-detectable | n/a | out of band | Treat as full compromise: rotate the token, review `command_audit` and `enforcement_actions`, check for unexpected restores. See the rotation runbook. |
| T22 | Malicious allowlist entry | compromised owner or delegate | `command_audit` records every `whitelist add` | direct | none — the entry is honoured | An allowlisted principal bypasses detection entirely. Keep scopes narrow, set expiries, review `/shield whitelist list` regularly. |
| T23 | Detection-loop abuse (tripping Shield deliberately to make it spam the API) | any member | n/a | n/a | token buckets per guild per purpose, durable cooldowns, hard write caps, escalation instead of repetition | A sustained attack can exhaust the enforcement budget; Shield then skips with `residual_risk=true` and alerts rather than hammering Discord. |
| T24 | Self-triggering during repair | Shield itself | n/a | n/a | every Shield write is pre-registered in the self-action guard and ignored | A write that takes longer than the 30s suppression TTL to be delivered could be re-detected; the restore burst registers wildcard credits to make that unlikely. |
| T25 | Cross-guild data leakage | a delegate in guild A probing guild B's incident IDs | every repository query is `guild_id`-scoped | direct | lookups in the wrong guild return "not found", indistinguishable from a non-existent ID | None known; covered by `test_incident_show_cannot_read_another_guild`. |
| T26 | Database compromise / stolen dump | infrastructure attacker | n/a | n/a | snapshots optionally Fernet-encrypted before insert; no message content, no webhook tokens, no member lists stored | Without `SNAPSHOT_ENCRYPTION_KEY`, guild structure is readable in a dump. Set the key. |

## Controls that apply to every threat

| Control | Mechanism |
|---|---|
| No sanction without proof | only `Confidence.CONFIRMED` can enforce; `LIKELY`/`UNKNOWN` alert |
| No owner sanctions | checked in trust evaluation, in the strip planner, and again in the executor |
| Minimal collateral damage | only dangerous, reachable, unmanaged roles are removed; safe roles preserved; `@everyone` never touched |
| Honest reporting | `PARTIAL` / `FAILED` / `SKIPPED` outcomes with the exact reason, surfaced in the Discord embed as `CONTAINMENT FAILED` |
| No double action | unique `idempotency_key` claimed before every Discord write |
| No runaway loops | token buckets, durable cooldowns, escalation, hard write caps |
| Owner kill switch | `/shield pause` stops all responses and notifications immediately |
| Full audit trail | `event_records`, `incidents`, `enforcement_actions`, `command_audit`, `restore_jobs`, all tied together by `correlation_id` |
| Reversibility | versioned snapshots, pre-restore snapshot, additive restore, recorded before/after state on every enforcement step |

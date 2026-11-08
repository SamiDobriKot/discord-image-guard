"""Discord-бот защиты от повторяющихся изображений.

Бот индексирует изображения во всех доступных каналах, ищет совпадения по
SHA-256 и pHash и применяет настроенное действие: бан, удаление сообщений
или интерактивное уведомление. Хеши хранятся только в локальной базе.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Optional

import discord
from discord import app_commands
from discord.ext import tasks
from dotenv import load_dotenv

from detection import (
    cluster_qualifies,
    incident_matches,
    select_cluster,
    unique_messages,
    unique_users,
)
from hashing import HashingError, ImageHashes, compute_hashes, is_image_attachment
from models import (
    ACTION_LABELS,
    MAX_PHASH_DISTANCE,
    MAX_THRESHOLD,
    MIN_THRESHOLD,
    STATUS_ACTIONED,
    STATUS_BANNED,
    STATUS_CANCELLED,
    STATUS_DELETED,
    STATUS_FAILED,
    STATUS_OPEN,
    STATUS_WATCHING,
    GuildConfig,
    Incident,
    format_duration,
    parse_ban_duration,
    parse_duration,
)
from reporting import (
    COLOR_BAN,
    COLOR_DELETE,
    COLOR_NOTIFY,
    build_alert_embed,
    build_bans_embed,
    build_report_embed,
    build_settings_embed,
)
from storage import Storage

load_dotenv()

log = logging.getLogger("image-guard")

DEFAULT_MAX_DOWNLOAD_MB = 32
DEFAULT_CONCURRENCY = 4
_UNSET = object()


def _env_int(name: str, default: Optional[int] = None) -> Optional[int]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise SystemExit(f"Переменная {name} должна быть целым числом, а не {raw!r}") from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "on", "да"}:
        return True
    if raw in {"0", "false", "no", "off", "нет"}:
        return False
    raise SystemExit(f"Переменная {name} должна быть true/false, а не {raw!r}")


class AlertDeleteButton(
    discord.ui.DynamicItem[discord.ui.Button],
    template=r"dup:(?P<id>\d+):delete",
):
    def __init__(self, incident_id: int) -> None:
        super().__init__(
            discord.ui.Button(
                label="Удалить сообщения",
                style=discord.ButtonStyle.secondary,
                custom_id=f"dup:{incident_id}:delete",
            )
        )
        self.incident_id = incident_id

    @classmethod
    async def from_custom_id(cls, interaction, item, match):  # noqa: ANN001
        return cls(int(match.group("id")))

    async def callback(self, interaction: discord.Interaction) -> None:
        await interaction.client.handle_alert_action(  # type: ignore[attr-defined]
            interaction, self.incident_id, "delete"
        )


class AlertBanButton(
    discord.ui.DynamicItem[discord.ui.Button],
    template=r"dup:(?P<id>\d+):ban",
):
    def __init__(self, incident_id: int) -> None:
        super().__init__(
            discord.ui.Button(
                label="Забанить пользователей",
                style=discord.ButtonStyle.danger,
                custom_id=f"dup:{incident_id}:ban",
            )
        )
        self.incident_id = incident_id

    @classmethod
    async def from_custom_id(cls, interaction, item, match):  # noqa: ANN001
        return cls(int(match.group("id")))

    async def callback(self, interaction: discord.Interaction) -> None:
        await interaction.client.handle_alert_action(  # type: ignore[attr-defined]
            interaction, self.incident_id, "ban"
        )


class ReportCancelButton(
    discord.ui.DynamicItem[discord.ui.Button],
    template=r"dup:(?P<id>\d+):cancel",
):
    def __init__(self, incident_id: int) -> None:
        super().__init__(
            discord.ui.Button(
                label="Прекратить удаление",
                style=discord.ButtonStyle.secondary,
                custom_id=f"dup:{incident_id}:cancel",
            )
        )
        self.incident_id = incident_id

    @classmethod
    async def from_custom_id(cls, interaction, item, match):  # noqa: ANN001
        return cls(int(match.group("id")))

    async def callback(self, interaction: discord.Interaction) -> None:
        await interaction.client.handle_cancel_delete(  # type: ignore[attr-defined]
            interaction, self.incident_id
        )


class DuplicateGuardBot(discord.Client):
    def __init__(
        self,
        *,
        storage: Storage,
        ignore_bots: bool = True,
        max_download_bytes: int = DEFAULT_MAX_DOWNLOAD_MB * 1024 * 1024,
        concurrency: int = DEFAULT_CONCURRENCY,
        hash_retention_seconds: int = 24 * 3600,
    ) -> None:
        intents = discord.Intents.none()
        intents.guilds = True
        intents.guild_messages = True
        intents.message_content = True

        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)
        self.storage = storage
        self.ignore_bots = ignore_bots
        self.max_download_bytes = max_download_bytes
        self.hash_retention_seconds = max(0, int(hash_retention_seconds))
        self._hash_slots = asyncio.Semaphore(max(1, concurrency))
        self._warned_at: dict[tuple[int, str], float] = {}
        self._excluded_roles: dict[int, set[int]] = {}

        self.add_dynamic_items(
            AlertDeleteButton, AlertBanButton, ReportCancelButton
        )
        register_commands(self)

    # --- жизненный цикл -------------------------------------------------
    async def setup_hook(self) -> None:
        await self.storage.init()
        reset = await self.storage.reset_actioning()
        if reset:
            log.warning("Возвращено в ожидание инцидентов после перезапуска: %d", reset)
        await self._purge_old_hashes()
        await self._sync_commands()

    async def _sync_commands(self) -> None:
        try:
            synced = await self.tree.sync()
            log.info("Глобальные команды синхронизированы: %d", len(synced))
        except discord.HTTPException:
            log.exception("Не удалось синхронизировать глобальные команды")

    async def on_ready(self) -> None:
        log.info(
            "Бот запущен: %s (id=%s), серверов: %d",
            self.user,
            self.user.id if self.user else "?",
            len(self.guilds),
        )

        if not self._expiry_loop.is_running():
            self._expiry_loop.start()
        if self.hash_retention_seconds > 0 and not self._cleanup_loop.is_running():
            self._cleanup_loop.start()

        await self._process_due_bans()
        if not self._unban_loop.is_running():
            self._unban_loop.start()

    # --- события --------------------------------------------------------
    async def on_message(self, message: discord.Message) -> None:
        if message.guild is None or message.is_system():
            return
        if self.user and message.author.id == self.user.id:
            return
        if self.ignore_bots and message.author.bot:
            return
        await self.process_message(message)

    async def on_message_edit(self, before: discord.Message, after: discord.Message) -> None:
        if after.guild is None or after.is_system():
            return
        if self.ignore_bots and after.author.bot:
            return
        before_ids = {attachment.id for attachment in before.attachments}
        after_ids = {attachment.id for attachment in after.attachments}
        if after_ids - before_ids:
            await self.process_message(after)

    # --- индексация и детекция ------------------------------------------
    async def process_message(self, message: discord.Message) -> int:
        attachments = [
            attachment
            for attachment in message.attachments
            if is_image_attachment(attachment)
        ]
        if not attachments:
            return 0

        guild = message.guild
        assert guild is not None

        if await self._is_excluded_author(message):
            return 0

        config = await self.storage.get_config(guild.id)
        indexed = 0

        for attachment in attachments:
            try:
                if await self.storage.get_image_by_attachment(attachment.id):
                    continue

                hashes = await self._hash_attachment(attachment, guild.id)
                if hashes is None:
                    continue

                image, created = await self.storage.insert_image(
                    guild_id=guild.id,
                    attachment_id=attachment.id,
                    message_id=message.id,
                    channel_id=message.channel.id,
                    user_id=message.author.id,
                    filename=attachment.filename,
                    sha256=hashes.sha256,
                    phash=hashes.phash,
                    attachment_url=attachment.url,
                    created_at=int(message.created_at.timestamp()),
                )
                if not created:
                    continue

                indexed += 1

                if config.report_channel_id is None:
                    continue

                await self._detect(guild, config, image)
            except HashingError as exc:
                self._warn(
                    guild.id,
                    f"Не удалось посчитать хэши для {attachment.filename!r}: {exc}",
                )
            except discord.HTTPException as exc:
                self._warn(
                    guild.id,
                    f"Не удалось обработать вложение {attachment.filename!r}: {exc}",
                )
        return indexed

    async def _is_excluded_author(self, message: discord.Message) -> bool:
        roles = getattr(message.author, "roles", None)
        if not roles or message.guild is None:
            return False
        excluded = self._excluded_roles.get(message.guild.id)
        if excluded is None:
            excluded = set(
                await self.storage.get_excluded_roles(message.guild.id)
            )
            self._excluded_roles[message.guild.id] = excluded
        return any(role.id in excluded for role in roles)

    async def _hash_attachment(
        self, attachment: discord.Attachment, guild_id: int
    ) -> Optional[ImageHashes]:
        if attachment.size and attachment.size > self.max_download_bytes:
            self._warn(
                guild_id,
                f"Файл {attachment.filename!r} "
                f"({attachment.size / (1024 * 1024):.1f} МБ) больше лимита — пропущен",
            )
            return None

        async with self._hash_slots:
            data = await attachment.read()
            if len(data) > self.max_download_bytes:
                self._warn(guild_id, "Файл оказался больше лимита — пропущен")
                return None
            return await asyncio.to_thread(compute_hashes, data)

    async def _detect(
        self, guild: discord.Guild, config: GuildConfig, image
    ) -> None:
        now = int(time.time())

        for incident in await self.storage.active_incidents(guild.id, now):
            if incident_matches(
                incident, image, config.phash_distance, config.multi_user
            ):
                await self._extend_incident(guild, config, incident, image)
                return

        since = now - config.window_seconds
        recent = await self.storage.recent_images(
            guild.id,
            since,
            user_id=None if config.multi_user else image.user_id,
        )
        cluster = select_cluster(image, recent, config.phash_distance)

        if not cluster_qualifies(
            cluster, config.threshold_count, config.cross_channel_only
        ):
            return

        await self._open_incident(guild, config, cluster)

    async def _open_incident(
        self, guild: discord.Guild, config: GuildConfig, cluster: list
    ) -> None:
        now = int(time.time())
        latest = cluster[-1]
        messages = unique_messages(cluster)

        incident = await self.storage.create_incident(
            guild_id=guild.id,
            action=config.action,
            status="pending",
            sha256=latest.sha256,
            phash=latest.phash,
            filename=latest.filename,
            image_url=latest.attachment_url,
            user_ids=unique_users(cluster),
            message_ids=messages,
            count=len(messages),
            created_at=now,
            last_activity_at=now,
            expires_at=now + config.window_seconds,
        )

        await self.storage.mark_actioned([item.id for item in cluster], now)
        await self._apply_action(guild, config, incident)

    async def _extend_incident(
        self, guild: discord.Guild, config: GuildConfig, incident: Incident, image
    ) -> None:
        now = int(time.time())
        fresh = await self.storage.get_incident(incident.id)
        if (
            fresh is None
            or fresh.window_closed
            or fresh.expires_at <= now
            or fresh.status not in (STATUS_OPEN, STATUS_WATCHING)
        ):
            return
        users = list(dict.fromkeys([*incident.user_ids, image.user_id]))
        messages = list(
            dict.fromkeys(
                [*incident.message_ids, (image.channel_id, image.message_id)]
            )
        )
        expires_at = now + config.window_seconds

        await self.storage.append_incident(
            incident.id,
            user_ids=users,
            message_ids=messages,
            count=len(messages),
            last_activity_at=now,
            expires_at=expires_at,
        )
        await self.storage.mark_actioned([image.id], now)

        incident.user_ids = users
        incident.message_ids = messages
        incident.count = len(messages)
        incident.last_activity_at = now
        incident.expires_at = expires_at

        if incident.action == "delete" or incident.status == STATUS_WATCHING:
            deleted, gone, failed = await self._delete_refs(
                guild, [(image.channel_id, image.message_id)]
            )
            result = self._delete_summary(
                deleted, gone, failed, monitoring=True, window=config.window_seconds
            )
            await self.storage.set_status(incident.id, STATUS_WATCHING, result=result)
            incident.status = STATUS_WATCHING
            incident.result = result
            await self._publish_report(
                guild,
                config,
                incident,
                title="Удаление сообщений",
                result_text=result,
                color=COLOR_DELETE,
                allow_cancel=True,
            )
        else:
            await self._publish_alert(guild, config, incident)

    # --- действия -------------------------------------------------------
    async def _apply_action(
        self, guild: discord.Guild, config: GuildConfig, incident: Incident
    ) -> None:
        now = int(time.time())

        if incident.action == "ban":
            result, success = await self._ban_and_delete(guild, config, incident)
            status = STATUS_BANNED if success else STATUS_FAILED
            await self.storage.set_status(
                incident.id, status, result=result, resolved_at=now
            )
            incident.status = status
            incident.result = result
            incident.resolved_at = now
            await self._publish_report(
                guild,
                config,
                incident,
                title="Бан пользователей",
                result_text=result,
                color=COLOR_BAN,
            )

        elif incident.action == "delete":
            deleted, gone, failed = await self._delete_refs(
                guild, incident.message_ids
            )
            result = self._delete_summary(
                deleted, gone, failed, monitoring=True, window=config.window_seconds
            )
            await self.storage.set_status(
                incident.id, STATUS_WATCHING, result=result
            )
            incident.status = STATUS_WATCHING
            incident.result = result
            await self._publish_report(
                guild,
                config,
                incident,
                title="Удаление сообщений",
                result_text=result,
                color=COLOR_DELETE,
                allow_cancel=True,
            )

        else:
            alert = await self._publish_alert(guild, config, incident)
            status = STATUS_OPEN if alert else STATUS_FAILED
            result = (
                "Уведомление отправлено, ожидается решение."
                if alert
                else "Не удалось отправить уведомление."
            )
            await self.storage.set_status(incident.id, status, result=result)
            incident.status = status
            incident.result = result
            await self._publish_report(
                guild,
                config,
                incident,
                title="Уведомление",
                result_text=result,
                color=COLOR_NOTIFY,
            )

    async def _ban_and_delete(
        self,
        guild: discord.Guild,
        config: GuildConfig,
        incident: Incident,
    ) -> tuple[str, bool]:
        reason = (
            f"Повторяющиеся изображения: {incident.count} сообщений "
            f"(инцидент #{incident.id})"
        )
        banned: list[int] = []
        failed: list[int] = []
        now = int(time.time())
        unban_at = (
            now + config.ban_duration_seconds
            if config.ban_duration_seconds > 0
            else 0
        )

        for user_id in incident.user_ids:
            target = (
                guild.get_member(user_id)
                or self.get_user(user_id)
                or discord.Object(id=user_id)
            )
            try:
                await guild.ban(
                    target,
                    reason=reason[:512],
                    delete_message_seconds=min(config.window_seconds, 604800),
                )
                banned.append(user_id)
                try:
                    if unban_at:
                        await self.storage.upsert_ban(
                            guild_id=guild.id,
                            user_id=user_id,
                            incident_id=incident.id,
                            banned_at=now,
                            unban_at=unban_at,
                        )
                    else:
                        await self.storage.clear_ban(guild.id, user_id)
                except Exception:
                    log.exception(
                        "Не удалось сохранить временный бан %s", user_id
                    )
            except discord.HTTPException as exc:
                failed.append(user_id)
                self._warn(
                    guild.id,
                    f"Не удалось забанить {user_id}: {exc}",
                )

        deleted, gone, delete_failed = await self._delete_refs(
            guild, incident.message_ids
        )

        parts: list[str] = []
        if banned:
            parts.append("Забанены: " + ", ".join(f"<@{user_id}>" for user_id in banned))
        if failed:
            parts.append(
                "Не удалось забанить: "
                + ", ".join(f"<@{user_id}>" for user_id in failed)
            )
        if unban_at and banned:
            parts.append(
                f"Временный бан до <t:{unban_at}:R> "
                f"(<t:{unban_at}:f>)."
            )
        parts.append(
            f"Сообщения: удалено {deleted}, уже отсутствовали {gone}, "
            f"ошибок {delete_failed}."
        )
        return "\n".join(parts), bool(banned)

    async def _delete_refs(
        self, guild: discord.Guild, refs: list[tuple[int, int]]
    ) -> tuple[int, int, int]:
        deleted = gone = failed = 0

        for channel_id, message_id in refs:
            channel = self._find_channel(guild, channel_id)
            if not isinstance(channel, (discord.TextChannel, discord.Thread)):
                failed += 1
                continue
            try:
                await channel.get_partial_message(message_id).delete()
                deleted += 1
            except discord.NotFound:
                gone += 1
            except discord.HTTPException:
                failed += 1

        return deleted, gone, failed

    @staticmethod
    def _delete_summary(
        deleted: int,
        gone: int,
        failed: int,
        *,
        monitoring: bool,
        window: int,
    ) -> str:
        text = (
            f"Удалено: {deleted}. Уже отсутствовали: {gone}. "
            f"Ошибок: {failed}."
        )
        if monitoring:
            text += f" Мониторинг новых дубликатов: {format_duration(window)}."
        return text

    # --- публикация -----------------------------------------------------
    async def _publish_alert(
        self, guild: discord.Guild, config: GuildConfig, incident: Incident
    ) -> bool:
        embed = build_alert_embed(incident, config.window_seconds)
        if incident.alert_channel_id and incident.alert_message_id:
            if await self._edit_message(
                guild,
                incident.alert_channel_id,
                incident.alert_message_id,
                embed=embed,
            ):
                return True

        channel = self._find_channel(
            guild, config.notify_channel_id or config.report_channel_id
        )
        if not isinstance(channel, (discord.TextChannel, discord.Thread)):
            channel = self._find_channel(guild, config.report_channel_id)
        if not isinstance(channel, (discord.TextChannel, discord.Thread)):
            self._warn(guild.id, "Канал уведомлений не найден или недоступен")
            return False

        view = discord.ui.View(timeout=None)
        view.add_item(AlertDeleteButton(incident.id))
        view.add_item(AlertBanButton(incident.id))

        try:
            message = await channel.send(
                embed=embed,
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except discord.HTTPException as exc:
            self._warn(guild.id, f"Не удалось отправить уведомление: {exc}")
            return False

        await self.storage.set_alert_message(incident.id, channel.id, message.id)
        incident.alert_channel_id = channel.id
        incident.alert_message_id = message.id
        return True

    async def _publish_report(
        self,
        guild: discord.Guild,
        config: GuildConfig,
        incident: Incident,
        *,
        title: str,
        result_text: str,
        color: int,
        allow_cancel: bool = False,
        remove_view: bool = False,
    ) -> None:
        embed = build_report_embed(
            incident, title=title, result_text=result_text, color=color
        )

        cancel_view = None
        if allow_cancel:
            cancel_view = discord.ui.View(timeout=None)
            cancel_view.add_item(ReportCancelButton(incident.id))

        if remove_view:
            view_arg = None
        elif allow_cancel:
            view_arg = cancel_view
        else:
            view_arg = _UNSET

        if incident.report_channel_id and incident.report_message_id:
            if await self._edit_message(
                guild,
                incident.report_channel_id,
                incident.report_message_id,
                embed=embed,
                view=view_arg,
            ):
                return

        channel = self._find_channel(guild, config.report_channel_id)
        if not isinstance(channel, (discord.TextChannel, discord.Thread)):
            self._warn(guild.id, "Канал отчётов не найден или недоступен")
            return

        try:
            message = await channel.send(
                embed=embed,
                view=cancel_view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except discord.HTTPException as exc:
            self._warn(guild.id, f"Не удалось отправить отчёт: {exc}")
            return

        await self.storage.set_report_message(incident.id, channel.id, message.id)
        incident.report_channel_id = channel.id
        incident.report_message_id = message.id

    async def _edit_message(
        self,
        guild: discord.Guild,
        channel_id: int,
        message_id: int,
        *,
        embed: discord.Embed,
        view=_UNSET,
    ) -> bool:
        channel = self._find_channel(guild, channel_id)
        if not isinstance(channel, (discord.TextChannel, discord.Thread)):
            return False
        kwargs = {"embed": embed}
        if view is not _UNSET:
            kwargs["view"] = view
        try:
            await channel.get_partial_message(message_id).edit(**kwargs)
            return True
        except discord.HTTPException:
            return False

    def _find_channel(self, guild: discord.Guild, channel_id: Optional[int]):
        if not channel_id:
            return None
        channel = guild.get_channel(channel_id)
        if channel is None:
            channel = guild.get_thread(channel_id)
        return channel

    # --- завершение окон ------------------------------------------------
    async def _close_alert_window(
        self, guild: discord.Guild, incident: Incident
    ) -> None:
        now = int(time.time())
        fresh = await self.storage.get_incident(incident.id)
        if fresh is None or fresh.expires_at > now:
            return
        config = await self.storage.get_config(guild.id)
        updated = await self.storage.set_status(
            incident.id,
            incident.status,
            window_closed=True,
            expected_status=STATUS_OPEN,
        )
        if not updated:
            return
        if incident.alert_channel_id and incident.alert_message_id:
            embed = build_alert_embed(
                incident, config.window_seconds, closed=True
            )
            await self._edit_message(
                guild,
                incident.alert_channel_id,
                incident.alert_message_id,
                embed=embed,
            )

    async def _finish_delete_watch(
        self, guild: discord.Guild, incident: Incident
    ) -> None:
        now = int(time.time())
        fresh = await self.storage.get_incident(incident.id)
        if fresh is None or fresh.expires_at > now:
            return
        config = await self.storage.get_config(guild.id)
        result = (
            f"Окно истекло. Всего сообщений: {incident.count}. "
            "Мониторинг новых дубликатов остановлен."
        )
        updated = await self.storage.set_status(
            incident.id,
            STATUS_DELETED,
            result=result,
            resolved_at=now,
            window_closed=True,
            expected_status=STATUS_WATCHING,
        )
        if not updated:
            return
        incident.status = STATUS_DELETED
        incident.result = result
        incident.resolved_at = now
        await self._publish_report(
            guild,
            config,
            incident,
            title="Удаление завершено",
            result_text=result,
            color=COLOR_DELETE,
            remove_view=True,
        )

    async def _purge_old_hashes(self) -> None:
        if self.hash_retention_seconds <= 0:
            return
        cutoff = int(time.time()) - self.hash_retention_seconds
        try:
            removed_images = await self.storage.purge_images_before(cutoff)
            removed_incidents = await self.storage.purge_incidents_before(cutoff)
            removed_bans = await self.storage.purge_bans_before(cutoff)
        except Exception:
            log.exception("Не удалось очистить старые хеши")
            return
        if removed_images or removed_incidents or removed_bans:
            log.info(
                "Очистка хранения (%s): изображений %d, "
                "закрытых инцидентов %d, старых банов %d",
                format_duration(self.hash_retention_seconds),
                removed_images,
                removed_incidents,
                removed_bans,
            )

    @tasks.loop(hours=1)
    async def _cleanup_loop(self) -> None:
        await self._purge_old_hashes()

    async def _process_due_bans(self) -> None:
        now = int(time.time())
        try:
            due = await self.storage.due_bans(now)
        except Exception:
            log.exception("Не удалось получить баны для разбана")
            return

        for ban in due:
            guild = self.get_guild(ban.guild_id)
            if guild is None:
                continue
            try:
                await guild.unban(
                    discord.Object(id=ban.user_id),
                    reason="Временный бан истёк",
                )
            except discord.NotFound:
                await self.storage.mark_unbanned(ban.guild_id, ban.user_id)
            except discord.HTTPException as exc:
                await self.storage.mark_ban_attempt(
                    ban.guild_id, ban.user_id, now
                )
                log.warning(
                    "Не удалось разбанить %s на сервере %s: %s",
                    ban.user_id,
                    ban.guild_id,
                    exc,
                )
            else:
                await self.storage.mark_unbanned(ban.guild_id, ban.user_id)
                log.info(
                    "Временный бан истёк: %s на сервере %s",
                    ban.user_id,
                    ban.guild_id,
                )

    @tasks.loop(seconds=60)
    async def _unban_loop(self) -> None:
        await self._process_due_bans()

    @tasks.loop(seconds=30)
    async def _expiry_loop(self) -> None:
        now = int(time.time())
        try:
            incidents = await self.storage.expired_incidents(now)
        except Exception:
            log.exception("Не удалось получить истёкшие инциденты")
            return

        for incident in incidents:
            guild = self.get_guild(incident.guild_id)
            if guild is None:
                continue
            try:
                if incident.status == STATUS_OPEN:
                    await self._close_alert_window(guild, incident)
                elif incident.status == STATUS_WATCHING:
                    await self._finish_delete_watch(guild, incident)
            except Exception:
                log.exception("Не удалось завершить инцидент #%s", incident.id)

    # --- кнопки ---------------------------------------------------------
    async def handle_cancel_delete(
        self, interaction: discord.Interaction, incident_id: int
    ) -> None:
        if interaction.guild is None or not isinstance(
            interaction.user, discord.Member
        ):
            await interaction.response.send_message(
                "Действие доступно только на сервере.", ephemeral=True
            )
            return

        member = interaction.user
        guild = interaction.guild
        if not await self._is_allowed(member):
            await interaction.response.send_message(
                "У вас нет доступа к этому действию.", ephemeral=True
            )
            return
        permissions = member.guild_permissions
        if not (permissions.administrator or permissions.manage_messages):
            await interaction.response.send_message(
                "Нужно право «Управлять сообщениями».", ephemeral=True
            )
            return

        incident = await self.storage.get_incident(incident_id)
        if incident is None or incident.guild_id != guild.id:
            await interaction.response.send_message(
                "Инцидент не найден.", ephemeral=True
            )
            return
        if incident.status != STATUS_WATCHING:
            await interaction.response.send_message(
                "Удаление уже завершено.", ephemeral=True
            )
            return

        await interaction.response.defer(ephemeral=True, thinking=True)
        now = int(time.time())
        result = f"Удаление остановлено: <@{member.id}>."
        if not await self.storage.cancel_delete(
            incident.id, result=result, resolved_at=now
        ):
            await interaction.followup.send(
                "Удаление уже завершено.", ephemeral=True
            )
            return

        incident.status = STATUS_CANCELLED
        incident.result = result
        incident.resolved_at = now
        incident.window_closed = True
        config = await self.storage.get_config(guild.id)
        await self._publish_report(
            guild,
            config,
            incident,
            title="Удаление остановлено",
            result_text=result,
            color=COLOR_DELETE,
            remove_view=True,
        )
        await interaction.followup.send(
            "Мониторинг удаления остановлен.", ephemeral=True
        )

    async def handle_alert_action(
        self, interaction: discord.Interaction, incident_id: int, action: str
    ) -> None:
        if interaction.guild is None or not isinstance(
            interaction.user, discord.Member
        ):
            await interaction.response.send_message(
                "Действие доступно только на сервере.", ephemeral=True
            )
            return

        member = interaction.user
        guild = interaction.guild

        if not await self._is_allowed(member):
            await interaction.response.send_message(
                "У вас нет доступа к этому действию.", ephemeral=True
            )
            return

        permissions = member.guild_permissions
        if action == "ban" and not (
            permissions.administrator or permissions.ban_members
        ):
            await interaction.response.send_message(
                "Нужно право «Банить участников».", ephemeral=True
            )
            return
        if action == "delete" and not (
            permissions.administrator or permissions.manage_messages
        ):
            await interaction.response.send_message(
                "Нужно право «Управлять сообщениями».", ephemeral=True
            )
            return

        incident = await self.storage.get_incident(incident_id)
        if incident is None or incident.guild_id != guild.id:
            await interaction.response.send_message(
                "Инцидент не найден.", ephemeral=True
            )
            return
        if incident.status != STATUS_OPEN:
            await interaction.response.send_message(
                "Это уведомление уже обработано.", ephemeral=True
            )
            return

        if not await self.storage.claim_for_action(incident_id):
            await interaction.response.send_message(
                "Это уведомление уже обрабатывается.", ephemeral=True
            )
            return

        await interaction.response.defer(ephemeral=True, thinking=True)
        config = await self.storage.get_config(guild.id)
        now = int(time.time())

        try:
            if action == "ban":
                result, success = await self._ban_and_delete(
                    guild, config, incident
                )
                status = STATUS_BANNED if success else STATUS_FAILED
                title = "Бан пользователей"
                color = COLOR_BAN
            else:
                deleted, gone, failed = await self._delete_refs(
                    guild, incident.message_ids
                )
                result = self._delete_summary(
                    deleted, gone, failed, monitoring=False, window=0
                )
                status = STATUS_ACTIONED
                title = "Удаление сообщений"
                color = COLOR_DELETE

            await self.storage.set_status(
                incident.id, status, result=result, resolved_at=now
            )
            incident.status = status
            incident.result = result
            incident.resolved_at = now

            embed = build_alert_embed(
                incident, config.window_seconds, closed=True
            )
            embed.add_field(name="Результат", value=result[:1024], inline=False)
            if incident.alert_channel_id and incident.alert_message_id:
                await self._edit_message(
                    guild,
                    incident.alert_channel_id,
                    incident.alert_message_id,
                    embed=embed,
                    view=None,
                )
            elif interaction.message is not None:
                try:
                    await interaction.message.edit(embed=embed, view=None)
                except discord.HTTPException:
                    pass

            await self._publish_report(
                guild,
                config,
                incident,
                title=title,
                result_text=result,
                color=color,
            )
            await interaction.followup.send("Готово.", ephemeral=True)
        except Exception:
            log.exception("Ошибка обработки уведомления #%s", incident_id)
            await self.storage.set_status(
                incident.id, STATUS_OPEN, expected_status=STATUS_ACTIONING
            )
            await interaction.followup.send(
                "Не удалось выполнить действие. Подробности в логе.",
                ephemeral=True,
            )

    # --- доступ ---------------------------------------------------------
    @staticmethod
    def _is_owner(member: discord.Member) -> bool:
        guild = getattr(member, "guild", None)
        return guild is not None and getattr(guild, "owner_id", None) == getattr(
            member, "id", None
        )

    async def _is_allowed(self, member: discord.Member) -> bool:
        if self._is_owner(member) or member.guild_permissions.administrator:
            return True
        roles = await self.storage.get_roles(member.guild.id)
        member_role_ids = {role.id for role in member.roles}
        return bool(member_role_ids.intersection(roles))

    async def _require_allowed(
        self, interaction: discord.Interaction
    ) -> Optional[GuildConfig]:
        if interaction.guild is None or not isinstance(
            interaction.user, discord.Member
        ):
            await interaction.response.send_message(
                "Команда доступна только на сервере.", ephemeral=True
            )
            return None
        if not await self._is_allowed(interaction.user):
            await interaction.response.send_message(
                "У вас нет доступа к настройкам бота.", ephemeral=True
            )
            return None
        return await self.storage.get_config(interaction.guild.id)

    async def _require_admin(self, interaction: discord.Interaction) -> bool:
        if interaction.guild is None or not isinstance(
            interaction.user, discord.Member
        ):
            await interaction.response.send_message(
                "Команда доступна только на сервере.", ephemeral=True
            )
            return False
        if not (
            self._is_owner(interaction.user)
            or interaction.user.guild_permissions.administrator
        ):
            await interaction.response.send_message(
                "Эта команда доступна только администраторам и владельцу.",
                ephemeral=True,
            )
            return False
        return True

    # --- команды --------------------------------------------------------
    async def cmd_channels(
        self,
        interaction: discord.Interaction,
        report: discord.TextChannel,
        notify: Optional[discord.TextChannel],
    ) -> None:
        config = await self._require_allowed(interaction)
        if config is None:
            return
        guild = interaction.guild
        assert guild is not None

        if report.guild.id != guild.id or (
            notify is not None and notify.guild.id != guild.id
        ):
            await interaction.response.send_message(
                "Канал должен быть с этого сервера.", ephemeral=True
            )
            return

        problems = self._channel_problems(report)
        if notify is not None:
            problems.extend(self._channel_problems(notify))
        if problems:
            await interaction.response.send_message(
                "Не хватает прав: " + ", ".join(sorted(set(problems))),
                ephemeral=True,
            )
            return

        config.report_channel_id = report.id
        config.notify_channel_id = notify.id if notify else None
        await self.storage.save_config(config)

        if notify:
            text = (
                f"Отчёты: {report.mention}. "
                f"Уведомления: {notify.mention}."
            )
        else:
            text = (
                f"Отчёты и уведомления: {report.mention}."
            )
        await interaction.response.send_message(text, ephemeral=True)

    def _channel_problems(self, channel: discord.TextChannel) -> list[str]:
        me = channel.guild.me
        if me is None:
            return ["бот ещё не получил данные сервера"]
        permissions = channel.permissions_for(me)
        problems = []
        if not permissions.view_channel:
            problems.append("«Просмотр канала»")
        if not permissions.send_messages:
            problems.append("«Отправка сообщений»")
        if not permissions.embed_links:
            problems.append("«Встраивание ссылок»")
        return problems

    async def cmd_behavior(
        self,
        interaction: discord.Interaction,
        action: str,
        duration: Optional[str] = None,
    ) -> None:
        config = await self._require_allowed(interaction)
        if config is None:
            return
        if action not in ACTION_LABELS:
            await interaction.response.send_message(
                "Неизвестное действие.", ephemeral=True
            )
            return

        ignored_duration = False
        if action == "ban" and duration is not None:
            try:
                config.ban_duration_seconds = parse_ban_duration(duration)
            except ValueError as exc:
                await interaction.response.send_message(str(exc), ephemeral=True)
                return
        elif action != "ban" and duration is not None:
            ignored_duration = True

        config.action = action
        await self.storage.save_config(config)

        parts = [f"Новое действие при срабатывании: {ACTION_LABELS[action]}."]
        if action == "ban":
            parts.append(
                "Время бана: "
                + (
                    format_duration(config.ban_duration_seconds)
                    if config.ban_duration_seconds > 0
                    else "бессрочно"
                )
                + "."
            )
        if ignored_duration:
            parts.append(
                "Параметр duration применяется только к действию «Бан» "
                "и был проигнорирован."
            )
        parts.append("Изменение применяется к новым инцидентам.")

        await interaction.response.send_message(
            " ".join(parts), ephemeral=True
        )

    async def cmd_bans(self, interaction: discord.Interaction) -> None:
        config = await self._require_allowed(interaction)
        if config is None:
            return
        guild = interaction.guild
        assert guild is not None
        records = await self.storage.get_active_bans(guild.id)
        await interaction.response.send_message(
            embed=build_bans_embed(records), ephemeral=True
        )

    async def cmd_detection(
        self,
        interaction: discord.Interaction,
        count: int,
        window: str,
        cross_channel: bool,
        phash_distance: Optional[int],
        multi_user: Optional[bool],
    ) -> None:
        config = await self._require_allowed(interaction)
        if config is None:
            return

        if not MIN_THRESHOLD <= count <= MAX_THRESHOLD:
            await interaction.response.send_message(
                f"Порог должен быть от {MIN_THRESHOLD} до {MAX_THRESHOLD}.",
                ephemeral=True,
            )
            return
        try:
            window_seconds = parse_duration(window)
        except ValueError as exc:
            await interaction.response.send_message(str(exc), ephemeral=True)
            return
        if (
            self.hash_retention_seconds > 0
            and window_seconds > self.hash_retention_seconds
        ):
            await interaction.response.send_message(
                "Окно не может быть больше срока хранения хешей "
                f"({format_duration(self.hash_retention_seconds)}). "
                "Увеличьте `HASH_RETENTION_HOURS` в `.env`.",
                ephemeral=True,
            )
            return
        if phash_distance is not None and not 0 <= phash_distance <= MAX_PHASH_DISTANCE:
            await interaction.response.send_message(
                f"Допуск pHash должен быть от 0 до {MAX_PHASH_DISTANCE}.",
                ephemeral=True,
            )
            return

        config.threshold_count = count
        config.window_seconds = window_seconds
        config.cross_channel_only = cross_channel
        if phash_distance is not None:
            config.phash_distance = phash_distance
        if multi_user is not None:
            config.multi_user = multi_user
        await self.storage.save_config(config)

        await interaction.response.send_message(
            "Настройки обнаружения обновлены:\n"
            f"• порог: {config.threshold_count} сообщений;\n"
            f"• окно: {format_duration(config.window_seconds)};\n"
            f"• только разные каналы: {'да' if config.cross_channel_only else 'нет'};\n"
            f"• несколько пользователей: {'да' if config.multi_user else 'нет'};\n"
            f"• допуск pHash: {config.phash_distance} бит.",
            ephemeral=True,
        )

    async def cmd_settings(self, interaction: discord.Interaction) -> None:
        config = await self._require_allowed(interaction)
        if config is None:
            return
        guild = interaction.guild
        assert guild is not None

        roles = await self.storage.get_roles(guild.id)
        excluded = await self.storage.get_excluded_roles(guild.id)
        stats = await self.storage.stats(guild.id)
        report_channel = self._find_channel(guild, config.report_channel_id)
        notify_channel = self._find_channel(guild, config.notify_channel_id)

        embed = build_settings_embed(
            config,
            roles,
            stats,
            report_channel=report_channel,
            notify_channel=notify_channel,
            excluded_role_ids=excluded,
            hash_retention_seconds=self.hash_retention_seconds,
            ban_duration_seconds=config.ban_duration_seconds,
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

    async def cmd_roles_add(
        self, interaction: discord.Interaction, role: discord.Role
    ) -> None:
        if not await self._require_admin(interaction):
            return
        if role.is_default():
            await interaction.response.send_message(
                "Роль @everyone нельзя добавить: это даст доступ всем.",
                ephemeral=True,
            )
            return

        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        assert guild is not None
        await self.storage.add_role(guild.id, role.id)
        await interaction.followup.send(
            f"Роль {role.mention} получила доступ к боту.", ephemeral=True
        )

    async def cmd_roles_remove(
        self, interaction: discord.Interaction, role: discord.Role
    ) -> None:
        if not await self._require_admin(interaction):
            return

        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        assert guild is not None
        await self.storage.remove_role(guild.id, role.id)
        await interaction.followup.send(
            f"Роль {role.mention} больше не имеет доступа.", ephemeral=True
        )

    async def cmd_roles_clear(self, interaction: discord.Interaction) -> None:
        if not await self._require_admin(interaction):
            return

        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        assert guild is not None
        await self.storage.clear_roles(guild.id)
        await interaction.followup.send(
            "Список ролей очищен. Доступ остался только у администраторов.",
            ephemeral=True,
        )

    async def cmd_roles_list(self, interaction: discord.Interaction) -> None:
        if not await self._require_admin(interaction):
            return
        guild = interaction.guild
        assert guild is not None
        roles = await self.storage.get_roles(guild.id)
        if not roles:
            text = "Настроенных ролей нет. Доступ только у администраторов."
        else:
            text = "\n".join(
                f"<@&{role_id}>" for role_id in roles
            )
        await interaction.response.send_message(text, ephemeral=True)

    async def cmd_roles_exclude(
        self, interaction: discord.Interaction, role: discord.Role
    ) -> None:
        if not await self._require_admin(interaction):
            return
        if role.is_default():
            await interaction.response.send_message(
                "Роль @everyone нельзя исключить: бот перестанет проверять всех.",
                ephemeral=True,
            )
            return

        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        assert guild is not None
        await self.storage.add_excluded_role(guild.id, role.id)
        self._excluded_roles.pop(guild.id, None)
        await interaction.followup.send(
            f"Сообщения роли {role.mention} больше не проверяются.",
            ephemeral=True,
        )

    async def cmd_roles_include(
        self, interaction: discord.Interaction, role: discord.Role
    ) -> None:
        if not await self._require_admin(interaction):
            return

        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        assert guild is not None
        await self.storage.remove_excluded_role(guild.id, role.id)
        self._excluded_roles.pop(guild.id, None)
        await interaction.followup.send(
            f"Сообщения роли {role.mention} снова проверяются.",
            ephemeral=True,
        )

    async def cmd_roles_excluded(self, interaction: discord.Interaction) -> None:
        if not await self._require_admin(interaction):
            return
        guild = interaction.guild
        assert guild is not None
        roles = await self.storage.get_excluded_roles(guild.id)
        if not roles:
            text = "Ролей-исключений нет."
        else:
            text = "\n".join(f"<@&{role_id}>" for role_id in roles)
        await interaction.response.send_message(text, ephemeral=True)

    # --- утилиты --------------------------------------------------------
    def _warn(self, guild_id: int, text: str) -> None:
        key = (guild_id, text)
        now = time.monotonic()
        if now - self._warned_at.get(key, 0.0) < 300:
            return
        self._warned_at[key] = now
        log.warning(text)


def register_commands(bot: DuplicateGuardBot) -> None:
    tree = bot.tree

    @tree.command(
        name="channels",
        description="Выбрать канал отчётов и канал уведомлений",
    )
    @app_commands.describe(
        report="Канал для отчётов о результатах",
        notify="Канал для уведомлений с кнопками (по умолчанию — канал отчётов)",
    )
    @app_commands.guild_only()
    async def channels(
        interaction: discord.Interaction,
        report: discord.TextChannel,
        notify: Optional[discord.TextChannel] = None,
    ) -> None:
        await bot.cmd_channels(interaction, report, notify)

    @tree.command(
        name="behavior",
        description="Что делать при обнаружении повторяющихся изображений",
    )
    @app_commands.choices(
        action=[
            app_commands.Choice(name="Бан", value="ban"),
            app_commands.Choice(name="Удаление сообщений", value="delete"),
            app_commands.Choice(name="Уведомление", value="notify"),
        ]
    )
    @app_commands.describe(
        action="Действие при срабатывании",
        duration=(
            "Только для действия «Бан»: 7d, 12h или 0/навсегда; "
            "пусто — не менять текущее значение"
        ),
    )
    @app_commands.guild_only()
    async def behavior(
        interaction: discord.Interaction,
        action: app_commands.Choice[str],
        duration: Optional[str] = None,
    ) -> None:
        await bot.cmd_behavior(interaction, action.value, duration)

    @tree.command(
        name="detection",
        description="Настроить порог, окно и поиск совпадений",
    )
    @app_commands.describe(
        count="Сколько сообщений с одинаковым изображением нужно для срабатывания",
        window="Окно времени: 45s, 30m, 2h, 1d (без единицы — минуты)",
        cross_channel="Считать только совпадения в разных каналах",
        phash_distance="Допуск pHash 0–64 (0 — только точный pHash)",
        multi_user="Считать сообщения нескольких пользователей",
    )
    @app_commands.guild_only()
    async def detection(
        interaction: discord.Interaction,
        count: app_commands.Range[int, 2, 100],
        window: str,
        cross_channel: bool,
        phash_distance: Optional[int] = None,
        multi_user: Optional[bool] = None,
    ) -> None:
        await bot.cmd_detection(
            interaction,
            count,
            window,
            cross_channel,
            phash_distance,
            multi_user,
        )

    @tree.command(name="settings", description="Показать настройки и статистику")
    @app_commands.guild_only()
    async def settings(interaction: discord.Interaction) -> None:
        await bot.cmd_settings(interaction)

    @tree.command(
        name="bans", description="Показать активные временные баны"
    )
    @app_commands.guild_only()
    async def bans(interaction: discord.Interaction) -> None:
        await bot.cmd_bans(interaction)

    roles_group = app_commands.Group(
        name="roles",
        description="Роли доступа и роли-исключения",
        default_permissions=discord.Permissions(administrator=True),
        guild_only=True,
    )

    @roles_group.command(name="add", description="Добавить роль")
    @app_commands.describe(role="Роль, которой нужен доступ")
    @app_commands.default_permissions(administrator=True)
    async def roles_add(
        interaction: discord.Interaction, role: discord.Role
    ) -> None:
        await bot.cmd_roles_add(interaction, role)

    @roles_group.command(name="remove", description="Убрать роль")
    @app_commands.describe(role="Роль, у которой нужно забрать доступ")
    @app_commands.default_permissions(administrator=True)
    async def roles_remove(
        interaction: discord.Interaction, role: discord.Role
    ) -> None:
        await bot.cmd_roles_remove(interaction, role)

    @roles_group.command(name="list", description="Показать роли с доступом")
    @app_commands.default_permissions(administrator=True)
    async def roles_list(interaction: discord.Interaction) -> None:
        await bot.cmd_roles_list(interaction)

    @roles_group.command(name="clear", description="Убрать все роли")
    @app_commands.default_permissions(administrator=True)
    async def roles_clear(interaction: discord.Interaction) -> None:
        await bot.cmd_roles_clear(interaction)

    @roles_group.command(
        name="exclude", description="Не проверять сообщения этой роли"
    )
    @app_commands.describe(role="Роль, чьи сообщения бот должен игнорировать")
    @app_commands.default_permissions(administrator=True)
    async def roles_exclude(
        interaction: discord.Interaction, role: discord.Role
    ) -> None:
        await bot.cmd_roles_exclude(interaction, role)

    @roles_group.command(
        name="include", description="Снова проверять сообщения этой роли"
    )
    @app_commands.describe(role="Роль, которую нужно убрать из исключений")
    @app_commands.default_permissions(administrator=True)
    async def roles_include(
        interaction: discord.Interaction, role: discord.Role
    ) -> None:
        await bot.cmd_roles_include(interaction, role)

    @roles_group.command(
        name="excluded", description="Показать роли-исключения"
    )
    @app_commands.default_permissions(administrator=True)
    async def roles_excluded(interaction: discord.Interaction) -> None:
        await bot.cmd_roles_excluded(interaction)

    tree.add_command(roles_group)

    @tree.error
    async def on_app_command_error(
        interaction: discord.Interaction, error: app_commands.AppCommandError
    ) -> None:
        log.error(
            "Ошибка выполнения команды /%s",
            getattr(interaction.command, "name", "?"),
            exc_info=(type(error), error, error.__traceback__),
        )
        text = "Не удалось выполнить команду. Подробности — в логе бота."
        try:
            if interaction.response.is_done():
                await interaction.followup.send(text, ephemeral=True)
            else:
                await interaction.response.send_message(text, ephemeral=True)
        except discord.HTTPException:
            pass


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    token = os.getenv("DISCORD_TOKEN", "").strip()
    if not token:
        raise SystemExit(
            "Не задан DISCORD_TOKEN. Скопируйте .env.example в .env и вставьте токен бота."
        )

    raw_max_mb = os.getenv("MAX_DOWNLOAD_MB", str(DEFAULT_MAX_DOWNLOAD_MB))
    try:
        max_download_mb = float(raw_max_mb)
    except ValueError as exc:
        raise SystemExit(
            f"MAX_DOWNLOAD_MB должен быть числом, а не {raw_max_mb!r}"
        ) from exc
    if max_download_mb <= 0:
        raise SystemExit("MAX_DOWNLOAD_MB должен быть больше нуля")

    retention_hours = _env_int("HASH_RETENTION_HOURS", 24)
    if retention_hours is None:
        retention_hours = 24
    if retention_hours < 0:
        raise SystemExit("HASH_RETENTION_HOURS не может быть отрицательным")

    bot = DuplicateGuardBot(
        storage=Storage(os.getenv("DATABASE_PATH", "data/guard.sqlite3")),
        ignore_bots=_env_bool("IGNORE_BOTS", True),
        max_download_bytes=int(max_download_mb * 1024 * 1024),
        concurrency=_env_int("MAX_CONCURRENT_HASHES", DEFAULT_CONCURRENCY)
        or DEFAULT_CONCURRENCY,
        hash_retention_seconds=retention_hours * 3600,
    )
    bot.run(token, log_handler=None)


if __name__ == "__main__":
    main()

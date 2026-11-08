"""Сборка embed-сообщений для отчётов, уведомлений и настроек."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Optional

import discord

from models import (
    ACTION_LABELS,
    BanRecord,
    GuildConfig,
    Incident,
    format_duration,
    plural,
)
from sanitize import safe_image_url, sanitize_text

COLOR_ALERT = 0xE67E22
COLOR_BAN = 0xE74C3C
COLOR_DELETE = 0x3498DB
COLOR_NOTIFY = 0x5865F2
COLOR_SETTINGS = 0x2ECC71
MAX_USER_MENTIONS = 20


def format_users(user_ids: Iterable[int], limit: int = MAX_USER_MENTIONS) -> str:
    ids = list(dict.fromkeys(user_ids))
    if not ids:
        return "неизвестно"
    shown = [f"<@{user_id}>" for user_id in ids[:limit]]
    if len(ids) > limit:
        shown.append(f"и ещё {len(ids) - limit}")
    return "\n".join(shown)


def format_links(
    guild_id: int, message_ids: Iterable[tuple[int, int]], limit: int = 8
) -> str:
    refs = list(message_ids)
    if not refs:
        return "—"

    lines = []
    for channel_id, message_id in refs[:limit]:
        url = f"https://discord.com/channels/{guild_id}/{channel_id}/{message_id}"
        lines.append(f"• [сообщение]({url}) в <#{channel_id}>")
    if len(refs) > limit:
        lines.append(f"• и ещё {len(refs) - limit}")
    return "\n".join(lines)


def _message_count_text(count: int) -> str:
    return f"{count} {plural(count, 'сообщение', 'сообщения', 'сообщений')}"


def build_alert_embed(
    incident: Incident,
    window_seconds: int,
    *,
    closed: bool = False,
) -> discord.Embed:
    """Уведомление с живым счётчиком и кнопками."""
    embed = discord.Embed(
        title="⚠️ Повторяющиеся изображения",
        colour=COLOR_ALERT,
        timestamp=datetime.now(timezone.utc),
    )
    description = (
        f"Обнаружено **{_message_count_text(incident.count)}** "
        "с одинаковым или похожим изображением."
    )
    if closed:
        description += "\nПриём новых сообщений по этому инциденту завершён."
    embed.description = description

    embed.add_field(
        name="Пользователи",
        value=format_users(incident.user_ids),
        inline=False,
    )
    embed.add_field(name="Сообщений", value=str(incident.count), inline=True)
    filename = sanitize_text(incident.filename, 200)
    if filename:
        embed.add_field(name="Файл", value=filename, inline=True)
    window_text = (
        "приём завершён"
        if closed
        else f"продлевается; сейчас до <t:{incident.expires_at}:R>"
    )
    embed.add_field(name="Окно", value=window_text, inline=True)
    embed.add_field(
        name="Ссылки",
        value=format_links(incident.guild_id, incident.message_ids),
        inline=False,
    )

    thumbnail = safe_image_url(incident.image_url)
    if thumbnail:
        embed.set_thumbnail(url=thumbnail)
    embed.set_footer(
        text=f"Инцидент #{incident.id} · действие: {ACTION_LABELS.get(incident.action, incident.action)}"
    )
    return embed


def build_report_embed(
    incident: Incident,
    *,
    title: str,
    result_text: str,
    color: int,
) -> discord.Embed:
    """Отчёт о результате действия."""
    embed = discord.Embed(
        title=title,
        colour=color,
        timestamp=datetime.now(timezone.utc),
    )
    embed.add_field(
        name="Пользователи",
        value=format_users(incident.user_ids),
        inline=False,
    )
    embed.add_field(name="Сообщений", value=str(incident.count), inline=True)
    filename = sanitize_text(incident.filename, 200)
    if filename:
        embed.add_field(name="Файл", value=filename, inline=True)
    embed.add_field(
        name="Окно",
        value=format_duration(max(0, incident.expires_at - incident.created_at)),
        inline=True,
    )
    embed.add_field(name="Результат", value=result_text, inline=False)
    embed.add_field(
        name="Ссылки",
        value=format_links(incident.guild_id, incident.message_ids),
        inline=False,
    )

    thumbnail = safe_image_url(incident.image_url)
    if thumbnail:
        embed.set_thumbnail(url=thumbnail)
    embed.set_footer(
        text=f"Инцидент #{incident.id} · {ACTION_LABELS.get(incident.action, incident.action)}"
    )
    return embed


def build_settings_embed(
    config: GuildConfig,
    role_ids: Iterable[int],
    stats: dict[str, int],
    *,
    report_channel: Optional[discord.abc.GuildChannel] = None,
    notify_channel: Optional[discord.abc.GuildChannel] = None,
    excluded_role_ids: Iterable[int] = (),
    hash_retention_seconds: int = 0,
    ban_duration_seconds: int = 0,
) -> discord.Embed:
    embed = discord.Embed(
        title="Настройки защиты от дубликатов",
        colour=COLOR_SETTINGS,
    )

    if report_channel is not None:
        report_value = report_channel.mention
    elif config.report_channel_id:
        report_value = f"канал `{config.report_channel_id}` недоступен"
    else:
        report_value = "не выбран — обнаружение отключено"
    embed.add_field(name="Канал отчётов", value=report_value, inline=True)

    if notify_channel is not None:
        notify_value = notify_channel.mention
    elif config.notify_channel_id:
        notify_value = f"канал `{config.notify_channel_id}` недоступен"
    else:
        notify_value = "как канал отчётов"
    embed.add_field(name="Канал уведомлений", value=notify_value, inline=True)

    embed.add_field(
        name="Действие",
        value=ACTION_LABELS.get(config.action, config.action),
        inline=True,
    )
    embed.add_field(
        name="Порог",
        value=(
            f"{config.threshold_count} "
            f"{plural(config.threshold_count, 'сообщение', 'сообщения', 'сообщений')}"
        ),
        inline=True,
    )
    embed.add_field(
        name="Окно",
        value=format_duration(config.window_seconds),
        inline=True,
    )
    embed.add_field(
        name="Только разные каналы",
        value="да" if config.cross_channel_only else "нет",
        inline=True,
    )
    embed.add_field(
        name="Несколько пользователей",
        value="да" if config.multi_user else "нет",
        inline=True,
    )
    embed.add_field(
        name="Допуск pHash",
        value=f"{config.phash_distance} бит",
        inline=True,
    )
    embed.add_field(
        name="Хранение хешей",
        value=(
            format_duration(hash_retention_seconds)
            if hash_retention_seconds > 0
            else "без ограничения"
        ),
        inline=True,
    )
    embed.add_field(
        name="Время бана",
        value=(
            format_duration(ban_duration_seconds)
            if ban_duration_seconds > 0
            else "бессрочно"
        ),
        inline=True,
    )

    roles = list(dict.fromkeys(role_ids))
    if roles:
        role_value = "\n".join(f"<@&{role_id}>" for role_id in roles[:20])
        if len(roles) > 20:
            role_value += f"\nи ещё {len(roles) - 20}"
    else:
        role_value = "не настроены (доступ только у администраторов)"
    embed.add_field(name="Роли с доступом", value=role_value, inline=False)

    excluded = list(dict.fromkeys(excluded_role_ids))
    if excluded:
        excluded_value = "\n".join(f"<@&{role_id}>" for role_id in excluded[:20])
        if len(excluded) > 20:
            excluded_value += f"\nи ещё {len(excluded) - 20}"
    else:
        excluded_value = "нет"
    embed.add_field(
        name="Роли-исключения", value=excluded_value, inline=False
    )

    embed.add_field(
        name="Статистика",
        value=(
            f"Изображений: {stats.get('images', 0)}\n"
            f"Инцидентов: {stats.get('incidents', 0)}"
        ),
        inline=False,
    )
    embed.set_footer(text="Хеши хранятся только в локальной базе и не публикуются")
    return embed


def build_bans_embed(records: Iterable[BanRecord]) -> discord.Embed:
    bans = list(records)
    embed = discord.Embed(title="Временные баны", colour=COLOR_BAN)
    if not bans:
        embed.description = "Активных временных банов нет."
        return embed

    lines = [
        f"<@{ban.user_id}> — до <t:{ban.unban_at}:R> "
        f"(<t:{ban.unban_at}:f>)"
        for ban in bans[:20]
    ]
    if len(bans) > 20:
        lines.append(f"и ещё {len(bans) - 20}")
    embed.description = "\n".join(lines)
    embed.set_footer(text=f"Всего активных: {len(bans)}")
    return embed

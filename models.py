"""Модели данных и общие константы."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

DEFAULT_ACTION = "notify"
DEFAULT_THRESHOLD = 3
DEFAULT_WINDOW_SECONDS = 60
DEFAULT_PHASH_DISTANCE = 8
MIN_THRESHOLD = 2
MAX_THRESHOLD = 100
MIN_WINDOW_SECONDS = 60
MAX_WINDOW_SECONDS = 30 * 24 * 3600
MAX_PHASH_DISTANCE = 64

ACTION_LABELS = {
    "ban": "бан",
    "delete": "удаление сообщений",
    "notify": "уведомление",
}

ACTION_TITLES = {
    "ban": "Бан пользователей",
    "delete": "Удаление сообщений",
    "notify": "Уведомление",
}

# Статусы инцидентов.
STATUS_OPEN = "open"          # уведомление отправлено, кнопки активны
STATUS_WATCHING = "watching"  # удаление и мониторинг новых дубликатов
STATUS_ACTIONING = "actioning"  # идёт обработка нажатия кнопки
STATUS_BANNED = "banned"
STATUS_DELETED = "deleted"
STATUS_ACTIONED = "actioned"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"
STATUS_MERGED = "merged"


@dataclass(slots=True)
class GuildConfig:
    guild_id: int
    report_channel_id: Optional[int] = None
    notify_channel_id: Optional[int] = None
    action: str = DEFAULT_ACTION
    threshold_count: int = DEFAULT_THRESHOLD
    window_seconds: int = DEFAULT_WINDOW_SECONDS
    cross_channel_only: bool = False
    phash_distance: int = DEFAULT_PHASH_DISTANCE
    multi_user: bool = False
    ban_duration_seconds: int = 0


@dataclass(slots=True)
class BanRecord:
    guild_id: int
    user_id: int
    unban_at: int
    banned_at: int
    incident_id: Optional[int] = None
    active: bool = True
    last_attempt_at: int = 0


@dataclass(slots=True)
class ImageRecord:
    id: int
    guild_id: int
    attachment_id: int
    message_id: int
    channel_id: int
    user_id: int
    filename: Optional[str]
    sha256: str
    phash: str
    attachment_url: Optional[str]
    created_at: int


@dataclass(frozen=True, slots=True)
class IncidentImage:
    sha256: str
    phash: str
    filename: Optional[str] = None
    image_url: Optional[str] = None


@dataclass(slots=True)
class Incident:
    id: int
    guild_id: int
    action: str
    status: str
    sha256: str
    phash: str
    filename: Optional[str]
    image_url: Optional[str]
    user_ids: list[int] = field(default_factory=list)
    message_ids: list[tuple[int, int]] = field(default_factory=list)
    count: int = 0
    created_at: int = 0
    last_activity_at: int = 0
    expires_at: int = 0
    alert_channel_id: Optional[int] = None
    alert_message_id: Optional[int] = None
    report_channel_id: Optional[int] = None
    report_message_id: Optional[int] = None
    result: Optional[str] = None
    window_closed: bool = False
    resolved_at: Optional[int] = None
    images: list[IncidentImage] = field(default_factory=list)


_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhdсчмд]?)\s*$", re.IGNORECASE)
_DURATION_UNITS = {
    "": 60,          # без единицы — минуты
    "s": 1,
    "с": 1,
    "m": 60,
    "м": 60,
    "h": 3600,
    "ч": 3600,
    "d": 86400,
    "д": 86400,
}
_PERMANENT_BAN_VALUES = frozenset(
    {"0", "off", "never", "permanent", "навсегда", "постоянно"}
)


def parse_duration(value: str) -> int:
    """Разбирает строку вида ``30m``, ``2h``, ``1d`` или ``45`` (минуты)."""
    match = _DURATION_RE.match(value or "")
    if not match:
        raise ValueError(
            "Не понял время. Примеры: 45s, 30m, 2h, 1d. Без единицы — минуты."
        )

    amount = int(match.group(1))
    unit = match.group(2).lower()
    seconds = amount * _DURATION_UNITS[unit]

    if seconds < MIN_WINDOW_SECONDS:
        raise ValueError("Минимальное окно — 60 секунд.")
    if seconds > MAX_WINDOW_SECONDS:
        raise ValueError("Максимальное окно — 30 дней.")
    return seconds


def parse_ban_duration(value: str) -> int:
    """Длительность бана: ``7d``, ``12h`` или ``0``/``навсегда``."""
    text = (value or "").strip().lower()
    if text in _PERMANENT_BAN_VALUES:
        return 0
    return parse_duration(text)


def format_duration(seconds: int) -> str:
    seconds = max(0, int(seconds))
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, secs = divmod(remainder, 60)

    parts: list[str] = []
    if days:
        parts.append(f"{days} д")
    if hours:
        parts.append(f"{hours} ч")
    if minutes:
        parts.append(f"{minutes} мин")
    if secs and not parts:
        parts.append(f"{secs} с")
    return " ".join(parts[:2]) or "0 с"


def plural(count: int, one: str, few: str, many: str) -> str:
    count = abs(int(count)) % 100
    if 11 <= count <= 19:
        return many
    count %= 10
    if count == 1:
        return one
    if 2 <= count <= 4:
        return few
    return many

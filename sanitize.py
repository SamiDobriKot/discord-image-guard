"""Очистка данных, попадающих в embed-сообщения.

Пользовательские значения (имена файлов, описания, ссылки) не должны
превращаться в разметку или подменять ссылки. Превью разрешено только
с Discord CDN.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

import discord

_CONTROL_CHARS = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f"
    r"\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]"
)
_WHITESPACE = re.compile(r"\s+")
_MASS_MENTIONS = re.compile(r"@(everyone|here)", re.IGNORECASE)

_ALLOWED_HOSTS = frozenset({"cdn.discordapp.com", "media.discordapp.net"})
_ALLOWED_PATH_PREFIXES = ("/attachments/", "/ephemeral-attachments/")


def sanitize_text(value: object, max_length: int = 256) -> str:
    """Убирает управляющие символы и экранирует markdown/упоминания."""
    if value is None:
        return ""
    text = _CONTROL_CHARS.sub("", str(value))
    text = _WHITESPACE.sub(" ", text).strip()
    text = discord.utils.escape_markdown(text)
    text = _MASS_MENTIONS.sub("@\u200b\\1", text)
    # Discord не экранирует ссылки и autolink-скобки в escape_markdown.
    text = text.replace("[", r"\[").replace("]", r"\]")
    text = text.replace("<", r"\<").replace(">", r"\>")
    return text[:max_length].rstrip()


def safe_image_url(value: object) -> str | None:
    """Возвращает URL, только если это https-вложение Discord CDN."""
    if not isinstance(value, str) or not value:
        return None
    if any(char.isspace() for char in value):
        return None

    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return None

    if parsed.scheme != "https":
        return None
    if parsed.username or parsed.password:
        return None
    if port not in (None, 443):
        return None

    host = (parsed.hostname or "").lower()
    if host not in _ALLOWED_HOSTS:
        return None
    if not parsed.path.startswith(_ALLOWED_PATH_PREFIXES):
        return None
    if ".." in parsed.path.split("/"):
        return None

    return value

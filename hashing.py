"""Вычисление SHA-256 и pHash для изображений-вложений Discord."""

from __future__ import annotations

import hashlib
import io
import logging
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import imagehash
from PIL import Image, UnidentifiedImageError

log = logging.getLogger(__name__)

# Защита от «бомб» декомпрессии: предупреждение после 64 Мп, ошибка после 128 Мп.
Image.MAX_IMAGE_PIXELS = 64_000_000

IMAGE_EXTENSIONS = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".jfif",
        ".gif",
        ".webp",
        ".bmp",
        ".tif",
        ".tiff",
        ".avif",
        ".ico",
        ".heic",
        ".heif",
    }
)

# SVG и подобное Pillow открыть не сможет — такие вложения не считаем изображениями.
UNSUPPORTED_CONTENT_TYPES = frozenset({"image/svg+xml"})

# Discord иногда отдаёт такой тип для файлов, которые не смог распознать.
GENERIC_CONTENT_TYPES = frozenset({"application/octet-stream", "binary/octet-stream"})


class AttachmentLike(Protocol):
    """Минимум полей discord.Attachment, нужный для проверки типа файла."""

    filename: str | None
    content_type: str | None


class HashingError(Exception):
    """Не удалось прочитать изображение или посчитать его хэши."""


@dataclass(frozen=True, slots=True)
class ImageHashes:
    sha256: str
    phash: str
    width: int
    height: int
    image_format: str


def is_image_attachment(attachment: AttachmentLike) -> bool:
    """Является ли вложение изображением, которое умеет открывать Pillow."""
    content_type = (attachment.content_type or "").split(";", 1)[0].strip().lower()
    if content_type in UNSUPPORTED_CONTENT_TYPES:
        return False
    if content_type and content_type not in GENERIC_CONTENT_TYPES:
        return content_type.startswith("image/")
    # Тип не пришёл или он общий — тогда смотрим на расширение.
    return Path(attachment.filename or "").suffix.lower() in IMAGE_EXTENSIONS


def _flatten_to_rgb(image: Image.Image) -> Image.Image:
    """Приводит изображение к RGB, заменяя прозрачность белым фоном."""
    if image.mode == "RGB":
        return image
    has_alpha = image.mode in {"RGBA", "LA", "PA"} or (
        image.mode == "P" and "transparency" in image.info
    )
    if not has_alpha:
        return image.convert("RGB")
    rgba = image.convert("RGBA")
    background = Image.new("RGB", rgba.size, (255, 255, 255))
    background.paste(rgba, mask=rgba.getchannel("A"))
    return background


def compute_hashes(data: bytes) -> ImageHashes:
    """Считает SHA-256 (от исходных байтов) и pHash (64 бита, hex-строка)."""
    if not data:
        raise HashingError("пустой файл")

    sha256 = hashlib.sha256(data).hexdigest()

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as image:
                image_format = (image.format or "unknown").upper()
                width, height = image.size
                phash = str(imagehash.phash(_flatten_to_rgb(image)))
    except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        raise HashingError("изображение слишком большое") from exc
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise HashingError(f"не удалось прочитать изображение: {exc}") from exc

    return ImageHashes(
        sha256=sha256,
        phash=phash,
        width=width,
        height=height,
        image_format=image_format,
    )

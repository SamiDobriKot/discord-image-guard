"""Сравнение изображений по SHA-256 и pHash."""

from __future__ import annotations

from typing import Iterable, Sequence

from models import ImageRecord, Incident


def phash_distance(first: str, second: str) -> int:
    """Расстояние Хэмминга между двумя 64-битными pHash."""
    if len(first) != len(second):
        raise ValueError("pHash должны быть одинаковой длины")
    return (int(first, 16) ^ int(second, 16)).bit_count()


def images_match(first: ImageRecord, second: ImageRecord, tolerance: int) -> bool:
    """Сначала точное совпадение SHA-256, затем похожесть pHash."""
    if first.sha256 == second.sha256:
        return True
    try:
        return phash_distance(first.phash, second.phash) <= tolerance
    except ValueError:
        return False


def select_cluster(
    current: ImageRecord,
    recent: Sequence[ImageRecord],
    tolerance: int,
) -> list[ImageRecord]:
    """Все недавние изображения, совпавшие с текущим по SHA или pHash."""
    result: list[ImageRecord] = [current]
    seen: set[int] = {current.id}

    for image in recent:
        if image.id in seen or image.attachment_id == current.attachment_id:
            continue
        if images_match(current, image, tolerance):
            result.append(image)
            seen.add(image.id)

    result.sort(key=lambda item: (item.created_at, item.id))
    return result


def unique_messages(images: Iterable[ImageRecord]) -> list[tuple[int, int]]:
    """Уникальные пары (channel_id, message_id), в порядке появления."""
    seen: set[tuple[int, int]] = set()
    result: list[tuple[int, int]] = []
    for image in images:
        key = (image.channel_id, image.message_id)
        if key not in seen:
            seen.add(key)
            result.append(key)
    return result


def unique_users(images: Iterable[ImageRecord]) -> list[int]:
    seen: set[int] = set()
    result: list[int] = []
    for image in images:
        if image.user_id not in seen:
            seen.add(image.user_id)
            result.append(image.user_id)
    return result


def unique_channels(images: Iterable[ImageRecord]) -> set[int]:
    return {image.channel_id for image in images}


def cluster_qualifies(
    images: Sequence[ImageRecord],
    threshold_count: int,
    cross_channel_only: bool,
) -> bool:
    messages = unique_messages(images)
    if len(messages) < max(2, threshold_count):
        return False
    if cross_channel_only and len(unique_channels(images)) < 2:
        return False
    return True


def incident_matches(
    incident: Incident,
    image: ImageRecord,
    tolerance: int,
    multi_user: bool,
) -> bool:
    if not multi_user and image.user_id not in incident.user_ids:
        return False
    if incident.sha256 == image.sha256:
        return True
    try:
        return phash_distance(incident.phash, image.phash) <= tolerance
    except ValueError:
        return False

"""Сравнение изображений по SHA-256 и pHash."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from models import ImageRecord, Incident, IncidentImage


@dataclass(slots=True)
class MessageGroup:
    message_id: int
    channel_id: int
    user_id: int
    created_at: int
    images: list[ImageRecord]


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


def unique_images_by_sha(images: Iterable[ImageRecord]) -> list[ImageRecord]:
    seen: set[str] = set()
    result: list[ImageRecord] = []
    for image in images:
        if image.sha256 in seen:
            continue
        seen.add(image.sha256)
        result.append(image)
    return result


def group_messages(images: Iterable[ImageRecord]) -> list[MessageGroup]:
    grouped: dict[int, MessageGroup] = {}
    for image in images:
        group = grouped.get(image.message_id)
        if group is None:
            grouped[image.message_id] = MessageGroup(
                message_id=image.message_id,
                channel_id=image.channel_id,
                user_id=image.user_id,
                created_at=image.created_at,
                images=[image],
            )
        else:
            group.images.append(image)
            group.created_at = min(group.created_at, image.created_at)
    return sorted(grouped.values(), key=lambda group: group.created_at)


def _unique_by_sha(images: Iterable[ImageRecord | IncidentImage]) -> list:
    seen: set[str] = set()
    result: list = []
    for image in images:
        if image.sha256 in seen:
            continue
        seen.add(image.sha256)
        result.append(image)
    return result


def _pair_matches(
    first: ImageRecord | IncidentImage,
    second: ImageRecord | IncidentImage,
    tolerance: int,
) -> bool:
    if first.sha256 == second.sha256:
        return True
    try:
        return phash_distance(first.phash, second.phash) <= tolerance
    except ValueError:
        return False


def image_sets_match(
    left: Sequence[ImageRecord | IncidentImage],
    right: Sequence[ImageRecord | IncidentImage],
    tolerance: int,
) -> bool:
    """Совпадают ли наборы картинок с точностью до порядка и pHash-допуска."""
    left_unique = _unique_by_sha(left)
    right_unique = _unique_by_sha(right)
    if len(left_unique) != len(right_unique):
        return False

    used: set[int] = set()

    def assign(index: int) -> bool:
        if index == len(left_unique):
            return True
        for other_index, other in enumerate(right_unique):
            if other_index in used:
                continue
            if _pair_matches(left_unique[index], other, tolerance):
                used.add(other_index)
                if assign(index + 1):
                    return True
                used.remove(other_index)
        return False

    return assign(0)


def incident_matches_set(
    incident: Incident,
    images: Sequence[ImageRecord],
    tolerance: int,
    multi_user: bool,
    user_id: int,
) -> bool:
    if not multi_user and user_id not in incident.user_ids:
        return False
    reference = incident.images or [
        IncidentImage(
            sha256=incident.sha256,
            phash=incident.phash,
            filename=incident.filename,
            image_url=incident.image_url,
        )
    ]
    return image_sets_match(images, reference, tolerance)


def incident_matches_message(
    incident: Incident,
    images: Sequence[ImageRecord],
    tolerance: int,
    multi_user: bool,
    user_id: int,
) -> bool:
    """Достаточно любой общей картинки, чтобы сообщение вошло в случай."""
    if not multi_user and user_id not in incident.user_ids:
        return False
    reference = incident.images or [
        IncidentImage(
            sha256=incident.sha256,
            phash=incident.phash,
            filename=incident.filename,
            image_url=incident.image_url,
        )
    ]
    return any(
        _pair_matches(image, known, tolerance)
        for image in images
        for known in reference
    )


def _group_overlap(
    first: "MessageGroup",
    second: "MessageGroup",
    tolerance: int,
) -> bool:
    return any(
        _pair_matches(left, right, tolerance)
        for left in first.images
        for right in second.images
    )


def connected_message_groups(
    groups: Sequence["MessageGroup"],
    start_message_id: int,
    tolerance: int,
) -> list["MessageGroup"]:
    """Связная группа сообщений, где соседи делят хотя бы одну картинку."""
    by_id = {group.message_id: group for group in groups}
    start = by_id.get(start_message_id)
    if start is None:
        return []

    component = [start]
    remaining = [
        group for group in groups if group.message_id != start_message_id
    ]
    changed = True
    while changed:
        changed = False
        for group in list(remaining):
            if any(
                _group_overlap(group, member, tolerance)
                for member in component
            ):
                component.append(group)
                remaining.remove(group)
                changed = True
    return component

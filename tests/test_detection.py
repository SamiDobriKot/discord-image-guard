"""Тесты сравнения изображений и группировки."""

from __future__ import annotations

import unittest

from detection import (
    cluster_qualifies,
    image_sets_match,
    incident_matches,
    incident_matches_set,
    phash_distance,
    select_cluster,
    unique_messages,
    unique_users,
)
from models import ImageRecord, Incident, IncidentImage


def make_image(
    image_id: int,
    *,
    sha256: str = "a" * 64,
    phash: str = "0" * 16,
    channel_id: int = 1,
    message_id: int = 100,
    user_id: int = 1,
    created_at: int = 1000,
) -> ImageRecord:
    return ImageRecord(
        id=image_id,
        guild_id=1,
        attachment_id=image_id,
        message_id=message_id,
        channel_id=channel_id,
        user_id=user_id,
        filename=f"{image_id}.png",
        sha256=sha256,
        phash=phash,
        attachment_url=None,
        created_at=created_at,
    )


def make_incident(
    *,
    sha256: str = "a" * 64,
    phash: str = "0" * 16,
    user_ids: list[int] | None = None,
) -> Incident:
    return Incident(
        id=1,
        guild_id=1,
        action="notify",
        status="open",
        sha256=sha256,
        phash=phash,
        filename="a.png",
        image_url=None,
        user_ids=user_ids or [1],
        message_ids=[(1, 100)],
        count=1,
        created_at=1000,
        last_activity_at=1000,
        expires_at=2000,
    )


class PHashTests(unittest.TestCase):
    def test_distance(self) -> None:
        self.assertEqual(phash_distance("0" * 16, "0" * 16), 0)
        self.assertEqual(phash_distance("0" * 16, "f" * 16), 64)
        self.assertEqual(phash_distance("0123456789abcdef", "0123456789abcdee"), 1)

    def test_length_mismatch(self) -> None:
        with self.assertRaises(ValueError):
            phash_distance("0" * 16, "0" * 15)


class ClusterTests(unittest.TestCase):
    def test_selects_sha_and_phash_matches(self) -> None:
        current = make_image(1, sha256="a" * 64, phash="0" * 16)
        exact = make_image(2, sha256="a" * 64, phash="f" * 16, created_at=1001)
        similar = make_image(3, sha256="b" * 64, phash="0000000000000001", created_at=1002)
        different = make_image(4, sha256="c" * 64, phash="f" * 16, created_at=1003)

        cluster = select_cluster(current, [exact, similar, different], 2)

        self.assertEqual([item.id for item in cluster], [1, 2, 3])

    def test_tolerance_zero_keeps_only_exact_sha_or_phash(self) -> None:
        current = make_image(1, sha256="a" * 64, phash="0" * 16)
        similar = make_image(2, sha256="b" * 64, phash="0000000000000001")

        cluster = select_cluster(current, [similar], 0)

        self.assertEqual([item.id for item in cluster], [1])

    def test_unique_messages_and_users(self) -> None:
        images = [
            make_image(1, channel_id=1, message_id=10, user_id=1),
            make_image(2, channel_id=1, message_id=10, user_id=2),
            make_image(3, channel_id=2, message_id=11, user_id=1),
        ]

        self.assertEqual(unique_messages(images), [(1, 10), (2, 11)])
        self.assertEqual(unique_users(images), [1, 2])

    def test_threshold(self) -> None:
        images = [
            make_image(1, message_id=10, channel_id=1),
            make_image(2, message_id=11, channel_id=1),
        ]

        self.assertTrue(cluster_qualifies(images, 2, False))
        self.assertFalse(cluster_qualifies(images, 3, False))

        images_cross = [
            make_image(1, message_id=10, channel_id=1),
            make_image(2, message_id=11, channel_id=2),
        ]
        self.assertTrue(cluster_qualifies(images_cross, 2, True))
        self.assertFalse(cluster_qualifies(images, 2, True))

    def test_incident_matching_respects_user_mode(self) -> None:
        incident = make_incident(user_ids=[1])
        other_user = make_image(2, user_id=2)

        self.assertTrue(
            incident_matches(
                make_incident(user_ids=[1]), make_image(1, user_id=1), 0, False
            )
        )
        self.assertFalse(incident_matches(incident, other_user, 0, False))
        self.assertTrue(incident_matches(incident, other_user, 0, True))

    def test_image_sets_match_order_independently(self) -> None:
        first = [
            make_image(1, sha256="a" * 64, phash="0" * 16, message_id=10),
            make_image(2, sha256="b" * 64, phash="f" * 16, message_id=10),
        ]
        second = [
            make_image(3, sha256="b" * 64, phash="f" * 16, message_id=11),
            make_image(4, sha256="a" * 64, phash="0" * 16, message_id=11),
        ]

        self.assertTrue(image_sets_match(first, second, 0))
        self.assertFalse(image_sets_match(first, second[:1], 0))

    def test_image_set_matching_with_phash_tolerance(self) -> None:
        current = [make_image(1, sha256="c" * 64, phash="0000000000000001")]
        stored = [make_image(2, sha256="d" * 64, phash="0" * 16)]

        self.assertTrue(image_sets_match(current, stored, 1))
        self.assertFalse(image_sets_match(current, stored, 0))

    def test_incident_matches_message_set(self) -> None:
        incident = make_incident(user_ids=[1])
        incident.images = [
            IncidentImage(
                sha256="a" * 64,
                phash="0" * 16,
                filename="a.png",
            ),
            IncidentImage(
                sha256="b" * 64,
                phash="f" * 16,
                filename="b.png",
            ),
        ]
        current = [
            make_image(1, sha256="b" * 64, phash="f" * 16),
            make_image(2, sha256="a" * 64, phash="0" * 16),
        ]

        self.assertTrue(incident_matches_set(incident, current, 0, False, 1))
        self.assertFalse(incident_matches_set(incident, current, 0, False, 2))


if __name__ == "__main__":
    unittest.main()

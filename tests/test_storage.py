"""Тесты SQLite-хранилища."""

from __future__ import annotations

import shutil
import sqlite3
import unittest
import uuid
from pathlib import Path

from models import STATUS_BANNED, STATUS_OPEN, STATUS_WATCHING, GuildConfig
from storage import Storage

TEST_TMP_ROOT = Path(__file__).resolve().parent / "_tmp"


class StorageTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        TEST_TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self._case_dir = TEST_TMP_ROOT / f"case-{uuid.uuid4().hex}"
        self._case_dir.mkdir()
        self.storage = Storage(self._case_dir / "guard.sqlite3")
        await self.storage.init()

    async def asyncTearDown(self) -> None:
        shutil.rmtree(self._case_dir, ignore_errors=True)

    async def _insert_image(
        self, attachment_id: int, *, user_id: int = 1, created_at: int = 1000
    ):
        record, created = await self.storage.insert_image(
            guild_id=1,
            attachment_id=attachment_id,
            message_id=attachment_id,
            channel_id=10,
            user_id=user_id,
            filename=f"{attachment_id}.png",
            sha256="a" * 64,
            phash="0" * 16,
            attachment_url=None,
            created_at=created_at,
        )
        self.assertTrue(created)
        return record

    async def _create_incident(self, **overrides):
        values = dict(
            guild_id=1,
            action="notify",
            status=STATUS_OPEN,
            sha256="a" * 64,
            phash="0" * 16,
            filename="a.png",
            image_url=None,
            user_ids=[1],
            message_ids=[(10, 100)],
            count=1,
            created_at=1000,
            last_activity_at=1000,
            expires_at=2000,
        )
        values.update(overrides)
        return await self.storage.create_incident(**values)

    async def test_config_roundtrip(self) -> None:
        config = await self.storage.get_config(1)
        self.assertEqual(config.action, "notify")
        self.assertIsNone(config.report_channel_id)

        config.report_channel_id = 10
        config.notify_channel_id = 11
        config.action = "delete"
        config.threshold_count = 4
        config.window_seconds = 7200
        config.cross_channel_only = True
        config.phash_distance = 6
        config.multi_user = True
        await self.storage.save_config(config)

        loaded = await self.storage.get_config(1)
        self.assertEqual(loaded, config)

    async def test_roles(self) -> None:
        await self.storage.add_role(1, 50)
        await self.storage.add_role(1, 51)
        await self.storage.add_role(1, 50)
        self.assertEqual(await self.storage.get_roles(1), [50, 51])

        await self.storage.remove_role(1, 50)
        self.assertEqual(await self.storage.get_roles(1), [51])

        await self.storage.clear_roles(1)
        self.assertEqual(await self.storage.get_roles(1), [])

    async def test_excluded_roles(self) -> None:
        await self.storage.add_excluded_role(1, 60)
        await self.storage.add_excluded_role(1, 61)
        await self.storage.add_excluded_role(1, 60)
        self.assertEqual(
            await self.storage.get_excluded_roles(1), [60, 61]
        )

        await self.storage.remove_excluded_role(1, 60)
        self.assertEqual(await self.storage.get_excluded_roles(1), [61])

    async def test_images_are_deduplicated(self) -> None:
        first = await self._insert_image(100)
        second, created = await self.storage.insert_image(
            guild_id=1,
            attachment_id=100,
            message_id=100,
            channel_id=10,
            user_id=1,
            filename="100.png",
            sha256="a" * 64,
            phash="0" * 16,
            attachment_url=None,
            created_at=1000,
        )
        self.assertFalse(created)
        self.assertEqual(first.id, second.id)

    async def test_recent_images_filters_actioned_and_user(self) -> None:
        old = await self._insert_image(100, created_at=1000)
        new = await self._insert_image(101, user_id=2, created_at=2000)
        await self.storage.mark_actioned([old.id], 3000)

        recent = await self.storage.recent_images(1, since=0)
        self.assertEqual([item.id for item in recent], [new.id])

        only_user_1 = await self.storage.recent_images(1, since=0, user_id=1)
        self.assertEqual(only_user_1, [])

    async def test_incident_lifecycle(self) -> None:
        incident = await self._create_incident()
        self.assertEqual(incident.status, STATUS_OPEN)
        self.assertEqual(incident.user_ids, [1])
        self.assertEqual(incident.message_ids, [(10, 100)])

        active = await self.storage.active_incidents(1, 1500)
        self.assertEqual([item.id for item in active], [incident.id])

        await self.storage.append_incident(
            incident.id,
            user_ids=[1, 2],
            message_ids=[(10, 100), (11, 101)],
            count=2,
            last_activity_at=1600,
            expires_at=2600,
        )
        updated = await self.storage.get_incident(incident.id)
        assert updated is not None
        self.assertEqual(updated.count, 2)
        self.assertEqual(updated.user_ids, [1, 2])
        self.assertEqual(updated.message_ids, [(10, 100), (11, 101)])

        await self.storage.set_alert_message(incident.id, 20, 30)
        await self.storage.set_report_message(incident.id, 21, 31)
        updated = await self.storage.get_incident(incident.id)
        assert updated is not None
        self.assertEqual(
            (updated.alert_channel_id, updated.alert_message_id), (20, 30)
        )
        self.assertEqual(
            (updated.report_channel_id, updated.report_message_id), (21, 31)
        )

        self.assertTrue(await self.storage.claim_for_action(incident.id))
        self.assertFalse(await self.storage.claim_for_action(incident.id))

    async def test_expired_incidents(self) -> None:
        incident = await self._create_incident(expires_at=1000)
        expired = await self.storage.expired_incidents(2000)
        self.assertEqual([item.id for item in expired], [incident.id])

        await self.storage.set_status(
            incident.id, STATUS_WATCHING, window_closed=True
        )
        self.assertEqual(await self.storage.expired_incidents(2000), [])

    async def test_stats(self) -> None:
        await self._insert_image(100)
        await self._create_incident()
        self.assertEqual(
            await self.storage.stats(1), {"images": 1, "incidents": 1}
        )
        self.assertEqual(
            await self.storage.stats(2), {"images": 0, "incidents": 0}
        )

    async def test_purge_old_images_and_terminal_incidents(self) -> None:
        old_image = await self._insert_image(100, created_at=1000)
        new_image = await self._insert_image(101, created_at=2000)
        with sqlite3.connect(self.storage.path) as connection:
            connection.execute(
                "UPDATE images SET indexed_at = 1000 WHERE id = ?", (old_image.id,)
            )
            connection.execute(
                "UPDATE images SET indexed_at = 3000 WHERE id = ?", (new_image.id,)
            )
            connection.commit()

        old_incident = await self._create_incident(status=STATUS_BANNED)
        await self.storage.set_status(
            old_incident.id, STATUS_BANNED, resolved_at=1000
        )
        open_incident = await self._create_incident(status=STATUS_OPEN)

        self.assertEqual(await self.storage.purge_images_before(2500), 1)
        self.assertEqual(await self.storage.purge_incidents_before(2500), 1)

        self.assertIsNone(await self.storage.get_incident(old_incident.id))
        self.assertIsNotNone(await self.storage.get_incident(open_incident.id))


if __name__ == "__main__":
    unittest.main()

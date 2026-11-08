"""Тесты конвейера индексации сообщений."""

from __future__ import annotations

import shutil
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from bot import DuplicateGuardBot
from hashing import ImageHashes
from models import STATUS_OPEN, STATUS_WATCHING, GuildConfig, Incident
from storage import Storage

TEST_TMP_ROOT = Path(__file__).resolve().parent / "_tmp"
HASHES = ImageHashes(
    sha256="a" * 64,
    phash="0123456789abcdef",
    width=100,
    height=50,
    image_format="PNG",
)


def make_attachment(attachment_id: int = 500) -> SimpleNamespace:
    return SimpleNamespace(
        id=attachment_id,
        filename="pic.png",
        content_type="image/png",
        size=2048,
        url="https://cdn.example/pic.png",
    )


def make_message(
    attachment: SimpleNamespace,
    *,
    message_id: int = 400,
    channel_id: int = 300,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=message_id,
        guild=SimpleNamespace(id=100, owner_id=999),
        channel=SimpleNamespace(id=channel_id),
        author=SimpleNamespace(id=200, bot=False, roles=[]),
        attachments=[attachment],
        created_at=datetime.now(timezone.utc),
    )


class ProcessMessageTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        TEST_TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self._case_dir = TEST_TMP_ROOT / f"case-{uuid.uuid4().hex}"
        self._case_dir.mkdir()
        self.storage = Storage(self._case_dir / "guard.sqlite3")
        await self.storage.init()
        self.bot = DuplicateGuardBot(storage=self.storage)
        self.detected: list = []

        async def hash_attachment(attachment, guild_id):  # noqa: ANN001
            return HASHES

        async def detect(guild, config, image):  # noqa: ANN001
            self.detected.append(image)

        self.bot._hash_attachment = hash_attachment  # type: ignore[method-assign]
        self.bot._detect = detect  # type: ignore[method-assign]

    async def asyncTearDown(self) -> None:
        shutil.rmtree(self._case_dir, ignore_errors=True)

    async def test_indexes_image_once(self) -> None:
        attachment = make_attachment()
        message = make_message(attachment)

        self.assertEqual(await self.bot.process_message(message), 1)
        self.assertEqual(await self.bot.process_message(message), 0)

    async def test_detection_skipped_without_report_channel(self) -> None:
        message = make_message(make_attachment())
        await self.bot.process_message(message)
        self.assertEqual(self.detected, [])

    async def test_detection_runs_with_report_channel(self) -> None:
        config = GuildConfig(guild_id=100, report_channel_id=999)
        await self.storage.save_config(config)

        message = make_message(make_attachment())
        await self.bot.process_message(message)

        self.assertEqual(len(self.detected), 1)
        self.assertEqual(self.detected[0].attachment_id, 500)

    async def test_command_tree(self) -> None:
        commands = {command.name: command for command in self.bot.tree.get_commands()}
        self.assertEqual(
            set(commands),
            {"channels", "behavior", "detection", "settings", "bans", "roles"},
        )
        self.assertEqual(
            {command.name for command in commands["roles"].commands},
            {
                "add",
                "remove",
                "list",
                "clear",
                "exclude",
                "include",
                "excluded",
            },
        )

    async def test_excluded_author_is_not_indexed(self) -> None:
        await self.storage.add_excluded_role(100, 60)
        message = make_message(make_attachment())
        message.author.roles = [SimpleNamespace(id=60)]

        self.assertEqual(await self.bot.process_message(message), 0)
        self.assertEqual(self.detected, [])
        self.assertEqual(await self.storage.recent_images(100, since=0), [])

    async def test_threshold_opens_incident(self) -> None:
        config = GuildConfig(
            guild_id=100,
            report_channel_id=999,
            threshold_count=2,
            action="notify",
        )
        await self.storage.save_config(config)
        opened: list = []

        async def apply_action(guild, cfg, incident):  # noqa: ANN001
            opened.append(incident)

        self.bot._apply_action = apply_action  # type: ignore[method-assign]
        self.bot._detect = DuplicateGuardBot._detect.__get__(  # type: ignore[method-assign]
            self.bot, DuplicateGuardBot
        )

        first = make_message(make_attachment(1), message_id=10)
        second = make_message(make_attachment(2), message_id=11)

        await self.bot.process_message(first)
        self.assertEqual(opened, [])
        await self.bot.process_message(second)

        self.assertEqual(len(opened), 1)
        self.assertEqual(opened[0].count, 2)
        self.assertEqual(opened[0].user_ids, [200])

    async def test_extend_notification_updates_count_and_window(self) -> None:
        now = int(datetime.now(timezone.utc).timestamp())
        incident = await self.storage.create_incident(
            guild_id=100,
            action="notify",
            status=STATUS_OPEN,
            sha256=HASHES.sha256,
            phash=HASHES.phash,
            filename="pic.png",
            image_url=None,
            user_ids=[200],
            message_ids=[(300, 10)],
            count=1,
            created_at=now,
            last_activity_at=now,
            expires_at=now + 10,
        )
        image, _ = await self.storage.insert_image(
            guild_id=100,
            attachment_id=501,
            message_id=11,
            channel_id=300,
            user_id=200,
            filename="pic.png",
            sha256=HASHES.sha256,
            phash=HASHES.phash,
            attachment_url=None,
            created_at=now,
        )
        alerts: list = []

        async def publish_alert(guild, config, current):  # noqa: ANN001
            alerts.append(current)
            return True

        self.bot._publish_alert = publish_alert  # type: ignore[method-assign]
        config = GuildConfig(guild_id=100, report_channel_id=999)

        await self.bot._extend_incident(
            SimpleNamespace(id=100), config, incident, image
        )

        self.assertEqual(incident.count, 2)
        self.assertGreater(incident.expires_at, now + 10)
        self.assertEqual(len(alerts), 1)
        stored = await self.storage.get_incident(incident.id)
        assert stored is not None
        self.assertEqual(stored.count, 2)

    async def test_extend_delete_watch_updates_report(self) -> None:
        now = int(datetime.now(timezone.utc).timestamp())
        incident = await self.storage.create_incident(
            guild_id=100,
            action="delete",
            status=STATUS_WATCHING,
            sha256=HASHES.sha256,
            phash=HASHES.phash,
            filename="pic.png",
            image_url=None,
            user_ids=[200],
            message_ids=[(300, 10)],
            count=1,
            created_at=now,
            last_activity_at=now,
            expires_at=now + 3600,
        )
        image, _ = await self.storage.insert_image(
            guild_id=100,
            attachment_id=502,
            message_id=12,
            channel_id=300,
            user_id=200,
            filename="pic.png",
            sha256=HASHES.sha256,
            phash=HASHES.phash,
            attachment_url=None,
            created_at=now,
        )
        reports: list = []

        async def delete_refs(guild, refs):  # noqa: ANN001
            return 1, 0, 0

        async def publish_report(
            guild, config, current, *, title, result_text, color, **kwargs
        ):  # noqa: ANN001
            reports.append((current, title, result_text))

        self.bot._delete_refs = delete_refs  # type: ignore[method-assign]
        self.bot._publish_report = publish_report  # type: ignore[method-assign]
        config = GuildConfig(guild_id=100, report_channel_id=999)

        await self.bot._extend_incident(
            SimpleNamespace(id=100), config, incident, image
        )

        self.assertEqual(incident.count, 2)
        self.assertEqual(incident.status, STATUS_WATCHING)
        self.assertEqual(len(reports), 1)
        self.assertIn("Удалено: 1", reports[0][2])

    async def test_ban_action_bans_all_users(self) -> None:
        incident = Incident(
            id=1,
            guild_id=100,
            action="ban",
            status=STATUS_OPEN,
            sha256=HASHES.sha256,
            phash=HASHES.phash,
            filename="pic.png",
            image_url=None,
            user_ids=[1, 2],
            message_ids=[(300, 10), (300, 11)],
            count=2,
            created_at=0,
            last_activity_at=0,
            expires_at=3600,
        )
        banned: list[int] = []

        class FakeGuild:
            id = 100

            def get_member(self, user_id):  # noqa: ANN001
                return SimpleNamespace(id=user_id)

            async def ban(self, user, **kwargs):  # noqa: ANN001
                banned.append(user.id)

        async def delete_refs(guild, refs):  # noqa: ANN001
            return 2, 0, 0

        self.bot._delete_refs = delete_refs  # type: ignore[method-assign]
        config = GuildConfig(
            guild_id=100, window_seconds=3600, ban_duration_seconds=3600
        )

        result, success = await self.bot._ban_and_delete(
            FakeGuild(), config, incident
        )

        self.assertTrue(success)
        self.assertEqual(banned, [1, 2])
        self.assertIn("<@1>", result)
        self.assertIn("<@2>", result)
        self.assertIn("Временный бан", result)

        records = await self.storage.get_active_bans(100)
        self.assertEqual({record.user_id for record in records}, {1, 2})
        for record in records:
            self.assertGreater(record.unban_at, record.banned_at)

    async def test_process_due_bans_unbans(self) -> None:
        await self.storage.upsert_ban(
            guild_id=100,
            user_id=42,
            incident_id=None,
            banned_at=0,
            unban_at=0,
        )
        calls: list[int] = []

        class FakeGuild:
            async def unban(self, user, **kwargs):  # noqa: ANN001
                calls.append(user.id)

        self.bot.get_guild = lambda guild_id: FakeGuild()  # type: ignore[method-assign]
        await self.bot._process_due_bans()

        self.assertEqual(calls, [42])
        self.assertEqual(await self.storage.get_active_bans(100), [])

    async def test_role_access(self) -> None:
        await self.storage.add_role(100, 50)

        member = SimpleNamespace(
            id=1,
            guild=SimpleNamespace(id=100, owner_id=999),
            guild_permissions=SimpleNamespace(administrator=False),
            roles=[SimpleNamespace(id=50)],
        )
        self.assertTrue(await self.bot._is_allowed(member))

        outsider = SimpleNamespace(
            id=2,
            guild=SimpleNamespace(id=100, owner_id=999),
            guild_permissions=SimpleNamespace(administrator=False),
            roles=[SimpleNamespace(id=51)],
        )
        self.assertFalse(await self.bot._is_allowed(outsider))

        admin = SimpleNamespace(
            id=3,
            guild=SimpleNamespace(id=100, owner_id=999),
            guild_permissions=SimpleNamespace(administrator=True),
            roles=[],
        )
        self.assertTrue(await self.bot._is_allowed(admin))

        owner = SimpleNamespace(
            id=999,
            guild=SimpleNamespace(id=100, owner_id=999),
            guild_permissions=SimpleNamespace(administrator=False),
            roles=[],
        )
        self.assertTrue(await self.bot._is_allowed(owner))


if __name__ == "__main__":
    unittest.main()

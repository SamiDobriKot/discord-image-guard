"""Тесты сборки embed-сообщений."""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from models import GuildConfig, Incident
from reporting import (
    build_alert_embed,
    build_report_embed,
    build_settings_embed,
    format_links,
    format_users,
)


def make_incident(*, users: list[int] | None = None, count: int = 3) -> Incident:
    return Incident(
        id=7,
        guild_id=100,
        action="notify",
        status="open",
        sha256="a" * 64,
        phash="0123456789abcdef",
        filename="photo.png",
        image_url=(
            "https://cdn.discordapp.com/attachments/10/20/photo.png"
            "?ex=66000000&is=65ff0000&hm=abc"
        ),
        user_ids=users or [1, 2],
        message_ids=[(10, 20), (11, 21)],
        count=count,
        created_at=1000,
        last_activity_at=2000,
        expires_at=4600,
    )


class ReportingTests(unittest.TestCase):
    def test_alert_contains_count_users_and_links_without_hashes(self) -> None:
        embed = build_alert_embed(make_incident(), 3600)
        values = "\n".join(field.value for field in embed.fields)
        names = "\n".join(field.name for field in embed.fields)

        self.assertIn("3", values)
        self.assertIn("<@1>", values)
        self.assertIn("<@2>", values)
        self.assertIn("https://discord.com/channels/100/10/20", values)
        self.assertNotIn("a" * 64, values)
        self.assertNotIn("0123456789abcdef", values)
        self.assertIn("Пользователи", names)
        self.assertIn("Сообщений", names)
        self.assertIn("Файл", names)
        self.assertIsNotNone(embed.thumbnail.url)

    def test_report_contains_result(self) -> None:
        embed = build_report_embed(
            make_incident(),
            title="Бан пользователей",
            result_text="Забанены: <@1>",
            color=0xE74C3C,
        )
        values = "\n".join(field.value for field in embed.fields)
        self.assertIn("Забанены: <@1>", values)
        self.assertNotIn("a" * 64, values)
        self.assertEqual(embed.title, "Бан пользователей")

    def test_preview_rejects_foreign_url(self) -> None:
        incident = make_incident()
        incident.image_url = "javascript:alert(1)"
        embed = build_alert_embed(incident, 3600)
        self.assertIsNone(embed.thumbnail.url)

        incident.image_url = "https://evil.example/attachments/1/2/a.png"
        embed = build_report_embed(
            incident, title="Тест", result_text="—", color=0
        )
        self.assertIsNone(embed.thumbnail.url)

    def test_filename_is_sanitized(self) -> None:
        incident = make_incident()
        incident.filename = "evil\u202e[click](https://evil).png"
        embed = build_alert_embed(incident, 3600)
        filename = next(field.value for field in embed.fields if field.name == "Файл")
        self.assertNotIn("\u202e", filename)
        self.assertNotIn("[click](https://evil)", filename)

    def test_settings_embed(self) -> None:
        config = GuildConfig(
            guild_id=100,
            report_channel_id=10,
            notify_channel_id=11,
            action="delete",
            threshold_count=4,
            window_seconds=7200,
            cross_channel_only=True,
            phash_distance=6,
            multi_user=True,
        )
        embed = build_settings_embed(
            config,
            [50, 51],
            {"images": 12, "incidents": 3},
            report_channel=SimpleNamespace(mention="#reports"),
            notify_channel=SimpleNamespace(mention="#alerts"),
            excluded_role_ids=[60],
            hash_retention_seconds=86400,
        )
        values = "\n".join(field.value for field in embed.fields)
        field_names = "\n".join(field.name for field in embed.fields)
        self.assertIn("#reports", values)
        self.assertIn("#alerts", values)
        self.assertIn("удаление сообщений", values)
        self.assertIn("4 сообщения", values)
        self.assertIn("2 ч", values)
        self.assertIn("1 д", values)
        self.assertIn("<@&50>", values)
        self.assertIn("<@&60>", values)
        self.assertIn("Роли-исключения", field_names)
        self.assertIn("12", values)

    def test_format_helpers(self) -> None:
        self.assertEqual(format_users([1, 2]), "<@1>\n<@2>")
        links = format_links(100, [(10, 20), (11, 21)])
        self.assertIn("https://discord.com/channels/100/10/20", links)
        self.assertIn("https://discord.com/channels/100/11/21", links)


if __name__ == "__main__":
    unittest.main()

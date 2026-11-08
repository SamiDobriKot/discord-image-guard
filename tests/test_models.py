"""Тесты моделей и разбора длительности."""

from __future__ import annotations

import unittest

from models import GuildConfig, format_duration, parse_duration, plural


class DurationTests(unittest.TestCase):
    def test_parse_units(self) -> None:
        self.assertEqual(parse_duration("30m"), 1800)
        self.assertEqual(parse_duration("2h"), 7200)
        self.assertEqual(parse_duration("1d"), 86400)
        self.assertEqual(parse_duration("45"), 2700)
        self.assertEqual(parse_duration("90s"), 90)
        self.assertEqual(parse_duration("1ч"), 3600)
        self.assertEqual(parse_duration("2д"), 172800)

    def test_parse_rejects_out_of_range(self) -> None:
        for value in ("0m", "10s", "31d", "abc", ""):
            with self.assertRaises(ValueError):
                parse_duration(value)

    def test_format(self) -> None:
        self.assertEqual(format_duration(45), "45 с")
        self.assertEqual(format_duration(3600), "1 ч")
        self.assertEqual(format_duration(5400), "1 ч 30 мин")
        self.assertEqual(format_duration(90000), "1 д 1 ч")

    def test_plural(self) -> None:
        self.assertEqual(plural(1, "сообщение", "сообщения", "сообщений"), "сообщение")
        self.assertEqual(plural(3, "сообщение", "сообщения", "сообщений"), "сообщения")
        self.assertEqual(plural(11, "сообщение", "сообщения", "сообщений"), "сообщений")
        self.assertEqual(plural(21, "сообщение", "сообщения", "сообщений"), "сообщение")


class ConfigTests(unittest.TestCase):
    def test_defaults(self) -> None:
        config = GuildConfig(guild_id=1)
        self.assertEqual(config.action, "notify")
        self.assertEqual(config.threshold_count, 3)
        self.assertEqual(config.window_seconds, 3600)
        self.assertEqual(config.phash_distance, 8)
        self.assertFalse(config.cross_channel_only)
        self.assertFalse(config.multi_user)


if __name__ == "__main__":
    unittest.main()

"""Тесты очистки текста и ссылок для embed-сообщений."""

from __future__ import annotations

import unittest

from sanitize import safe_image_url, sanitize_text


class SafeImageUrlTests(unittest.TestCase):
    def test_allows_discord_cdn_attachments(self) -> None:
        url = (
            "https://cdn.discordapp.com/attachments/1/2/photo.png"
            "?ex=66000000&is=65ff0000&hm=abc"
        )
        self.assertEqual(safe_image_url(url), url)
        self.assertEqual(
            safe_image_url("https://media.discordapp.net/attachments/1/2/photo.jpg"),
            "https://media.discordapp.net/attachments/1/2/photo.jpg",
        )
        self.assertEqual(
            safe_image_url("https://cdn.discordapp.com/ephemeral-attachments/1/2/a.png"),
            "https://cdn.discordapp.com/ephemeral-attachments/1/2/a.png",
        )

    def test_rejects_foreign_and_dangerous_urls(self) -> None:
        for url in (
            "http://cdn.discordapp.com/attachments/1/2/photo.png",
            "https://evil.example/attachments/1/2/photo.png",
            "https://cdn.discordapp.com.evil.example/attachments/1/2/a.png",
            "https://cdn.discordapp.com/other/1/2/a.png",
            "https://cdn.discordapp.com/attachments/../../etc/passwd",
            "https://user:pass@cdn.discordapp.com/attachments/1/2/a.png",
            "https://cdn.discordapp.com:8443/attachments/1/2/a.png",
            "javascript:alert(1)",
            "https://cdn.discordapp.com/attachments/1/2/a.png\njavascript:alert(1)",
            None,
            "",
            123,
        ):
            self.assertIsNone(safe_image_url(url), url)


class SanitizeTextTests(unittest.TestCase):
    def test_removes_control_and_bidi_characters(self) -> None:
        value = "pic\u202e\u0000ture\u200b.png"
        cleaned = sanitize_text(value)
        for char in ("\u202e", "\u0000", "\u200b"):
            self.assertNotIn(char, cleaned)

    def test_escapes_markdown_and_mentions(self) -> None:
        cleaned = sanitize_text("[клик](https://evil) *жирный* @everyone")
        self.assertNotIn("[клик](https://evil)", cleaned)
        self.assertNotIn("*жирный*", cleaned)
        self.assertNotIn("@everyone", cleaned)

    def test_truncates(self) -> None:
        self.assertLessEqual(len(sanitize_text("x" * 500, max_length=20)), 20)


if __name__ == "__main__":
    unittest.main()

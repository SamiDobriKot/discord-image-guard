"""Тесты хэширования изображений."""

from __future__ import annotations

import hashlib
import io
import unittest

from PIL import Image

from hashing import HashingError, compute_hashes, is_image_attachment


def make_image_bytes(
    size: tuple[int, int] = (320, 240), fmt: str = "PNG", seed: int = 0
) -> bytes:
    image = Image.new("RGB", size, (240, 240, 240))
    pixels = image.load()
    width, height = size
    for x in range(width):
        for y in range(height):
            pixels[x, y] = (
                (x * 7 + y * 3 + seed * 31) % 256,
                (x * 2 + y * 11 + seed * 17) % 256,
                (x * x + y + seed * 13) % 256,
            )
    buffer = io.BytesIO()
    image.save(buffer, format=fmt)
    return buffer.getvalue()


def hamming(first: str, second: str) -> int:
    return (int(first, 16) ^ int(second, 16)).bit_count()


class FakeAttachment:
    def __init__(self, filename: str | None, content_type: str | None) -> None:
        self.filename = filename
        self.content_type = content_type


class ComputeHashesTests(unittest.TestCase):
    def test_sha256_matches_hashlib_and_metadata(self) -> None:
        data = make_image_bytes()

        hashes = compute_hashes(data)

        self.assertEqual(hashes.sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(len(hashes.sha256), 64)
        self.assertRegex(hashes.phash, r"^[0-9a-f]{16}$")
        self.assertEqual((hashes.width, hashes.height), (320, 240))
        self.assertEqual(hashes.image_format, "PNG")

    def test_phash_is_deterministic(self) -> None:
        data = make_image_bytes()

        self.assertEqual(compute_hashes(data).phash, compute_hashes(data).phash)

    def test_phash_survives_resize_and_jpeg(self) -> None:
        original = Image.open(io.BytesIO(make_image_bytes()))
        resized = original.resize((160, 120))
        buffer = io.BytesIO()
        resized.save(buffer, format="JPEG", quality=80)

        distance = hamming(
            compute_hashes(make_image_bytes()).phash,
            compute_hashes(buffer.getvalue()).phash,
        )

        self.assertLessEqual(distance, 10, f"pHash слишком сильно изменился: {distance}")

    def test_different_images_have_different_phash(self) -> None:
        distance = hamming(
            compute_hashes(make_image_bytes(seed=0)).phash,
            compute_hashes(make_image_bytes(seed=7)).phash,
        )

        self.assertGreater(distance, 10, f"pHash разных картинок совпал: {distance}")

    def test_transparent_png_is_flattened_on_white(self) -> None:
        transparent = Image.new("RGBA", (100, 100), (0, 0, 0, 0))
        buffer = io.BytesIO()
        transparent.save(buffer, format="PNG")

        white = Image.new("RGB", (100, 100), (255, 255, 255))
        white_buffer = io.BytesIO()
        white.save(white_buffer, format="PNG")

        distance = hamming(
            compute_hashes(buffer.getvalue()).phash,
            compute_hashes(white_buffer.getvalue()).phash,
        )
        self.assertEqual(distance, 0)

    def test_empty_and_garbage_data_raise(self) -> None:
        with self.assertRaises(HashingError):
            compute_hashes(b"")
        with self.assertRaises(HashingError):
            compute_hashes(b"definitely not an image")


class IsImageAttachmentTests(unittest.TestCase):
    def test_content_type_wins(self) -> None:
        self.assertTrue(is_image_attachment(FakeAttachment("file.bin", "image/png")))
        self.assertFalse(is_image_attachment(FakeAttachment("file.png", "text/plain")))
        self.assertFalse(is_image_attachment(FakeAttachment("file.svg", "image/svg+xml")))

    def test_extension_fallback_without_content_type(self) -> None:
        self.assertTrue(is_image_attachment(FakeAttachment("photo.WEBP", None)))
        self.assertTrue(is_image_attachment(FakeAttachment("photo.jpg", "")))
        self.assertFalse(is_image_attachment(FakeAttachment("archive.zip", None)))
        self.assertFalse(is_image_attachment(FakeAttachment(None, None)))

    def test_generic_content_type_falls_back_to_extension(self) -> None:
        self.assertTrue(
            is_image_attachment(FakeAttachment("photo.png", "application/octet-stream"))
        )
        self.assertFalse(
            is_image_attachment(FakeAttachment("archive.zip", "application/octet-stream"))
        )


if __name__ == "__main__":
    unittest.main()

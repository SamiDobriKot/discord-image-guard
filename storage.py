"""SQLite-хранилище конфигурации, изображений и инцидентов."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar

from models import (
    DEFAULT_ACTION,
    STATUS_ACTIONED,
    STATUS_ACTIONING,
    STATUS_BANNED,
    STATUS_CANCELLED,
    STATUS_DELETED,
    STATUS_FAILED,
    STATUS_MERGED,
    STATUS_OPEN,
    STATUS_WATCHING,
    BanRecord,
    GuildConfig,
    ImageRecord,
    Incident,
    IncidentImage,
)

T = TypeVar("T")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS guild_config (
    guild_id            INTEGER PRIMARY KEY,
    report_channel_id   INTEGER,
    notify_channel_id   INTEGER,
    action              TEXT NOT NULL DEFAULT 'notify',
    threshold_count     INTEGER NOT NULL DEFAULT 3,
    window_seconds      INTEGER NOT NULL DEFAULT 60,
    cross_channel_only  INTEGER NOT NULL DEFAULT 0,
    phash_distance      INTEGER NOT NULL DEFAULT 8,
    multi_user          INTEGER NOT NULL DEFAULT 0,
    ban_duration_seconds INTEGER NOT NULL DEFAULT 0,
    updated_at          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS allowed_roles (
    guild_id INTEGER NOT NULL,
    role_id  INTEGER NOT NULL,
    PRIMARY KEY (guild_id, role_id)
);

CREATE TABLE IF NOT EXISTS excluded_roles (
    guild_id INTEGER NOT NULL,
    role_id  INTEGER NOT NULL,
    PRIMARY KEY (guild_id, role_id)
);

CREATE TABLE IF NOT EXISTS images (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id       INTEGER NOT NULL,
    attachment_id  INTEGER NOT NULL UNIQUE,
    message_id     INTEGER NOT NULL,
    channel_id     INTEGER NOT NULL,
    user_id        INTEGER NOT NULL,
    filename       TEXT,
    sha256         TEXT NOT NULL,
    phash          TEXT NOT NULL,
    attachment_url TEXT,
    created_at     INTEGER NOT NULL,
    indexed_at     INTEGER NOT NULL,
    actioned_at    INTEGER
);

CREATE INDEX IF NOT EXISTS idx_images_guild_created
    ON images (guild_id, created_at);
CREATE INDEX IF NOT EXISTS idx_images_guild_sha
    ON images (guild_id, sha256);
CREATE INDEX IF NOT EXISTS idx_images_indexed
    ON images (indexed_at);

CREATE TABLE IF NOT EXISTS incidents (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id          INTEGER NOT NULL,
    action            TEXT NOT NULL,
    status            TEXT NOT NULL,
    sha256            TEXT NOT NULL,
    phash             TEXT NOT NULL,
    filename          TEXT,
    image_url         TEXT,
    images            TEXT,
    user_ids          TEXT NOT NULL,
    message_ids       TEXT NOT NULL,
    count             INTEGER NOT NULL,
    created_at        INTEGER NOT NULL,
    last_activity_at  INTEGER NOT NULL,
    expires_at        INTEGER NOT NULL,
    alert_channel_id  INTEGER,
    alert_message_id  INTEGER,
    report_channel_id INTEGER,
    report_message_id INTEGER,
    result            TEXT,
    window_closed     INTEGER NOT NULL DEFAULT 0,
    resolved_at       INTEGER
);

CREATE INDEX IF NOT EXISTS idx_incidents_guild_status
    ON incidents (guild_id, status);
CREATE INDEX IF NOT EXISTS idx_incidents_expiry
    ON incidents (window_closed, expires_at);

CREATE TABLE IF NOT EXISTS bans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id        INTEGER NOT NULL,
    user_id         INTEGER NOT NULL,
    incident_id     INTEGER,
    banned_at       INTEGER NOT NULL,
    unban_at        INTEGER NOT NULL,
    active          INTEGER NOT NULL DEFAULT 1,
    last_attempt_at INTEGER NOT NULL DEFAULT 0,
    UNIQUE (guild_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_bans_due
    ON bans (active, unban_at);
"""


class Storage:
    """Небольшая обёртка над SQLite с выполнением операций в отдельном потоке."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = asyncio.Lock()

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        return connection

    async def _run(self, func: Callable[[], T]) -> T:
        async with self._lock:
            return await asyncio.to_thread(func)

    async def init(self) -> None:
        def _create() -> None:
            with closing(self._connect()) as connection, connection:
                connection.executescript(_SCHEMA)
                columns = {
                    row["name"]
                    for row in connection.execute("PRAGMA table_info(guild_config)")
                }
                if "ban_duration_seconds" not in columns:
                    connection.execute(
                        "ALTER TABLE guild_config "
                        "ADD COLUMN ban_duration_seconds INTEGER NOT NULL DEFAULT 0"
                    )

                incident_columns = {
                    row["name"]
                    for row in connection.execute("PRAGMA table_info(incidents)")
                }
                if "images" not in incident_columns:
                    connection.execute(
                        "ALTER TABLE incidents ADD COLUMN images TEXT"
                    )

        await self._run(_create)

    # --- конфигурация ---------------------------------------------------
    async def get_config(self, guild_id: int) -> GuildConfig:
        def _query() -> GuildConfig:
            with closing(self._connect()) as connection:
                row = connection.execute(
                    "SELECT * FROM guild_config WHERE guild_id = ?", (guild_id,)
                ).fetchone()
            if row is None:
                return GuildConfig(guild_id=guild_id)
            return GuildConfig(
                guild_id=guild_id,
                report_channel_id=row["report_channel_id"],
                notify_channel_id=row["notify_channel_id"],
                action=row["action"] or DEFAULT_ACTION,
                threshold_count=int(row["threshold_count"]),
                window_seconds=int(row["window_seconds"]),
                cross_channel_only=bool(row["cross_channel_only"]),
                phash_distance=int(row["phash_distance"]),
                multi_user=bool(row["multi_user"]),
                ban_duration_seconds=int(row["ban_duration_seconds"]),
            )

        return await self._run(_query)

    async def save_config(self, config: GuildConfig) -> None:
        def _upsert() -> None:
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    """
                    INSERT INTO guild_config (
                        guild_id, report_channel_id, notify_channel_id, action,
                        threshold_count, window_seconds, cross_channel_only,
                        phash_distance, multi_user, ban_duration_seconds,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(guild_id) DO UPDATE SET
                        report_channel_id = excluded.report_channel_id,
                        notify_channel_id = excluded.notify_channel_id,
                        action = excluded.action,
                        threshold_count = excluded.threshold_count,
                        window_seconds = excluded.window_seconds,
                        cross_channel_only = excluded.cross_channel_only,
                        phash_distance = excluded.phash_distance,
                        multi_user = excluded.multi_user,
                        ban_duration_seconds = excluded.ban_duration_seconds,
                        updated_at = excluded.updated_at
                    """,
                    (
                        config.guild_id,
                        config.report_channel_id,
                        config.notify_channel_id,
                        config.action,
                        config.threshold_count,
                        config.window_seconds,
                        int(config.cross_channel_only),
                        config.phash_distance,
                        int(config.multi_user),
                        config.ban_duration_seconds,
                        int(time.time()),
                    ),
                )

        await self._run(_upsert)

    # --- роли -----------------------------------------------------------
    async def get_roles(self, guild_id: int) -> list[int]:
        def _query() -> list[int]:
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    "SELECT role_id FROM allowed_roles WHERE guild_id = ? ORDER BY role_id",
                    (guild_id,),
                ).fetchall()
            return [int(row["role_id"]) for row in rows]

        return await self._run(_query)

    async def add_role(self, guild_id: int, role_id: int) -> None:
        def _insert() -> None:
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    "INSERT OR IGNORE INTO allowed_roles (guild_id, role_id) VALUES (?, ?)",
                    (guild_id, role_id),
                )

        await self._run(_insert)

    async def remove_role(self, guild_id: int, role_id: int) -> None:
        def _delete() -> None:
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    "DELETE FROM allowed_roles WHERE guild_id = ? AND role_id = ?",
                    (guild_id, role_id),
                )

        await self._run(_delete)

    async def clear_roles(self, guild_id: int) -> None:
        def _delete() -> None:
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    "DELETE FROM allowed_roles WHERE guild_id = ?", (guild_id,)
                )

        await self._run(_delete)

    # --- роли-исключения ------------------------------------------------
    async def get_excluded_roles(self, guild_id: int) -> list[int]:
        def _query() -> list[int]:
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    "SELECT role_id FROM excluded_roles "
                    "WHERE guild_id = ? ORDER BY role_id",
                    (guild_id,),
                ).fetchall()
            return [int(row["role_id"]) for row in rows]

        return await self._run(_query)

    async def add_excluded_role(self, guild_id: int, role_id: int) -> None:
        def _insert() -> None:
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    "INSERT OR IGNORE INTO excluded_roles (guild_id, role_id) "
                    "VALUES (?, ?)",
                    (guild_id, role_id),
                )

        await self._run(_insert)

    async def remove_excluded_role(self, guild_id: int, role_id: int) -> None:
        def _delete() -> None:
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    "DELETE FROM excluded_roles WHERE guild_id = ? AND role_id = ?",
                    (guild_id, role_id),
                )

        await self._run(_delete)

    # --- изображения ----------------------------------------------------
    def _row_to_image(self, row: sqlite3.Row) -> ImageRecord:
        return ImageRecord(
            id=int(row["id"]),
            guild_id=int(row["guild_id"]),
            attachment_id=int(row["attachment_id"]),
            message_id=int(row["message_id"]),
            channel_id=int(row["channel_id"]),
            user_id=int(row["user_id"]),
            filename=row["filename"],
            sha256=row["sha256"],
            phash=row["phash"],
            attachment_url=row["attachment_url"],
            created_at=int(row["created_at"]),
        )

    async def get_image_by_attachment(self, attachment_id: int) -> Optional[ImageRecord]:
        def _query() -> Optional[ImageRecord]:
            with closing(self._connect()) as connection:
                row = connection.execute(
                    "SELECT * FROM images WHERE attachment_id = ?", (attachment_id,)
                ).fetchone()
            return self._row_to_image(row) if row else None

        return await self._run(_query)

    async def insert_image(
        self,
        *,
        guild_id: int,
        attachment_id: int,
        message_id: int,
        channel_id: int,
        user_id: int,
        filename: Optional[str],
        sha256: str,
        phash: str,
        attachment_url: Optional[str],
        created_at: int,
    ) -> tuple[ImageRecord, bool]:
        """Возвращает запись и признак, что она создана впервые."""

        def _insert() -> tuple[ImageRecord, bool]:
            now = int(time.time())
            with closing(self._connect()) as connection, connection:
                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO images (
                        guild_id, attachment_id, message_id, channel_id, user_id,
                        filename, sha256, phash, attachment_url, created_at, indexed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        guild_id,
                        attachment_id,
                        message_id,
                        channel_id,
                        user_id,
                        filename,
                        sha256,
                        phash,
                        attachment_url,
                        created_at,
                        now,
                    ),
                )
                created = cursor.rowcount == 1
                row = connection.execute(
                    "SELECT * FROM images WHERE attachment_id = ?", (attachment_id,)
                ).fetchone()
            assert row is not None
            return self._row_to_image(row), created

        return await self._run(_insert)

    async def recent_images(
        self,
        guild_id: int,
        since: int,
        *,
        user_id: Optional[int] = None,
        limit: int = 3000,
    ) -> list[ImageRecord]:
        def _query() -> list[ImageRecord]:
            sql = (
                "SELECT * FROM images "
                "WHERE guild_id = ? AND created_at >= ? AND actioned_at IS NULL"
            )
            params: list[Any] = [guild_id, since]
            if user_id is not None:
                sql += " AND user_id = ?"
                params.append(user_id)
            sql += " ORDER BY created_at DESC, id DESC LIMIT ?"
            params.append(limit)

            with closing(self._connect()) as connection:
                rows = connection.execute(sql, params).fetchall()
            return [self._row_to_image(row) for row in rows]

        return await self._run(_query)

    async def mark_actioned(self, image_ids: list[int], timestamp: int) -> None:
        if not image_ids:
            return

        def _update() -> None:
            placeholders = ",".join("?" for _ in image_ids)
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    f"UPDATE images SET actioned_at = ? "
                    f"WHERE id IN ({placeholders}) AND actioned_at IS NULL",
                    [timestamp, *image_ids],
                )

        await self._run(_update)

    async def purge_images_before(self, cutoff: int) -> int:
        """Удаляет записи изображений и их хеши, сохранённые раньше cutoff."""

        def _delete() -> int:
            with closing(self._connect()) as connection, connection:
                cursor = connection.execute(
                    "DELETE FROM images WHERE indexed_at < ?", (cutoff,)
                )
                return cursor.rowcount

        return await self._run(_delete)

    async def purge_incidents_before(self, cutoff: int) -> int:
        """Удаляет завершённые инциденты старше cutoff (открытые не трогает)."""

        terminal = (
            STATUS_BANNED,
            STATUS_DELETED,
            STATUS_ACTIONED,
            STATUS_FAILED,
            STATUS_CANCELLED,
            STATUS_MERGED,
        )

        def _delete() -> int:
            with closing(self._connect()) as connection, connection:
                cursor = connection.execute(
                    """
                    DELETE FROM incidents
                    WHERE status IN (?, ?, ?, ?, ?, ?)
                      AND COALESCE(resolved_at, created_at) < ?
                    """,
                    (*terminal, cutoff),
                )
                return cursor.rowcount

        return await self._run(_delete)

    async def purge_bans_before(self, cutoff: int) -> int:
        """Удаляет старые записи уже снятых временных банов."""

        def _delete() -> int:
            with closing(self._connect()) as connection, connection:
                cursor = connection.execute(
                    "DELETE FROM bans WHERE active = 0 AND unban_at < ?",
                    (cutoff,),
                )
                return cursor.rowcount

        return await self._run(_delete)

    # --- инциденты ------------------------------------------------------
    @staticmethod
    def _serialize_images(images: list[IncidentImage]) -> str:
        return json.dumps(
            [
                {
                    "sha256": image.sha256,
                    "phash": image.phash,
                    "filename": image.filename,
                    "image_url": image.image_url,
                }
                for image in images
            ]
        )

    def _row_to_incident(self, row: sqlite3.Row) -> Incident:
        raw_images = json.loads(row["images"]) if row["images"] else []
        images = [
            IncidentImage(
                sha256=item["sha256"],
                phash=item["phash"],
                filename=item.get("filename"),
                image_url=item.get("image_url"),
            )
            for item in raw_images
        ]
        if not images:
            images = [
                IncidentImage(
                    sha256=row["sha256"],
                    phash=row["phash"],
                    filename=row["filename"],
                    image_url=row["image_url"],
                )
            ]
        return Incident(
            id=int(row["id"]),
            guild_id=int(row["guild_id"]),
            action=row["action"],
            status=row["status"],
            sha256=row["sha256"],
            phash=row["phash"],
            filename=row["filename"],
            image_url=row["image_url"],
            user_ids=[int(value) for value in json.loads(row["user_ids"])],
            message_ids=[
                (int(channel_id), int(message_id))
                for channel_id, message_id in json.loads(row["message_ids"])
            ],
            count=int(row["count"]),
            created_at=int(row["created_at"]),
            last_activity_at=int(row["last_activity_at"]),
            expires_at=int(row["expires_at"]),
            alert_channel_id=row["alert_channel_id"],
            alert_message_id=row["alert_message_id"],
            report_channel_id=row["report_channel_id"],
            report_message_id=row["report_message_id"],
            result=row["result"],
            window_closed=bool(row["window_closed"]),
            resolved_at=row["resolved_at"],
            images=images,
        )

    async def create_incident(
        self,
        *,
        guild_id: int,
        action: str,
        status: str,
        sha256: str,
        phash: str,
        filename: Optional[str],
        image_url: Optional[str],
        user_ids: list[int],
        message_ids: list[tuple[int, int]],
        count: int,
        created_at: int,
        last_activity_at: int,
        expires_at: int,
        images: Optional[list[IncidentImage]] = None,
    ) -> Incident:
        image_payload = self._serialize_images(
            images
            if images is not None
            else [
                IncidentImage(
                    sha256=sha256,
                    phash=phash,
                    filename=filename,
                    image_url=image_url,
                )
            ]
        )

        def _insert() -> Incident:
            with closing(self._connect()) as connection, connection:
                cursor = connection.execute(
                    """
                    INSERT INTO incidents (
                        guild_id, action, status, sha256, phash, filename, image_url,
                        images, user_ids, message_ids, count, created_at,
                        last_activity_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        guild_id,
                        action,
                        status,
                        sha256,
                        phash,
                        filename,
                        image_url,
                        image_payload,
                        json.dumps(user_ids),
                        json.dumps([list(ref) for ref in message_ids]),
                        count,
                        created_at,
                        last_activity_at,
                        expires_at,
                    ),
                )
                incident_id = int(cursor.lastrowid)
                row = connection.execute(
                    "SELECT * FROM incidents WHERE id = ?", (incident_id,)
                ).fetchone()
            assert row is not None
            return self._row_to_incident(row)

        return await self._run(_insert)

    async def get_incident(self, incident_id: int) -> Optional[Incident]:
        def _query() -> Optional[Incident]:
            with closing(self._connect()) as connection:
                row = connection.execute(
                    "SELECT * FROM incidents WHERE id = ?", (incident_id,)
                ).fetchone()
            return self._row_to_incident(row) if row else None

        return await self._run(_query)

    async def active_incidents(self, guild_id: int, now: int) -> list[Incident]:
        def _query() -> list[Incident]:
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    """
                    SELECT * FROM incidents
                    WHERE guild_id = ? AND status IN (?, ?) AND expires_at > ?
                    ORDER BY last_activity_at DESC
                    """,
                    (guild_id, STATUS_OPEN, STATUS_WATCHING, now),
                ).fetchall()
            return [self._row_to_incident(row) for row in rows]

        return await self._run(_query)

    async def append_incident(
        self,
        incident_id: int,
        *,
        user_ids: list[int],
        message_ids: list[tuple[int, int]],
        count: int,
        last_activity_at: int,
        expires_at: int,
        images: Optional[list[IncidentImage]] = None,
    ) -> None:
        def _update() -> None:
            fields = [
                "user_ids = ?",
                "message_ids = ?",
                "count = ?",
                "last_activity_at = ?",
                "expires_at = ?",
            ]
            params: list[Any] = [
                json.dumps(user_ids),
                json.dumps([list(ref) for ref in message_ids]),
                count,
                last_activity_at,
                expires_at,
            ]
            if images is not None:
                fields.append("images = ?")
                params.append(self._serialize_images(images))
            params.append(incident_id)
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    f"UPDATE incidents SET {', '.join(fields)} WHERE id = ?",
                    params,
                )

        await self._run(_update)

    async def set_alert_message(
        self, incident_id: int, channel_id: int, message_id: int
    ) -> None:
        def _update() -> None:
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    "UPDATE incidents SET alert_channel_id = ?, alert_message_id = ? "
                    "WHERE id = ?",
                    (channel_id, message_id, incident_id),
                )

        await self._run(_update)

    async def set_report_message(
        self, incident_id: int, channel_id: int, message_id: int
    ) -> None:
        def _update() -> None:
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    "UPDATE incidents SET report_channel_id = ?, report_message_id = ? "
                    "WHERE id = ?",
                    (channel_id, message_id, incident_id),
                )

        await self._run(_update)

    async def set_status(
        self,
        incident_id: int,
        status: str,
        *,
        result: Optional[str] = None,
        resolved_at: Optional[int] = None,
        window_closed: Optional[bool] = None,
        expected_status: Optional[str] = None,
    ) -> bool:
        def _update() -> bool:
            fields = ["status = ?"]
            params: list[Any] = [status]
            if result is not None:
                fields.append("result = ?")
                params.append(result)
            if resolved_at is not None:
                fields.append("resolved_at = ?")
                params.append(resolved_at)
            if window_closed is not None:
                fields.append("window_closed = ?")
                params.append(int(window_closed))
            where = "id = ?"
            params.append(incident_id)
            if expected_status is not None:
                where += " AND status = ?"
                params.append(expected_status)
            with closing(self._connect()) as connection, connection:
                cursor = connection.execute(
                    f"UPDATE incidents SET {', '.join(fields)} WHERE {where}",
                    params,
                )
                return cursor.rowcount == 1

        return await self._run(_update)

    async def claim_for_action(self, incident_id: int) -> bool:
        """Атомарно забирает уведомление в обработку, чтобы кнопки не сработали дважды."""

        def _update() -> bool:
            with closing(self._connect()) as connection, connection:
                cursor = connection.execute(
                    "UPDATE incidents SET status = ? WHERE id = ? AND status = ?",
                    (STATUS_ACTIONING, incident_id, STATUS_OPEN),
                )
                return cursor.rowcount == 1

        return await self._run(_update)

    async def cancel_delete(
        self, incident_id: int, *, result: str, resolved_at: int
    ) -> bool:
        """Останавливает мониторинг удаления, только если он ещё активен."""

        def _update() -> bool:
            with closing(self._connect()) as connection, connection:
                cursor = connection.execute(
                    """
                    UPDATE incidents SET
                        status = ?, result = ?, resolved_at = ?, window_closed = 1
                    WHERE id = ? AND status = ?
                    """,
                    (
                        STATUS_CANCELLED,
                        result,
                        resolved_at,
                        incident_id,
                        STATUS_WATCHING,
                    ),
                )
                return cursor.rowcount == 1

        return await self._run(_update)

    async def reset_actioning(self) -> int:
        """Возвращает в open инциденты, зависшие в обработке после перезапуска."""

        def _update() -> int:
            with closing(self._connect()) as connection, connection:
                cursor = connection.execute(
                    "UPDATE incidents SET status = ? WHERE status = ?",
                    (STATUS_OPEN, STATUS_ACTIONING),
                )
                return cursor.rowcount

        return await self._run(_update)

    async def expired_incidents(self, now: int) -> list[Incident]:
        def _query() -> list[Incident]:
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    """
                    SELECT * FROM incidents
                    WHERE status IN (?, ?) AND window_closed = 0 AND expires_at <= ?
                    """,
                    (STATUS_OPEN, STATUS_WATCHING, now),
                ).fetchall()
            return [self._row_to_incident(row) for row in rows]

        return await self._run(_query)

    # --- временные баны -------------------------------------------------
    @staticmethod
    def _row_to_ban(row: sqlite3.Row) -> BanRecord:
        return BanRecord(
            guild_id=int(row["guild_id"]),
            user_id=int(row["user_id"]),
            unban_at=int(row["unban_at"]),
            banned_at=int(row["banned_at"]),
            incident_id=row["incident_id"],
            active=bool(row["active"]),
            last_attempt_at=int(row["last_attempt_at"]),
        )

    async def upsert_ban(
        self,
        *,
        guild_id: int,
        user_id: int,
        incident_id: Optional[int],
        banned_at: int,
        unban_at: int,
    ) -> None:
        def _upsert() -> None:
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    """
                    INSERT INTO bans (
                        guild_id, user_id, incident_id, banned_at, unban_at,
                        active, last_attempt_at
                    ) VALUES (?, ?, ?, ?, ?, 1, 0)
                    ON CONFLICT(guild_id, user_id) DO UPDATE SET
                        incident_id = excluded.incident_id,
                        banned_at = excluded.banned_at,
                        unban_at = excluded.unban_at,
                        active = 1,
                        last_attempt_at = 0
                    """,
                    (guild_id, user_id, incident_id, banned_at, unban_at),
                )

        await self._run(_upsert)

    async def clear_ban(self, guild_id: int, user_id: int) -> None:
        def _delete() -> None:
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    "DELETE FROM bans WHERE guild_id = ? AND user_id = ?",
                    (guild_id, user_id),
                )

        await self._run(_delete)

    async def get_active_bans(self, guild_id: int) -> list[BanRecord]:
        def _query() -> list[BanRecord]:
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    "SELECT * FROM bans "
                    "WHERE guild_id = ? AND active = 1 "
                    "ORDER BY unban_at ASC",
                    (guild_id,),
                ).fetchall()
            return [self._row_to_ban(row) for row in rows]

        return await self._run(_query)

    async def due_bans(self, now: int) -> list[BanRecord]:
        """Баны, срок которых истёк; неудачные попытки повторяются раз в час."""

        retry_before = now - 3600

        def _query() -> list[BanRecord]:
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    """
                    SELECT * FROM bans
                    WHERE active = 1 AND unban_at <= ?
                      AND (last_attempt_at = 0 OR last_attempt_at <= ?)
                    ORDER BY unban_at ASC
                    """,
                    (now, retry_before),
                ).fetchall()
            return [self._row_to_ban(row) for row in rows]

        return await self._run(_query)

    async def mark_unbanned(self, guild_id: int, user_id: int) -> None:
        def _update() -> None:
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    "UPDATE bans SET active = 0 WHERE guild_id = ? AND user_id = ?",
                    (guild_id, user_id),
                )

        await self._run(_update)

    async def mark_ban_attempt(
        self, guild_id: int, user_id: int, timestamp: int
    ) -> None:
        def _update() -> None:
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    "UPDATE bans SET last_attempt_at = ? "
                    "WHERE guild_id = ? AND user_id = ?",
                    (timestamp, guild_id, user_id),
                )

        await self._run(_update)

    async def stats(self, guild_id: int) -> dict[str, int]:
        def _query() -> dict[str, int]:
            with closing(self._connect()) as connection:
                images = connection.execute(
                    "SELECT COUNT(*) AS value FROM images WHERE guild_id = ?",
                    (guild_id,),
                ).fetchone()
                incidents = connection.execute(
                    "SELECT COUNT(*) AS value FROM incidents WHERE guild_id = ?",
                    (guild_id,),
                ).fetchone()
            return {
                "images": int(images["value"]) if images else 0,
                "incidents": int(incidents["value"]) if incidents else 0,
            }

        return await self._run(_query)

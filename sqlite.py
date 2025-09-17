import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Set, Iterable, Optional, List, Tuple
import time

SQL_TABLE_HASHTAGS = """
CREATE TABLE IF NOT EXISTS `hashtags` (tag TEXT PRIMARY KEY UNIQUE)
"""

SQL_TABLE_STORAGE = """
CREATE TABLE IF NOT EXISTS `storage` (key TEXT PRIMARY KEY, value TEXT)
"""

SQL_TABLE_CHAT_MESSAGES = """
CREATE TABLE IF NOT EXISTS `chat_messages` (
    chat_id INTEGER PRIMARY KEY,
    latest_message_id INTEGER NOT NULL
)
"""

SQL_TABLE_DNS_QUERIES = """
CREATE TABLE IF NOT EXISTS `dns_queries` (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER,
    client TEXT,
    domain TEXT
)
"""

SQL_TABLE_WIREGUARD_CLIENTS = """
CREATE TABLE IF NOT EXISTS `wireguard_clients` (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    ipv4 TEXT NOT NULL,
    ipv6 TEXT NOT NULL,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    preshared_key TEXT NOT NULL,
    config_file TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    created_by INTEGER NOT NULL
)
"""

SQL_GET_NAV_MESSAGE_ID = 'SELECT value FROM storage WHERE key = "navigation_message_id"'

SQL_UPDATE_NAV_MESSAGE_ID = """
INSERT OR REPLACE INTO `storage` (key, value)
VALUES (?, ?)
"""

SQL_GET_MEDIA_GIF_ID = 'SELECT value FROM storage WHERE key = "media_gif_id"'

SQL_UPDATE_MEDIA_GIF_ID = """
INSERT OR REPLACE INTO `storage` (key, value)
VALUES (?, ?)
"""

SQL_GET_ALL_HASHTAGS = "SELECT `tag` FROM `hashtags`"
SQL_DELETE_ALL_HASHTAGS = "DELETE FROM `hashtags`"
SQL_INSERT_HASHTAG = "INSERT INTO hashtags (tag) VALUES (?)"

SQL_GET_CHAT_MESSAGE_ID = "SELECT latest_message_id FROM chat_messages WHERE chat_id = ?"
SQL_UPDATE_CHAT_MESSAGE_ID = """
INSERT OR REPLACE INTO chat_messages (chat_id, latest_message_id)
VALUES (?, ?)
"""
SQL_DELETE_CHAT_MESSAGE = "DELETE FROM chat_messages WHERE chat_id = ?"


class SQLite:
    """Class for working with SQLite database of hashtags, settings and WireGuard clients."""

    def __init__(self, db_file: str = "db.sqlite3") -> None:
        """
        Initialize database connection.

        :param db_file: Path to the database file
        """
        self.file = Path(db_file)
        self.database = sqlite3.connect(self.file, check_same_thread=False)
        self._initialize_database()

    def _initialize_database(self) -> None:
        """Initialize database tables."""
        try:
            with self.database as connect:
                with closing(connect.cursor()) as cursor:
                    cursor.execute(SQL_TABLE_HASHTAGS)
                    cursor.execute(SQL_TABLE_STORAGE)
                    cursor.execute(SQL_TABLE_CHAT_MESSAGES)
                    cursor.execute(SQL_TABLE_DNS_QUERIES)
                    cursor.execute(SQL_TABLE_WIREGUARD_CLIENTS)
        except sqlite3.Error as e:
            print(f"Error initializing database: {e}")

    def get_hashtags(self) -> Set[str]:
        """Get all hashtags from the database."""
        try:
            with self.database as connect:
                with closing(connect.cursor()) as cursor:
                    request = cursor.execute(SQL_GET_ALL_HASHTAGS)
                    return {row[0] for row in request.fetchall()}
        except sqlite3.Error as e:
            print(f"Error getting hashtags: {e}")
            return set()

    def update_hashtags(self, tags: Iterable[str]) -> None:
        """Update the hashtags list in the database."""
        try:
            with self.database as connect:
                with closing(connect.cursor()) as cursor:
                    cursor.execute(SQL_DELETE_ALL_HASHTAGS)
                    cursor.executemany(
                        SQL_INSERT_HASHTAG,
                        [(tag,) for tag in tags]
                    )
        except sqlite3.Error as e:
            print(f"Error updating hashtags: {e}")

    def get_navigation_message_id(self) -> int:
        """Get the navigation message ID."""
        try:
            with self.database as connect:
                with closing(connect.cursor()) as cursor:
                    result = cursor.execute(SQL_GET_NAV_MESSAGE_ID).fetchone()
                    return int(result[0]) if result else 0
        except (sqlite3.Error, ValueError) as e:
            print(f"Error getting message ID: {e}")
            return 0

    def update_navigation_message_id(self, message_id: int) -> None:
        """Update the navigation message ID."""
        try:
            with self.database as connect:
                with closing(connect.cursor()) as cursor:
                    cursor.execute(
                        SQL_UPDATE_NAV_MESSAGE_ID,
                        ("navigation_message_id", str(message_id)),
                    )
        except sqlite3.Error as e:
            print(f"Error updating message ID: {e}")

    def get_media_gif_id(self) -> Optional[str]:
        """Get the cached media GIF ID."""
        try:
            with self.database as connect:
                with closing(connect.cursor()) as cursor:
                    result = cursor.execute(SQL_GET_MEDIA_GIF_ID).fetchone()
                    return result[0] if result else None
        except sqlite3.Error as e:
            print(f"Error getting media GIF ID: {e}")
            return None

    def update_media_gif_id(self, gif_id: str) -> None:
        """Update the cached media GIF ID."""
        try:
            with self.database as connect:
                with closing(connect.cursor()) as cursor:
                    cursor.execute(
                        SQL_UPDATE_MEDIA_GIF_ID,
                        ("media_gif_id", gif_id),
                    )
        except sqlite3.Error as e:
            print(f"Error updating media GIF ID: {e}")

    def get_chat_latest_message_id(self, chat_id: int) -> Optional[int]:
        """Get the latest message ID for a specific chat."""
        try:
            with self.database as connect:
                with closing(connect.cursor()) as cursor:
                    result = cursor.execute(SQL_GET_CHAT_MESSAGE_ID, (chat_id,)).fetchone()
                    return int(result[0]) if result else None
        except (sqlite3.Error, ValueError) as e:
            print(f"Error getting chat message ID: {e}")
            return None

    def update_chat_latest_message_id(self, chat_id: int, message_id: int) -> None:
        """Update the latest message ID for a specific chat."""
        try:
            with self.database as connect:
                with closing(connect.cursor()) as cursor:
                    cursor.execute(SQL_UPDATE_CHAT_MESSAGE_ID, (chat_id, message_id))
        except sqlite3.Error as e:
            print(f"Error updating chat message ID: {e}")

    def delete_chat_message_record(self, chat_id: int) -> None:
        """Delete the message record for a specific chat."""
        try:
            with self.database as connect:
                with closing(connect.cursor()) as cursor:
                    cursor.execute(SQL_DELETE_CHAT_MESSAGE, (chat_id,))
        except sqlite3.Error as e:
            print(f"Error deleting chat message record: {e}")

    def add_dns_query(self, client: str, domain: str) -> None:
        """Save a DNS query for a client and domain with current timestamp (seconds)."""
        try:
            with self.database as connect:
                with closing(connect.cursor()) as cursor:
                    cursor.execute(
                        "INSERT INTO dns_queries (ts, client, domain) VALUES (?, ?, ?)",
                        (int(time.time()), client, domain),
                    )
        except sqlite3.Error as e:
            print(f"Error saving dns query: {e}")

    def get_domains_last_hours(self, client: str, hours: int = 24) -> List[Tuple[str, int, int]]:
        """Return list of (domain, count, last_ts) for last N hours for a client, sorted by count desc."""
        try:
            since_ts = int(time.time()) - hours * 3600
            with self.database as connect:
                with closing(connect.cursor()) as cursor:
                    rows = cursor.execute(
                        """
                        SELECT domain, COUNT(*) as cnt, MAX(ts) as last_ts
                        FROM dns_queries
                        WHERE client = ? AND ts >= ?
                        GROUP BY domain
                        ORDER BY cnt DESC
                        """,
                        (client, since_ts),
                    ).fetchall()
                    return [(row[0], int(row[1]), int(row[2])) for row in rows]
        except sqlite3.Error as e:
            print(f"Error getting domains: {e}")
            return []

    def cleanup_old(self, days: int) -> int:
        """Delete records older than N days. Returns number of deleted rows."""
        try:
            cutoff = int(time.time()) - days * 86400
            with self.database as connect:
                with closing(connect.cursor()) as cursor:
                    cursor.execute("DELETE FROM dns_queries WHERE ts < ?", (cutoff,))
                    return cursor.rowcount or 0
        except sqlite3.Error as e:
            print(f"Error cleaning up old dns queries: {e}")
            return 0

    def add_wireguard_client(self, name: str, ipv4: str, ipv6: str,
                             public_key: str, private_key: str, preshared_key: str,
                             config_file: str, created_by: int) -> bool:
        """Add a new WireGuard client to the database."""
        try:
            with self.database as connect:
                with closing(connect.cursor()) as cursor:
                    cursor.execute(
                        """INSERT INTO wireguard_clients
                           (name, ipv4, ipv6, public_key, private_key, preshared_key, config_file, created_at, created_by)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (name, ipv4, ipv6, public_key, private_key, preshared_key, config_file, int(time.time()), created_by)
                    )
            return True
        except sqlite3.Error as e:
            print(f"Error adding WireGuard client: {e}")
            return False

    def remove_wireguard_client(self, name: str) -> bool:
        """Remove a WireGuard client from the database."""
        try:
            with self.database as connect:
                with closing(connect.cursor()) as cursor:
                    cursor.execute("DELETE FROM wireguard_clients WHERE name = ?", (name,))
                    return cursor.rowcount > 0
        except sqlite3.Error as e:
            print(f"Error removing WireGuard client: {e}")
            return False

    def get_wireguard_client(self, name: str) -> Optional[Tuple]:
        """Get WireGuard client information by name."""
        try:
            with self.database as connect:
                with closing(connect.cursor()) as cursor:
                    result = cursor.execute(
                        "SELECT name, ipv4, ipv6, public_key, private_key, preshared_key, config_file, created_at, created_by FROM wireguard_clients WHERE name = ?",
                        (name,)
                    ).fetchone()
                    return result
        except sqlite3.Error as e:
            print(f"Error getting WireGuard client: {e}")
            return None

    def list_wireguard_clients(self) -> List[Tuple]:
        """Get list of all WireGuard clients."""
        try:
            with self.database as connect:
                with closing(connect.cursor()) as cursor:
                    results = cursor.execute(
                        "SELECT name, ipv4, ipv6, public_key, private_key, preshared_key, config_file, created_at, created_by FROM wireguard_clients ORDER BY created_at DESC"
                    ).fetchall()
                    return results
        except sqlite3.Error as e:
            print(f"Error listing WireGuard clients: {e}")
            return []

    def wireguard_client_exists(self, name: str) -> bool:
        """Check if WireGuard client exists."""
        try:
            with self.database as connect:
                with closing(connect.cursor()) as cursor:
                    result = cursor.execute(
                        "SELECT 1 FROM wireguard_clients WHERE name = ?",
                        (name,)
                    ).fetchone()
                    return result is not None
        except sqlite3.Error as e:
            print(f"Error checking WireGuard client existence: {e}")
            return False

    def close(self) -> None:
        """Close the database connection."""
        self.database.close()

    def __del__(self) -> None:
        """Destructor that closes the connection."""
        self.close()

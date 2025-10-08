#!/usr/bin/env python3
# 0 12 */3 * * /opt/userbot/.venv/bin/python3 /opt/userbot/backup.py >> /var/log/backup.log 2>&1

__doc__ = "A simple backup script for important data in the Telegram channel"

import os
import tarfile
import logging
from datetime import datetime
from telethon import TelegramClient
from dotenv import load_dotenv
from utils import get_session_file

# ================= Logging setup =================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# ================= Backup configuration =================
BACKUP_DIR = "/tmp"
DATE = datetime.now().strftime("%Y-%m-%d-%H-%M")
ARCHIVE_NAME = os.path.join(BACKUP_DIR, f"backup-{DATE}.tar.gz")

FILES_TO_BACKUP = [
    "/etc/wireguard",
    "/etc/sysctl.d/",
    "/etc/zapret",
    "/etc/hosts",
    "/etc/ssh",
    "/opt/AdGuardHome/data",
    "/opt/userbot/db.sqlite3",
    "/opt/userbot/sessions",
    "/opt/userbot/media",
    "/opt/userbot/.env",
    "/opt/zapret/config",
    "/opt/zapret/init.d/sysv/custom.d/",
    "/opt/zapret/ipset/zapret-hosts-user.txt",
    "/opt/zapret/ipset/zapret-hosts-user-exclude.txt",
    "/root/wireguard-install.sh",
    "/root/.ssh",
    "/root/.bashrc",
    "/root/.config/systemd/journald.conf",
    # __file__,
]


# ================= Functions =================
def create_archive(archive_name, files):
    """Create a tar.gz archive from the list of files/folders."""
    os.makedirs(os.path.dirname(archive_name), exist_ok=True)
    logging.info("Creating archive: %s", archive_name)
    with tarfile.open(archive_name, "w:gz") as tar:
        for f in files:
            if os.path.exists(f):
                tar.add(f)
                logging.info("Added: %s", f)
            else:
                logging.warning("File or folder not found: %s", f)
    logging.info("Archive created: %s", archive_name)
    return archive_name


def send_file(api_id, api_hash, dest, file_path, session):
    """Send the archive file to Telegram channel/user."""
    client = TelegramClient(session, api_id, api_hash)

    async def _send():
        await client.start()
        size_mb = os.path.getsize(file_path) / 1024 / 1024
        logging.info("Sending %s (%.2f MB) -> %s", file_path, size_mb, dest)

        def progress(current, total):
            percent = current * 100 / total if total else 0
            logging.info("Progress: %.1f%%", percent)

        await client.send_file(
            dest,
            file_path,
            progress_callback=progress,
        )
        logging.info("File sent successfully")

    with client:
        client.loop.run_until_complete(_send())


# ================= Main logic =================
def main():
    load_dotenv()

    api_id = int(os.getenv("API_ID", "0"))
    api_hash = os.getenv("API_HASH", "")
    dest = int(os.getenv("BACKUP_CHANNEL_ID", "0"))
    session = get_session_file(os.getenv("BACKUPER_SESSION", ""))

    if not api_id or not api_hash or not dest:
        logging.error("API_ID, API_HASH or BACKUP_CHANNEL_ID not set in .env")
        return

    archive = create_archive(ARCHIVE_NAME, FILES_TO_BACKUP)
    send_file(api_id, api_hash, dest, archive, session)
    os.remove(archive)


if __name__ == "__main__":
    main()

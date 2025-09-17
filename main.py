# pylint: disable=too-many-lines
__doc__ = "The userbot to managing my personal data"

import os
import sys
import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Set, List

from dotenv import load_dotenv
from telethon import TelegramClient, events, types
from telethon.errors import (
    MessageDeleteForbiddenError, 
    FilePart0MissingError, 
    FilePartMissingError
)

from sqlite import SQLite
from utils import (
    extract_hashtags,
    get_session_file,
    prompt_to_text,
    normalize_domain,
    write_to_zapret_file,
    get_all_zapret_files,
    check_site_in_zapret_file,
)
from wireguard import WireGuardManager
from strings import (
    MSG_HELP,
    MSG_UNAUTHORIZED_ACCESS,
    CMD_STATS,
    CMD_WGADD,
    CMD_WGREMOVE,
    CMD_WGRENAME,
    CMD_WGLIST,
    CMD_WGCONFIG,
    CMD_HASHTAG_REMOVE,
    CMD_HASHTAG_LIST,
    CMD_HELP,
    CMD_ZAPRET_ADD,
    CMD_ZAPRET_CHECK,
)

# Load configuration from .env file
load_dotenv()
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(name)s: %(message)s",
    stream=sys.stdout,
)


@dataclass
class Config:
    """Configuration class for Telegram bot"""

    api_id: int
    api_hash: str
    channel_id: int
    session_name: Path = get_session_file(os.getenv("MAIN_SESSION", ""))
    proxy: Optional[Dict[str, Any]] = None
    allowed_chats: Optional[List[int]] = None

    @classmethod
    def from_env(cls):
        """Create config from environment variables"""
        proxy = None
        if os.getenv("USE_PROXY", "").lower() == "true":
            proxy = {
                "proxy_type": os.getenv("PROXY_TYPE", "socks5"),
                "addr": os.getenv("PROXY_ADDR"),
                "port": int(os.getenv("PROXY_PORT", "1080")),
                "username": os.getenv("PROXY_USERNAME"),
                "password": os.getenv("PROXY_PASSWORD"),
                "rdns": os.getenv("PROXY_RDNS", "true").lower() == "true",
            }

        chats_env = os.getenv("ALLOWED_CHATS", "")
        allowed_chats = [
            int(item.strip())
            for item in chats_env.split(",")
            if item and item.strip().lstrip("-").isdigit()
        ]

        return cls(
            api_id=int(os.getenv("API_ID")),
            api_hash=os.getenv("API_HASH"),
            channel_id=int(os.getenv("CHANNEL_ID")),
            proxy=proxy,
            allowed_chats=allowed_chats,
        )


class TelegramBot:
    """Telegram bot for managing channel posts and hashtags"""

    def __init__(self, config: Config):
        """Initialize bot with configuration"""
        self.config = config
        self.client = TelegramClient(
            session=config.session_name,
            api_id=config.api_id,
            api_hash=config.api_hash,
            proxy=config.proxy,
        )
        self.db = SQLite()
        self.wg_manager = WireGuardManager(db=self.db)
        self.hashtags: Set[str] = set()
        self.nav_message_id: Optional[int] = None
        self.cached_gif_file: Optional[Any] = None
        self.processing_groups: Set[int] = set()

        # Configure logging
        self.logger = logging.getLogger(self.__class__.__name__)

        # Load initial state
        self._load_state()

    def _load_state(self):
        """Load initial state from database"""
        self.hashtags = self.db.get_hashtags()
        self.nav_message_id = self.db.get_navigation_message_id()
        self.logger.info(
            "Loaded initial state: %d hashtags, nav message ID: %s",
            len(self.hashtags),
            self.nav_message_id,
        )

    async def run(self):
        """Run the bot"""
        self.logger.info("Starting Telegram bot...")

        # Register event handlers
        self.client.add_event_handler(
            self._handle_new_pin,
            events.ChatAction(chats=self.config.channel_id, func=lambda e: e.new_pin),
        )

        # Separate handlers for single messages and albums
        self.client.add_event_handler(
            self._handle_album,
            events.Album(chats=self.config.channel_id),
        )

        self.client.add_event_handler(
            self._handle_single_message,
            events.NewMessage(
                chats=self.config.channel_id,
                func=lambda e: e.message.id != self.nav_message_id
                and not e.message.grouped_id,
            ),
        )

        # Handler for message edits
        self.client.add_event_handler(
            self._handle_message_edit,
            events.MessageEdited(
                chats=self.config.channel_id,
                func=lambda e: e.message.id != self.nav_message_id,
            ),
        )

        # Handler for WireGuard stats
        self.client.add_event_handler(
            self._handle_stats_command,
            events.NewMessage(
                from_users=self.config.allowed_chats,
                func=lambda e: e.message.text
                and e.message.text.strip().lower().split()[0] in CMD_STATS,
            ),
        )

        # Handler for WireGuard management commands
        self.client.add_event_handler(
            self._handle_wg_add_command,
            events.NewMessage(
                from_users=self.config.allowed_chats,
                func=lambda e: e.message.text
                and e.message.text.strip().lower().startswith(CMD_WGADD),
            ),
        )

        self.client.add_event_handler(
            self._handle_wg_remove_command,
            events.NewMessage(
                from_users=self.config.allowed_chats,
                func=lambda e: e.message.text
                and e.message.text.strip().lower().startswith(CMD_WGREMOVE),
            ),
        )

        self.client.add_event_handler(
            self._handle_wg_rename_command,
            events.NewMessage(
                from_users=self.config.allowed_chats,
                func=lambda e: e.message.text
                and e.message.text.strip().lower().startswith(CMD_WGRENAME),
            ),
        )

        self.client.add_event_handler(
            self._handle_wg_list_command,
            events.NewMessage(
                from_users=self.config.allowed_chats,
                func=lambda e: e.message.text
                and e.message.text.strip().lower() in CMD_WGLIST,
            ),
        )

        self.client.add_event_handler(
            self._handle_wg_config_command,
            events.NewMessage(
                from_users=self.config.allowed_chats,
                func=lambda e: e.message.text
                and e.message.text.strip().lower().startswith(CMD_WGCONFIG),
            ),
        )

        # Add handler for help command
        self.client.add_event_handler(
            self._handle_help_command,
            events.NewMessage(
                func=lambda e: e.message.text
                and e.message.text.strip().lower() in CMD_HELP
            ),
        )

        # Add handler for hashtag remove command
        self.client.add_event_handler(
            self._handle_hashtag_remove_command,
            events.NewMessage(
                from_users=self.config.allowed_chats,
                func=lambda e: e.message.text
                and e.message.text.strip().lower().startswith(CMD_HASHTAG_REMOVE),
            ),
        )

        # Add handler for hashtag list command
        self.client.add_event_handler(
            self._handle_hashtag_list_command,
            events.NewMessage(
                from_users=self.config.allowed_chats,
                func=lambda e: e.message.text
                and e.message.text.strip().lower() in CMD_HASHTAG_LIST,
            ),
        )

        # Add handler for zapret add command
        self.client.add_event_handler(
            self._handle_zapret_add_command,
            events.NewMessage(
                from_users=self.config.allowed_chats,
                func=lambda e: e.message.text
                and e.message.text.strip().lower().split()[0] in CMD_ZAPRET_ADD,
            ),
        )

        # Add handler for zapret check command
        self.client.add_event_handler(
            self._handle_zapret_check_command,
            events.NewMessage(
                from_users=self.config.allowed_chats,
                func=lambda e: e.message.text
                and e.message.text.strip().lower().split()[0] in CMD_ZAPRET_CHECK,
            ),
        )

        async with self.client:
            self.logger.info("Bot is running. Press Ctrl+C to stop.")
            await self.client.run_until_disconnected()

    # --------------------------------------
    # Internal helpers (responses & utilities)
    # --------------------------------------

    async def _send_text_and_cleanup(
        self, event: events.common.EventBuilder, text: str
    ):
        """Send text message and perform per-chat cleanup bookkeeping."""
        new_message = await self.client.send_message(event.chat_id, text)
        await self._cleanup_and_update_chat(event, new_message.id)
        return new_message

    async def _send_file_and_cleanup(
        self,
        event: events.common.EventBuilder,
        file: Any,
        caption: Optional[str] = None,
    ):
        """Send file (path or already uploaded object) and cleanup bookkeeping."""
        new_message = await self.client.send_file(event.chat_id, file, caption=caption)
        await self._cleanup_and_update_chat(event, new_message.id)
        return new_message

    async def _handle_wg_rename_command(self, event: events.NewMessage.Event):
        """Handle WireGuard rename client command"""
        try:
            # Extract old and new client names from command
            command_text = event.message.text.strip()
            parts = command_text.split()

            if len(parts) < 3:
                message_text = (
                    "Error: Specify old and new client names\n\n"
                    "Usage: `wgrename <old_name> <new_name>`\n"
                    "Example: `wgrename myclient newclient`"
                )
                await self._send_text_and_cleanup(event, message_text)
            else:
                old_name = parts[1]
                new_name = parts[2]

                try:
                    # Log the rename attempt
                    self.logger.info(
                        "Attempting to rename client '%s' to '%s'", old_name, new_name
                    )

                    # Rename client
                    _, message = self.wg_manager.rename_client(old_name, new_name)
                    message_text = message

                    # Log the result
                    self.logger.info("Rename result: %s", message)

                except ValueError as e:
                    message_text = f"Validation error: {str(e)}"
                except RuntimeError as e:
                    message_text = f"Client rename error: {str(e)}"
                except (OSError, IOError, ConnectionError) as e:
                    self.logger.error(
                        "Unexpected error in wg rename command: %s",
                        str(e),
                        exc_info=True,
                    )
                    message_text = f"Unexpected error: {str(e)}"

                await self._send_text_and_cleanup(event, message_text)

        except (OSError, IOError, ConnectionError) as e:
            self.logger.error(
                "Error in wg rename command handler: %s", str(e), exc_info=True
            )
            message_text = f"Command processing error: {str(e)}"

            # Send error response
            await self._send_text_and_cleanup(event, message_text)

    async def _handle_new_pin(self, event: events.ChatAction.Event):
        """Handle new pinned message event"""
        if not event.action_message or not event.action_message.action:
            self.logger.warning("Received pin event without action message")
            return

        if isinstance(event.action_message.action, types.MessageActionPinMessage):
            self.logger.info(
                "New pinned message detected. ID: %d", event.action_message.id
            )
            try:
                await event.delete()
                self.logger.info(
                    "Successfully deleted pin notification for message ID: %d",
                    event.action_message.id,
                )
            except MessageDeleteForbiddenError as e:
                self.logger.error("Failed to delete pin notification: %s", str(e))
            except (OSError, IOError, ConnectionError) as e:
                self.logger.error(
                    "Unexpected error deleting pin notification: %s",
                    str(e),
                    exc_info=True,
                )

    async def _handle_single_message(self, event: events.NewMessage.Event):
        """Handle single (non-album) messages"""
        await self._process_message_content(event.message)

    async def _handle_album(self, event: events.Album.Event):
        """Handle media albums (groups of messages)"""
        # Skip if we're already processing this group
        if event.grouped_id in self.processing_groups:
            return

        self.processing_groups.add(event.grouped_id)
        try:
            # Get all messages in the album
            messages = event.messages

            # Find the first message with text (usually the main caption)
            main_message = next((msg for msg in messages if msg.text), messages[0])

            # Combine all text from all messages in the album
            combined_text = "\n".join(msg.text for msg in messages if msg.text)

            # Process as a single message
            await self._process_message_content(main_message, combined_text)
        finally:
            self.processing_groups.discard(event.grouped_id)

    async def _process_message_content(
        self, message: types.Message, custom_text: str = None
    ):
        """Common processing logic for both single messages and albums"""
        text = custom_text if custom_text is not None else (message.text or "")

        self.logger.info("Processing message ID: %d", message.id)

        # Extract and process hashtags
        tags = extract_hashtags(text)
        need_check_tags = bool(tags) or not self.hashtags

        self.logger.debug(
            "Message contains hashtags: %s. Need check: %s", tags, need_check_tags
        )

        # Collect hashtags from channel if storage is empty
        if not self.hashtags and need_check_tags:
            self.logger.info("No existing hashtags. Collecting from channel...")
            extracted_from_channel = await self._collect_posts_from_channel(message.id)
            self.hashtags.update(extracted_from_channel)
            self.db.update_hashtags(self.hashtags)
            self.logger.info(
                "Collected %d unique hashtags from channel", len(extracted_from_channel)
            )

        # Add new hashtags if found
        if tags and need_check_tags:
            new_tags = [tag for tag in tags if tag not in self.hashtags]
            if new_tags:
                self.logger.info("Adding %d new hashtags: %s", len(new_tags), new_tags)
                self.hashtags.update(new_tags)
                self.db.update_hashtags(self.hashtags)

        # Update navigation message
        await self._update_navigation_message()

    async def _handle_message_edit(self, event: events.MessageEdited.Event):
        """Handle message edit events to update hashtags"""
        self.logger.info("Processing edited message ID: %d", event.message.id)

        # Extract hashtags from edited message
        text = event.message.text or ""
        new_tags = extract_hashtags(text)

        if new_tags:
            self.logger.info(
                "Found %d hashtags in edited message: %s", len(new_tags), new_tags
            )

            # Check if there are new hashtags to add
            new_hashtags = [tag for tag in new_tags if tag not in self.hashtags]
            if new_hashtags:
                self.logger.info(
                    "Adding %d new hashtags from edit: %s",
                    len(new_hashtags),
                    new_hashtags,
                )
                self.hashtags.update(new_hashtags)
                self.db.update_hashtags(self.hashtags)

                # Update navigation message
                await self._update_navigation_message()
            else:
                self.logger.debug("No new hashtags found in edited message")
        else:
            self.logger.debug("No hashtags found in edited message")

    async def _collect_posts_from_channel(self, exclude_post_id: int) -> Set[str]:
        """Collect hashtags from channel posts"""
        tags = set()
        self.logger.info(
            "Collecting hashtags from channel posts (excluding ID: %d)", exclude_post_id
        )

        async for message in self.client.iter_messages(
            entity=self.config.channel_id,
        ):
            if message.id == exclude_post_id or not message.text:
                continue

            extracted = extract_hashtags(message.text)
            if extracted:
                tags.update(extracted)
                self.logger.debug(
                    "Found %d hashtags in message ID: %d", len(extracted), message.id
                )

        self.logger.info("Total collected unique hashtags: %d", len(tags))
        return tags

    async def _load_gif_file(self) -> Optional[Any]:
        """Load and cache GIF file in memory"""
        gif_path = Path("media/media.gif")

        if not gif_path.exists():
            self.logger.warning("media.gif not found at %s", gif_path)
            return None

        try:
            # Upload file to Telegram and cache the uploaded file object
            uploaded_file = await self.client.upload_file(gif_path)
            self.cached_gif_file = uploaded_file

            self.logger.info("Successfully loaded and cached GIF file")
            return self.cached_gif_file

        except (OSError, IOError, ConnectionError) as e:
            self.logger.error("Failed to load GIF: %s", str(e), exc_info=True)
            return None

    async def _update_navigation_message(self):
        """Update or create navigation message with hashtags and GIF"""
        message_text = prompt_to_text(self.hashtags)

        # Try to delete existing message first
        if self.nav_message_id:
            try:
                await self.client.delete_messages(
                    self.config.channel_id,
                    self.nav_message_id,
                )
                self.logger.info(
                    "Delete old navigation message ID: %d", self.nav_message_id
                )
            except MessageDeleteForbiddenError:
                self.logger.debug("Navigation message not deleted")
                return
            except (OSError, IOError, ConnectionError) as e:
                self.logger.warning(
                    "Failed to edit navigation message (will create new): %s", str(e)
                )

        # Get or load cached GIF
        gif_file = self.cached_gif_file
        if not gif_file:
            gif_file = await self._load_gif_file()

        try:
            if gif_file:
                # Send message with GIF using cached file object
                new_message = await self.client.send_file(
                    self.config.channel_id,
                    gif_file,
                    caption=message_text,
                )
            else:
                # Fallback to text-only message if GIF is not available
                new_message = await self.client.send_message(
                    self.config.channel_id,
                    message_text,
                )

            self.nav_message_id = new_message.id
            self.db.update_navigation_message_id(new_message.id)
            self.logger.info("Created new navigation message ID: %d", new_message.id)
        except (FilePart0MissingError, FilePartMissingError) as e:
            self.logger.error(
                "Cached GIF file expired, reloading from disk: %s", str(e)
            )
            gif_file = await self._load_gif_file()
            self.cached_gif_file = gif_file

            if gif_file:
                try:
                    # Retry with freshly loaded GIF
                    new_message = await self.client.send_file(
                        self.config.channel_id,
                        gif_file,
                        caption=message_text,
                    )
                    self.nav_message_id = new_message.id
                    self.db.update_navigation_message_id(new_message.id)
                    self.logger.info(
                        "Created navigation message with reloaded GIF ID: %d",
                        new_message.id,
                    )
                except (FilePart0MissingError, FilePartMissingError) as retry_e:
                    self.logger.error(
                        "GIF file corrupted on disk, falling back to text: %s",
                        str(retry_e),
                    )
                    # Final fallback to text-only
                    new_message = await self.client.send_message(
                        self.config.channel_id,
                        message_text,
                    )
                    self.nav_message_id = new_message.id
                    self.db.update_navigation_message_id(new_message.id)
                    self.logger.info(
                        "Created text-only navigation message ID: %d", new_message.id
                    )
                except (OSError, IOError, ConnectionError) as retry_e:
                    self.logger.error(
                        "Failed to create navigation message after reload: %s",
                        str(retry_e),
                        exc_info=True,
                    )
            else:
                # Fallback to text-only if GIF loading failed
                try:
                    new_message = await self.client.send_message(
                        self.config.channel_id,
                        message_text,
                    )
                    self.nav_message_id = new_message.id
                    self.db.update_navigation_message_id(new_message.id)
                    self.logger.info(
                        "Created text-only navigation message ID: %d", new_message.id
                    )
                except (OSError, IOError, ConnectionError) as retry_e:
                    self.logger.error(
                        "Failed to create text-only navigation message: %s",
                        str(retry_e),
                        exc_info=True,
                    )
        except (OSError, IOError, ConnectionError) as e:
            self.logger.error(
                "Failed to create navigation message: %s", str(e), exc_info=True
            )

    async def _cleanup_and_update_chat(
        self, event: events.common.EventBuilder, new_message_id: int
    ):
        """Delete previous bot message in chat and update latest message id."""
        previous_message_id = self.db.get_chat_latest_message_id(event.chat_id)
        if previous_message_id:
            await self.client.delete_messages(
                event.chat_id, [event.message.id, previous_message_id]
            )
        self.db.update_chat_latest_message_id(event.chat_id, new_message_id)

    async def _handle_stats_command(self, event: events.NewMessage.Event):
        """Handle stats command by executing wgshow script and sending output to the current chat"""
        message: str = event.message.text
        ip = "ip" in message.strip().split()

        try:
            message_text = self.wg_manager.get_clients_stats(ip)
            message_text = f"```\n{message_text}\n```"

        except (OSError, IOError, ConnectionError) as e:
            self.logger.error(
                "Error executing stats command: %s", str(e), exc_info=True
            )
            message_text = f"Error executing command: \n```\n{str(e)}\n```"

        finally:
            await self._send_text_and_cleanup(event, message_text)

    async def _handle_wg_add_command(self, event: events.NewMessage.Event):
        """Handle WireGuard add client command"""
        try:
            # Extract client name from command
            command_text = event.message.text.strip()
            parts = command_text.split()

            if len(parts) < 2:
                message_text = (
                    "Error: Specify client name\n\nUsage: `wgadd <client_name>`"
                )
                await self._send_text_and_cleanup(event, message_text)
            else:
                client_name = parts[1]

                try:
                    # Create client
                    client = self.wg_manager.add_client(
                        client_name, created_by=event.sender_id
                    )

                    message_text = f"Client '{client_name}' successfully added!\n\n"
                    message_text += f"IPv4: `{client.ipv4}`\n"
                    message_text += f"IPv6: `{client.ipv6}`\n"
                    message_text += f"Public key: `{client.public_key}`\n\n"

                    # Send configuration file
                    if os.path.exists(client.config_file):
                        await self._send_file_and_cleanup(
                            event, client.config_file, caption=message_text
                        )
                    else:
                        warn_text = f"Warning: Configuration file not found at {client.config_file}"
                        await self._send_text_and_cleanup(event, warn_text)

                except ValueError as e:
                    message_text = f"Validation error: {str(e)}"
                    await self._send_text_and_cleanup(event, message_text)
                except RuntimeError as e:
                    message_text = f"Client creation error: {str(e)}"
                    await self._send_text_and_cleanup(event, message_text)
                except (OSError, IOError, ConnectionError) as e:
                    self.logger.error(
                        "Unexpected error in wg add command: %s", str(e), exc_info=True
                    )
                    message_text = f"Unexpected error: {str(e)}"
                    await self._send_text_and_cleanup(event, message_text)

        except (OSError, IOError, ConnectionError) as e:
            self.logger.error(
                "Error in wg add command handler: %s", str(e), exc_info=True
            )
            message_text = f"Command processing error: {str(e)}"

            # Send error response
            await self._send_text_and_cleanup(event, message_text)

    async def _handle_wg_remove_command(self, event: events.NewMessage.Event):
        """Handle WireGuard remove client command"""
        try:
            # Extract client name from command
            command_text = event.message.text.strip()
            parts = command_text.split()

            if len(parts) < 2:
                message_text = (
                    "Error: Specify client name\n\nUsage: `wgremove <client_name>`"
                )
            else:
                client_name = parts[1]

                try:
                    # Remove client
                    success = self.wg_manager.remove_client(client_name)

                    if success:
                        message_text = f"Client '{client_name}' successfully removed!"
                    else:
                        message_text = f"Client '{client_name}' not found"

                except RuntimeError as e:
                    message_text = f"Client removal error: {str(e)}"
                except (OSError, IOError, ConnectionError) as e:
                    self.logger.error(
                        "Unexpected error in wg remove command: %s",
                        str(e),
                        exc_info=True,
                    )
                    message_text = f"Unexpected error: {str(e)}"

        except (OSError, IOError, ConnectionError) as e:
            self.logger.error(
                "Error in wg remove command handler: %s", str(e), exc_info=True
            )
            message_text = f"Command processing error: {str(e)}"

        # Send response
        await self._send_text_and_cleanup(event, message_text)

    async def _handle_wg_list_command(self, event: events.NewMessage.Event):
        """Handle WireGuard list clients command"""
        try:
            clients = self.wg_manager.list_clients()

            if not clients:
                message_text = "WireGuard clients list is empty"
            else:
                message_text = f"WireGuard clients list ({len(clients)}):\n\n"
                for i, client_name in enumerate(clients, 1):
                    message_text += f"{i}. `{client_name}`\n"

                message_text += "\nUse `wgconfig <client_name>` to get configuration"

        except (OSError, IOError, ConnectionError) as e:
            self.logger.error(
                "Error in wg list command handler: %s", str(e), exc_info=True
            )
            message_text = f"Error getting clients list: {str(e)}"

        # Send response
        await self._send_text_and_cleanup(event, message_text)

    async def _handle_wg_config_command(self, event: events.NewMessage.Event):
        """Handle WireGuard get client config command"""
        try:
            # Extract client name from command
            command_text = event.message.text.strip()
            parts = command_text.split()

            if len(parts) < 2:
                message_text = (
                    "Error: Specify client name\n\nUsage: `wgconfig <client_name>`"
                )
                await self._send_text_and_cleanup(event, message_text)
            else:
                client_name = parts[1]

                # Get client configuration
                config = self.wg_manager.get_client_config(client_name)

                if config:
                    message_text = f"```\n{config}\n```"

                    # Send configuration file
                    client = self.wg_manager.db.get_wireguard_client(client_name)
                    if client and os.path.exists(client[6]):
                        await self._send_file_and_cleanup(
                            event, client[6], caption=message_text
                        )
                    else:
                        await self._send_text_and_cleanup(event, message_text)
                else:
                    message_text = f"Client '{client_name}' not found"
                    await self._send_text_and_cleanup(event, message_text)

        except (OSError, IOError, ConnectionError) as e:
            self.logger.error(
                "Error in wg config command handler: %s", str(e), exc_info=True
            )
            message_text = f"Error getting configuration: {str(e)}"

            # Send error response
            await self._send_text_and_cleanup(event, message_text)

    async def _handle_help_command(self, event: events.NewMessage.Event):
        """Handle help command - show all available commands"""

        if event.sender_id not in self.config.allowed_chats:
            message_text = MSG_UNAUTHORIZED_ACCESS
        else:
            message_text = MSG_HELP

        # Send response
        await self._send_text_and_cleanup(event, message_text)

    async def _handle_hashtag_remove_command(self, event: events.NewMessage.Event):
        """Handle hashtag remove command"""
        try:
            # Extract hashtag from command
            command_text = event.message.text.strip()
            parts = command_text.split()

            if len(parts) < 2:
                message_text = (
                    "Error: Specify hashtag to remove\n\nUsage: `tagremove <hashtag>`\n"
                    "Example: `tagremove #python`"
                )
                await self._send_text_and_cleanup(event, message_text)
            else:
                hashtag = parts[1].lower()

                # Ensure hashtag starts with #
                if not hashtag.startswith("#"):
                    hashtag = "#" + hashtag

                if hashtag in self.hashtags:
                    # Remove hashtag from set and database
                    self.hashtags.discard(hashtag)
                    self.db.update_hashtags(self.hashtags)

                    # Update navigation message
                    await self._update_navigation_message()

                    message_text = (
                        f"Hashtag `{hashtag}` successfully removed from navigation!"
                    )
                    self.logger.info(
                        "Hashtag %s removed by user %d", hashtag, event.sender_id
                    )
                else:
                    message_text = f"Hashtag `{hashtag}` not found in navigation"

                await self._send_text_and_cleanup(event, message_text)

        except (OSError, IOError, ConnectionError) as e:
            self.logger.error("Error in hashtag remove command handler: %s", str(e))
            message_text = f"Command processing error: {str(e)}"
            await self._send_text_and_cleanup(event, message_text)

    async def _handle_hashtag_list_command(self, event: events.NewMessage.Event):
        """Handle hashtag list command"""
        try:
            if not self.hashtags:
                message_text = "No hashtags found in navigation"
            else:
                sorted_hashtags = sorted(self.hashtags)
                message_text = (
                    f"**Hashtags in navigation ({len(sorted_hashtags)}):**\n\n"
                )

                # Format hashtags in groups of 10 for better readability
                for i in range(0, len(sorted_hashtags), 10):
                    group = sorted_hashtags[i : i + 10]
                    message_text += " ".join(group) + "\n"

                message_text += f"\nTotal: {len(sorted_hashtags)} hashtags"

        except (OSError, IOError, ConnectionError) as e:
            self.logger.error("Error in hashtag list command handler: %s", str(e))
            message_text = f"Error getting hashtags list: {str(e)}"

        # Send response
        await self._send_text_and_cleanup(event, message_text)

    async def _handle_zapret_add_command(self, event: events.NewMessage.Event):
        """Handle zapretadd <file> <sites...> command.
        <file>: general, hosts, exclude
        <sites>: space separated domains/hosts; schemes/paths are stripped
        """
        text = event.message.text.strip()
        parts = text.split()

        if len(parts) < 3:
            message_text = (
                "Error: Specify file and sites\n\n"
                "Usage: `zapretadd <file> <site1 site2 ...>`\n"
                "Examples:\n"
                "`zapretadd general example.com test.org`\n"
            )
            await self._send_text_and_cleanup(event, message_text)
            return

        list_name = parts[1].lower().strip()
        sites = parts[2:]

        # Parse sites: normalize to bare domains
        sites = [normalize_domain(s) for s in sites]

        if not sites:
            message_text = "Error: Provide at least one valid site"
            await self._send_text_and_cleanup(event, message_text)
            return

        existed: List[str] = []
        writed: List[str] = []

        try:
            for domain in sites:
                if write_to_zapret_file(list_name, domain):
                    writed.append(domain)
                    continue
                existed.append(domain)

        except (OSError, IOError) as e:
            self.logger.error("Failed to write %s: %s", list_name, str(e))
            message_text = f"Write error: {str(e)}"
            await self._send_text_and_cleanup(event, message_text)
        else:
            added = ", ".join(writed) if writed else "-"
            existed_str = ", ".join(existed) if existed else "-"
            message_text = (
                f"Updated **{list_name}** list.\n"
                f"Added: `{added}`\n"
                f"Existed: `{existed_str}`"
            )
            await self._send_text_and_cleanup(event, message_text)

    async def _handle_zapret_check_command(self, event: events.NewMessage.Event):
        """Handle zapretcheck <site> command: report if site is in zapret lists."""
        text = event.message.text.strip()
        parts = text.split()
        if len(parts) < 2:
            message_text = "Error: Specify site to check\n\nUsage: `zapretcheck <site>`"
            await self._send_text_and_cleanup(event, message_text)
            return

        try:
            site = normalize_domain(parts[1])
            files = get_all_zapret_files()
            founded = False
            for file in files:
                if check_site_in_zapret_file(file, site):
                    founded = True
                    message_text = f"`{site}` —> `{file.name}`"
                    self.logger.debug("Site {%s} was found in {%s}", site, str(file))
                    break
            if not founded:
                message_text = f"Site `{site}` was not found in files."
                self.logger.debug("Site {%s} was not found in files.", site)
        except (OSError, IOError, ConnectionError) as e:
            self.logger.error(
                "Error in zapret check handler: %s", str(e), exc_info=True
            )
            message_text = f"Command processing error: {str(e)}"

        await self._send_text_and_cleanup(event, message_text)


def main():
    try:
        config = Config.from_env()
        bot = TelegramBot(config)

        loop = asyncio.get_event_loop()
        loop.run_until_complete(bot.run())

    except KeyboardInterrupt:
        logging.info("Bot stopped by user")
    except (OSError, IOError, ConnectionError) as e:
        logging.error("Fatal error: %s", str(e), exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

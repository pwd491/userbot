import os
import re
import time
import shutil
import logging
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from sqlite import SQLite


@dataclass
class WireGuardClient:
    """Class representing a WireGuard client"""

    name: str
    ipv4: str
    ipv6: str
    public_key: str
    private_key: str
    preshared_key: str
    config_file: str


class WireGuardManager:
    """Manager for WireGuard clients"""

    def __init__(self, config_path: str = "/etc/wireguard/params", db: SQLite = None):
        """
        Initialize WireGuard manager

        Args:
            config_path: Path to WireGuard parameters file
            db: SQLite database instance
        """
        self.config_path = config_path
        self.wireguard_dir = Path("/etc/wireguard")
        self.clients_dir = self.wireguard_dir / "clients"
        self.logger = logging.getLogger(self.__class__.__name__)
        self.db = db or SQLite()

        # Load server parameters
        self.server_params = self._load_server_params()

        # Sync existing clients with database
        self._sync_existing_clients()

    def _load_server_params(self) -> Dict[str, str]:
        """Load server parameters from configuration file"""
        params = {}
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if "=" in line:
                            key, value = line.split("=", 1)
                            params[key] = value
            else:
                self.logger.error("Parameters file not found: %s", self.config_path)
        except (OSError, IOError) as e:
            self.logger.error("Error loading parameters: %s", e)

        return params

    def _sync_existing_clients(self):
        """Sync existing WireGuard clients with database"""
        try:
            server_config = (
                self.wireguard_dir
                / f"{self.server_params.get('SERVER_WG_NIC', 'wg0')}.conf"
            )

            if not server_config.exists():
                self.logger.info("Server config not found, skipping client sync")
                return

            # Get clients from server configuration
            config_clients = self._get_clients_from_config(server_config)

            # Get clients from database
            db_clients = {client[0] for client in self.db.list_wireguard_clients()}

            # Find clients that exist in config but not in database
            missing_in_db = []
            for client_name in config_clients:
                if client_name not in db_clients:
                    missing_in_db.append(client_name)

            # Add missing clients to database
            for client_name in missing_in_db:
                self._add_missing_client_to_db(client_name)

            if missing_in_db:
                self.logger.info(
                    "Synced %d existing clients to database: %s",
                    len(missing_in_db),
                    ", ".join(missing_in_db),
                )
            else:
                self.logger.info("All existing clients are already in database")

        except Exception as e:
            self.logger.error("Error syncing existing clients: %s", e)

    def _get_clients_from_config(self, server_config: Path) -> List[str]:
        """Extract client names from server configuration file"""
        clients = []
        try:
            with open(server_config, "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("### Client "):
                        client_name = line.replace("### Client ", "").strip()
                        clients.append(client_name)
        except (OSError, IOError) as e:
            self.logger.error("Error reading client list from configuration: %s", e)

        return clients

    def _add_missing_client_to_db(self, client_name: str):
        """Add missing client to database with available information"""
        try:
            # Try to get client info from config file
            config_file = (
                self.clients_dir
                / f"{self.server_params.get('SERVER_WG_NIC', 'wg0')}-client-{client_name}.conf"
            )

            if config_file.exists():
                # Parse client config file to extract information
                client_info = self._parse_client_config(config_file)

                if client_info:
                    # Add to database
                    self.db.add_wireguard_client(
                        name=client_name,
                        ipv4=client_info.get("ipv4", ""),
                        ipv6=client_info.get("ipv6", ""),
                        public_key=client_info.get("public_key", ""),
                        private_key=client_info.get("private_key", ""),
                        preshared_key=client_info.get("preshared_key", ""),
                        config_file=str(config_file),
                        created_by=0,  # Unknown creator
                    )
                    self.logger.info(
                        "Added existing client '%s' to database", client_name
                    )
                else:
                    self.logger.warning(
                        "Could not parse config file for client '%s'", client_name
                    )
            else:
                # Config file doesn't exist, add with minimal info
                self.db.add_wireguard_client(
                    name=client_name,
                    ipv4="",
                    ipv6="",
                    public_key="",
                    private_key="",
                    preshared_key="",
                    config_file="",
                    created_by=0,
                )
                self.logger.info(
                    "Added existing client '%s' to database (minimal info)", client_name
                )

        except Exception as e:
            self.logger.error(
                "Error adding missing client '%s' to database: %s", client_name, e
            )

    def _parse_client_config(self, config_file: Path) -> Optional[Dict[str, str]]:
        """Parse client configuration file to extract information"""
        try:
            client_info = {}

            with open(config_file, "r", encoding="utf-8") as f:
                content = f.read()

                # Extract private key
                private_key_match = re.search(r"PrivateKey\s*=\s*([^\s\n]+)", content)
                if private_key_match:
                    client_info["private_key"] = private_key_match.group(1)

                    # Generate public key from private key
                    try:
                        result = subprocess.run(
                            ["wg", "pubkey"],
                            input=client_info["private_key"],
                            capture_output=True,
                            text=True,
                            check=True,
                        )
                        client_info["public_key"] = result.stdout.strip()
                    except subprocess.CalledProcessError:
                        pass

                # Extract preshared key
                preshared_key_match = re.search(
                    r"PresharedKey\s*=\s*([^\s\n]+)", content
                )
                if preshared_key_match:
                    client_info["preshared_key"] = preshared_key_match.group(1)

                # Extract addresses
                address_match = re.search(r"Address\s*=\s*([^\s\n]+)", content)
                if address_match:
                    addresses = address_match.group(1).split(",")
                    for addr in addresses:
                        addr = addr.strip()
                        if "." in addr:  # IPv4
                            client_info["ipv4"] = addr.split("/")[0]
                        elif ":" in addr:  # IPv6
                            client_info["ipv6"] = addr.split("/")[0]

            return client_info if client_info else None

        except Exception as e:
            self.logger.error("Error parsing client config file %s: %s", config_file, e)
            return None

    def _get_available_ipv4(self) -> Optional[str]:
        """Find available IPv4 address for new client"""
        server_config = (
            self.wireguard_dir
            / f"{self.server_params.get('SERVER_WG_NIC', 'wg0')}.conf"
        )

        if not server_config.exists():
            return None

        # Read server configuration
        with open(server_config, "r", encoding="utf-8") as f:
            content = f.read()

        # Extract base IP (e.g., 10.66.66.1 -> 10.66.66)
        server_ip = self.server_params.get("SERVER_WG_IPV4", "10.66.66.1")
        base_ip = ".".join(server_ip.split(".")[:-1])

        # Find used IP addresses
        used_ips = set()
        for match in re.finditer(rf"{re.escape(base_ip)}\.(\d+)", content):
            used_ips.add(int(match.group(1)))

        # Find free IP
        for i in range(2, 255):
            if i not in used_ips:
                return f"{base_ip}.{i}"

        return None

    def _get_available_ipv6(self) -> Optional[str]:
        """Find available IPv6 address for new client"""
        server_config = (
            self.wireguard_dir
            / f"{self.server_params.get('SERVER_WG_NIC', 'wg0')}.conf"
        )

        if not server_config.exists():
            return None

        # Read server configuration
        with open(server_config, "r", encoding="utf-8") as f:
            content = f.read()

        # Extract base IPv6 (e.g., fd42:42:42::1 -> fd42:42:42::)
        server_ipv6 = self.server_params.get("SERVER_WG_IPV6", "fd42:42:42::1")
        base_ipv6 = server_ipv6.rsplit(":", 1)[0] + ":"

        # Find used IPv6 addresses
        used_ips = set()
        for match in re.finditer(rf"{re.escape(base_ipv6)}(\d+)", content):
            used_ips.add(int(match.group(1)))

        # Find free IPv6
        for i in range(2, 255):
            if i not in used_ips:
                return f"{base_ipv6}{i}"

        return None

    def _generate_keys(self) -> Tuple[str, str, str]:
        """Generate keys for client"""
        try:
            # Generate private key
            result = subprocess.run(
                ["wg", "genkey"], capture_output=True, text=True, check=True
            )
            private_key = result.stdout.strip()

            # Generate public key
            result = subprocess.run(
                ["wg", "pubkey"],
                input=private_key,
                capture_output=True,
                text=True,
                check=True,
            )
            public_key = result.stdout.strip()

            # Generate preshared key
            result = subprocess.run(
                ["wg", "genpsk"], capture_output=True, text=True, check=True
            )
            preshared_key = result.stdout.strip()

            return private_key, public_key, preshared_key

        except subprocess.CalledProcessError as e:
            self.logger.error("Error generating keys: %s", e)
            raise
        except FileNotFoundError:
            self.logger.error("WireGuard not installed or not found in PATH")
            raise

    def _update_server_config(self, client: WireGuardClient, remove: bool = False):
        """Update server configuration"""
        server_config = (
            self.wireguard_dir
            / f"{self.server_params.get('SERVER_WG_NIC', 'wg0')}.conf"
        )

        if not server_config.exists():
            raise FileNotFoundError("Server configuration not found")

        # Read current configuration
        with open(server_config, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Find client section
        client_section_start = None
        client_section_end = None

        for i, line in enumerate(lines):
            if f"### Client {client.name}" in line:
                client_section_start = i
            elif (
                client_section_start is not None
                and line.strip() == ""
                and i > client_section_start
            ):
                client_section_end = i
                break

        if remove:
            # Remove client section
            if client_section_start is not None:
                if client_section_end is not None:
                    del lines[client_section_start : client_section_end + 1]
                else:
                    # Remove to end of file
                    del lines[client_section_start:]
        else:
            # Add or update client section
            client_config = f"""
### Client {client.name}
[Peer]
PublicKey = {client.public_key}
PresharedKey = {client.preshared_key}
AllowedIPs = {client.ipv4}/32,{client.ipv6}/128
"""

            if client_section_start is not None:
                # Update existing section
                if client_section_end is not None:
                    lines[client_section_start : client_section_end + 1] = [
                        client_config
                    ]
                else:
                    lines[client_section_start:] = [client_config]
            else:
                # Add new section at the end
                lines.append(client_config)

        # Write updated configuration
        with open(server_config, "w", encoding="utf-8") as f:
            f.writelines(lines)

    def _create_client_config(self, client: WireGuardClient):
        """Create client configuration file"""
        server_pub_ip = self.server_params.get("SERVER_PUB_IP", "")
        server_port = self.server_params.get("SERVER_PORT", "51820")
        server_pub_key = self.server_params.get("SERVER_PUB_KEY", "")
        client_dns_1 = self.server_params.get("CLIENT_DNS_1", "1.1.1.1")
        client_dns_2 = self.server_params.get("CLIENT_DNS_2", "1.0.0.1")
        allowed_ips = self.server_params.get("ALLOWED_IPS", "0.0.0.0/0,::/0")

        # Form endpoint
        if ":" in server_pub_ip and not server_pub_ip.startswith("["):
            endpoint = f"[{server_pub_ip}]:{server_port}"
        else:
            endpoint = f"{server_pub_ip}:{server_port}"

        # Create client configuration
        client_config = f"""[Interface]
PrivateKey = {client.private_key}
Address = {client.ipv4}/32,{client.ipv6}/128
DNS = {client_dns_1},{client_dns_2}

[Peer]
PublicKey = {server_pub_key}
PresharedKey = {client.preshared_key}
Endpoint = {endpoint}
AllowedIPs = {allowed_ips}
"""

        # Write configuration to file
        config_file = (
            self.clients_dir
            / f"{self.server_params.get('SERVER_WG_NIC', 'wg0')}-client-{client.name}.conf"
        )
        with open(config_file, "w", encoding="utf-8") as f:
            f.write(client_config)

        # Set file permissions
        os.chmod(config_file, 0o600)

        return str(config_file)

    def _sync_wireguard_safe(self):
        """Synchronize WireGuard configuration safely"""
        try:
            server_nic = self.server_params.get("SERVER_WG_NIC", "wg0")
            server_config = self.wireguard_dir / f"{server_nic}.conf"

            if not server_config.exists():
                self.logger.warning("Server config not found: %s", server_config)
                return

            subprocess.run(
                ["wg", "syncconf", server_nic, "/dev/stdin"],
                input=subprocess.run(
                    ["wg-quick", "strip", server_nic],
                    capture_output=True,
                    text=True,
                    check=True,
                ).stdout,
                text=True,
                check=True,
            )

            self.logger.info("WireGuard configuration synchronized successfully")

        except subprocess.CalledProcessError as e:
            self.logger.error("Error synchronizing WireGuard: %s", e)
            self.logger.warning(
                "You may need to restart WireGuard manually: sudo systemctl restart wg-quick@%s",
                self.server_params.get("SERVER_WG_NIC", "wg0"),
            )
        except FileNotFoundError:
            self.logger.warning("WireGuard tools not found, skipping sync")

    def add_client(self, name: str, created_by: int = 0) -> WireGuardClient:
        """
        Add new WireGuard client

        Args:
            name: Client name
            created_by: ID of user who created the client

        Returns:
            WireGuardClient: Created client object

        Raises:
            ValueError: If client name is invalid or already exists
            RuntimeError: If client creation failed
        """
        # Validate client name
        if not re.match(r"^[a-zA-Z0-9_-]+$", name) or len(name) > 15:
            raise ValueError(
                "Client name must contain only letters, numbers, underscores and dashes, and not exceed 15 characters"
            )

        # Check if client with this name already exists
        if self.client_exists(name) or self.db.wireguard_client_exists(name):
            raise ValueError(f"Client with name '{name}' already exists")

        # Get available IP addresses
        ipv4 = self._get_available_ipv4()
        ipv6 = self._get_available_ipv6()

        if not ipv4 or not ipv6:
            raise RuntimeError("No available IP addresses for new client")

        # Generate keys
        private_key, public_key, preshared_key = self._generate_keys()

        # Create client object
        client = WireGuardClient(
            name=name,
            ipv4=ipv4,
            ipv6=ipv6,
            public_key=public_key,
            private_key=private_key,
            preshared_key=preshared_key,
            config_file="",
        )

        try:
            # Create client configuration file
            config_file = self._create_client_config(client)
            client.config_file = config_file

            # Update server configuration
            self._update_server_config(client)

            # Synchronize WireGuard configuration
            self._sync_wireguard_safe()

            # Save client to database
            if not self.db.add_wireguard_client(
                name=client.name,
                ipv4=client.ipv4,
                ipv6=client.ipv6,
                public_key=client.public_key,
                private_key=client.private_key,
                preshared_key=client.preshared_key,
                config_file=client.config_file,
                created_by=created_by,
            ):
                self.logger.warning("Failed to save client '%s' to database", name)

            self.logger.info("Client '%s' successfully added", name)
            return client

        except Exception as e:
            # Remove created configuration file in case of error
            if client.config_file and os.path.exists(client.config_file):
                os.remove(client.config_file)
            raise RuntimeError(f"Error creating client: {e}") from e

    def remove_client(self, name: str) -> bool:
        """
        Remove WireGuard client

        Args:
            name: Client name

        Returns:
            bool: True if client was removed, False if not found

        Raises:
            RuntimeError: If error occurred during removal
        """
        if not self.client_exists(name) and not self.db.wireguard_client_exists(name):
            return False

        try:
            # Remove client configuration file
            config_file = (
                self.clients_dir
                / f"{self.server_params.get('SERVER_WG_NIC', 'wg0')}-client-{name}.conf"
            )
            if config_file.exists():
                os.remove(config_file)

            # Create temporary client object for removal from server configuration
            client = WireGuardClient(
                name=name,
                ipv4="",
                ipv6="",
                public_key="",
                private_key="",
                preshared_key="",
                config_file="",
            )

            # Remove client from server configuration
            self._update_server_config(client, remove=True)

            # Synchronize WireGuard configuration
            self._sync_wireguard_safe()

            # Remove client from database
            self.db.remove_wireguard_client(name)

            self.logger.info("Client '%s' successfully removed", name)
            return True

        except Exception as e:
            raise RuntimeError(f"Error removing client: {e}") from e

    def rename_client(self, old_name: str, new_name: str) -> Tuple[bool, str]:
        """
        Rename WireGuard client

        Args:
            old_name: Current client name
            new_name: New client name

        Returns:
            Tuple[bool, str]: (success, message) - success status and detailed message

        Raises:
            ValueError: If client names are invalid
            RuntimeError: If error occurred during rename
        """
        self.logger.info("Starting rename operation: '%s' -> '%s'", old_name, new_name)

        # Validate client names
        if not re.match(r"^[a-zA-Z0-9_-]+$", old_name) or len(old_name) > 15:
            raise ValueError(
                "Old client name must contain only letters, numbers, underscores and dashes, and not exceed 15 characters"
            )

        if not re.match(r"^[a-zA-Z0-9_-]+$", new_name) or len(new_name) > 15:
            raise ValueError(
                "New client name must contain only letters, numbers, underscores and dashes, and not exceed 15 characters"
            )

        # Check if old client exists
        old_exists_in_config = self.client_exists(old_name)
        old_exists_in_db = self.db.wireguard_client_exists(old_name)

        self.logger.info("Client '%s' exists - config: %s, database: %s", old_name, old_exists_in_config, old_exists_in_db)

        if not old_exists_in_config and not old_exists_in_db:
            self.logger.warning("Client '%s' not found in system", old_name)
            return False, f"Client '{old_name}' not found in system (checked config and database)"

        # Check if new client name already exists
        new_exists_in_config = self.client_exists(new_name)
        new_exists_in_db = self.db.wireguard_client_exists(new_name)

        self.logger.info("Client '%s' exists - config: %s, database: %s", new_name, new_exists_in_config, new_exists_in_db)

        # If new name exists in database, it's definitely a conflict
        if new_exists_in_db:
            self.logger.warning("Client '%s' already exists in database", new_name)
            return False, f"Client '{new_name}' already exists in database"
        
        # If new name exists only in config, check if it's the same client we're renaming
        if new_exists_in_config:
            # Check if the new name corresponds to the same client we're renaming
            # by comparing public keys
            if old_name == new_name:
                self.logger.info("Renaming client to the same name - no change needed")
                return True, f"Client '{old_name}' is already named '{new_name}'"
            
            # Get public key of the old client from database
            old_client_data = self.db.get_wireguard_client(old_name)
            if not old_client_data:
                self.logger.warning("Client '%s' not found in database", old_name)
                return False, f"Client '{old_name}' not found in database"
            
            old_public_key = old_client_data[3]  # public_key
            
            # Get public key of the client with new name from config
            new_public_key = self._get_client_public_key_from_config(new_name)
            
            if old_public_key == new_public_key:
                self.logger.info("Client '%s' in config has same public key as '%s' - allowing rename", new_name, old_name)
                # This is the same client, we can proceed with rename
            else:
                # Different client in config, it's a conflict
                self.logger.warning("Client '%s' already exists in config with different public key", new_name)
                return False, f"Client '{new_name}' already exists in config"

        try:
            # Get client information from database
            client_data = self.db.get_wireguard_client(old_name)
            if not client_data:
                return False, f"Client '{old_name}' data not found in database"

            # Create new client object with new name
            client = WireGuardClient(
                name=new_name,
                ipv4=client_data[1],  # ipv4
                ipv6=client_data[2],  # ipv6
                public_key=client_data[3],  # public_key
                private_key=client_data[4],  # private_key
                preshared_key=client_data[5],  # preshared_key
                config_file="",  # Will be updated below
            )

            # Create new client configuration file
            new_config_file = self._create_client_config(client)
            client.config_file = new_config_file

            # Update server configuration (remove old, add new)
            old_client = WireGuardClient(
                name=old_name,
                ipv4=client_data[1],
                ipv6=client_data[2],
                public_key=client_data[3],
                private_key=client_data[4],
                preshared_key=client_data[5],
                config_file="",
            )

            # Remove old client from server configuration
            self._update_server_config(old_client, remove=True)

            # Add new client to server configuration
            self._update_server_config(client)

            # Synchronize WireGuard configuration
            self._sync_wireguard_safe()

            # Update database
            self.db.remove_wireguard_client(old_name)
            self.db.add_wireguard_client(
                name=client.name,
                ipv4=client.ipv4,
                ipv6=client.ipv6,
                public_key=client.public_key,
                private_key=client.private_key,
                preshared_key=client.preshared_key,
                config_file=client.config_file,
                created_by=client_data[7],  # created_by
            )

            # Remove old client configuration file
            old_config_file = (
                self.clients_dir
                / f"{self.server_params.get('SERVER_WG_NIC', 'wg0')}-client-{old_name}.conf"
            )
            if old_config_file.exists():
                os.remove(old_config_file)

            self.logger.info("Client '%s' successfully renamed to '%s'", old_name, new_name)
            return True, f"Client '{old_name}' successfully renamed to '{new_name}'"

        except Exception as e:
            # Clean up new config file if it was created
            if 'new_config_file' in locals() and os.path.exists(new_config_file):
                os.remove(new_config_file)
            raise RuntimeError(f"Error renaming client: {e}") from e

    def _get_client_public_key_from_config(self, name: str) -> Optional[str]:
        """
        Get client public key from WireGuard configuration file
        
        Args:
            name: Client name
            
        Returns:
            Optional[str]: Public key if found, None otherwise
        """
        try:
            iface = self.server_params.get("SERVER_WG_NIC", "wg0")
            config_file = Path(self.wireguard_dir) / f"{iface}.conf"
            
            if not config_file.exists():
                return None
                
            with open(config_file, "r", encoding="utf-8") as f:
                conf = f.read().splitlines()
                
            for i, line in enumerate(conf):
                if line.startswith("### Client") and name in line:
                    # Look for the public key in the next few lines
                    for j in range(i + 1, min(i + 10, len(conf))):
                        if conf[j].startswith("PublicKey = "):
                            return conf[j].split("=", 1)[1].strip()
            return None
            
        except (OSError, IOError) as e:
            self.logger.error("Error reading config file: %s", e)
            return None

    def client_exists(self, name: str) -> bool:
        """
        Check if client with specified name exists

        Args:
            name: Client name

        Returns:
            bool: True if client exists
        """
        server_config = (
            self.wireguard_dir
            / f"{self.server_params.get('SERVER_WG_NIC', 'wg0')}.conf"
        )

        if not server_config.exists():
            return False

        try:
            with open(server_config, "r", encoding="utf-8") as f:
                content = f.read()
                return f"### Client {name}" in content
        except (OSError, IOError):
            return False

    def list_clients(self) -> List[str]:
        """
        Return list of all clients

        Returns:
            List[str]: List of client names
        """
        # First get clients from database
        db_clients = [client[0] for client in self.db.list_wireguard_clients()]

        # Also check server configuration for desynchronization
        server_config = (
            self.wireguard_dir
            / f"{self.server_params.get('SERVER_WG_NIC', 'wg0')}.conf"
        )

        config_clients = []
        if server_config.exists():
            try:
                with open(server_config, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("### Client "):
                            client_name = line.replace("### Client ", "").strip()
                            config_clients.append(client_name)
            except (OSError, IOError) as e:
                self.logger.error("Error reading client list from configuration: %s", e)

        # Combine lists and remove duplicates
        all_clients = list(set(db_clients + config_clients))
        return sorted(all_clients)

    def get_client_config(self, name: str) -> Optional[str]:
        """
        Return client configuration

        Args:
            name: Client name

        Returns:
            Optional[str]: Client configuration or None if not found
        """
        config_file = (
            self.clients_dir
            / f"{self.server_params.get('SERVER_WG_NIC', 'wg0')}-client-{name}.conf"
        )

        if not config_file.exists():
            return None

        try:
            with open(config_file, "r", encoding="utf-8") as f:
                return f.read()
        except (OSError, IOError) as e:
            self.logger.error("Error reading client configuration: %s", e)
            return None

    def get_clients_stats(self, print_ip: bool = False) -> str:
        """
        Return client statistics (WireGuard peers)

        Args:
            print_ip (bool): Print clients' IP addresses

        Returns:
            str: Formatted clients statistics
        """
        iface = self.server_params.get("SERVER_WG_NIC", "wg0")
        config_file = Path(self.wireguard_dir) / f"{iface}.conf"

        try:
            result = subprocess.run(
                ["wg", "show", iface, "dump"],
                check=True,
                text=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            self.logger.error("Error running wg show: %s", e.stderr)
            return e.stderr

        lines = result.stdout.strip().splitlines()
        if len(lines) <= 1:
            self.logger.warning("No clients found")
            return "No clients found"

        header_line = f"{'Имя':<20} {'Активность':<15}" + (f" {'IP':<15}" if print_ip else "")
        now = int(time.time())

        # Collect client data for sorting
        client_data = []

        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) < 8:
                continue
            pubkey, _, _, allowed, latest, _, _, _ = parts[:8]

            name = "(без имени)"
            try:
                with open(config_file, "r", encoding="utf-8") as f:
                    conf = f.read().splitlines()
                for i, l in enumerate(conf):
                    if pubkey in l:
                        if i >= 2 and conf[i - 2].startswith("### Client"):
                            name = conf[i - 2].replace("### Client", "").strip()
                        break
            except FileNotFoundError:
                pass

            # Latest handshake
            try:
                latest = int(latest)
            except ValueError:
                latest = 0
            if latest == 0:
                latest_str = "нет"
            else:
                diff = now - latest
                if diff < 60:
                    latest_str = f"{diff}s назад"
                elif diff < 3600:
                    latest_str = f"{diff // 60}m назад"
                elif diff < 86400:
                    latest_str = f"{diff // 3600}h назад"
                else:
                    latest_str = f"{diff // 86400}d назад"

            vpn_ip = ""
            if print_ip:
                vpn_ip = allowed.split(",")[0].split("/")[0] if allowed else ""

            line_fmt = f"{name:<20} {latest_str:<15}" + (
                f" {vpn_ip:<15}" if print_ip else ""
            )
            client_data.append((name, line_fmt))

        # Sort clients alphabetically by name
        client_data.sort(key=lambda x: x[0].lower())

        # Build final output with header and sorted clients
        out_lines = [header_line]
        for _, line_fmt in client_data:
            out_lines.append(line_fmt)

        return "\n".join(out_lines)

    def get_client_qr_code(self, name: str) -> Optional[str]:
        """
        Generate QR code for client configuration

        Args:
            name: Client name

        Returns:
            Optional[str]: QR code in text format or None if generation failed
        """
        config = self.get_client_config(name)
        if not config:
            return None

        try:
            # Check if qrencode is installed
            if not shutil.which("qrencode"):
                self.logger.warning(
                    "qrencode not installed, QR code cannot be generated"
                )
                return None

            result = subprocess.run(
                ["qrencode", "-t", "ansiutf8", "-l", "L"],
                input=config,
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            self.logger.error("Error generating QR code: %s", e)
            return None
        except FileNotFoundError:
            self.logger.warning("qrencode not found in system")
            return None

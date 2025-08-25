#!/usr/bin/env python3
"""
Shared utilities for the Enhanced Botnet Implementation

This module provides common utilities for encryption, logging, validation,
and other shared functionality across the botnet components.

Author: Enhanced by AI Assistant
License: Educational/Research Use Only
"""

import os
import logging
import hashlib
import datetime
try:
    import asyncio
except ImportError:
    asyncio = None
import ssl
import json
import re
from typing import Optional, Union, Dict, Any, List
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import base64


class SecureConfig:
    """
    Secure configuration management using environment variables and config files.
    """

    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize secure configuration.

        Args:
            config_file: Optional path to configuration file
        """
        self.config_file = config_file
        self._config: Dict[str, Any] = {}
        self._load_config()

    def _load_config(self) -> None:
        """Load configuration from environment and optional config file."""
        # Load from environment variables first
        self._config.update(
            {
                "SERVER_HOST": os.getenv("BOTNET_HOST", "127.0.0.1"),
                "SERVER_PORT": int(os.getenv("BOTNET_PORT", "9999")),
                "ENCRYPTION_KEY": os.getenv("BOTNET_ENCRYPTION_KEY"),
                "ADMIN_PASSWORD": os.getenv("BOTNET_ADMIN_PASSWORD"),
                "TLS_CERT_PATH": os.getenv("BOTNET_TLS_CERT"),
                "TLS_KEY_PATH": os.getenv("BOTNET_TLS_KEY"),
                "LOG_LEVEL": os.getenv("BOTNET_LOG_LEVEL", "INFO"),
                "MAX_CONNECTIONS": int(os.getenv("BOTNET_MAX_CONNECTIONS", "100")),
                "WEB_PORT": int(os.getenv("BOTNET_WEB_PORT", "8080")),
                "MAX_MESSAGE_SIZE": int(os.getenv("BOTNET_MAX_MESSAGE_SIZE", "1048576")),  # 1MB default
            }
        )

        # Load from config file if provided and exists
        if self.config_file and Path(self.config_file).exists():
            try:
                with open(self.config_file, "r") as f:
                    file_config = json.load(f)
                    # Only update non-sensitive values from file
                    safe_keys = [
                        "SERVER_HOST",
                        "SERVER_PORT",
                        "LOG_LEVEL",
                        "MAX_CONNECTIONS",
                        "WEB_PORT",
                        "MAX_MESSAGE_SIZE",
                    ]
                    for key in safe_keys:
                        if key in file_config:
                            self._config[key] = file_config[key]
            except (json.JSONDecodeError, IOError) as e:
                logging.warning(f"Could not load config file {self.config_file}: {e}")

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return self._config.get(key, default)

    @property
    def max_message_size(self) -> int:
        """Get maximum message size."""
        return self._config.get("MAX_MESSAGE_SIZE", 1048576)

    def get_encryption_key(self) -> bytes:
        """Get or generate encryption key."""
        key_str = self._config.get("ENCRYPTION_KEY")
        if key_str:
            try:
                return base64.b64decode(key_str.encode())
            except Exception:
                logging.warning("Invalid encryption key format. Generating new key.")

        # Generate a new 32-byte key and warn user
        key = os.urandom(32)
        logging.warning(
            "No encryption key configured. Generated new key. "
            "Set BOTNET_ENCRYPTION_KEY environment variable for production."
        )
        return key


class SecureEncryption:
    """
    Secure AES encryption utilities with proper key management.
    """

    def __init__(self, key: Optional[bytes] = None):
        """
        Initialize encryption with provided key or generate new one.

        Args:
            key: 32-byte encryption key. If None, generates new key.
        """
        if key is None:
            key = os.urandom(32)
        elif len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes long")

        self.key = key

    def encrypt(self, data: Union[str, bytes]) -> bytes:
        """
        Encrypt data using AES-256-CBC.

        Args:
            data: Data to encrypt (string or bytes)

        Returns:
            Encrypted data (IV + ciphertext)
        """
        if isinstance(data, str):
            data = data.encode("utf-8")

        # Generate random IV
        iv = os.urandom(16)

        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key), modes.CBC(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()

        # Pad data
        padder = PKCS7(128).padder()
        padded_data = padder.update(data)
        padded_data += padder.finalize()

        # Encrypt
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return iv + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt data using AES-256-CBC.

        Args:
            data: Encrypted data (IV + ciphertext)

        Returns:
            Decrypted data
        """
        if len(data) < 16:
            raise ValueError("Invalid encrypted data")

        iv = data[:16]
        ciphertext = data[16:]

        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key), modes.CBC(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()

        # Decrypt
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad
        unpadder = PKCS7(128).unpadder()
        data = unpadder.update(padded_data)
        data += unpadder.finalize()

        return data

    @staticmethod
    def derive_key_from_password(password: str, salt: Optional[bytes] = None) -> bytes:
        """
        Derive encryption key from password using PBKDF2.

        Args:
            password: Password string
            salt: Optional salt (generates random if None)

        Returns:
            32-byte derived key
        """
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        return kdf.derive(password.encode())


class InputValidator:
    """
    Input validation utilities to prevent injection attacks and ensure data integrity.
    """

    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """
        Validate IP address format.

        Args:
            ip: IP address string

        Returns:
            True if valid IP address
        """
        try:
            import ipaddress

            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_port(port: Union[int, str]) -> bool:
        """
        Validate port number.

        Args:
            port: Port number

        Returns:
            True if valid port (1-65535)
        """
        try:
            port_int = int(port)
            return 1 <= port_int <= 65535
        except (ValueError, TypeError):
            return False

    @staticmethod
    def sanitize_command(command: str) -> str:
        """
        Sanitize command input to prevent injection attacks.

        Args:
            command: Raw command string

        Returns:
            Sanitized command string
        """
        if not command or not isinstance(command, str):
            return ""

        # Remove null bytes and control characters except tab and newline
        sanitized = "".join(
            char for char in command if ord(char) >= 32 or char in "\t\n"
        )

        # Limit length
        return sanitized[:1024]

    @staticmethod
    def validate_json_payload(payload: str) -> Optional[Dict[str, Any]]:
        """
        Validate and parse JSON payload.

        Args:
            payload: JSON string

        Returns:
            Parsed JSON dict or None if invalid
        """
        try:
            data = json.loads(payload)
            if not isinstance(data, dict):
                return None

            # Basic structure validation
            required_fields = ["timestamp", "type"]
            if not all(field in data for field in required_fields):
                return None

            return data
        except (json.JSONDecodeError, TypeError):
            return None


class SecureLogger:
    """
    Secure logging utilities that prevent information leakage.
    """

    def __init__(self, name: str, level: str = "INFO", log_file: Optional[str] = None):
        """
        Initialize secure logger.

        Args:
            name: Logger name
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Optional log file path
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))

        # Remove existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)

        # Create formatter
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        # File handler if specified
        if log_file:
            try:
                file_handler = logging.FileHandler(log_file)
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)
            except IOError as e:
                self.logger.warning(f"Could not create log file {log_file}: {e}")

    def _sanitize_message(self, message: str) -> str:
        """Sanitize log message to prevent information leakage."""
        # Remove potential sensitive patterns
        patterns = [
            (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP_REDACTED]"),  # IP addresses
            # Only redact Base64 strings that are likely keys (with context and longer length)
            (r"\b(?:key|secret|token|private|api[_-]?key)\s*[:=]\s*[A-Za-z0-9+/]{32,}={0,2}\b", "[KEY_REDACTED]"),  # Contextual Base64 keys
            (r"\bpassword\s*[:=]\s*\S+", "password=[REDACTED]"),  # Passwords
            (r"\bkey\s*[:=]\s*[A-Za-z0-9+/]+={0,2}", "key=[KEY_REDACTED]"),  # Keys
        ]

        sanitized = message
        for pattern, replacement in patterns:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

        return sanitized

    def info(self, message: str) -> None:
        """Log info message with sanitization."""
        self.logger.info(self._sanitize_message(message))

    def warning(self, message: str) -> None:
        """Log warning message with sanitization."""
        self.logger.warning(self._sanitize_message(message))

    def error(self, message: str) -> None:
        """Log error message with sanitization."""
        self.logger.error(self._sanitize_message(message))

    def debug(self, message: str) -> None:
        """Log debug message with sanitization."""
        self.logger.debug(self._sanitize_message(message))


class BotTracker:
    """
    Efficient bot tracking using sets and dictionaries for fast lookups.
    """

    def __init__(self):
        """Initialize bot tracker."""
        self.active_bots: Dict[str, Dict[str, Any]] = {}
        self.connection_history: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()

    async def add_bot(
        self, bot_id: str, ip_address: str, metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Add or update bot information.

        Args:
            bot_id: Unique bot identifier
            ip_address: Bot IP address
            metadata: Optional additional metadata
        """
        async with self._lock:
            bot_info = {
                "id": bot_id,
                "ip": ip_address,
                "connected_at": datetime.datetime.now().isoformat(),
                "last_seen": datetime.datetime.now().isoformat(),
                "commands_sent": 0,
                "commands_completed": 0,
                "metadata": metadata or {},
            }

            self.active_bots[bot_id] = bot_info
            self.connection_history.append(
                {
                    "bot_id": bot_id,
                    "ip": ip_address,
                    "event": "connected",
                    "timestamp": bot_info["connected_at"],
                }
            )

    async def remove_bot(self, bot_id: str) -> None:
        """
        Remove bot from active tracking.

        Args:
            bot_id: Bot identifier to remove
        """
        async with self._lock:
            if bot_id in self.active_bots:
                bot_info = self.active_bots.pop(bot_id)
                self.connection_history.append(
                    {
                        "bot_id": bot_id,
                        "ip": bot_info["ip"],
                        "event": "disconnected",
                        "timestamp": datetime.datetime.now().isoformat(),
                    }
                )

    async def update_bot_activity(self, bot_id: str, activity: str = "ping") -> None:
        """
        Update bot's last seen time and activity.

        Args:
            bot_id: Bot identifier
            activity: Type of activity
        """
        async with self._lock:
            if bot_id in self.active_bots:
                self.active_bots[bot_id][
                    "last_seen"
                ] = datetime.datetime.now().isoformat()
                if activity == "command_sent":
                    self.active_bots[bot_id]["commands_sent"] += 1
                elif activity == "command_completed":
                    self.active_bots[bot_id]["commands_completed"] += 1

    def get_active_bots(self) -> Dict[str, Dict[str, Any]]:
        """Get dictionary of all active bots."""
        return self.active_bots.copy()

    def get_bot_count(self) -> int:
        """Get count of active bots."""
        return len(self.active_bots)


class TLSHelper:
    """
    TLS/SSL utilities for secure communication.
    """

    @staticmethod
    def create_ssl_context(
        cert_path: Optional[str] = None, key_path: Optional[str] = None
    ) -> Optional[ssl.SSLContext]:
        """
        Create SSL context for secure communication.

        Args:
            cert_path: Path to SSL certificate file
            key_path: Path to SSL private key file

        Returns:
            SSL context or None if TLS not available
        """
        if not cert_path or not key_path:
            return None

        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(cert_path, key_path)
            context.set_ciphers(
                "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
            )
            return context
        except (ssl.SSLError, IOError) as e:
            logging.error(f"Failed to create SSL context: {e}")
            return None


def generate_bot_id(ip_address: str, additional_data: str = "") -> str:
    """
    Generate unique bot ID from IP address and optional additional data.

    Args:
        ip_address: Bot IP address
        additional_data: Optional additional data for uniqueness

    Returns:
        8-character hexadecimal bot ID
    """
    data = f"{ip_address}:{additional_data}:{datetime.datetime.now().isoformat()}"
    return hashlib.sha256(data.encode()).hexdigest()[:8]


def create_command_payload(
    command: str, encryption: SecureEncryption, priority: Optional[int] = None
) -> Dict[str, Any]:
    """
    Create encrypted command payload.

    Args:
        command: Command to encrypt
        encryption: Encryption instance
        priority: Optional command priority

    Returns:
        Command payload dictionary
    """
    encrypted_cmd = encryption.encrypt(command)

    return {
        "timestamp": datetime.datetime.now().timestamp(),
        "cmd": base64.b64encode(encrypted_cmd).decode("ascii"),
        "type": "command",
        "priority": priority or (int(datetime.datetime.now().timestamp()) % 100),
    }

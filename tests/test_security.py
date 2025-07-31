#!/usr/bin/env python3
"""
Security-focused tests for the Enhanced Botnet Implementation.

These tests validate the security features and ensure no vulnerabilities
are introduced by the enhancements.
"""

import unittest
import asyncio
import os
import tempfile
import json
import base64
from unittest.mock import patch, MagicMock

from utils import (
    SecureConfig,
    SecureEncryption,
    InputValidator,
    SecureLogger,
    BotTracker,
    TLSHelper,
    generate_bot_id,
)


class TestSecurityFeatures(unittest.TestCase):
    """Test security-related functionality."""

    def test_secure_encryption_strength(self):
        """Test that encryption uses proper key lengths and algorithms."""
        # Test with different key lengths
        for key_length in [16, 24, 32]:
            key = os.urandom(key_length)
            encryption = SecureEncryption(key)

            test_data = b"sensitive test data"
            encrypted = encryption.encrypt(test_data)
            decrypted = encryption.decrypt(encrypted)

            self.assertEqual(decrypted, test_data)
            self.assertNotEqual(encrypted, test_data)
            self.assertGreaterEqual(len(encrypted), len(test_data) + 16)  # IV + padding

    def test_encryption_randomness(self):
        """Test that encryption produces different outputs for same input."""
        encryption = SecureEncryption()
        test_data = b"same input data"

        encrypted1 = encryption.encrypt(test_data)
        encrypted2 = encryption.encrypt(test_data)

        # Should be different due to random IV
        self.assertNotEqual(encrypted1, encrypted2)

        # But should decrypt to same value
        self.assertEqual(encryption.decrypt(encrypted1), test_data)
        self.assertEqual(encryption.decrypt(encrypted2), test_data)

    def test_invalid_encryption_key_length(self):
        """Test that invalid key lengths are rejected."""
        with self.assertRaises(ValueError):
            SecureEncryption(b"too_short")

        with self.assertRaises(ValueError):
            SecureEncryption(b"invalid_length_key_17")

    def test_input_validation_ip_addresses(self):
        """Test IP address validation."""
        validator = InputValidator()

        # Valid IP addresses
        self.assertTrue(validator.validate_ip_address("127.0.0.1"))
        self.assertTrue(validator.validate_ip_address("192.168.1.1"))
        self.assertTrue(validator.validate_ip_address("::1"))
        self.assertTrue(validator.validate_ip_address("2001:db8::1"))

        # Invalid IP addresses
        self.assertFalse(validator.validate_ip_address("256.1.1.1"))
        self.assertFalse(validator.validate_ip_address("invalid.ip"))
        self.assertFalse(validator.validate_ip_address(""))
        self.assertFalse(validator.validate_ip_address("192.168.1"))

    def test_input_validation_ports(self):
        """Test port number validation."""
        validator = InputValidator()

        # Valid ports
        self.assertTrue(validator.validate_port(80))
        self.assertTrue(validator.validate_port(443))
        self.assertTrue(validator.validate_port(65535))
        self.assertTrue(validator.validate_port("9999"))

        # Invalid ports
        self.assertFalse(validator.validate_port(0))
        self.assertFalse(validator.validate_port(65536))
        self.assertFalse(validator.validate_port(-1))
        self.assertFalse(validator.validate_port("invalid"))
        self.assertFalse(validator.validate_port(None))

    def test_command_sanitization(self):
        """Test command input sanitization."""
        validator = InputValidator()

        # Test null byte removal
        dirty_cmd = "command\x00with\x00nulls"
        clean_cmd = validator.sanitize_command(dirty_cmd)
        self.assertNotIn("\x00", clean_cmd)

        # Test control character removal
        dirty_cmd = "command\x01\x02\x03with\x1fcontrol"
        clean_cmd = validator.sanitize_command(dirty_cmd)
        for char in dirty_cmd:
            if ord(char) < 32 and char not in "\t\n":
                self.assertNotIn(char, clean_cmd)

        # Test length limiting
        long_cmd = "A" * 2000
        clean_cmd = validator.sanitize_command(long_cmd)
        self.assertLessEqual(len(clean_cmd), 1024)

        # Test empty/invalid input
        self.assertEqual(validator.sanitize_command(""), "")
        self.assertEqual(validator.sanitize_command(None), "")

    def test_json_payload_validation(self):
        """Test JSON payload validation."""
        validator = InputValidator()

        # Valid JSON payload
        valid_payload = json.dumps(
            {"timestamp": 1234567890, "type": "command", "data": "test_data"}
        )
        result = validator.validate_json_payload(valid_payload)
        self.assertIsNotNone(result)
        self.assertIn("timestamp", result)
        self.assertIn("type", result)

        # Invalid JSON
        self.assertIsNone(validator.validate_json_payload("invalid json"))
        self.assertIsNone(validator.validate_json_payload(""))

        # Missing required fields
        incomplete_payload = json.dumps({"data": "test"})
        self.assertIsNone(validator.validate_json_payload(incomplete_payload))

    def test_secure_config_environment_loading(self):
        """Test secure configuration loading from environment."""
        test_env = {
            "BOTNET_HOST": "10.0.0.1",
            "BOTNET_PORT": "8080",
            "BOTNET_ENCRYPTION_KEY": base64.b64encode(os.urandom(32)).decode(),
            "BOTNET_LOG_LEVEL": "DEBUG",
        }

        with patch.dict(os.environ, test_env):
            config = SecureConfig()

            self.assertEqual(config.get("SERVER_HOST"), "10.0.0.1")
            self.assertEqual(config.get("SERVER_PORT"), 8080)
            self.assertEqual(config.get("LOG_LEVEL"), "DEBUG")

            # Test encryption key loading
            key = config.get_encryption_key()
            self.assertEqual(len(key), 32)

    def test_secure_config_defaults(self):
        """Test secure configuration defaults."""
        # Clear environment variables
        env_keys = ["BOTNET_HOST", "BOTNET_PORT", "BOTNET_ENCRYPTION_KEY"]
        with patch.dict(os.environ, {}, clear=True):
            config = SecureConfig()

            self.assertEqual(config.get("SERVER_HOST"), "0.0.0.0")
            self.assertEqual(config.get("SERVER_PORT"), 9999)
            self.assertEqual(config.get("LOG_LEVEL"), "INFO")

            # Should generate key if not provided
            key = config.get_encryption_key()
            self.assertEqual(len(key), 32)

    def test_secure_logger_sanitization(self):
        """Test that sensitive data is sanitized in logs."""
        logger = SecureLogger("test_logger", "DEBUG")

        # Capture log output
        with patch("logging.StreamHandler.emit") as mock_emit:
            # Test IP address redaction
            logger.info("Connection from 192.168.1.100")
            log_record = mock_emit.call_args[0][0]
            self.assertIn("[IP_REDACTED]", log_record.getMessage())

            # Test key redaction
            logger.info("Using key: YWJjZGVmZ2hpams=")
            log_record = mock_emit.call_args[0][0]
            self.assertIn("[KEY_REDACTED]", log_record.getMessage())

            # Test password redaction
            logger.info("password=secret123")
            log_record = mock_emit.call_args[0][0]
            self.assertIn("[REDACTED]", log_record.getMessage())

    def test_bot_id_generation_uniqueness(self):
        """Test that bot IDs are unique and deterministic."""
        ip1 = "192.168.1.1"
        ip2 = "192.168.1.2"

        # Same IP should generate different IDs with different additional data
        bot_id1 = generate_bot_id(ip1, "session1")
        bot_id2 = generate_bot_id(ip1, "session2")
        self.assertNotEqual(bot_id1, bot_id2)

        # Different IPs should generate different IDs
        bot_id3 = generate_bot_id(ip2, "session1")
        self.assertNotEqual(bot_id1, bot_id3)

        # All IDs should be 8 characters
        self.assertEqual(len(bot_id1), 8)
        self.assertEqual(len(bot_id2), 8)
        self.assertEqual(len(bot_id3), 8)

    def test_tls_context_creation(self):
        """Test TLS context creation."""
        # Test with no cert/key paths
        context = TLSHelper.create_ssl_context()
        self.assertIsNone(context)

        # Test with invalid paths
        context = TLSHelper.create_ssl_context("nonexistent.crt", "nonexistent.key")
        self.assertIsNone(context)


class TestSecurityBotTracker(unittest.IsolatedAsyncioTestCase):
    """Test security aspects of bot tracking."""

    async def test_bot_tracker_concurrent_access(self):
        """Test that bot tracker handles concurrent access safely."""
        tracker = BotTracker()

        # Add bots concurrently
        tasks = []
        for i in range(10):
            tasks.append(tracker.add_bot(f"bot_{i}", f"192.168.1.{i}"))

        await asyncio.gather(*tasks)

        # Check all bots were added
        active_bots = tracker.get_active_bots()
        self.assertEqual(len(active_bots), 10)

        # Remove bots concurrently
        remove_tasks = []
        for i in range(5):
            remove_tasks.append(tracker.remove_bot(f"bot_{i}"))

        await asyncio.gather(*remove_tasks)

        # Check remaining bots
        active_bots = tracker.get_active_bots()
        self.assertEqual(len(active_bots), 5)

    async def test_bot_tracker_activity_updates(self):
        """Test bot activity tracking for security monitoring."""
        tracker = BotTracker()

        bot_id = "test_bot"
        await tracker.add_bot(bot_id, "192.168.1.1")

        # Test activity updates
        await tracker.update_bot_activity(bot_id, "command_sent")
        await tracker.update_bot_activity(bot_id, "command_completed")

        active_bots = tracker.get_active_bots()
        bot_info = active_bots[bot_id]

        self.assertEqual(bot_info["commands_sent"], 1)
        self.assertEqual(bot_info["commands_completed"], 1)
        self.assertIsNotNone(bot_info["last_seen"])


class TestSecurityEdgeCases(unittest.TestCase):
    """Test security edge cases and error conditions."""

    def test_encryption_with_empty_data(self):
        """Test encryption with edge case inputs."""
        encryption = SecureEncryption()

        # Empty data
        encrypted = encryption.encrypt(b"")
        decrypted = encryption.decrypt(encrypted)
        self.assertEqual(decrypted, b"")

        # Unicode data
        unicode_text = "测试数据 🔐"
        encrypted = encryption.encrypt(unicode_text)
        decrypted = encryption.decrypt(encrypted)
        self.assertEqual(decrypted.decode("utf-8"), unicode_text)

    def test_decryption_with_invalid_data(self):
        """Test decryption error handling."""
        encryption = SecureEncryption()

        # Too short data
        with self.assertRaises(ValueError):
            encryption.decrypt(b"short")

        # Invalid encrypted data
        with self.assertRaises(Exception):
            encryption.decrypt(b"invalid_encrypted_data_that_is_long_enough")

    def test_password_key_derivation(self):
        """Test password-based key derivation security."""
        password = "test_password"
        salt = b"test_salt_16byte"

        key1 = SecureEncryption.derive_key_from_password(password, salt)
        key2 = SecureEncryption.derive_key_from_password(password, salt)

        # Same password and salt should produce same key
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 32)

        # Different salt should produce different key
        key3 = SecureEncryption.derive_key_from_password(password, b"different_salt16")
        self.assertNotEqual(key1, key3)


if __name__ == "__main__":
    unittest.main()

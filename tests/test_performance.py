#!/usr/bin/env python3
"""
Performance tests for the Enhanced Botnet Implementation.

These tests validate performance characteristics and ensure the enhancements
provide better scalability and resource efficiency.
"""

import unittest
import asyncio
import time
import threading
import gc
import sys
from unittest.mock import AsyncMock, MagicMock, patch

from utils import SecureEncryption, BotTracker, SecureLogger
import botnet_controller
import botnet_server_enhanced


class TestPerformanceBasics(unittest.TestCase):
    """Test basic performance characteristics."""

    def test_encryption_performance(self):
        """Test encryption/decryption performance."""
        encryption = SecureEncryption()
        test_data = b"A" * 1024  # 1KB of data

        # Measure encryption time
        start_time = time.time()
        for _ in range(100):
            encrypted = encryption.encrypt(test_data)
            decrypted = encryption.decrypt(encrypted)
        end_time = time.time()

        # Should complete 100 operations in reasonable time
        total_time = end_time - start_time
        self.assertLess(total_time, 0.2, "Encryption should be fast (100 ops < 0.2s)")

        # Verify correctness
        self.assertEqual(decrypted, test_data)

    def test_large_data_encryption(self):
        """Test encryption with large data sizes."""
        encryption = SecureEncryption()
        large_data = b"X" * (1024 * 1024)  # 1MB of data

        start_time = time.time()
        encrypted = encryption.encrypt(large_data)
        decrypted = encryption.decrypt(encrypted)
        end_time = time.time()

        # Should handle large data efficiently
        self.assertLess(
            end_time - start_time, 2.0, "Large data encryption should be reasonable"
        )
        self.assertEqual(decrypted, large_data)

    def test_memory_usage_encryption(self):
        """Test memory efficiency of encryption operations."""
        encryption = SecureEncryption()

        # Force garbage collection and measure initial memory
        gc.collect()
        initial_objects = len(gc.get_objects())

        # Perform many encryption operations
        test_data = b"test data for memory testing"
        for _ in range(1000):
            encrypted = encryption.encrypt(test_data)
            decrypted = encryption.decrypt(encrypted)
            del encrypted, decrypted

        # Force garbage collection and measure final memory
        gc.collect()
        final_objects = len(gc.get_objects())

        # Should not have significant memory leaks
        object_growth = final_objects - initial_objects
        self.assertLess(object_growth, 100, "Should not leak significant objects")


class TestPerformanceAsync(unittest.IsolatedAsyncioTestCase):
    """Test performance of async components."""

    async def test_bot_tracker_scalability(self):
        """Test bot tracker performance with many bots."""
        tracker = BotTracker()

        # Add many bots quickly
        start_time = time.time()

        tasks = []
        for i in range(1000):
            tasks.append(tracker.add_bot(f"bot_{i:04d}", f"192.168.{i//255}.{i%255}"))

        await asyncio.gather(*tasks)
        end_time = time.time()

        # Should handle 1000 bots quickly
        self.assertLess(end_time - start_time, 1.0, "Should add 1000 bots quickly")
        self.assertEqual(tracker.get_bot_count(), 1000)

        # Test lookup performance
        start_time = time.time()
        active_bots = tracker.get_active_bots()
        end_time = time.time()

        self.assertLess(end_time - start_time, 0.1, "Bot lookup should be fast")
        self.assertEqual(len(active_bots), 1000)

    async def test_concurrent_bot_operations(self):
        """Test concurrent bot operations performance."""
        tracker = BotTracker()

        # Add initial bots
        for i in range(100):
            await tracker.add_bot(f"bot_{i}", f"192.168.1.{i}")

        # Perform concurrent operations
        async def update_activity(bot_id):
            for _ in range(10):
                await tracker.update_bot_activity(bot_id, "ping")
                await asyncio.sleep(0.001)  # Small delay

        start_time = time.time()

        # Run concurrent updates
        tasks = [update_activity(f"bot_{i}") for i in range(50)]
        await asyncio.gather(*tasks)

        end_time = time.time()

        # Should handle concurrent operations efficiently
        self.assertLess(
            end_time - start_time, 2.0, "Concurrent operations should be efficient"
        )

    async def test_async_server_mock_performance(self):
        """Test async server performance with mocked connections."""
        server = botnet_server_enhanced.EnhancedBotnetServer()

        # Mock multiple concurrent connections
        async def mock_connection():
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.get_extra_info = MagicMock(return_value=("127.0.0.1", 12345))
            mock_writer.is_closing = MagicMock(return_value=False)
            mock_writer.write = MagicMock()
            mock_writer.drain = AsyncMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()

            # Mock quick connection handling
            with patch.object(server, "_process_bot_commands") as mock_process:
                mock_process.return_value = None
                await server.handle_client_connection(mock_reader, mock_writer)

        # Test handling multiple connections
        start_time = time.time()

        tasks = [mock_connection() for _ in range(50)]
        await asyncio.gather(*tasks, return_exceptions=True)

        end_time = time.time()

        # Should handle multiple connections efficiently
        self.assertLess(
            end_time - start_time, 2.0, "Should handle 50 connections quickly"
        )


class TestPerformanceComparison(unittest.TestCase):
    """Compare performance improvements vs original implementation."""

    def test_data_structure_efficiency(self):
        """Test efficiency of using sets vs lists for bot tracking."""
        # Simulate list-based tracking (old method)
        bot_list = []

        # Add bots to list
        start_time = time.time()
        for i in range(1000):
            bot_info = {"id": f"bot_{i}", "ip": f"192.168.{i//255}.{i%255}"}
            bot_list.append(bot_info)
        list_add_time = time.time() - start_time

        # Search in list (O(n))
        start_time = time.time()
        for i in range(100):
            target_id = f"bot_{i*5}"
            found = any(bot["id"] == target_id for bot in bot_list)
        list_search_time = time.time() - start_time

        # Simulate dict-based tracking (new method)
        bot_dict = {}

        # Add bots to dict
        start_time = time.time()
        for i in range(1000):
            bot_id = f"bot_{i}"
            bot_dict[bot_id] = {"id": bot_id, "ip": f"192.168.{i//255}.{i%255}"}
        dict_add_time = time.time() - start_time

        # Search in dict (O(1))
        start_time = time.time()
        for i in range(100):
            target_id = f"bot_{i*5}"
            found = target_id in bot_dict
        dict_search_time = time.time() - start_time

        # Dict should be much faster for lookups
        self.assertLess(
            dict_search_time,
            list_search_time / 5,
            "Dict lookups should be much faster than list",
        )

        print(f"List search time: {list_search_time:.4f}s")
        print(f"Dict search time: {dict_search_time:.4f}s")
        print(f"Speedup: {list_search_time/dict_search_time:.1f}x")

    def test_logging_performance(self):
        """Test logging performance and non-blocking behavior."""
        logger = SecureLogger("perf_test", "INFO")

        # Test rapid logging
        start_time = time.time()
        for i in range(1000):
            logger.info(f"Performance test message {i}")
        end_time = time.time()

        # Should handle rapid logging efficiently
        total_time = end_time - start_time
        self.assertLess(total_time, 2.0, "Should log 1000 messages quickly")

        # Test with sensitive data (should be sanitized)
        start_time = time.time()
        for i in range(100):
            logger.info(f"Connection from 192.168.1.{i} with key ABC123DEF456")
        end_time = time.time()

        # Sanitization should not significantly impact performance
        sanitization_time = end_time - start_time
        self.assertLess(sanitization_time, 1.0, "Sanitization should be efficient")


class TestMemoryAndResourceManagement(unittest.TestCase):
    """Test memory usage and resource management."""

    def test_connection_cleanup(self):
        """Test that connections are properly cleaned up."""
        controller = botnet_controller.BotnetController()

        # Track initial state
        initial_connections = len(controller.active_connections)
        initial_bots = controller.bot_tracker.get_bot_count()

        # Simulate connections being added and removed
        # (This would typically happen in real async context)
        mock_writer1 = MagicMock()
        mock_writer2 = MagicMock()

        controller.active_connections.add(mock_writer1)
        controller.active_connections.add(mock_writer2)

        # Verify connections added
        self.assertEqual(len(controller.active_connections), initial_connections + 2)

        # Simulate cleanup
        controller.active_connections.discard(mock_writer1)
        controller.active_connections.discard(mock_writer2)

        # Verify cleanup
        self.assertEqual(len(controller.active_connections), initial_connections)

    def test_memory_efficient_bot_tracking(self):
        """Test memory efficiency of bot tracking."""
        tracker = BotTracker()

        # Force garbage collection
        gc.collect()
        initial_memory = self._get_memory_usage()

        # Add many bots
        for i in range(1000):
            asyncio.run(tracker.add_bot(f"bot_{i}", f"192.168.{i//255}.{i%255}"))

        # Measure memory after adding bots
        gc.collect()
        with_bots_memory = self._get_memory_usage()

        # Remove all bots
        for i in range(1000):
            asyncio.run(tracker.remove_bot(f"bot_{i}"))

        # Measure memory after cleanup
        gc.collect()
        final_memory = self._get_memory_usage()

        # Memory should be efficiently managed
        memory_growth = with_bots_memory - initial_memory
        memory_after_cleanup = final_memory - initial_memory

        # After cleanup, memory should be mostly recovered
        self.assertLess(
            memory_after_cleanup,
            memory_growth * 0.1,
            "Memory should be recovered after cleanup",
        )

    def _get_memory_usage(self):
        """Get current memory usage (simplified metric)."""
        return len(gc.get_objects())


class TestStressConditions(unittest.IsolatedAsyncioTestCase):
    """Test behavior under stress conditions."""

    async def test_high_concurrency_bot_operations(self):
        """Test high concurrency scenarios."""
        tracker = BotTracker()

        # Create many concurrent operations
        async def rapid_bot_lifecycle(bot_id):
            await tracker.add_bot(bot_id, "192.168.1.1")
            await asyncio.sleep(0.001)
            await tracker.update_bot_activity(bot_id, "ping")
            await asyncio.sleep(0.001)
            await tracker.remove_bot(bot_id)

        start_time = time.time()

        # Run many concurrent bot lifecycles
        tasks = [rapid_bot_lifecycle(f"stress_bot_{i}") for i in range(200)]
        await asyncio.gather(*tasks, return_exceptions=True)

        end_time = time.time()

        # Should handle stress without errors
        self.assertLess(end_time - start_time, 5.0, "Should handle stress efficiently")

        # All bots should be cleaned up
        self.assertEqual(tracker.get_bot_count(), 0)

    async def test_rapid_encryption_operations(self):
        """Test rapid encryption/decryption under load."""
        encryption = SecureEncryption()

        async def encryption_worker():
            for _ in range(100):
                data = f"test data {time.time()}".encode()
                encrypted = encryption.encrypt(data)
                decrypted = encryption.decrypt(encrypted)
                assert decrypted == data
                await asyncio.sleep(0.001)  # Small delay

        start_time = time.time()

        # Run multiple encryption workers concurrently
        tasks = [encryption_worker() for _ in range(10)]
        await asyncio.gather(*tasks)

        end_time = time.time()

        # Should handle concurrent encryption efficiently
        self.assertLess(
            end_time - start_time, 3.0, "Concurrent encryption should be efficient"
        )


if __name__ == "__main__":
    # Set up test environment
    import sys
    import warnings

    # Suppress warnings for cleaner output
    warnings.filterwarnings("ignore", category=RuntimeWarning)

    # Run tests with performance timing
    suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    if result.wasSuccessful():
        print("\n✅ All performance tests passed!")
    else:
        print(
            f"\n❌ {len(result.failures)} test(s) failed, {len(result.errors)} error(s)"
        )
        sys.exit(1)

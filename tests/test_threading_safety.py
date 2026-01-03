#!/usr/bin/env python3
"""
Test the thread safety improvements to BotTracker.

This test validates that the BotTracker properly handles concurrent access
from multiple threads while also supporting async operations.
"""

import asyncio
import unittest
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from utils import BotTracker


def ensure_event_loop():
    """Ensure an event loop exists for tests running in the main thread."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())


class TestBotTrackerThreadSafety(unittest.TestCase):
    """Test BotTracker thread safety features."""

    def setUp(self):
        """Set up test fixtures."""
        ensure_event_loop()
        self.tracker = BotTracker()

    def test_threading_lock_attributes(self):
        """Test that BotTracker has proper locking attributes."""
        self.assertTrue(hasattr(self.tracker, "_thread_lock"))
        self.assertTrue(hasattr(self.tracker, "_async_lock"))
        self.assertTrue(isinstance(self.tracker._thread_lock, type(threading.RLock())))
        self.assertIsInstance(self.tracker._async_lock, asyncio.Lock)

    def test_synchronous_operations_thread_safety(self):
        """Test that synchronous operations are thread-safe."""
        num_threads = 10
        operations_per_thread = 50
        results = []

        def add_bots_sync(thread_id):
            """Add bots synchronously from a thread."""
            count = 0
            for i in range(operations_per_thread):
                # We can't use async operations directly in sync context,
                # but we can test the thread-safe accessors
                self.tracker.get_bot_count()  # initial_count
                # Simulate some work
                time.sleep(0.001)
                self.tracker.get_bot_count()  # current_count
                count += 1
            return count

        # Run operations in multiple threads
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = []
            for thread_id in range(num_threads):
                future = executor.submit(add_bots_sync, thread_id)
                futures.append(future)

            # Collect results
            for future in futures:
                results.append(future.result())

        # Verify all threads completed their operations
        expected_total = num_threads * operations_per_thread
        actual_total = sum(results)
        self.assertEqual(actual_total, expected_total)

    def test_concurrent_get_operations(self):
        """Test concurrent get operations are thread-safe."""

        # First, add some bots using async
        async def setup_bots():
            for i in range(20):
                await self.tracker.add_bot(f"test_bot_{i}", f"192.168.1.{i}")

        # Run setup
        asyncio.run(setup_bots())

        # Now test concurrent access from multiple threads
        def get_bots_info(thread_id):
            """Get bot information from multiple threads."""
            results = []
            for _ in range(100):
                active_bots = self.tracker.get_active_bots()
                bot_count = self.tracker.get_bot_count()
                results.append((len(active_bots), bot_count))
                time.sleep(0.001)  # Small delay to increase concurrency
            return results

        # Run concurrent get operations
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for thread_id in range(5):
                future = executor.submit(get_bots_info, thread_id)
                futures.append(future)

            # Collect all results
            all_results = []
            for future in futures:
                all_results.extend(future.result())

        # Verify consistency - all reads should return the same values
        for active_count, bot_count in all_results:
            self.assertEqual(active_count, 20)
            self.assertEqual(bot_count, 20)

    def test_mixed_async_thread_operations(self):
        """Test that async and threaded operations work together."""

        def run_async_in_thread(coro):
            """Helper to run async coroutine in a new event loop."""
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(coro)
            finally:
                loop.close()

        async def async_operations():
            """Perform async bot operations."""
            # Add bots
            for i in range(10):
                await self.tracker.add_bot(f"async_bot_{i}", f"10.0.0.{i}")

            # Update some bot activities
            for i in range(5):
                await self.tracker.update_bot_activity(f"async_bot_{i}", "command_sent")

            return self.tracker.get_bot_count()

        # Run async operations in a separate thread
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(run_async_in_thread, async_operations())
            result = future.result()

        # Verify the operations completed successfully
        self.assertEqual(result, 10)

        # Verify we can still access the bots from the main thread
        active_bots = self.tracker.get_active_bots()
        self.assertEqual(len(active_bots), 10)

        # Check that some bots have command_sent activity
        bots_with_commands = [
            bot for bot in active_bots.values() if bot["commands_sent"] > 0
        ]
        self.assertEqual(len(bots_with_commands), 5)


class TestBotTrackerThreadSafetyAsync(unittest.IsolatedAsyncioTestCase):
    """Async tests for BotTracker thread safety."""

    async def test_async_operations_with_threading_protection(self):
        """Test that async operations work correctly with threading protection."""
        tracker = BotTracker()

        # Perform concurrent async operations
        tasks = []
        for i in range(20):
            tasks.append(tracker.add_bot(f"concurrent_bot_{i}", f"172.16.0.{i}"))

        await asyncio.gather(*tasks)

        # Verify all bots were added
        active_bots = tracker.get_active_bots()
        self.assertEqual(len(active_bots), 20)

        # Test concurrent updates
        update_tasks = []
        for i in range(10):
            update_tasks.append(
                tracker.update_bot_activity(f"concurrent_bot_{i}", "command_sent")
            )

        await asyncio.gather(*update_tasks)

        # Verify updates
        active_bots = tracker.get_active_bots()
        updated_bots = [bot for bot in active_bots.values() if bot["commands_sent"] > 0]
        self.assertEqual(len(updated_bots), 10)

        # Test concurrent removals
        remove_tasks = []
        for i in range(5):
            remove_tasks.append(tracker.remove_bot(f"concurrent_bot_{i}"))

        await asyncio.gather(*remove_tasks)

        # Verify removals
        final_bots = tracker.get_active_bots()
        self.assertEqual(len(final_bots), 15)


if __name__ == "__main__":
    unittest.main()

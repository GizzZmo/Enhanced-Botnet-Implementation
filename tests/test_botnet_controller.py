import unittest
from unittest.mock import MagicMock, patch, AsyncMock
import asyncio
import json
import botnet_controller


class TestBotnetController(unittest.TestCase):

    def test_encrypt_decrypt(self):
        test_data = b"command:test"
        encrypted = botnet_controller.encrypt(test_data)
        decrypted = botnet_controller.decrypt(encrypted)
        self.assertEqual(decrypted, test_data)

    def test_encryption_changed(self):
        data1 = b"test1"
        data2 = b"test2"
        self.assertNotEqual(
            botnet_controller.encrypt(data1),
            botnet_controller.encrypt(data2)
        )

    @patch('getpass.getpass', return_value='test_password')
    @patch.dict('os.environ', {'BOTNET_ADMIN_PASSWORD': 'test_password'})
    def test_botnet_controller_init(self, mock_getpass):
        """Test controller initialization."""
        controller = botnet_controller.BotnetController()
        self.assertIsNotNone(controller.config)
        self.assertIsNotNone(controller.encryption)
        self.assertIsNotNone(controller.bot_tracker)
        self.assertEqual(controller.host, '0.0.0.0')
        self.assertEqual(controller.port, 9999)

    def test_legacy_compatibility(self):
        """Test that legacy encrypt/decrypt functions still work."""
        test_data = b"legacy test data"
        encrypted = botnet_controller.encrypt(test_data)
        decrypted = botnet_controller.decrypt(encrypted)
        self.assertEqual(decrypted, test_data)

    def test_async_handle_client_structure(self):
        """Test that handle_client is an async function with proper signature."""
        controller = botnet_controller.BotnetController()
        
        # Check that handle_client is a coroutine function
        import inspect
        self.assertTrue(inspect.iscoroutinefunction(controller.handle_client))
        
        # Check the method exists and has the right signature
        self.assertTrue(hasattr(controller, 'handle_client'))


class TestBotnetControllerAsync(unittest.IsolatedAsyncioTestCase):
    """Async tests for the enhanced controller."""

    async def test_async_handle_client_mock(self):
        """Test async handle_client with mocked streams."""
        controller = botnet_controller.BotnetController()
        
        # Mock async streams
        mock_reader = AsyncMock()
        mock_writer = MagicMock()  # Use regular Mock for writer
        mock_writer.get_extra_info = MagicMock(return_value=('127.0.0.1', 12345))
        mock_writer.is_closing = MagicMock(return_value=False)
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        
        # Mock the admin command input to avoid blocking
        with patch.object(controller, '_get_admin_command', new_callable=AsyncMock) as mock_get_cmd:
            mock_get_cmd.return_value = 'quit'  # Immediately quit
            
            # This should not raise an exception
            await controller.handle_client(mock_reader, mock_writer)
            
            # Verify that write operations were called
            self.assertTrue(mock_writer.write.called)
            # Either drain or close should be called
            self.assertTrue(mock_writer.drain.called or mock_writer.close.called)


if __name__ == '__main__':
    unittest.main()

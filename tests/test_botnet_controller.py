import unittest
from unittest.mock import MagicMock, patch
import botnet_controller
import json


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

    @patch('builtins.input', side_effect=['!status', 'quit'])
    def test_handle_client(self, mock_input):
        controller = botnet_controller.BotnetController()
        fake_socket = MagicMock()
        fake_socket.recv.return_value = b''
        fake_socket.send = MagicMock()
        address = ('127.0.0.1', 12345)
        controller.handle_client(fake_socket, address)
        self.assertGreaterEqual(fake_socket.send.call_count, 2)
        found_json = False
        for call in fake_socket.send.call_args_list:
            try:
                data = call[0][0]
                if isinstance(data, bytes):
                    data = data.decode()
                obj = json.loads(data)
                if 'cmd' in obj and 'timestamp' in obj:
                    found_json = True
            except Exception:
                continue
        self.assertTrue(found_json, "Should send JSON payload with command.")


if __name__ == '__main__':
    unittest.main()

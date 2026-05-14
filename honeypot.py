"""
SSH Honeypot Server
===================
A fake SSH server built with Paramiko that:
  - Listens on port 2222 for incoming SSH connections
  - Captures every login attempt
  - Always rejects authentication — never grants access
  - Logs all events to a JSON Lines file (events.jsonl)
  - Tracks attempt counts per IP

Usage:
  python3 honeypot.py

Test (second terminal):
  ssh -p 2222 -o StrictHostKeyChecking=no root@<SERVER_IP>

Stop: Ctrl+C
"""

import socket
import threading
import paramiko
import json
import os
from datetime import datetime, timezone
from collections import defaultdict

# ── Configuration ─────────────────────────────────────────────────────────────
HOST = "0.0.0.0"       # listen on all interfaces (use 127.0.0.1 for local testing)
PORT = 2222
HOST_KEY_FILE = "host_key_rsa"
LOG_FILE = "events.jsonl"

# Realistic SSH banner
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"

# ── Shared state ──────────────────────────────────────────────────────────────
attempts_per_ip = defaultdict(int)
lock = threading.Lock()

# ── Host key ──────────────────────────────────────────────────────────────────
if not os.path.exists(HOST_KEY_FILE):
    print("[*] Generating RSA host key (2048 bit)...")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_FILE)
    print(f"[*] Key saved to '{HOST_KEY_FILE}'")

HOST_KEY = paramiko.RSAKey(filename=HOST_KEY_FILE)


# ── Logging ───────────────────────────────────────────────────────────────────

def log_event(event_type, ip, **kwargs):
    """
    Write a structured event to the JSON Lines log file and print to console.

    Example output line:
    {"timestamp": "2026-03-25T10:23:41Z", "type": "auth_attempt",
     "ip": "1.2.3.4", "username": "root", "password": "123456",
     "client_version": "SSH-2.0-Go", "attempt_n": 3}
    """
    event = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "type":      event_type,
        "ip":        ip,
        **kwargs
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")


# ── SSH server interface ───────────────────────────────────────────────────────

class HoneypotServer(paramiko.ServerInterface):
    """
    Implements the Paramiko ServerInterface.
    Called automatically by Paramiko during the SSH handshake.

    Key methods:
      check_auth_password  — called when client sends username + password
      check_auth_publickey — called when client tries key-based auth
      check_channel_request — called if auth succeeds (never happens here)
    """

    def __init__(self, transport, ip):
        self.ip = ip
        self.transport = transport

    def check_auth_password(self, username, password):
        with lock:
            attempts_per_ip[self.ip] += 1
            n = attempts_per_ip[self.ip]

        client_version = getattr(self.transport, "remote_version", "unknown")

        log_event(
            "auth_attempt",
            self.ip,
            username=username,
            password=password,
            client_version=client_version,
            attempt_n=n
        )
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        log_event(
            "auth_attempt",
            self.ip,
            username=username,
            method="publickey",
            key_type=key.get_name(),
            fingerprint=key.get_fingerprint().hex()
        )
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password,publickey"


# ── Connection handler ────────────────────────────────────────────────────────

def handle_connection(client_socket, client_address):
    """
    Runs in a separate thread for each incoming connection.
    Passes the raw TCP socket to Paramiko which handles the SSH protocol.
    """
    ip, port = client_address
    log_event("connection", ip, source_port=port)

    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = SSH_BANNER
        transport.add_server_key(HOST_KEY)

        server = HoneypotServer(transport, ip)
        transport.start_server(server=server)
        transport.accept(15)

    except paramiko.SSHException as e:
        # Normal: clients that close immediately, scanners that
        # don't complete the handshake, etc.
        log_event("connection", ip, error=str(e))
    except Exception as e:
        err_str = str(e)
        normal_codes = ["10038", "10054", "9", "EOF", "connection reset"]
        if not any(c in err_str for c in normal_codes):
            log_event("connection", ip, unexpected_error=str(e))
    finally:
        try:
            client_socket.close()
        except:
            pass
        log_event("disconnection", ip)
        with lock:
            n = attempts_per_ip.get(ip, 0)
        if n > 0:
            print(f"  → Total attempts from {ip}: {n}\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print(f"[*] SSH Honeypot started on {HOST}:{PORT}")
    print(f"[*] Logging to: {LOG_FILE}")
    print(f"[*] Banner: {SSH_BANNER}")
    print(f"[*] Press Ctrl+C to stop\n")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(10)
    server_socket.settimeout(1.0)

    
    try:
        while True:
            try:
                client_socket, client_address = server_socket.accept()
            except socket.timeout:
                continue
            thread = threading.Thread(
                target=handle_connection,
                args=(client_socket, client_address),
                daemon=True
            )
            thread.start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        print(f"[*] Logs saved to {LOG_FILE}")
        if attempts_per_ip:
            print("\n[*] Attempt summary by IP:")
            for ip, n in sorted(attempts_per_ip.items(), key=lambda x: -x[1]):
                print(f"    {ip}: {n} attempts")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()

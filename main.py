#!/usr/bin/env python3
"""
PeerTalk — P2P Encrypted Chat (GUI, No Server)

- One peer Hosts (listens on a TCP port), the other Connects to host IP:port
- Ephemeral X25519 ECDH -> HKDF(SHA256) -> AESGCM(256-bit)
- Unique nonce per message (random 8-byte prefix + uint32 counter)
- Messages include plaintext SHA-256 for auditable integrity (AEAD already authenticates)
- SAS Fingerprint derived from both public keys + Room Code; compare it to prevent MITM
"""

import os
import json
import socket
import struct
import threading
import time
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

APP_NAME = "PeerTalk"
PROTOCOL_TAG = b"PEERTALKv1"       # Used as HKDF info/AAD
HELLO1 = b"HELLO1"                 # initiator -> responder (pubkey, salt)
HELLO2 = b"HELLO2"                 # responder -> initiator (pubkey, salt)
READ_CHUNK = 4096

# -------- Framing helpers (length-prefixed messages over TCP) --------
def send_frame(sock: socket.socket, payload: bytes):
    # 4-byte big-endian length + payload
    sock.sendall(struct.pack(">I", len(payload)) + payload)

def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed")
        buf += chunk
    return buf

def recv_frame(sock: socket.socket) -> bytes:
    hdr = recv_exact(sock, 4)
    (length,) = struct.unpack(">I", hdr)
    if length > 10_000_000:
        raise ValueError("Frame too large")
    return recv_exact(sock, length)

# -------- SAS Fingerprint (Short Authentication String) --------
def sas_fingerprint(room_code: str, pub_a: bytes, pub_b: bytes) -> str:
    """
    Deterministic short string both peers can compare out-of-band.
    Uses HMAC-like construction with room code as a salt-ish input.
    Order-independent: XOR sort by bytes to avoid role bias.
    """
    if pub_a <= pub_b:
        combo = pub_a + pub_b
    else:
        combo = pub_b + pub_a
    h = hashlib.sha256(room_code.encode("utf-8") + b"|" + combo + b"|" + PROTOCOL_TAG).hexdigest()
    # show a short, readable code
    return f"{h[:4]}-{h[4:8]}-{h[8:12]}-{h[12:16]}"

# -------- Session object --------
class SecureSession:
    def __init__(self):
        self.aesgcm: AESGCM | None = None
        self.send_prefix = os.urandom(8)    # 8 bytes
        self.send_counter = 0               # 32-bit

    def set_key(self, key_bytes: bytes):
        self.aesgcm = AESGCM(key_bytes)

    def _next_nonce(self) -> bytes:
        # 12-byte nonce = 8-byte random prefix + 4-byte counter (big-endian)
        self.send_counter = (self.send_counter + 1) & 0xFFFFFFFF
        return self.send_prefix + struct.pack(">I", self.send_counter)

    def encrypt_message(self, plaintext: bytes) -> bytes:
        assert self.aesgcm is not None
        nonce = self._next_nonce()
        # Use PROTOCOL_TAG as AAD for integrity binding
        ct = self.aesgcm.encrypt(nonce, plaintext, PROTOCOL_TAG)
        return nonce + ct  # prepend nonce so receiver can decrypt

    def decrypt_message(self, data: bytes) -> bytes:
        assert self.aesgcm is not None
        if len(data) < 12:
            raise ValueError("Ciphertext too short")
        nonce, ct = data[:12], data[12:]
        return self.aesgcm.decrypt(nonce, ct, PROTOCOL_TAG)

# -------- Networking Peer --------
class Peer:
    def __init__(self, ui_ref):
        self.ui = ui_ref
        self.sock: socket.socket | None = None
        self.alive = False
        self.sess = SecureSession()
        self.room_code = ""
        self.role = None  # "host" or "client"

        # ECDH keys
        self.priv = X25519PrivateKey.generate()
        self.pub = self.priv.public_key().public_bytes_raw()

        # Peer's pubkey and salts
        self.peer_pub: bytes | None = None
        self.initiator_salt: bytes | None = None
        self.responder_salt: bytes | None = None

    # ---- Host & Accept ----
    def host(self, port: int, room_code: str, bind_ip: str = "0.0.0.0"):
        self.role = "host"
        self.room_code = room_code
        t = threading.Thread(target=self._do_host, args=(bind_ip, port), daemon=True)
        t.start()

    def _do_host(self, bind_ip: str, port: int):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((bind_ip, port))
            srv.listen(1)
            self.ui.log(f"[Host] Listening on {bind_ip}:{port} ...")
            conn, addr = srv.accept()
            self.sock = conn
            self.alive = True
            self.ui.on_connected(addr)
            self._handshake_as_responder()
            self._recv_loop()
        except Exception as e:
            self.ui.log(f"[Host] Error: {e}")
            self.ui.on_disconnected()

    # ---- Connect to Host ----
    def connect(self, ip: str, port: int, room_code: str):
        self.role = "client"
        self.room_code = room_code
        t = threading.Thread(target=self._do_connect, args=(ip, port), daemon=True)
        t.start()

    def _do_connect(self, ip: str, port: int):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            self.sock = s
            self.alive = True
            self.ui.on_connected((ip, port))
            self._handshake_as_initiator()
            self._recv_loop()
        except Exception as e:
            self.ui.log(f"[Client] Error: {e}")
            self.ui.on_disconnected()

    # ---- Handshake (Initiator) ----
    def _handshake_as_initiator(self):
        assert self.sock
        self.initiator_salt = os.urandom(16)
        # Send HELLO1: our pubkey + initiator_salt
        hello1 = {
            "t": HELLO1.decode(),
            "pub": self.pub.hex(),
            "salt_i": self.initiator_salt.hex(),
            "tag": PROTOCOL_TAG.decode()
        }
        send_frame(self.sock, json.dumps(hello1).encode("utf-8"))

        # Receive HELLO2
        data = recv_frame(self.sock)
        msg = json.loads(data.decode("utf-8"))
        if msg.get("t") != HELLO2.decode() or msg.get("tag") != PROTOCOL_TAG.decode():
            raise ValueError("Invalid handshake response

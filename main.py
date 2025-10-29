#!/usr/bin/env python3
"""
LanternChat — P2P Encrypted Chat with GUI (Tkinter)

Crypto:
- Ephemeral X25519 key exchange over TCP
- HKDF-SHA256 derives 32-byte key from ECDH shared + both salts (+ optional PSK)
- AES-GCM (256-bit) for message encryption with 12-byte random nonces

Transport:
- One peer Hosts (listens), the other Connects (dials)
- Simple length-prefixed JSON frames
- Handshake: client sends hello; server replies hello; both compute safety code & key

GUI:
- Host/Connect controls, message view, input box, send button, save transcript
- "Codes Match" gate unlocks the chat after manual verification

No server. No logs unless you **Save Transcript** manually.
"""
import base64
import json
import os
import queue
import socket
import struct
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

APP_NAME = "LanternChat"
PROTOCOL_VERSION = 1
FRAME_HDR = "!I"  # 4-byte big-endian length
RECV_BUFSIZE = 65536

# ------------- utilities -------------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def send_frame(sock: socket.socket, obj: dict):
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    hdr = struct.pack(FRAME_HDR, len(data))
    sock.sendall(hdr + data)

def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf += chunk
    return buf

def recv_frame(sock: socket.socket) -> dict:
    hdr = recv_exact(sock, 4)
    (length,) = struct.unpack(FRAME_HDR, hdr)
    payload = recv_exact(sock, length)
    return json.loads(payload.decode("utf-8"))

def hkdf_key(shared: bytes, saltA: bytes, saltB: bytes, psk: Optional[str]) -> bytes:
    # order-independent salt: concat salts in lexicographic order
    salts = [saltA, saltB]
    salts.sort()
    salt = salts[0] + salts[1]
    info = b"LanternChat v1"
    if psk:
        info += b" | PSK:" + hashes.Hash(hashes.SHA256())
        h = hashes.Hash(hashes.SHA256())
        h.update(psk.encode("utf-8"))
        info += h.finalize()
    hk = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    return hk.derive(shared)

def safety_code(pubA: bytes, pubB: bytes) -> str:
    # order-independent short code (16 hex chars grouped)
    pubs = sorted([pubA, pubB])
    h = hashes.Hash(hashes.SHA256())
    h.update(pubs[0])
    h.update(pubs[1])
    digest = h.finalize()
    short = digest[:8].hex().upper()
    return "-".join([short[i:i+2] for i in range(0, len(short), 2)])

@dataclass
class Session:
    sock: socket.socket
    key: bytes
    aes: AESGCM
    peer_addr: Tuple[str, int]
    established: bool = False

# ------------- networking threads -------------
class HostServer(threading.Thread):
    def __init__(self, app, port: int, psk: Optional[str]):
        super().__init__(daemon=True)
        self.app = app
        self.port = port
        self.psk = psk
        self.stop_evt = threading.Event()
        self.listen_sock: Optional[socket.socket] = None

    def run(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("", self.port))
            s.listen(1)
            self.listen_sock = s
            self.app.ui_log(f"[HOST] Listening on 0.0.0.0:{self.port} …")
            s.settimeout(1.0)
            while not self.stop_evt.is_set():
                try:
                    conn, addr = s.accept()
                except socket.timeout:
                    continue
                self.app.ui_log(f"[HOST] Incoming from {addr[0]}:{addr[1]}")
                try:
                    self.app.establish_session(conn, addr, role="server", psk=self.psk)
                except Exception as e:
                    self.app.ui_log(f"[ERR] Handshake failed: {e}")
                    try: conn.close()
                    except: pass
        except Exception as e:
            self.app.ui_log(f"[ERR] Host error: {e}")
        finally:
            if self.listen_sock:
                try: self.listen_sock.close()
                except: pass

    def stop(self):
        self.stop_evt.set()

class ClientConnector(threading.Thread):
    def __init__(self, app, host: str, port: int, psk: Optional[str]):
        super().__init__(daemon=True)
        self.app = app
        self.host = host
        self.port = port
        self.psk = psk

    def run(self):
        try:
            self.app.ui_log(f"[CLIENT] Connecting to {self.host}:{self.port} …")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((self.host, self.port))
            self.app.establish_session(s, (self.host, self.port), role="client", psk=self.psk)
        except Exception as e:
            self.app.ui_log(f"[ERR] Connect failed: {e}")

class Receiver(threading.Thread):
    def __init__(self, app, sess: Session):
        super().__init__(daemon=True)
        self.app = app
        self.sess = sess

    def run(self):
        try:
            while True:
                pkt = recv_frame(self.sess.sock)
                t = pkt.get("type")
                if t == "msg":
                    n = b64d(pkt["n"])
                    c = b64d(pkt["c"])
                    pt = self.sess.aes.decrypt(n, c, None).decode("utf-8", errors="replace")
                    self.app.enqueue_incoming(f"[Peer] {pt}")
                elif t == "bye":
                    self.app.ui_log("[INFO] Peer closed the session.")
                    break
                else:
                    # Unknown or post-handshake control
                    continue
        except Exception as e:
            self.app.ui_log(f"[INFO] Receiver ended: {e}")
        finally:
            self.app.close_session(from_thread=True)

# ------------- GUI app -------------
class LanternApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("820x560")
        self.resizable(True, True)

        # state
        self.server: Optional[HostServer] = None
        self.client: Optional[ClientConnector] = None
        self.sess: Optional[Session] = None
        self.incoming_q: queue.Queue[str] = queue.Queue()
        self.codes_verified = False

        # ui vars
        self.var_host_ip = tk.StringVar()
        self.var_port = tk.StringVar(value="5005")
        self.var_pass = tk.StringVar()
        self.var_safety = tk.StringVar(value="—")
        self.var_status = tk.StringVar(value="Idle.")

        self._build_ui()
        self.after(100, self._poll_incoming)

    # ----- UI building -----
    def _build_ui(self):
        top = ttk.Frame(self, padding=8)
        top.pack(fill=tk.X)

        ttk.Label(top, text="Peer IP:").pack(side=tk.LEFT)
        ttk.Entry(top, textvariable=self.var_host_ip, width=18).pack(side=tk.LEFT, padx=(4,10))
        ttk.Label(top, text="Port:").pack(side=tk.LEFT)
        ttk.Entry(top, textvariable=self.var_port, width=8).pack(side=tk.LEFT, padx=(4,10))
        ttk.Label(top, text="Session Passphrase (optional):").pack(side=tk.LEFT)
        ttk.Entry(top, textvariable=self.var_pass, width=22, show="•").pack(side=tk.LEFT, padx=(4,10))

        btns = ttk.Frame(self, padding=(8,0))
        btns.pack(fill=tk.X)
        ttk.Button(btns, text="Host", command=self.on_host).pack(side=tk.LEFT)
        ttk.Button(btns, text="Connect", command=self.on_connect).pack(side=tk.LEFT, padx=(8,0))
        ttk.Button(btns, text="Disconnect", command=self.on_disconnect).pack(side=tk.LEFT, padx=(8,0))

        codebox = ttk.Frame(self, padding=(8,6))
        codebox.pack(fill=tk.X)
        ttk.Label(codebox, text="Safety Code:").pack(side=tk.LEFT)
        ttk.Label(codebox, textvariable=self.var_safety, foreground="blue").pack(side=tk.LEFT, padx=(6,10))
        ttk.Button(codebox, text="Codes Match", command=self.on_codes_match).pack(side=tk.LEFT)
        ttk.Label(codebox, textvariable=self.var_status, foreground="gray").pack(side=tk.RIGHT)

        mid = ttk.Frame(self, padding=8)
        mid.pack(fill=tk.BOTH, expand=True)

        self.txt = tk.Text(mid, height=20, wrap=tk.WORD, state=tk.DISABLED)
        self.txt.pack(fill=tk.BOTH, expand=True)

        inputf = ttk.Frame(self, padding=8)
        inputf.pack(fill=tk.X)
        self.var_msg = tk.StringVar()
        ent = ttk.Entry(inputf, textvariable=self.var_msg)
        ent.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ent.bind("<Return>", lambda e: self.on_send())
        ttk.Button(inputf, text="Send", command=self.on_send).pack(side=tk.LEFT, padx=(8,0))
        ttk.Button(inputf, text="Save Transcript", command=self.on_save).pack(side=tk.LEFT, padx=(8,0))

    # ----- UI helpers -----
    def ui_log(self, line: str):
        self.txt.config(state=tk.NORMAL)
        self.txt.insert(tk.END, time.strftime("[%H:%M:%S] ") + line + "\n")
        self.txt.see(tk.END)
        self.txt.config(state=tk.DISABLED)

    def enqueue_incoming(self, line: str):
        self.incoming_q.put(line)

    def _poll_incoming(self):
        try:
            while True:
                line = self.incoming_q.get_nowait()
                self.ui_log(line)
        except queue.Empty:
            pass
        self.after(100, self._poll_incoming)

    # ----- session lifecycle -----
    def establish_session(self, sock: socket.socket, addr, role: str, psk: Optional[str]):
        """
        Perform the authenticated key exchange and start the receiver thread.
        role: "client" or "server"
        """
        # Generate ephemeral keypair & salt
        priv = X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        salt_local = os.urandom(16)

        # Protocol: client sends hello first; server replies hello
        if role == "client":
            hello = {"type":"hello","v":PROTOCOL_VERSION,"pub":b64e(pub),"salt":b64e(salt_local)}
            send_frame(sock, hello)
            srv_hello = recv_frame(sock)
            if srv_hello.get("type") != "hello":
                raise ValueError("unexpected server hello")
            peer_pub = b64d(srv_hello["pub"])
            salt_peer = b64d(srv_hello["salt"])
        else:
            # server: wait hello, then send ours
            cli_hello = recv_frame(sock)
            if cli_hello.get("type") != "hello":
                raise ValueError("unexpected client hello")
            peer_pub = b64d(cli_hello["pub"])
            salt_peer = b64d(cli_hello["salt"])
            hello = {"type":"hello","v":PROTOCOL_VERSION,"pub":b64e(pub),"salt":b64e(salt_local)}
            send_frame(sock, hello)

        # Derive shared key
        peer_key = X25519PublicKey.from_public_bytes(peer_pub)
        shared = priv.exchange(peer_key)
        key = hkdf_key(shared, salt_local, salt_peer, psk)
        aes = AESGCM(key)

        # Safety code (both should match)
        code = safety_code(pub, peer_pub)
        self.var_safety.set(code)
        self.var_status.set("Verify safety code, then click 'Codes Match'.")

        self.sess = Session(sock=sock, key=key, aes=aes, peer_addr=(addr[0], addr[1]), established=False)
        self.ui_log(f"[SECURE?] Safety Code shown. Verify with peer: {code}")

        # Start receiver
        recv_thr = Receiver(self, self.sess)
        recv_thr.start()

    def on_host(self):
        try:
            port = int(self.var_port.get().strip())
            if self.server:
                self.server.stop()
            self.server = HostServer(self, port, self.var_pass.get().strip() or None)
            self.server.start()
            self.var_status.set(f"Hosting on port {port}. Waiting for peer…")
            self.ui_log(f"[INFO] Your IP (LAN) may be: {self._guess_lan_ip()}  (share with your peer)")
        except Exception as e:
            messagebox.showerror("Host error", str(e))

    def on_connect(self):
        try:
            host = self.var_host_ip.get().strip()
            port = int(self.var_port.get().strip())
            self.client = ClientConnector(self, host, port, self.var_pass.get().strip() or None)
            self.client.start()
            self.var_status.set(f"Connecting to {host}:{port} …")
        except Exception as e:
            messagebox.showerror("Connect error", str(e))

    def on_disconnect(self):
        self.close_session(from_thread=False)

    def on_codes_match(self):
        if not self.sess:
            messagebox.showwarning("Not connected", "No session.")
            return
        self.codes_verified = True
        self.sess.established = True
        self.var_status.set("Secure chat established.")
        self.ui_log("[SECURE] Codes matched. Chat unlocked.")

    def on_send(self):
        msg = self.var_msg.get()
        self.var_msg.set("")
        if not msg.strip():
            return
        if not self.sess or not self.sess.established:
            self.ui_log("[WARN] Not secure yet. Verify codes first.")
            return
        try:
            n = os.urandom(12)
            c = self.sess.aes.encrypt(n, msg.encode("utf-8"), None)
            pkt = {"type":"msg","n":b64e(n),"c":b64e(c)}
            send_frame(self.sess.sock, pkt)
            self.ui_log(f"[You] {msg}")
        except Exception as e:
            self.ui_log(f"[ERR] Send failed: {e}")
            self.close_session(from_thread=False)

    def on_save(self):
        os.makedirs("transcripts", exist_ok=True)
        path = filedialog.asksaveasfilename(
            title="Save Transcript",
            defaultextension=".txt",
            initialdir="transcripts",
            filetypes=[("Text Files","*.txt"),("All Files","*.*")]
        )
        if not path:
            return
        try:
            content = self.txt.get("1.0", tk.END)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("Saved", f"Transcript saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    def close_session(self, from_thread: bool):
        if self.sess:
            try:
                if self.sess.sock:
                    try:
                        send_frame(self.sess.sock, {"type":"bye"})
                    except Exception:
                        pass
                    self.sess.sock.close()
            except Exception:
                pass
            self.sess = None
        # stop hosting listener
        if self.server:
            self.server.stop()
            self.server = None
        self.codes_verified = False
        self.var_safety.set("—")
        self.var_status.set("Idle.")
        if not from_thread:
            self.ui_log("[INFO] Disconnected.")

    def _guess_lan_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "Unknown"

if __name__ == "__main__":
    app = LanternApp()
    app.mainloop()

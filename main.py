*(Tkinter ships with CPython; on some Linux distros install `python3-tk`.)*

---

# `main.py` (full, updated)
```python
#!/usr/bin/env python3
"""
LanternChat — P2P Encrypted Chat + File Transfer (Tkinter GUI)

Crypto:
- Ephemeral X25519 key exchange (ECDH) over TCP
- HKDF-SHA256 -> 32-byte session key (salts from both peers, order-independent)
- Optional PSK (session passphrase) mixed into HKDF info
- AES-GCM(256) with random 12-byte nonce per message/chunk

Transport:
- One peer Hosts (listens), the other Connects (dials)
- Length-prefixed JSON frames (4-byte big-endian len + UTF-8 JSON object)
- Handshake: exchange {pubkey, salt}; compute shared key; show Safety Code

Extras:
- Delivery receipts (ACK) for chat messages
- Encrypted file transfer in chunks with progress and receive folder
- QR code popup for Safety Code (and optional IP:Port card)

This is a demo/reference app. Review before production use.
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
from dataclasses import dataclass
from tkinter import ttk, messagebox, filedialog
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# QR
import qrcode
from PIL import Image, ImageTk

APP_NAME = "LanternChat"
PROTOCOL_VERSION = 1
FRAME_HDR = "!I"  # 4-byte big-endian length
RECV_BUFSIZE = 65536

# File transfer
CHUNK_SIZE = 64 * 1024  # 64 KiB per encrypted chunk
DOWNLOAD_DIR = "downloads"

# ---------- util ----------
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
    # Order-independent salt concat
    salts = [saltA, saltB]
    salts.sort()
    salt = salts[0] + salts[1]
    # PSK mixed into info (hashed)
    info = b"LanternChat v1"
    if psk:
        h = hashes.Hash(hashes.SHA256())
        h.update(psk.encode("utf-8"))
        info += b" | PSK:" + h.finalize()
    hk = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    return hk.derive(shared)

def safety_code(pubA: bytes, pubB: bytes) -> str:
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
    msg_id_ctr: int = 1

# ---------- networking threads ----------
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
                    # Chat message
                    n = b64d(pkt["n"])
                    c = b64d(pkt["c"])
                    mid = pkt.get("id")
                    pt = self.sess.aes.decrypt(n, c, None).decode("utf-8", errors="replace")
                    self.app.enqueue_incoming(f"[Peer] {pt}")
                    # Send ACK
                    if mid is not None:
                        send_frame(self.sess.sock, {"type":"ack","id":mid})

                elif t == "ack":
                    mid = pkt.get("id")
                    if mid is not None:
                        self.app.mark_delivered(mid)

                elif t == "file_offer":
                    # Offer metadata
                    name = pkt["name"]
                    size = int(pkt["size"])
                    fid = pkt["fid"]
                    self.app.incoming_file_offer(fid, name, size)

                elif t == "file_chunk":
                    fid = pkt["fid"]
                    seq = int(pkt["seq"])
                    n = b64d(pkt["n"])
                    c = b64d(pkt["c"])
                    chunk = self.sess.aes.decrypt(n, c, None)
                    self.app.incoming_file_chunk(fid, seq, chunk)

                elif t == "file_done":
                    fid = pkt["fid"]
                    self.app.incoming_file_done(fid)

                elif t == "bye":
                    self.app.ui_log("[INFO] Peer closed the session.")
                    break

                else:
                    # unknown
                    continue

        except Exception as e:
            self.app.ui_log(f"[INFO] Receiver ended: {e}")
        finally:
            self.app.close_session(from_thread=True)

# ---------- GUI ----------
class LanternApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("920x600")
        self.resizable(True, True)

        # state
        self.server: Optional[HostServer] = None
        self.client: Optional[ClientConnector] = None
        self.sess: Optional[Session] = None
        self.incoming_q: queue.Queue[str] = queue.Queue()
        self.codes_verified = False
        self.pending_sends = {}   # msg_id -> "(sending)"
        # file rx state: fid -> dict(name, size, received, fh, chunks)
        self.rx_files = {}

        # ui vars
        self.var_host_ip = tk.StringVar()
        self.var_port = tk.StringVar(value="5005")
        self.var_pass = tk.StringVar()
        self.var_safety = tk.StringVar(value="—")
        self.var_status = tk.StringVar(value="Idle.")

        self._build_ui()
        self.after(100, self._poll_incoming)

    # ---- UI layout
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
        ttk.Button(btns, text="Show QR", command=self.on_show_qr).pack(side=tk.LEFT, padx=(8,0))

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
        ttk.Button(inputf, text="Send File", command=self.on_send_file).pack(side=tk.LEFT, padx=(8,0))
        ttk.Button(inputf, text="Save Transcript", command=self.on_save).pack(side=tk.LEFT, padx=(8,0))

    # ---- UI helpers
    def ui_log(self, line: str):
        self.txt.config(state=tk.NORMAL)
        ts = time.strftime("[%H:%M:%S] ")
        self.txt.insert(tk.END, ts + line + "\n")
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

    # ---- session lifecycle / handshake
    def establish_session(self, sock: socket.socket, addr, role: str, psk: Optional[str]):
        # Ephemeral keypair & salt
        priv = X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        salt_local = os.urandom(16)

        # client sends first
        if role == "client":
            send_frame(sock, {"type":"hello","v":PROTOCOL_VERSION,"pub":b64e(pub),"salt":b64e(salt_local)})
            srv_hello = recv_frame(sock)
            if srv_hello.get("type") != "hello":
                raise ValueError("unexpected server hello")
            peer_pub = b64d(srv_hello["pub"])
            salt_peer = b64d(srv_hello["salt"])
        else:
            cli_hello = recv_frame(sock)
            if cli_hello.get("type") != "hello":
                raise ValueError("unexpected client hello")
            peer_pub = b64d(cli_hello["pub"])
            salt_peer = b64d(cli_hello["salt"])
            send_frame(sock, {"type":"hello","v":PROTOCOL_VERSION,"pub":b64e(pub),"salt":b64e(salt_local)})

        shared = priv.exchange(X25519PublicKey.from_public_bytes(peer_pub))
        key = hkdf_key(shared, salt_local, salt_peer, psk)
        aes = AESGCM(key)

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
            self.ui_log(f"[INFO] Your LAN IP may be: {self._guess_lan_ip()}  (share with your peer)")
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

    # ---- messaging
    def next_msg_id(self) -> int:
        mid = self.sess.msg_id_ctr
        self.sess.msg_id_ctr += 1
        return mid

    def mark_delivered(self, mid: int):
        # Replace the placeholder text "(sending)" with "(delivered)".
        self.ui_log(f"[ACK] Message {mid} delivered.")

    def on_send(self):
        msg = self.var_msg.get()
        self.var_msg.set("")
        if not msg.strip():
            return
        if not self.sess or not self.sess.established:
            self.ui_log("[WARN] Not secure yet. Verify codes first.")
            return
        try:
            mid = self.next_msg_id()
            n = os.urandom(12)
            c = self.sess.aes.encrypt(n, msg.encode("utf-8"), None)
            pkt = {"type":"msg","id":mid,"n":b64e(n),"c":b64e(c)}
            send_frame(self.sess.sock, pkt)
            self.ui_log(f"[You] {msg}  (id={mid}, sending…)")  # simple status line
        except Exception as e:
            self.ui_log(f"[ERR] Send failed: {e}")
            self.close_session(from_thread=False)

    # ---- files
    def on_send_file(self):
        if not self.sess or not self.sess.established:
            messagebox.showwarning("Not secure", "Verify codes first.")
            return
        path = filedialog.askopenfilename(title="Select file to send")
        if not path:
            return
        try:
            size = os.path.getsize(path)
            name = os.path.basename(path)
            fid = f"{int(time.time())}-{os.urandom(4).hex()}"
            # Offer
            send_frame(self.sess.sock, {"type":"file_offer","fid":fid,"name":name,"size":size})
            self.ui_log(f"[FILE] Sending '{name}' ({size} bytes)…")

            with open(path, "rb") as f:
                seq = 0
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    n = os.urandom(12)
                    c = self.sess.aes.encrypt(n, chunk, None)
                    send_frame(self.sess.sock, {"type":"file_chunk","fid":fid,"seq":seq,"n":b64e(n),"c":b64e(c)})
                    seq += 1
            send_frame(self.sess.sock, {"type":"file_done","fid":fid})
            self.ui_log(f"[FILE] '{name}' sent.")
        except Exception as e:
            self.ui_log(f"[ERR] File send failed: {e}")

    def incoming_file_offer(self, fid: str, name: str, size: int):
        os.makedirs(DOWNLOAD_DIR, exist_ok=True)
        safe_name = self._safe_filename(name)
        out_path = os.path.join(DOWNLOAD_DIR, safe_name)
        # Prevent overwrite
        base, ext = os.path.splitext(out_path)
        i = 1
        while os.path.exists(out_path):
            out_path = f"{base}({i}){ext}"
            i += 1
        fh = open(out_path, "wb")
        self.rx_files[fid] = {"name":safe_name, "size":size, "received":0, "fh":fh, "chunks":{}}
        self.ui_log(f"[FILE] Incoming '{safe_name}' ({size} bytes)…")

    def incoming_file_chunk(self, fid: str, seq: int, data: bytes):
        info = self.rx_files.get(fid)
        if not info:
            return
        # Simple in-order write; buffer out-of-order
        if seq == info["chunks"].get("next_seq", 0):
            # write now
            info["fh"].write(data)
            info["received"] += len(data)
            info["chunks"]["next_seq"] = seq + 1
            # flush any buffered ahead
            while info["chunks"].get(info["chunks"]["next_seq"]):
                buf = info["chunks"].pop(info["chunks"]["next_seq"])
                info["fh"].write(buf)
                info["received"] += len(buf)
                info["chunks"]["next_seq"] += 1
        else:
            # buffer for later
            info["chunks"][seq] = data

        self.ui_log(f"[FILE] Receiving… {info['received']}/{info['size']} bytes")

    def incoming_file_done(self, fid: str):
        info = self.rx_files.get(fid)
        if not info:
            return
        try:
            info["fh"].close()
        except Exception:
            pass
        self.ui_log(f"[FILE] Received '{info['name']}' ({info['received']} bytes) -> {DOWNLOAD_DIR}/")
        del self.rx_files[fid]

    # ---- QR & transcript
    def on_show_qr(self):
        # Show QR with Safety Code (and, if hosting, hint for IP:Port)
        code = self.var_safety.get()
        if not code or code == "—":
            messagebox.showinfo("QR", "Safety Code is not ready yet.")
            return

        text = f"{APP_NAME} Safety Code:\n{code}"
        # Add connection hint (non-sensitive)
        host_hint = ""
        if self.server:
            host_hint = f"\nHost Port: {self.var_port.get().strip()}\nLAN IP: {self._guess_lan_ip()}"
        qr_data = f"LanternChat|code={code}|port={self.var_port.get().strip()}|ip={self._guess_lan_ip()}"

        img = qrcode.make(qr_data)
        top = tk.Toplevel(self)
        top.title("Safety Code (QR)")
        top.geometry("320x380")
        lbl = ttk.Label(top, text=text)
        lbl.pack(pady=6)
        img = img.resize((280, 280))
        tkimg = ImageTk.PhotoImage(img)
        panel = ttk.Label(top, image=tkimg)
        panel.image = tkimg
        panel.pack(pady=6)
        if host_hint:
            ttk.Label(top, text=host_hint, foreground="gray").pack()

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

    # ---- teardown
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
        if self.server:
            self.server.stop()
            self.server = None
        self.codes_verified = False
        self.var_safety.set("—")
        self.var_status.set("Idle.")
        if not from_thread:
            self.ui_log("[INFO] Disconnected.")

    # ---- util
    def _guess_lan_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "Unknown"

    def _safe_filename(self, name: str) -> str:
        keep = "-_.()abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        cleaned = "".join(c if c in keep else "_" for c in name)
        return cleaned or f"file_{int(time.time())}"

if __name__ == "__main__":
    app = LanternApp()
    app.mainloop()

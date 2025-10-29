# peer-to-peer-encrypted-chat-app
# LanternChat — Peer-to-Peer Encrypted Chat (GUI)

**LanternChat** is a tiny, serverless, peer-to-peer chat app.  
Two users connect directly via IP/port, derive a shared key using **X25519** (ECDH), verify a short **safety code**, and then chat using **AES-GCM** end-to-end encryption. No cloud, no accounts.

> ⚠️ NAT note: If peers are not on the same LAN/Wi-Fi, the host will likely need to forward a TCP port on their router (or use a VPN). There is no relay server.

## Features
- **No server**: direct TCP between two devices.
- **Strong crypto**: X25519 key exchange → HKDF-SHA256 → 256-bit AES-GCM.
- **Safety code**: both sides see the same short code if there is no MITM.
- **Optional passphrase**: bind the session to a shared secret for extra protection.
- **Simple GUI**: host/connect, send/receive, save transcript (local, optional).
- **Cross-platform**: Python + Tkinter.
update 
# LanternChat — P2P Encrypted Chat (GUI)

Serverless peer-to-peer chat & file transfer with end-to-end encryption.

## What’s inside
- No server: one peer clicks **Host**, the other **Connects** by IP:Port.
- X25519 ECDH → HKDF-SHA256 → AES-GCM(256) encryption per message.
- **Safety Code** verification (word-by-word/QR) to detect MITM.
- **Encrypted file transfer** (chunked) with progress & receipts.
- Optional **Session Passphrase (PSK)** mixed into key derivation.
- GUI built with Tkinter (cross-platform).

> NAT note: If you’re not on the same LAN, host needs port forwarding or use a VPN.

## Quick Start
```bash
git clone https://github.com/<your-username>/lanternchat.git
cd lanternchat
python -m venv venv
# Windows: venv\Scripts\activate
source venv/bin/activate
pip install -r requirements.txt
python main.py


## Quick Start
```bash
git clone https://github.com/<your-username>/lanternchat.git
cd lanternchat
python -m venv venv
# Windows: venv\Scripts\activate
source venv/bin/activate
pip install -r requirements.txt
python main.py
How to Use
On one device (the host):

Open the app → set a Port (e.g., 5005) → optionally set a Session Passphrase → click Host.

Share your IP and Port with your friend (and the passphrase if you set one).

On the other device (the joiner):

Enter the host’s IP and Port, the same Session Passphrase if used, then click Connect.

Verify Safety Code:

Both apps will display a short Safety Code (e.g., 7F-BC-1A-30).

Confirm the codes match via phone/voice/video.

Click Codes Match to unlock chatting. (If they don’t match, disconnect.)

Chat:

Type messages and press Enter or Send.

Use Save Transcript to export the current chat to a local text file.

Security Design
Key exchange: Ephemeral X25519 (each session) over TCP; peers exchange public keys and random salts.

Key derivation: HKDF-SHA256 with combined salts (order-independent) and optional PSK (passphrase) mixed into the info.

Encryption: AES-GCM (256-bit) with a fresh 96-bit nonce per message.

Authentication: GCM tag ensures integrity; a Safety Code (hash of both public keys in canonical order) helps humans detect MITM.

No storage: Keys live in memory only; passphrase is not stored.

Limitations / Notes
No NAT traversal; use port forwarding / VPN if needed.

Safety code verification is manual (like Signal’s safety number).

This is a demo/reference app; do your own review before production use.

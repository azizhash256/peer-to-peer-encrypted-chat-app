# peer-to-peer-encrypted-chat-app

# PeerTalk — P2P Encrypted Chat (No Server, GUI)

**PeerTalk** is a tiny peer-to-peer chat app with end-to-end encryption and a simple Tkinter GUI.  
There’s **no central server**: one peer clicks **Host** (listens on a port), the other **Connects** using the host’s IP:port. Both enter the same **Room Code** (a shared secret) and chat.

## Crypto design (high level)
- **Key agreement:** Ephemeral **X25519** (ECDH)
- **Key derivation:** **HKDF-SHA256** deriving a 32-byte session key
- **AEAD:** **AESGCM** (AES-256-GCM) with 12-byte nonces
- **Integrity:** AEAD provides authenticity; we also include a **SHA-256** hash of the plaintext in the message body (auditable)
- **SAS / Fingerprint:** Both peers see a short verification string derived from both public keys + Room Code. Compare verbally to detect MITM.

> ⚠️ NAT note: peers must be able to reach each other by IP:port. This works on the same LAN, via VPN, or with port forwarding. No TURN/STUN is included.

## Features
- P2P, no server
- GUI (Tkinter), single file run
- ECDH handshake → AES-GCM session
- Unique per-message nonces (counter with random prefix)
- Message SHA-256 included for auditing
- SAS fingerprint check to verify peers
- Light, dependency-minimal

## Quick start
`bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py
How to use
Both users agree a Room Code (shared secret string).

One user clicks Host, chooses a port (e.g., 7777), and tells their IP:port to the other.

The other user enters the host’s IP and port and clicks Connect.

Both will see a Fingerprint value. Compare out-of-band (voice/message). If they match, your session is safe.

Start chatting.

Troubleshooting
If the connection fails, check firewalls and NAT. On LAN, use the local IP of the host machine (e.g., 192.168.1.20).

If fingerprints don’t match, do not continue—you may be under MITM.

Security notes
Without a trusted directory or public-key pinning, P2P ECDH is susceptible to MITM unless users verify the Fingerprint. Always compare it.

Room Code strengthens authentication of the handshake (used in HKDF/SAS inputs).

AES-GCM requires unique nonces per session key; this app uses a random prefix + monotonic counter to avoid reuse.

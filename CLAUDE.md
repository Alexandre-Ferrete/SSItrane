# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SSItrane is a secure end-to-end encrypted (E2EE) P2P chat system built for a university Systems Security course (2025/2026). It uses a hybrid architecture: a central server handles authentication, PKI, and directory lookups, but messages are sent directly peer-to-peer — the server never sees plaintext.

## Commands

**Install dependencies:**
```bash
pip install -r requirements.txt
```

**Start server (from `src/`):**
```bash
python -m server.server --host 0.0.0.0 --port 5555
# Server key password: "server"
```

**Start client (from `src/`):**
```bash
python -m client.client --host localhost --port 5555 --username alice
```

**Run tests (from repo root):**
```bash
python run_tests.py          # Core unit tests
python run_p2p_test.py       # P2P connection tests
python run_offline_test.py   # Offline messaging tests
```

## Architecture

### Network Model

- **Server** (port 5555, async TCP): Directory service and CA. Handles registration, authentication, key distribution, and offline message storage. Does NOT relay live messages.
- **Clients** (P2P port 6767, threaded TCP): Connect to server for auth/lookup; connect directly to each other for encrypted messaging.

### Key Components

**`src/server/`**
- `server.py` — async event loop, CLI, startup
- `tcp_handler.py` — per-client connection state machine; all server-side protocol logic lives here
- `user_manager.py` — in-memory online user directory (protected by `asyncio.Lock`)
- `storage.py` — SQLite persistence for users and offline messages (protected by `threading.Lock`)
- `message_router.py` — routes messages to online users or queues for offline delivery
- `server_keys_generator.py` — CA key generation and X.509 certificate issuance

**`src/client/`**
- `client.py` — connects to server, spawns P2P listener thread, CLI command loop
- `session_manager.py` — owns all cryptographic state: key pairs, ratchet counters, session keys

**`src/crypto/`**
- `symmetric.py` — AES-256-GCM encrypt/decrypt primitives
- `hybrid.py` — ECDH (X25519) + AES-GCM hybrid encryption (used for offline messages)

**`src/protocol/messages.py`** — `MessageType` enum and message serialization. Add new message types here first.

**`src/utils/helpers.py`** — base64 encoding helpers, logging setup.

### Cryptographic Design

**Client-Server channel:** X25519 handshake at connect time, then a hash ratchet advances the symmetric key after every message (AES-256-GCM).

**P2P channel:** Ephemeral X25519 key exchange per session; a salt ratchet advances the key every ~10 messages (Perfect Forward Secrecy). Both sides authenticate via Ed25519 signatures over their X.509 certificates issued by the server CA.

**Offline messages:** Ephemeral-static ECDH — sender uses a fresh ephemeral key + recipient's long-term public key to encrypt. Server stores the ciphertext blob without being able to decrypt it.

**PKI:** Server acts as CA. On registration, it signs each user's Ed25519 public key in an X.509 certificate. P2P connections validate each other's certificates against the server's root cert.

### Security Model

- Threat model: "honest but curious" server — trusted for routing/auth, untrusted for confidentiality.
- Server sees: who is online, who talks to whom, message timing and sizes.
- Server does NOT see: message content, even for offline messages.

### Adding a New Protocol Message

1. Add the `MessageType` to `src/protocol/messages.py`.
2. Handle it in `ClientHandler` in `src/server/tcp_handler.py`.
3. Add the send path in `src/client/client.py` and any key-management side effects in `src/client/session_manager.py`.

### Concurrency Notes

- Server is fully `asyncio`; use `await` and `asyncio.Lock` for shared server state.
- The client runs a background `threading.Thread` for the P2P listener; use `threading.Lock` when accessing shared client state from both threads.
- `Storage` uses its own `threading.Lock` because SQLite is called from both the async server and background threads.

## Logs & Defaults

- Server logs: `src/logs/server.log`
- Client output: stdout
- Default ports: server `5555`, P2P `6767`
- Server key encryption password: `"server"`

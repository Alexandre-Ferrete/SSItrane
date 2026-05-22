# Work Division - Secure E2EE Chat System (P2P)

## Project Overview
- **Course:** System Security Project 2025/2026
- **Deadline:** May 24, 2026
- **Architecture:** Hybrid Client-Server + P2P messaging

---

## Team Division (3 People)

---

### Person 1: Server Core

**Responsibility:** Server infrastructure, user management with IP tracking, persistence, and P2P coordination.

| File | Description |
|------|-------------|
| `server/server.py` | Main server, TCP accept loop, admin CLI |
| `server/tcp_handler.py` | Client connection handling, GET_IP handling |
| `server/user_manager.py` | User registration/authentication, User->IP mapping |
| `server/storage.py` | Persistence layer (SQLite) |
| `server/message_router.py` | P2P coordination, room management |
| `server/ca.py` | Certificate Authority |

**Key Features to Implement:**
- TCP socket server with threading
- User registration and authentication
- User->IP mapping storage on login
- IP lookup service (GET_IP command)
- Message routing (direct + rooms)
- Admin CLI commands

---

### Person 2: Client & Protocol

**Responsibility:** Client application, CLI interface, P2P connections, and communication protocol.

| File | Description |
|------|-------------|
| `client/client.py` | TCP client, P2P listener, message send/receive |
| `client/cli.py` | Command interpreter |
| `client/session_manager.py` | Key storage, session management |
| `protocol/messages.py` | Message type definitions |
| `protocol/commands.py` | Command parsing |

**Key Features to Implement:**
- TCP client connection to server
- P2P listener for incoming connections
- User authentication flow
- IP request to server -> direct P2P connection
- Send/receive encrypted messages via P2P
- CLI command parser
- Session key management

---

### Person 3: Cryptography

**Responsibility:** All cryptographic primitives and security mechanisms.

| File | Description |
|------|-------------|
| `crypto/ecdh.py` | Ephemeral key exchange (PFS) |
| `crypto/symmetric.py` | AES-GCM encryption |
| `crypto/hybrid.py` | Hybrid encryption wrapper |
| `crypto/certificates.py` | X.509 certificate handling |
| `crypto/signatures.py` | ECDSA digital signatures |
| `crypto/asymmetric.py` | RSA encryption (if needed) |
| `utils/helpers.py` | Encoding, hashing, logging |

**Key Features to Implement:**
- ECDH key exchange for Perfect Forward Secrecy
- AES-256-GCM symmetric encryption
- X.509 certificate generation and validation
- ECDSA digital signatures
- Hybrid encryption (ECDH + AES-GCM)
- HKDF key derivation

---

## Communication Flow (P2P)

```
User A Login:
  1. Connect to server
  2. Authenticate
  3. Server stores A's IP (from connection)

User A -> User B message:
  1. A requests B's IP via GET_IP to server
  2. Server returns B's IP (if online)
  3. A connects directly to B (P2P)
  4. A and B perform ECDH handshake
  5. Messages encrypted E2E, sent directly
```

---

## Grading Breakdown (Reference)

| Component | Weight |
|-----------|--------|
| Security | 35% |
| Functionality | 25% |
| Valorizações (Advanced Features) | 25% |
| Report | 15% |

---

## Shared Dependencies

All team members need to coordinate on:
1. **Protocol format:** `[4 bytes length][JSON payload]`
2. **Message types:** Consistent between client/server
3. **GET_IP protocol:** Server returns IP for online users
4. **P2P handshake:** ECDH-based key exchange

---

## File Structure Reference

```
src/
├── server/
│   ├── server.py          # Person 1
│   ├── tcp_handler.py     # Person 1
│   ├── user_manager.py    # Person 1 (with IP tracking)
│   ├── storage.py         # Person 1
│   ├── message_router.py # Person 1
│   └── ca.py             # Person 1
├── client/
│   ├── client.py          # Person 2 (with P2P)
│   ├── cli.py             # Person 2
│   └── session_manager.py # Person 2
├── crypto/
│   ├── ecdh.py            # Person 3
│   ├── symmetric.py      # Person 3
│   ├── hybrid.py         # Person 3
│   ├── certificates.py   # Person 3
│   ├── signatures.py     # Person 3
│   └── asymmetric.py    # Person 3
├── protocol/
│   ├── messages.py       # Person 2
│   └── commands.py       # Person 2
└── utils/
    └── helpers.py        # Person 3
```

---

## Notes

- **Person 1** adds IP tracking to user management
- **Person 2** adds P2P connection handling to client
- **Person 3** (Cryptography) has the most security-critical code
- All three persons should test their modules independently first
- Integration testing should be done once each person completes their core modules

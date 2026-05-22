# Secure E2EE Chat System

**Course:** System Security Project  
**Academic Year:** 2025/2026  
**Deadline:** May 24, 2026

---

## 1. Architecture

### 1.1 System Overview

This is a secure End-to-End Encrypted (E2EE) chat system implemented in Python using the `cryptography` library. The system follows a **hybrid client-server/P2P architecture**:

- **Server**: Acts as a directory service, managing user registration and providing IP addresses for P2P connections
- **Clients**: Connect directly to each other for messaging (P2P), with E2EE encryption

### 1.2 Components

```
┌─────────────────────────────────────────────────────────────────┐
│                         Server                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │ User Mgmt   │  │   PKI/CA    │  │  IP Directory          │ │
│  │ - Register  │  │ - Certs     │  │  - User -> IP mapping │ │
│  │ - Login     │  │ - Validation│  │  - Online status      │ │
│  │ - Online    │  │ - Revocation│  │  - P2P coordination    │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                    │                │
          IP Lookup │                │ Direct P2P
                    ▼                ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Client A                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │  CLI UI     │  │  Crypto     │  │ P2P Connection        │ │
│  │ - Commands  │  │ - E2EE      │  │ - Direct to Peer       │ │
│  │ - Input     │  │ - ECDH      │  │ - Listen on port       │ │
│  │ - Display   │  │ - AES-GCM   │  │ - Message handling     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                               │
                         P2P TCP
                               │
┌─────────────────────────────────────────────────────────────────┐
│                         Client B                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │  CLI UI     │  │  Crypto     │  │ P2P Connection        │ │
│  │ - Commands  │  │ - E2EE      │  │ - Direct to Peer       │ │
│  │ - Input     │  │ - ECDH      │  │ - Listen on port       │ │
│  │ - Display   │  │ - AES-GCM   │  │ - Message handling     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### 1.3 Communication Flow

#### Registration Phase
1. Client connects to server via TCP
2. Client requests CA certificate from server
3. Client generates EC keypair (SECP256R1)
4. Client creates self-signed certificate
5. Client sends registration request with public key and certificate
6. Server validates certificate and stores user

#### P2P Connection Setup
1. Client A wants to message Client B
2. Client A requests B's IP from server (via GET_IP command)
3. Server returns B's IP address if B is online
4. Client A connects directly to Client B via P2P TCP socket
5. Both clients perform ECDH key exchange
6. Derived shared secret is used for AES-GCM encryption

#### Messaging (P2P)
1. Sender encrypts message using hybrid encryption (ECDH + AES-GCM)
2. Encrypted blob sent directly to recipient via P2P connection
3. Recipient decrypts using their private key and ephemeral public key
4. Server is not involved in message transmission

---

## 2. Security Model

### 2.1 Cryptographic Primitives

| Primitive | Algorithm | Purpose |
|-----------|-----------|---------|
| Key Exchange | ECDH (SECP256R1) | Perfect Forward Secrecy |
| Digital Signature | ECDSA (SHA-256) | Authentication |
| Symmetric Encryption | AES-256-GCM | Data confidentiality |
| Key Derivation | HKDF-SHA256 | Key material derivation |
| Certificate Format | X.509 (PEM) | Identity management |

### 2.2 Security Guarantees

#### Confidentiality
- All messages are encrypted end-to-end using AES-256-GCM
- The server never sees plaintext messages
- Only the intended recipient can decrypt messages

#### Integrity
- AES-GCM provides authenticated encryption
- Any tampering is detected during decryption

#### Authenticity
- X.509 certificates issued by internal CA
- ECDSA signatures verify message sender
- Certificate fingerprint verification

#### Perfect Forward Secrecy (PFS)
- Each message uses ephemeral ECDH keypairs
- Compromise of long-term keys does not expose past messages

### 2.3 Threat Mitigation

#### Man-in-the-Middle (MitM) Protection
- Certificate validation against trusted CA
- Fingerprint verification for key exchange
- Signed message envelopes

#### Metadata Protection
- Server only sees encrypted blobs
- No message content metadata stored
- Group membership is minimal

---

## 3. Features

### 3.1 Core Features

1. **User Registration/Login**
   - Username-based identity
   - X.509 certificate authentication

2. **Direct Messaging**
   - E2EE using hybrid encryption
   - Perfect Forward Secrecy via ECDH

3. **Group Chat**
   - Group creation and management
   - Group key distribution
   - Secure multi-user messaging

4. **Offline Messaging**
   - Store-and-forward mechanism
   - Encrypted blob storage
   - Automatic delivery on login

### 3.2 Advanced Features (Valorizações)

1. **Internal PKI**
   - Self-signed Certificate Authority
   - Certificate issuance and validation
   - Certificate revocation support

2. **Perfect Forward Secrecy**
   - Ephemeral key exchange (ECDH)
   - Session-specific keys

3. **Hybrid Encryption**
   - Asymmetric (ECDH) for key encapsulation
   - Symmetric (AES-GCM) for data transport

4. **Group Key Management**
   - Group key generation and distribution
   - Member access control

---

## 4. Limitations

### 4.1 Inherent Weaknesses

1. **Server as Directory**
   - Server only stores IPs, not messages (improved privacy)
   - But server knows who is communicating with whom
   - No message content stored, only metadata

2. **Key Storage**
   - Private keys stored in memory only (lost on disconnect)
   - No secure key derivation from passwords

3. **Metadata Exposure**
   - Usernames visible to server
   - Connection timing patterns
   - IP addresses of online users visible

4. **No Forward Secrecy for Groups**
   - Group keys are static until re-created
   - New members can receive past group messages (if stored)

5. **Denial of Service**
   - No rate limiting
   - No message size limits

### 4.2 Implementation Limitations

1. **No Persistence**
   - Messages not persisted to disk
   - User sessions lost on restart

2. **Single Session**
   - Multiple sessions per user not supported

3. **No Key Escrow**
   - Lost keys cannot be recovered

---

## 5. Future Work

### 5.1 Potential Improvements

1. **Enhanced PKI**
   - Hierarchical CA structure
   - Certificate revocation checking (OCSP)
   - Certificate transparency logs

2. **Password-Based Key Derivation**
   - PBKDF2/Argon2 for key hardening
   - Password-protected private keys

3. **Double Ratchet Algorithm**
   - Forward secrecy for group messages
   - Post-compromise security

4. **File Transfer**
   - Encrypted file sharing
   - Chunked transfer

5. **Multi-Device Support**
   - Device key registration
   - Cross-device synchronization

6. **Message Authentication**
   - Read receipts
   - Typing indicators

7. **Server Improvements**
   - Database persistence
   - Message search (encrypted indices)
   - Rate limiting

---

## 6. Usage

### 6.1 Installation

```bash
pip install -r requirements.txt
```

### 6.2 Running the Server

```bash
cd src
python -m server.server --host 0.0.0.0 --port 5555
```

### 6.3 Running the Client

```bash
cd src
python -m client.client --host localhost --port 5555 --username alice
```

### 6.4 Client Commands

#### Pre-login Commands
| Command | Description |
|---------|-------------|
| `register <username> <password>` | Create new account |
| `login <username> <password>` | Login to account |
| `help` | Show help |
| `exit` | Disconnect and exit |

#### Post-login Commands
| Command | Description |
|---------|-------------|
| `msg <username> <message>` | Send P2P message to user |
| `connect <username>` | Request IP and connect P2P |
| `users` | List online users |
| `rooms` | List available rooms |
| `create_room <name>` | Create new room |
| `join <room_name>` | Join a room |
| `leave <room_name>` | Leave a room |
| `history` | View message history |
| `whoami` | Show current user info |
| `logout` | Logout |
| `help` | Show help |
| `exit` | Disconnect and exit |

### 6.5 Server Admin Commands
| Command | Description |
|---------|-------------|
| `start` | Start the server |
| `stop` | Stop the server |
| `status` | Show server status |
| `users` | List all registered users |
| `online` | List online users |
| `rooms` | List active rooms |
| `stats` | Show statistics |
| `ban <username>` | Ban a user |
| `unban <username>` | Unban a user |
| `help` | Show help |
| `exit` | Exit admin interface |

---

## 7. File Structure

```
ProjetoSingle/
├── work.md                 # Project requirements
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── src/
│   ├── __init__.py
│   ├── server/            # Server implementation
│   │   ├── __init__.py
│   │   ├── server.py      # Main server + admin CLI
│   │   ├── tcp_handler.py # Client connection handling
│   │   ├── user_manager.py # User auth/IP management
│   │   ├── storage.py     # Persistence layer
│   │   ├── message_router.py # P2P coordination
│   │   └── ca.py          # Certificate Authority
│   │
│   ├── client/            # Client implementation
│   │   ├── __init__.py
│   │   ├── client.py     # TCP client + P2P listener
│   │   ├── cli.py        # Command interpreter
│   │   └── session_manager.py # Key management
│   │
│   ├── crypto/            # Cryptographic primitives
│   │   ├── __init__.py
│   │   ├── asymmetric.py  # RSA encryption
│   │   ├── ecdh.py       # ECDH key exchange (PFS)
│   │   ├── symmetric.py  # AES-GCM encryption
│   │   ├── hybrid.py     # Hybrid encryption
│   │   ├── certificates.py # X.509 certificates
│   │   └── signatures.py  # Digital signatures
│   │
│   ├── protocol/          # Communication protocol
│   │   ├── __init__.py
│   │   ├── messages.py   # Message types
│   │   └── commands.py   # Command parsing
│   │
│   └── utils/             # Shared utilities
│       ├── __init__.py
│       └── helpers.py    # Encoding, hashing, logging
│
└── data/                  # Runtime data (generated)
    ├── server.db         # SQLite database
    └── keys/             # CA keys and certificates
```
ProjetoSingle/
├── work.md                 # Project requirements
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── src/
│   ├── __init__.py
│   ├── server/            # Server implementation
│   │   ├── __init__.py
│   │   ├── server.py      # Main server + admin CLI
│   │   ├── tcp_handler.py # TCP connection handling
│   │   ├── user_manager.py # User auth/registration
│   │   ├── ca.py          # Certificate Authority
│   │   ├── storage.py     # Persistence layer
│   │   └── message_router.py # Message routing
│   │
│   ├── client/            # Client implementation
│   │   ├── __init__.py
│   │   ├── client.py     # TCP client
│   │   ├── cli.py        # Command interpreter
│   │   └── session_manager.py # Key management
│   │
│   ├── crypto/            # Cryptographic primitives
│   │   ├── __init__.py
│   │   ├── asymmetric.py  # RSA encryption
│   │   ├── ecdh.py       # ECDH key exchange (PFS)
│   │   ├── symmetric.py  # AES-GCM encryption
│   │   ├── hybrid.py     # Hybrid encryption
│   │   ├── certificates.py # X.509 certificates
│   │   └── signatures.py  # Digital signatures
│   │
│   ├── protocol/          # Communication protocol
│   │   ├── __init__.py
│   │   ├── messages.py   # Message types
│   │   └── commands.py   # Command parsing
│   │
│   └── utils/             # Shared utilities
│       ├── __init__.py
│       └── helpers.py    # Encoding, hashing, logging
│
└── data/                  # Runtime data (generated)
    ├── server.db         # SQLite database
    └── keys/             # CA keys and certificates
```

---

## 8. Protocol Specification

### 8.1 Message Format

All messages use a length-prefixed protocol over TCP:

```
[4 bytes: length (big-endian)][N bytes: JSON message]
```

### 8.2 Message Types

#### Client -> Server
| Message Type | Description |
|--------------|-------------|
| `register` | User registration with public key |
| `auth` | User authentication |
| `get_ip` | Request IP address of a user for P2P connection |
| `create_room` | Create new chat room |
| `join_room` | Join existing room |
| `leave_room` | Leave room |
| `get_users` | Request online users list |
| `get_rooms` | Request rooms list |
| `get_offline` | Request offline messages |
| `disconnect` | Clean disconnect |

#### Server -> Client
| Message Type | Description |
|--------------|-------------|
| `register_response` | Registration result |
| `auth_response` | Authentication result |
| `ip_response` | IP address response for P2P connection |
| `chat_response` | Message delivery status |
| `message` | Incoming direct message (via P2P) |
| `room_message` | Incoming room message |
| `user_online` | User came online notification |
| `user_offline` | User went offline notification |
| `room_created` | Room created confirmation |
| `room_joined` | Room joined confirmation |
| `room_left` | Room left confirmation |
| `users_list` | List of online users |
| `rooms_list` | List of available rooms |
| `offline_messages` | Queued offline messages |
| `error` | Error response |
| `success` | Generic success response |

---

## 9. Security Analysis

### 9.1 Attack Vectors

| Attack | Protection |
|--------|------------|
| Eavesdropping | AES-256-GCM encryption |
| MitM | Certificate validation, ECDH |
| Replay | Timestamps, nonces |
| Tampering | GCM authentication tag |
| Impersonation | Certificate verification |

### 9.2 Security Properties

- **Confidentiality**: Only recipient can decrypt
- **Integrity**: Tampering detected
- **Authentication**: Verified via certificates
- **Forward Secrecy**: Ephemeral keys per session
- **Non-repudiation**: ECDSA signatures

---

*Generated for System Security Project 2025/2026*

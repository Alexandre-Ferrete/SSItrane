# Architecture & Security Specification

## 1. System Overview
This project implements a secure, decentralized Peer-to-Peer (P2P) chat application with a Server-Mediated architecture for routing, presence, and offline message storage. The architecture is divided into two primary communication channels:
1. **Client-Server (C-S) Channel**: Used for authentication, discovering peers, and storing/retrieving offline messages.
2. **Client-Client (P2P) Channel**: Used for direct, low-latency, end-to-end encrypted messaging between online users.

## 2. Cryptographic Primitives & Algorithms

### Why these specific algorithms?
- **Ed25519 (Digital Signatures)**: Chosen for identity verification. It is significantly faster and more secure against side-channel attacks than legacy algorithms like RSA or ECDSA.
- **X25519 / ECDH (Key Exchange)**: Elliptic Curve Diffie-Hellman over Curve25519 is the modern standard for establishing shared secrets. It provides Perfect Forward Secrecy (PFS) by using ephemeral keys that are discarded after use.
- **AES-GCM 256-bit (Symmetric Encryption)**: An Authenticated Encryption with Associated Data (AEAD) cipher. It was chosen over AES-CBC because GCM simultaneously guarantees both confidentiality and data integrity/authenticity (via the auth tag), preventing ciphertext malleability attacks.
- **HKDF (Key Derivation)**: Used to derive cryptographically strong session keys from the raw ECDH shared secrets.
- **PBKDF2-HMAC-SHA256 (Password Hashing)**: Used to derive a Key Encryption Key (KEK) from the user's password to securely wrap their private keys on local disk storage.

---

## 3. Key Architectural Decisions

### 3.1. Server as a Certificate Authority (CA)
**Decision**: Instead of clients blindly trusting self-signed public keys, the Server acts as a Certificate Authority. During registration, the server signs the client's Ed25519 public key.
**Why**: This prevents Man-in-the-Middle (MITM) attacks. When Alice connects to Bob via P2P, she verifies Bob's certificate against the hardcoded `ca_public.key`. This centralized trust model ensures that an attacker cannot impersonate Bob by simply generating a new keypair.

### 3.2. Hybrid Encryption
**Decision**: The system uses a combination of Asymmetric cryptography (ECDH) for key exchange and Symmetric cryptography (AES-GCM) for data encryption.
**Why**: Asymmetric cryptography is computationally expensive and has strict data size limits (cannot encrypt large files/messages directly). Symmetric cryptography is extremely fast and can encrypt streams of data, but requires both parties to safely share a key.
* **Pros**: 
  - Extremely fast and scalable data transfer (AES is hardware-accelerated on most CPUs).
  - Solves the key-distribution problem (ECDH securely creates the shared AES key over an insecure channel).
  - Enables Perfect Forward Secrecy (by using one-time ephemeral asymmetric keys).
* **Cons**:
  - Implementation complexity (requires managing multiple key types, KDFs, nonces, and tags).
  - Requires robust random number generators for Nonces/Ephemeral keys.

### 3.3. Dual Ratcheting Systems
**Decision**: We implemented two different ratcheting mechanisms for the two different channels.
1. **Continuous Hash Ratchet (Client-Server)**: 
   - The initial C-S session key is split into independent `tx_key` (Transmit) and `rx_key` (Receive).
   - After *every* single packet, the keys are hashed (`HKDF`) to create the next key.
   - **Why**: TCP is full-duplex. Using independent, continuously updating keys prevents race conditions (Alice and Server sending at the exact same millisecond) and ensures that compromising a key today doesn't compromise the commands sent 5 minutes ago.
2. **Interval Salt Ratchet (P2P)**:
   - Every 10 messages, clients exchange a new random 16-byte salt, sign it with their Identity Key, and derive a new AES session key.
   - **Why**: Limits the amount of data encrypted under a single AES key, mitigating cryptanalysis.

### 3.4. Offline Messaging via Ephemeral-Static ECDH
**Decision**: For offline users, the sender generates a one-time (ephemeral) X25519 key, performs ECDH with the recipient's long-term (static) X25519 key, and sends the ciphertext + ephemeral public key to the server.
**Why**: This guarantees End-to-End Encryption (E2EE) even when routed through the server. The server only sees ciphertext and public keys; it cannot derive the AES key. 
**Rotation**: To limit exposure, the static X25519 key is rotated every time the user logs in.

---

## 4. Evolution of the System (Recent Upgrades)

During the development process, the system underwent a major security overhaul to move from a "Functional Prototype" to a "Security-First Architecture." The key evolutions were:

### 4.1. From Plaintext to Ratcheted C-S Tunnel
*   **Initial State**: Commands like `/login` and `/register` sent sensitive data (including hashed passwords) in plaintext JSON over the network.
*   **Upgrade**: Implemented a mandatory X25519/Ed25519 handshake upon connection. All system traffic is now wrapped in a bidirectional AES-GCM tunnel with a continuous hash ratchet.

### 4.2. Server transformed into a Certificate Authority (CA)
*   **Initial State**: Clients used self-signed certificates, which were vulnerable to MITM attacks since there was no way to verify if a public key actually belonged to the claimed user.
*   **Upgrade**: The Server now acts as a CA. It signs client public keys during registration. Clients now verify peer identities using the Server's master public key (`ca_public.key`), establishing a "Circle of Trust."

### 4.3. Secured Offline Messaging (Zero-Knowledge)
*   **Initial State**: Offline messages were either insecure or relied on the server to handle the encryption keys (Server-Mediated).
*   **Upgrade**: Implemented Ephemeral-Static ECDH. The server now only stores encrypted blobs and ephemeral public keys. It has zero knowledge of the message content or the session keys.
*   **Rotation**: Added "Option A" rotation, where a user's static encryption key is replaced every time they log in to minimize the impact of long-term key theft.

### 4.4. Atomic P2P Ratchet Handshake
*   **Initial State**: The P2P key rotation was prone to race conditions where one party would update their key while the other was still using the old one, leading to "Invalid Tag" errors.
*   **Upgrade**: Refactored the ratchet into a synchronized 2-step handshake. Keys are only "committed" once both parties have confirmed receipt of the new salt contributions.

---

## 5. Technical Debt (Problems to Work On)

While the cryptography is solid, the software architecture has several structural problems that should be addressed in future refactoring:
1. **Blocking Database Calls**: `sqlite3` is synchronous. Under heavy load, database queries in `storage.py` will block the `asyncio` event loop in the Server, causing latency spikes for all connected clients. A library like `aiosqlite` should be adopted.
2. **In-Memory State Management**: The server tracks online users in a Python dictionary. This prevents the server from scaling horizontally (e.g., running multiple server instances behind a load balancer).
3. **P2P Socket Error Handling**: Currently, if a P2P socket drops, the client falls back to sending the message to the server for offline storage. However, there is no robust queue system to ensure message ordering or delivery guarantees if a socket drops mid-transmission.
4. **Lack of Payload Padding**: AES-GCM leaks the exact length of the plaintext. An attacker observing traffic can infer the length of the messages being sent. Fixed-length padding should be added before encryption.

---

## 5. Security Vulnerabilities & Limitations

No system is perfectly secure. The current implementation has known security trade-offs:

### 1. Metadata and Traffic Analysis Leakage
While the server cannot read the *contents* of the messages, it acts as a central router. It knows:
- Who is online and their IP addresses.
- Exactly *who* is talking to *whom* (via `GET_IP` and `OFFLINE_STORE` requests).
- The exact time and volume of messages exchanged.
*Mitigation*: Implement a mixnet or Tor-like routing, or use sealed-sender techniques to hide the sender's identity from the server.

### 2. Forward Secrecy Window in Offline Messages
We use "Option A" for offline key rotation (keys rotate on login). 
- If Bob's computer is seized by an attacker *before* he logs in, the attacker can extract his current static X25519 private key from the disk (if they bypass the password protection). 
- The attacker can then ask the server for all pending offline messages and decrypt them. 
*Mitigation*: Implement Signal's "Pre-Key" system, where a unique, single-use key is consumed from the server for *every single* offline message.

### 3. Local Storage Memory Protections
- The user's `password` and derived `iden_kdf` remain in the Python process memory (RAM) for the duration of the session. If the OS is compromised, an attacker can dump the memory to extract these keys.
- Python's garbage collector does not securely wipe memory.
*Mitigation*: Use secure memory enclaves or OS-level keystores (e.g., Windows Credential Credential Manager, macOS Keychain) instead of holding raw bytes in Python variables.

### 4. Lack of Post-Compromise Security (PCS) in P2P Ratchet
Our P2P ratchet exchanges new random *salts* to derive new symmetric keys. However, it does not exchange new *Asymmetric (DH)* keys. 
- If an attacker steals the active symmetric session key, they can potentially calculate future keys if they can capture the plaintext salts exchanged over the network.
*Mitigation*: Implement a true **Double Ratchet Algorithm** (like Signal), where every message mixes in new Diffie-Hellman ephemeral keys, guaranteeing recovery even if a symmetric key is fully compromised.

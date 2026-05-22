# Cryptographic Flow Documentation

This document explains the end-to-end cryptographic flow of the system, focusing on identity, authentication, and secure communication.

---

## 1. Identity & PKI (Public Key Infrastructure)

The system uses a combination of RSA for the Certificate Authority (CA) and Ed25519 for user identities.

### 1.1 Root of Trust (Server)
* **CA Generation**: Upon startup, the server generates a Root CA (RSA 4096-bit) and a self-signed certificate.
* **CA Role**: The server acts as a trust anchor. It can sign user public keys to issue X.509 certificates.

### 1.2 User Identity (Client)
* **Key Generation**: Every client generates a long-term **Ed25519** keypair for digital signatures and identity proof.
* **Certificate**: During registration, the client generates an X.509 certificate containing its Ed25519 public key.
* **Storage**: Private keys are stored encrypted on disk (`client_data/`) using **AES-256-CBC** with a key derived from the user's password via **PBKDF2**.

---

## 2. Authentication Flow (Client <-> Server)

The system avoids sending passwords in plain text and uses a challenge-response mechanism.

1.  **Login Initiation**: Client sends a login request with its username.
2.  **Challenge**: The server generates a random **16-byte nonce** and sends it to the client.
3.  **Response**: The client signs the nonce using its **Ed25519 private key** and sends the signature back.
4.  **Verification**: The server retrieves the user's stored public key and verifies the signature. If valid, the user is authenticated.

---

## 3. Secure P2P Communication (Client <-> Client)

All P2P communication is protected by **End-to-End Encryption (E2EE)** with **Perfect Forward Secrecy (PFS)**.

### 3.1 Handshake (ECDHE)
1.  **Discovery**: Client A asks the server for Client B's IP and public key.
2.  **Handshake (`P2P_HELLO`)**:
    *   Client A generates an ephemeral **X25519** keypair.
    *   Client A sends its ephemeral public key to Client B.
    *   Client B generates its own ephemeral **X25519** keypair and sends the public key to Client A.
3.  **Shared Secret**: Both clients perform an **ECDH exchange** to derive a raw shared secret.
4.  **Key Derivation (HKDF)**: The shared secret is passed through **HKDF-SHA256** to derive a 32-byte symmetric session key.

### 3.2 Data Encryption (AES-GCM)
*   **Primitiva**: **AES-256-GCM**.
*   **Packet**: Each message consists of:
    *   `content`: AES-encrypted ciphertext (Base64).
    *   `nonce`: 12-byte random value (Base64).
    *   `tag`: 16-byte authentication tag for integrity (Base64).
*   **Security**: Provides confidentiality, integrity, and authenticity.

### 3.3 Key Rotation (Ratchet)
*   To further limit the impact of a compromised session key, the system implements a "ratchet" mechanism.
*   Every **10 messages**, the clients automatically perform a new ECDHE exchange to generate a fresh session key.

---

## 4. Offline Messaging (Hybrid Encryption)

When a recipient is offline, the sender cannot perform a real-time ECDHE handshake.

1.  **Encryption**: The sender uses the recipient's **long-term public key** (retrieved from the server) to encrypt the message.
2.  **Hybrid Approach**:
    *   A symmetric session key is derived (using a KDF on the recipient's public key as a fallback or RSA if applicable).
    *   The message is encrypted with this key.
3.  **Storage**: The encrypted package (ciphertext, nonce, tag) is stored on the server.
4.  **Retrieval**: When the recipient logs in, they download the encrypted messages and use their **long-term private key** to decrypt them.

---

## 5. Cryptographic Primitives Summary

| Purpose | Algorithm | Implementation |
| :--- | :--- | :--- |
| **Identity** | Ed25519 | `hazmat.primitives.asymmetric.ed25519` |
| **Key Exchange** | X25519 (ECDH) | `hazmat.primitives.asymmetric.x25519` |
| **Key Derivation** | HKDF (SHA256) | `hazmat.primitives.kdf.hkdf` |
| **Symmetric Encryption** | AES-256-GCM | `hazmat.primitives.ciphers.aead.AESGCM` |
| **Password Hashing** | PBKDF2 | `hazmat.primitives.kdf.pbkdf2` |
| **Certificates** | X.509 | `cryptography.x509` |
| **CA Keys** | RSA (4096-bit) | `hazmat.primitives.asymmetric.rsa` |

---

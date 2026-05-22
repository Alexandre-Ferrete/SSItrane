"""
Symmetric Encryption (AES-GCM)
=============================
AES-GCM for encrypting message data.

TODO:
- Generate symmetric key
- Encrypt data (with authentication)
- Decrypt and verify
"""

from typing import Tuple


# Key sizes
KEY_SIZE_256 = 32  # AES-256
KEY_SIZE_128 = 16  # AES-128


import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key(key_size: int = KEY_SIZE_256) -> bytes:
    """
    Generate random symmetric key.
    Args:
        key_size: Key size in bytes (16 or 32)
    Returns:
        Random key bytes
    """
    if key_size not in (KEY_SIZE_128, KEY_SIZE_256):
        raise ValueError("Key size must be 16 or 32 bytes.")
    return os.urandom(key_size)


def encrypt(key: bytes, plaintext: bytes, aad: bytes = None) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt data with AES-GCM (authenticated encryption).
    Args:
        key: Symmetric key (16 or 32 bytes)
        plaintext: Data to encrypt
        aad: Additional Authenticated Data (optional)
    Returns:
        (ciphertext, nonce, tag)
    """
    nonce = os.urandom(12)  # AES-GCM uses 12 byte nonce
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    # In cryptography's AESGCM, tag is appended to ciphertext (16 last bytes)
    tag = ciphertext[-16:]
    ciphertext_wo_tag = ciphertext[:-16]
    return ciphertext_wo_tag, nonce, tag


def decrypt(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes, aad: bytes = None) -> bytes:
    """
    Decrypt and verify data with AES-GCM.
    Args:
        key: Symmetric key
        ciphertext: Encrypted data (without tag)
        nonce: Nonce used during encryption
        tag: Authentication tag
        aad: Additional Authenticated Data (if used during encryption)
    Returns:
        Decrypted plaintext
    Raises:
        Exception if authentication fails
    """
    aesgcm = AESGCM(key)
    ct_with_tag = ciphertext + tag
    return aesgcm.decrypt(nonce, ct_with_tag, aad)


def encrypt_with_iv(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt with AES-CBC (legacy, use with care!).
    Args:
        key: Symmetric key (16 or 32 bytes)
        plaintext: Data to encrypt (must be padded to block size)
    Returns:
        (ciphertext, iv)
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    # PKCS7 padding (for demonstration; for production systems, use authenticated ciphers!)
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len]) * pad_len
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return ciphertext, iv


def decrypt_with_iv(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    """
    Decrypt AES-CBC (legacy, use with care). Strips PKCS7 padding.
    Args:
        key: Symmetric key
        ciphertext: Encrypted data
        iv: Initialization vector
    Returns:
        Decrypted plaintext (unpadded)
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    # Remove PKCS7 padding
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid PKCS7 padding.")
    return padded[:-pad_len]


# ============================================================================
# SECURITY NOTES
# ============================================================================
#
# AES-GCM (Galois/Counter Mode):
# - Provides both confidentiality AND authentication
# - Authenticated encryption (AEAD)
# - No separate MAC needed
# - 12-byte nonce (never reuse with same key!)
# - 16-byte authentication tag
#
# AES-CBC (legacy, avoid):
# - Provides only confidentiality
# - Requires separate HMAC for authentication
# - Must use random IV
#
# Recommended: AES-GCM
#
# ============================================================================

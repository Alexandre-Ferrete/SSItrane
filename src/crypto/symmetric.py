"""
Symmetric Encryption (AES-GCM)
=============================
AES-GCM for encrypting message data.
"""

import os
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Key sizes
KEY_SIZE_256 = 32  # AES-256


def generate_key(key_size: int = KEY_SIZE_256) -> bytes:
    """
    Generate random symmetric key.
    """
    return os.urandom(key_size)


def encrypt(key: bytes, plaintext: bytes, aad: bytes = None) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt data with AES-GCM (authenticated encryption).
    Returns: (ciphertext_wo_tag, nonce, tag)
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
    """
    aesgcm = AESGCM(key)
    ct_with_tag = ciphertext + tag
    return aesgcm.decrypt(nonce, ct_with_tag, aad)

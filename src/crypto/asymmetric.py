"""
Asymmetric Encryption (RSA)
===========================
RSA encryption and decryption for key encapsulation.

TODO:
- Generate RSA keypair
- Encrypt data (typically for key encapsulation)
- Decrypt data
"""

from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


def generate_keypair(key_size: int = 2048) -> Tuple[bytes, bytes]:
    """
    Generate RSA keypair.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def encrypt(public_key_pem: bytes, data: bytes) -> bytes:
    """
    Encrypt data with RSA public key (using OAEP SHA256).
    """
    key = load_public_key(public_key_pem)
    ciphertext = key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def decrypt(private_key_pem: bytes, encrypted_data: bytes) -> bytes:
    """
    Decrypt data using RSA private key (OAEP SHA256).
    """
    key = load_private_key(private_key_pem)
    plaintext = key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def load_public_key(public_key_pem: bytes):
    """Load public key from PEM."""
    return serialization.load_pem_public_key(public_key_pem)


def load_private_key(private_key_pem: bytes):
    """Load private key from PEM."""
    return serialization.load_pem_private_key(private_key_pem, password=None)


# ============================================================================
# USAGE NOTES
# ============================================================================
#
# RSA is typically used for:
# - Key encapsulation (encrypting symmetric keys)
# - Digital signatures
#
# For large data, use hybrid encryption:
# 1. Generate random AES key
# 2. Encrypt data with AES
# 3. Encrypt AES key with RSA
# 4. Send both encrypted key + encrypted data
#
# Key Sizes:
# - 2048 bits: Minimum secure (recommended)
# - 4096 bits: Higher security
#
# ============================================================================

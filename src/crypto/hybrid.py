"""
Hybrid Encryption
=================
Combines asymmetric and symmetric encryption for efficient data encryption.
"""

import base64
from typing import Tuple, Dict, Optional
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from . import symmetric


def encrypt_ecdh(
    recipient_public_key: bytes,
    plaintext: bytes
) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    Encrypt using ECDH key exchange (PFS).
    """
    # Generate ephemeral keypair
    ephemeral_priv = x25519.X25519PrivateKey.generate()
    ephemeral_pub = ephemeral_priv.public_key()
    
    # Load recipient public key
    peer_pub = x25519.X25519PublicKey.from_public_bytes(recipient_public_key)
    
    # Perform exchange
    shared_secret = ephemeral_priv.exchange(peer_pub)
    
    # Derive session key
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"HybridEncryption"
    )
    session_key = hkdf.derive(shared_secret)
    
    # Encrypt data
    ciphertext, nonce, tag = symmetric.encrypt(session_key, plaintext)
    
    ephemeral_pub_bytes = ephemeral_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    return ephemeral_pub_bytes, nonce, tag, ciphertext


def decrypt_ecdh(
    private_key: bytes,
    ephemeral_public_key: bytes,
    nonce: bytes,
    tag: bytes,
    ciphertext: bytes
) -> bytes:
    """
    Decrypt using ECDH key exchange.
    """
    # Load keys
    my_priv = x25519.X25519PrivateKey.from_private_bytes(private_key)
    peer_pub = x25519.X25519PublicKey.from_public_bytes(ephemeral_public_key)
    
    # Perform exchange
    shared_secret = my_priv.exchange(peer_pub)
    
    # Derive session key
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"HybridEncryption"
    )
    session_key = hkdf.derive(shared_secret)
    
    # Decrypt data
    return symmetric.decrypt(session_key, ciphertext, nonce, tag)


def encrypt_content(plaintext: str, recipient_enc_pub_key_b64: str) -> dict:
    """
    Encrypt offline message for recipient using ECDH with their X25519 public key.
    """
    pub_key_bytes = base64.b64decode(recipient_enc_pub_key_b64)
    eph_pub, nonce, tag, ciphertext = encrypt_ecdh(pub_key_bytes, plaintext.encode('utf-8'))
    return {
        "content":       base64.b64encode(ciphertext).decode('utf-8'),
        "nonce":         base64.b64encode(nonce).decode('utf-8'),
        "tag":           base64.b64encode(tag).decode('utf-8'),
        "ephemeral_key": base64.b64encode(eph_pub).decode('utf-8'),
    }

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
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
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


def encrypt_content(plaintext: str, recipient_pub_key_b64: str) -> dict:
    """
    Encripta mensagem para destinatário offline usando chave pública.
    """
    pub_key_bytes = base64.b64decode(recipient_pub_key_b64)
    
    # For offline messages, we use a simpler derivation if it's Ed25519
    kdf = ConcatKDFHash(
        algorithm=hashes.SHA256(),
        length=32,
        other_info=b"OfflineMessage"
    )
    session_key = kdf.derive(pub_key_bytes)
    
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext, nonce, tag = symmetric.encrypt(session_key, plaintext_bytes)
    
    return {
        "content": base64.b64encode(ciphertext).decode('utf-8'),
        "nonce":   base64.b64encode(nonce).decode('utf-8'),
        "tag":     base64.b64encode(tag).decode('utf-8')
    }

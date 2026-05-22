"""
Digital Signatures
=================
Message signing and verification for authenticity.

TODO:
- Sign messages
- Verify signatures
- Sign certificates
"""
import base64
from typing import Tuple
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa, ed25519
from cryptography.exceptions import InvalidSignature


def generate_keypair_Ed25519():
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key() 

def sign(private_key_pem: bytes, message: bytes) -> bytes:
    """
    Sign a message with RSA/ECC/Ed25519 private key.
    """

    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if isinstance(key, rsa.RSAPrivateKey):
        signature = key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        signature = key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
    elif isinstance(key, ed25519.Ed25519PrivateKey):
        signature = key.sign(message)
    else:
        raise ValueError("Unsupported key type for signing")
    return signature


def verify(public_key_pem: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify a signature with RSA/ECC/Ed25519 public key.
    """
    key = serialization.load_pem_public_key(public_key_pem)
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(
                signature, message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, message)
        else:
            return False
    except InvalidSignature:
        return False
    return True


def sign_certificate(
    private_key_pem: bytes,
    certificate_data: bytes
) -> bytes:
    """
    Sign a certificate payload with CA private key.
    """
    # In X.509, typically the certificate is signed using the signing algorithm.
    # Here, just sign the certificate_data like a blob
    return sign(private_key_pem, certificate_data)


def create_signature_payload(
    sender: str,
    recipient: str,
    message_id: str,
    encrypted_content: bytes,
    timestamp: int
) -> bytes:
    """
    Create signature payload for chat message (canonical serialization).
    """
    # Use a deterministic structure; fields (sender, recipient, message_id, encrypted_content, timestamp)
    # Format: sender<sep>recipient<sep>id<sep>base64(content)<sep>timestamp
    sep = b'|'
    payload = (
        sender.encode('utf-8') + sep +
        recipient.encode('utf-8') + sep +
        message_id.encode('utf-8') + sep +
        base64.b64encode(encrypted_content) + sep +
        str(timestamp).encode('utf-8')
    )
    return payload


# ============================================================================
# SIGNATURE USE CASES
# ============================================================================
#
# 1. Certificate Signing:
#    - CA signs user certificates
#    - Clients verify certificate chain
#
# 2. Message Authentication:
#    - Sender signs message
#    - Recipient verifies sender identity
#    - Combined with encryption for E2EE
#
# 3. Key Exchange Authentication:
#    - Sign ephemeral public keys
#    - Prevents MitM attacks
#
# Algorithm Choices:
# -----------------
# - RSA-PSS: Recommended for RSA keys
# - ECDSA: Recommended for ECC keys
# - Ed25519: Modern, fast (if supported)
#
# ============================================================================

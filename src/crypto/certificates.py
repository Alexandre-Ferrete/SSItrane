"""
X.509 Certificates
==================
X.509 certificate creation and validation.

TODO:
- Create self-signed CA certificate
- Create user certificate signed by CA
- Parse certificate
- Validate certificate signature
"""

from datetime import datetime
from typing import Tuple, Optional
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes


def generate_ca_certificate(
    ca_private_key: bytes,
    ca_public_key: bytes,
    common_name: str = "ChatServer CA",
    validity_days: int = 3650
) -> bytes:
    """
    Generate a self-signed CA certificate.
    """
    from cryptography.hazmat.primitives import serialization, hashes
    import datetime as dt
    private_key = serialization.load_pem_private_key(ca_private_key, password=None)
    public_key = serialization.load_pem_public_key(ca_public_key)
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)
    ])
    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(subject)
    cert_builder = cert_builder.issuer_name(issuer)
    cert_builder = cert_builder.public_key(public_key)
    cert_builder = cert_builder.serial_number(x509.random_serial_number())
    cert_builder = cert_builder.not_valid_before(dt.datetime.utcnow())
    cert_builder = cert_builder.not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=validity_days))
    cert_builder = cert_builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    )
    cert_builder = cert_builder.add_extension(
        x509.KeyUsage(
            digital_signature=True, key_encipherment=True,
            key_cert_sign=True, crl_sign=True, content_commitment=False,
            data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False
        ), critical=True
    )
    cert = cert_builder.sign(private_key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert_pem


def generate_user_certificate(
    ca_private_key: bytes,
    user_public_key: bytes,
    username: str,
    ca_cert: bytes,
    validity_days: int = 365
) -> bytes:
    """
    Generate a user certificate signed by CA.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization, hashes
    import datetime as dt
    ca_key = serialization.load_pem_private_key(ca_private_key, password=None)
    user_pubkey = serialization.load_pem_public_key(user_public_key)
    ca_cert_obj = x509.load_pem_x509_certificate(ca_cert)
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, username)
    ])
    issuer = ca_cert_obj.subject
    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(subject)
    cert_builder = cert_builder.issuer_name(issuer)
    cert_builder = cert_builder.public_key(user_pubkey)
    cert_builder = cert_builder.serial_number(x509.random_serial_number())
    cert_builder = cert_builder.not_valid_before(dt.datetime.utcnow())
    cert_builder = cert_builder.not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=validity_days))
    cert_builder = cert_builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )
    cert_builder = cert_builder.add_extension(
        x509.KeyUsage(
            digital_signature=True, key_encipherment=True,
            key_cert_sign=False, crl_sign=False, content_commitment=False,
            data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False
        ), critical=True
    )
    cert_builder = cert_builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(username)]), critical=False
    )
    cert = cert_builder.sign(ca_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM)


def load_certificate(cert_pem: bytes):
    """
    Load certificate from PEM bytes to x509 object.
    """
    from cryptography import x509
    return x509.load_pem_x509_certificate(cert_pem)


def get_subject(cert) -> str:
    """
    Get subject common name from certificate object.
    """
    from cryptography.x509.oid import NameOID
    for attr in cert.subject:
        if attr.oid == NameOID.COMMON_NAME:
            return attr.value
    return ""


def get_public_key(cert) -> bytes:
    """
    Extract public key from certificate, return as PEM bytes.
    """
    from cryptography.hazmat.primitives import serialization
    return cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def verify_signature(
    cert: bytes,
    signing_cert: bytes
) -> bool:
    """
    Verify certificate was signed by CA.
    """
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
    user_cert = x509.load_pem_x509_certificate(cert)
    ca_cert = x509.load_pem_x509_certificate(signing_cert)
    ca_pubkey = ca_cert.public_key()
    
    try:
        if isinstance(ca_pubkey, rsa.RSAPublicKey):
            ca_pubkey.verify(
                user_cert.signature,
                user_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                user_cert.signature_hash_algorithm
            )
        elif isinstance(ca_pubkey, ec.EllipticCurvePublicKey):
            ca_pubkey.verify(
                user_cert.signature,
                user_cert.tbs_certificate_bytes,
                ec.ECDSA(user_cert.signature_hash_algorithm)
            )
        else:
            return False
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def is_expired(cert) -> bool:
    """Check if certificate is expired."""
    from datetime import datetime
    now = datetime.utcnow()
    return now < cert.not_valid_before or now > cert.not_valid_after


def get_validity_period(cert) -> Tuple[datetime, datetime]:
    """Get certificate validity period (notBefore, notAfter)."""
    return cert.not_valid_before, cert.not_valid_after


# ============================================================================
# CERTIFICATE STRUCTURE
# ============================================================================
#
# X.509 Certificate Fields:
# --------------------------
# - Version: v3
# - Serial Number: Unique identifier
# - Signature Algorithm: SHA256 with RSA/ECDSA
# - Issuer: CN=ChatServer CA, O=SecureChat
# - Validity: NotBefore, NotAfter
# - Subject: CN=<username>
# - Subject Public Key: User's encryption key
# - Extensions:
#     * Basic Constraints: CA:FALSE
#     * Key Usage: Digital Signature, Key Encipherment
#     * Subject Alternative Name: <username>
#
# Trust Chain:
# ------------
# Client trusts the CA certificate (distributed with client)
# Server signs user certificates with CA key
# Client verifies user certificate against CA certificate
#
# ============================================================================

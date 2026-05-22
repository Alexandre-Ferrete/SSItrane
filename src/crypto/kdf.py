"""
HKDF - Key Derivation Function
===========================
HMAC-based Key Derivation Function (HKDF) for deriving keys from shared secrets.
"""

import os
from typing import Optional
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as HKDFPrimitive
from cryptography.hazmat.primitives import hashes


class HKDF:
    """HKDF key derivation function."""
    
    def __init__(self, hash_algorithm: str = "sha384"):
        """
        Initialize HKDF with hash algorithm.
        
        Args:
            hash_algorithm: Hash algorithm name ("sha256", "sha384", "sha512")
        """
        self.hash_algorithm = hash_algorithm.lower()
        
        if self.hash_algorithm == "sha256":
            self._hash = hashes.SHA256()
        elif self.hash_algorithm == "sha384":
            self._hash = hashes.SHA384()
        elif self.hash_algorithm == "sha512":
            self._hash = hashes.SHA512()
        else:
            raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")
    
    def derive_key(
        self,
        input_key_material: bytes,
        length: int,
        context: bytes = b""
    ) -> bytes:
        """
        Derive key using HKDF.
        
        Args:
            input_key_material: Shared secret or key material
            length: Desired key length in bytes
            context: Optional context string for domain separation
            
        Returns:
            Derived key bytes
        """
        hkdf = HKDFPrimitive(
            algorithm=self._hash,
            length=length,
            salt=None,
            info=context,
        )
        return hkdf.derive(input_key_material)


def derive_key(
    input_key_material: bytes,
    length: int,
    hash_algorithm: str = "sha384",
    context: bytes = b""
) -> bytes:
    """
    Convenience function to derive a key using HKDF.
    
    Args:
        input_key_material: Shared secret or key material
        length: Desired key length in bytes
        hash_algorithm: Hash algorithm ("sha256", "sha384", "sha512")
        context: Optional context string for domain separation
        
    Returns:
        Derived key bytes
    """
    hkdf = HKDF(hash_algorithm)
    return hkdf.derive_key(input_key_material, length, context)

def derive_key_PBKDF2HMAC(password, salt):
    if not salt:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC (
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    password_kdf = kdf.derive(password.encode("utf-8"))
    return password_kdf, salt
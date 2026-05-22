# PKI interna - emite e verifica certificados dos utilizadores
# Funcionalidades: gerar chaves CA, assinar certificados, revogar

import os
import logging
from typing import Optional, Tuple


class CertificateAuthority:
    """
    Internal PKI Certificate Authority.
    """
    
    def __init__(self, storage):
        """TODO: Initialize CA."""
        pass
    
    def initialize(self):
        """TODO: Initialize CA - load existing or generate new."""
        pass
    
    def generate_ca_keys(self) -> Tuple[bytes, bytes]:
        """TODO: Generate new CA keypair."""
        pass
    
    def load_ca_keys(self) -> bool:
        """TODO: Load existing CA keys from storage."""
        pass
    
    def save_ca_keys(self, private_key_pem: bytes, cert_pem: bytes):
        """TODO: Save CA keys to storage."""
        pass
    
    def sign_user_certificate(
        self,
        username: str,
        public_key: bytes,
        csr: bytes = None
    ) -> bytes:
        """TODO: Sign a user's certificate request."""
        pass
    
    def verify_certificate(self, cert_pem: bytes) -> bool:
        """TODO: Verify a certificate is signed by this CA."""
        pass
    
    def revoke_certificate(self, username: str):
        """TODO: Revoke a user's certificate."""
        pass
    
    def is_revoked(self, username: str) -> bool:
        """TODO: Check if certificate is revoked."""
        pass
    
    def get_ca_certificate(self) -> Optional[bytes]:
        """TODO: Get CA certificate for distribution to clients."""
        pass
    
    def get_user_certificate(self, username: str) -> Optional[bytes]:
        """TODO: Get a user's certificate."""
        pass
    
    def get_user_public_key(self, username: str) -> Optional[bytes]:
        """TODO: Get a user's public key."""
        pass
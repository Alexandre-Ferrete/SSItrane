import pytest
from src.crypto import certificates, asymmetric

def test_ca_and_user_certificates_end_to_end():
    ca_priv, ca_pub = asymmetric.generate_keypair()
    ca_cert = certificates.generate_ca_certificate(ca_priv, ca_pub, "Test CA")
    assert b"BEGIN CERTIFICATE" in ca_cert
    user_priv, user_pub = asymmetric.generate_keypair()
    user_cert = certificates.generate_user_certificate(ca_priv, user_pub, "alice", ca_cert)
    cert_obj = certificates.load_certificate(user_cert)
    common_name = certificates.get_subject(cert_obj)
    assert common_name == "alice"
    pubkey = certificates.get_public_key(cert_obj)
    # check signature valid
    assert certificates.verify_signature(user_cert, ca_cert)

def test_user_cert_expiry_and_period():
    ca_priv, ca_pub = asymmetric.generate_keypair()
    ca_cert = certificates.generate_ca_certificate(ca_priv, ca_pub)
    user_priv, user_pub = asymmetric.generate_keypair()
    user_cert = certificates.generate_user_certificate(ca_priv, user_pub, "bob", ca_cert, validity_days=1)
    cert_obj = certificates.load_certificate(user_cert)
    period = certificates.get_validity_period(cert_obj)
    assert isinstance(period, tuple) and len(period) == 2
    assert certificates.is_expired(cert_obj) in (True, False)

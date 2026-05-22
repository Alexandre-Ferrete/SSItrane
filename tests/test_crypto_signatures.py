import pytest
from src.crypto import signatures, asymmetric

def test_sign_and_verify():
    priv, pub = asymmetric.generate_keypair()
    message = b'Hello'
    sig = signatures.sign(priv, message)
    assert signatures.verify(pub, message, sig)

def test_signature_wrong_pub_fails():
    priv, pub = asymmetric.generate_keypair()
    priv2, pub2 = asymmetric.generate_keypair()
    message = b'asdf'
    sig = signatures.sign(priv, message)
    assert not signatures.verify(pub2, message, sig)

def test_signature_payload_structure():
    payload = signatures.create_signature_payload("alice", "bob", "mid", b"xxx", 987432)
    assert b"alice" in payload and b"bob" in payload
    assert isinstance(payload, bytes)

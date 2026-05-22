import pytest
from src.crypto import ecdh

def test_ecdh_key_exchange_and_derive():
    priv_a, pub_a = ecdh.generate_keypair()
    priv_b, pub_b = ecdh.generate_keypair()
    secret_ab = ecdh.perform_exchange(priv_a, pub_b)
    secret_ba = ecdh.perform_exchange(priv_b, pub_a)
    assert secret_ab == secret_ba
    key_ab = ecdh.derive_key(secret_ab)
    key_ba = ecdh.derive_key(secret_ba)
    assert key_ab == key_ba

def test_ecdh_keypair_shapes():
    priv, pub = ecdh.generate_keypair()
    assert isinstance(priv, bytes)
    assert isinstance(pub, bytes)

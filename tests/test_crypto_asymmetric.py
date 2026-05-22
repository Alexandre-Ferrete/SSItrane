import pytest
from src.crypto import asymmetric

def test_rsa_keypair_encrypt_decrypt():
    priv, pub = asymmetric.generate_keypair()
    message = b'sample message'
    ciphertext = asymmetric.encrypt(pub, message)
    plain = asymmetric.decrypt(priv, ciphertext)
    assert plain == message

def test_rsa_encrypt_decrypt_wrong_key_fails():
    priv1, pub1 = asymmetric.generate_keypair()
    priv2, pub2 = asymmetric.generate_keypair()
    message = b'Important!'
    ciphertext = asymmetric.encrypt(pub1, message)
    with pytest.raises(Exception):
        asymmetric.decrypt(priv2, ciphertext)

def test_invalid_key_load_fails():
    with pytest.raises(Exception):
        asymmetric.load_private_key(b"not a PEM")
    with pytest.raises(Exception):
        asymmetric.load_public_key(b"not a PEM")

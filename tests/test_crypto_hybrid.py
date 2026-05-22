import pytest
from src.crypto import hybrid, asymmetric, ecdh

def test_hybrid_encrypt_decrypt():
    priv, pub = asymmetric.generate_keypair()
    plaintext = b"Hybrid message"
    enc_key, nonce, tag, ciphertext = hybrid.encrypt(pub, plaintext)
    out = hybrid.decrypt(priv, enc_key, nonce, tag, ciphertext)
    assert out == plaintext

def test_hybrid_ecdh_encrypt_decrypt():
    priv, pub = ecdh.generate_keypair()
    plaintext = b"PFS hybrid msg"
    eph_pub, nonce, tag, ciphertext = hybrid.encrypt_ecdh(pub, plaintext)
    out = hybrid.decrypt_ecdh(priv, eph_pub, nonce, tag, ciphertext)
    assert out == plaintext

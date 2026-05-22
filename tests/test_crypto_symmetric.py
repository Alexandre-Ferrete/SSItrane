import pytest
from src.crypto import symmetric


def test_aes_gcm_encrypt_decrypt():
    key = symmetric.generate_key()
    plaintext = b"Secret test message"
    ciphertext, nonce, tag = symmetric.encrypt(key, plaintext)
    # Check types/sizes
    assert isinstance(ciphertext, bytes)
    assert isinstance(nonce, bytes) and len(nonce) == 12
    assert isinstance(tag, bytes) and len(tag) == 16

    # Roundtrip
    decrypted = symmetric.decrypt(key, ciphertext, nonce, tag)
    assert decrypted == plaintext


def test_aes_gcm_decrypt_with_wrong_tag_fails():
    key = symmetric.generate_key()
    plaintext = b"attack at dawn"
    ciphertext, nonce, tag = symmetric.encrypt(key, plaintext)
    # Tamper tag
    bad_tag = b"\x00"*16
    with pytest.raises(Exception):
        symmetric.decrypt(key, ciphertext, nonce, bad_tag)


def test_generate_key_sizes():
    k128 = symmetric.generate_key(symmetric.KEY_SIZE_128)
    k256 = symmetric.generate_key(symmetric.KEY_SIZE_256)
    assert len(k128) == 16
    assert len(k256) == 32


def test_aes_cbc_encrypt_decrypt():
    key = symmetric.generate_key(symmetric.KEY_SIZE_128)
    message = b"16 bytes string!"  # exactly 16 bytes, for padding demo
    ciphertext, iv = symmetric.encrypt_with_iv(key, message)
    # Type checks
    assert isinstance(ciphertext, bytes)
    assert isinstance(iv, bytes) and len(iv) == 16
    out = symmetric.decrypt_with_iv(key, ciphertext, iv)
    assert out == message


def test_aes_cbc_decrypt_with_wrong_padding():
    key = symmetric.generate_key(symmetric.KEY_SIZE_128)
    message = b"TEST TEST 123456"
    ciphertext, iv = symmetric.encrypt_with_iv(key, message)
    # Tamper with last byte (padding)
    tampered = ciphertext[:-1] + b"\x01"
    with pytest.raises(ValueError):
        symmetric.decrypt_with_iv(key, tampered, iv)

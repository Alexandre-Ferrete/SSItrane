import pytest
from src.utils import helpers
import os
import tempfile

def test_base64_encode_decode():
    data = os.urandom(20)
    encoded = helpers.encode_base64(data)
    decoded = helpers.decode_base64(encoded)
    assert decoded == data
    assert isinstance(encoded, str)

def test_hex_encode_decode():
    data = b'abc\x00\x01'
    hexed = helpers.encode_hex(data)
    unhexed = helpers.decode_hex(hexed)
    assert unhexed == data

def test_password_hash_roundtrip():
    pw = "SecretP@ssw0rd"
    h, s = helpers.hash_password(pw)
    assert helpers.verify_password(pw, h, s)
    # Fail on wrong password
    assert not helpers.verify_password("fail", h, s)

def test_generate_ids_are_uuid():
    mid = helpers.generate_message_id()
    sid = helpers.generate_session_id()
    import uuid
    uuid.UUID(mid)  # should not raise
    uuid.UUID(sid)

def test_validate_username_password():
    assert helpers.validate_username("user_123")
    assert not helpers.validate_username("x")
    assert helpers.validate_password("Pass123456")
    assert not helpers.validate_password("short1")

def test_file_io_helpers():
    with tempfile.TemporaryDirectory() as tmp:
        fpath = os.path.join(tmp, "foo.bin")
        data = b"bincontents"
        helpers.ensure_directory(tmp)
        helpers.write_file(fpath, data)
        out = helpers.read_file(fpath)
        assert out == data

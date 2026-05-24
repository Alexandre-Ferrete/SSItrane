"""
Helpers
=======
Utility functions for the project.

TODO:
- Logging setup
- Encoding/decoding helpers
- Validation helpers
- Password hashing
"""

import os
from typing import Optional
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidKey
import base64
import hashlib
import hmac


# =========================================================================
# Encoding Helpers
# =========================================================================

def encode_base64(data: bytes) -> str:
    """
    Encode bytes to base64 string.

    Args:
        data: Bytes to encode
    Returns:
        Base64 encoded string (utf-8)
    """
    return base64.b64encode(data).decode('utf-8')


def decode_base64(data: str) -> bytes:
    """
    Decode base64 string to bytes.

    Args:
        data: Base64 string (utf-8 or ascii)
    Returns:
        Decoded bytes
    """
    return base64.b64decode(data.encode('utf-8'))


def hash_sha256(data: bytes) -> bytes:
    """
    SHA-256 hash of data.
    
    Args:
        data: Data to hash
    Returns:
        Hash digest (32 bytes)
    """
    return hashlib.sha256(data).digest()


def hash_sha256_hex(data: bytes) -> str:
    """
    SHA-256 hash as hex string.
    
    Args:
        data: Data to hash
    Returns:
        Hash hex string (64 characters)
    """
    return hashlib.sha256(data).hexdigest()


def secure_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.
    
    Args:
        length: Number of random bytes
    Returns:
        Random bytes
    """
    return os.urandom(length)

def bytes_to_hex(data: bytes) -> str:
    """
    Convert bytes to hexadecimal string.
    
    Args:
        data: Bytes to convert
    Returns:
        Hexadecimal string
    """
    return data.hex()


def hex_to_bytes(hex_str: str) -> bytes:
    """
    Convert hexadecimal string to bytes.
    
    Args:
        hex_str: Hex string
    Returns:
        Bytes
    """
    return bytes.fromhex(hex_str)


def encode_hex(data: bytes) -> str:
    """Alias for bytes_to_hex."""
    return bytes_to_hex(data)


def decode_hex(data: str) -> bytes:
    """Alias for hex_to_bytes."""
    return hex_to_bytes(data)


# =========================================================================
# Password Hashing
# =========================================================================

def hash_password(password: str, salt: Optional[bytes] = None) -> tuple:
    """
    TODO: Hash password with salt.
    
    Args:
        password: Plain text password
        salt: Optional salt (generated if not provided)
        
    Returns:
        (hash, salt) - both as hex strings
    """
    if salt is None:
        salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )

    password_hash = kdf.derive(password.encode())
    return password_hash.hex(), salt.hex()


def verify_password(password: str, hash: str, salt: str) -> bool:
    """
    TODO: Verify password against hash.
    
    Args:
        password: Plain text password
        hash: Stored hash (hex)
        salt: Stored salt (hex)
        
    Returns:
        True if password matches
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(salt),
        iterations=480000,
    )

    try:
        kdf.verify(password.encode(), bytes.fromhex(hash))
        return True
    except InvalidKey:
        return False


# =========================================================================
# UUID Generation
# =========================================================================

import uuid

def generate_message_id() -> str:
    """
    Generate a unique message ID (UUID4).
    Returns:
        UUID string
    """
    return str(uuid.uuid4())


def generate_session_id() -> str:
    """
    Generate a unique session ID (UUID4).
    Returns:
        UUID string
    """
    return str(uuid.uuid4())


# =========================================================================
# Validation
# =========================================================================

def validate_username(username: str) -> bool:
    """
    Validate username format (alphanumeric, min/max length).
    Args:
        username: Username to validate
    Returns:
        True if valid (letters/digits/underscore, 3..32 chars)
    """
    if not isinstance(username, str):
        return False
    if not (USERNAME_MIN_LENGTH <= len(username) <= USERNAME_MAX_LENGTH):
        return False
    return username.isidentifier() and username.isascii()



def validate_password(password: str) -> bool:
    """
    Validate password strength (min length, mix of chars).
    Args:
        password: Password to validate
    Returns:
        True if meets minimum requirements (min 8 chars, max 100, at least 1 letter and 1 digit)
    """
    if not isinstance(password, str) or len(password) < PASSWORD_MIN_LENGTH or len(password) > PASSWORD_MAX_LENGTH:
        return False
    has_digit = any(c.isdigit() for c in password)
    has_alpha = any(c.isalpha() for c in password)
    return has_digit and has_alpha


# =========================================================================
# Logging
# =========================================================================

import logging

def setup_logging(level: str = "INFO", log_file: Optional[str] = None):
    """
    Setup logging configuration (console or file).
    Args:
        level: Logging level ("DEBUG", "INFO", etc.)
        log_file: Optional log file path
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    handlers = []
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
    if log_file is not None:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)
    else:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        handlers.append(stream_handler)
    logging.basicConfig(level=numeric_level, handlers=handlers, force=True)


def get_logger(name: str):
    """
    Get logger for module.
    Args:
        name: Logger name (__name__)
    Returns:
        Logger instance
    """
    return logging.getLogger(name)


# =========================================================================
# Time
# =========================================================================

import time

def get_timestamp() -> int:
    """
    Get current Unix timestamp (int).
    Returns:
        Seconds since epoch (UTC)
    """
    return int(time.time())


def format_timestamp(timestamp: int) -> str:
    """
    Format Unix timestamp to human-readable (UTC) string.
    Args:
        timestamp: Unix timestamp (int)
    Returns:
        Formatted string
    """
    return time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(timestamp))


# =========================================================================
# File Operations
# =========================================================================

def ensure_directory(path: str):
    """
    Ensure that the specified directory exists (like mkdir -p).
    Args:
        path: Directory path
    """
    os.makedirs(path, exist_ok=True)


def read_file(path: str) -> bytes:
    """
    Read file contents as bytes.
    Args:
        path: File path
    Returns:
        File contents (bytes)
    """
    with open(path, 'rb') as f:
        return f.read()


def write_file(path: str, data: bytes):
    """
    Write bytes to a file (overwrites).
    Args:
        path: File path
        data: Data to write (bytes)
    """
    with open(path, 'wb') as f:
        f.write(data)


def load_pem(file_path: str) -> bytes:
    """
    Load PEM-encoded file.
    
    Args:
        file_path: Path to PEM file
    Returns:
        PEM contents as bytes
    """
    with open(file_path, 'rb') as f:
        return f.read()


def save_pem(data: bytes, file_path: str) -> None:
    """
    Save PEM-encoded data to file.
    
    Args:
        data: PEM data bytes
        file_path: Path to save file
    """
    with open(file_path, 'wb') as f:
        f.write(data)


# =========================================================================
# Constants
# =========================================================================

BUFFER_SIZE = 4096
MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB
DEFAULT_PORT = 5555
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 100
USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 32

# =========================================================================

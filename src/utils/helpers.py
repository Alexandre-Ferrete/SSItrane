
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
        iterations=600000,
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
        iterations=600000,
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
import sys

# --- ANSI colour codes ---------------------------------------------------
_RESET   = "\033[0m"
_BOLD    = "\033[1m"
_RED     = "\033[31m"
_GREEN   = "\033[32m"
_YELLOW  = "\033[33m"
_CYAN    = "\033[36m"
_MAGENTA = "\033[35m"
_WHITE   = "\033[37m"

_LEVEL_COLORS: dict = {
    "DEBUG":    _CYAN,
    "INFO":     _WHITE,
    "WARNING":  _YELLOW,
    "ERROR":    _BOLD + _RED,
    "CRITICAL": _BOLD + _RED,
    "SECURITY": _BOLD + _MAGENTA,
}

# Custom level between INFO (20) and WARNING (30) — security events
SECURITY_LEVEL = 25
logging.addLevelName(SECURITY_LEVEL, "SECURITY")


def _security_log(self: logging.Logger, msg: str, *args, **kwargs):
    if self.isEnabledFor(SECURITY_LEVEL):
        self._log(SECURITY_LEVEL, msg, args, **kwargs)

logging.Logger.security = _security_log  # type: ignore[attr-defined]


def _enable_ansi_windows():
    """Enable VT100 escape codes on Windows consoles — no-op elsewhere."""
    if sys.platform == "win32":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            pass


class _ColorFormatter(logging.Formatter):
    """Console formatter with per-level ANSI colours."""

    _BASE = "%(asctime)s {c}[%(levelname)-8s]{r}  %(name)s — %(message)s"

    def __init__(self):
        super().__init__(datefmt="%H:%M:%S")

    def format(self, record: logging.LogRecord) -> str:
        c = _LEVEL_COLORS.get(record.levelname, _WHITE)
        fmt = self._BASE.format(c=c, r=_RESET)
        return logging.Formatter(fmt, datefmt="%H:%M:%S").format(record)


class _SecurityFilter(logging.Filter):
    """Passes only records tagged with [SEC] — routes them to security.log."""

    def filter(self, record: logging.LogRecord) -> bool:
        return "[SEC]" in record.getMessage()


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    security_log_file: Optional[str] = None,
    colored: bool = True,
) -> None:
    """
    Configure application-wide logging.

    Args:
        level:             Root log level ('DEBUG', 'INFO', 'WARNING', …).
        log_file:          Path for the full application log (UTF-8).
        security_log_file: Path for a security-only log; only messages tagged
                           [SEC] are written here.
        colored:           Use ANSI colours on the console (default True).
    """
    if colored:
        _enable_ansi_windows()

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)   # individual handlers filter by level
    root.handlers.clear()

    # Console handler
    console = logging.StreamHandler()
    console.setLevel(numeric_level)
    console.setFormatter(
        _ColorFormatter() if colored else
        logging.Formatter(
            "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    root.addHandler(console)

    # Full application log file
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)-8s] %(name)s:%(lineno)d — %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        root.addHandler(fh)

    # Security-only log file (filtered to [SEC] messages)
    if security_log_file:
        sh = logging.FileHandler(security_log_file, encoding="utf-8")
        sh.setLevel(logging.DEBUG)
        sh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)-8s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        sh.addFilter(_SecurityFilter())
        root.addHandler(sh)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger."""
    return logging.getLogger(name)


# --- Security-aware print helpers (client CLI) ---------------------------

def sec_ok(msg: str) -> str:
    """Green bold prefix for security success."""
    return f"{_BOLD}{_GREEN}[SEGURANÇA ✓]{_RESET} {msg}"


def sec_warn(msg: str) -> str:
    """Yellow bold prefix for security warnings."""
    return f"{_BOLD}{_YELLOW}[SEGURANÇA ⚠]{_RESET}  {msg}"


def sec_err(msg: str) -> str:
    """Red bold prefix for security errors."""
    return f"{_BOLD}{_RED}[SEGURANÇA ✗]{_RESET}  {msg}"


def sec_info(msg: str) -> str:
    """Cyan prefix for security info."""
    return f"{_CYAN}[SEGURANÇA ℹ]{_RESET}  {msg}"


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


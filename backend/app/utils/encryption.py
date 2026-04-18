import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from app.config import settings


def _get_key() -> bytes:
    """Get or generate the AES-256 encryption key."""
    if settings.ENCRYPTION_KEY:
        return base64.b64decode(settings.ENCRYPTION_KEY)
    # Derive from SECRET_KEY if no explicit key set
    key = settings.SECRET_KEY.encode()[:32]
    return key.ljust(32, b"\x00")


def encrypt_file(data: bytes) -> tuple[bytes, str]:
    """
    Encrypt file data with AES-256-CBC.
    Returns (encrypted_bytes, iv_hex_string)
    """
    key = _get_key()
    iv = os.urandom(16)
    
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    
    return encrypted, iv.hex()


def decrypt_file(encrypted_data: bytes, iv_hex: str) -> bytes:
    """
    Decrypt AES-256-CBC encrypted file data.
    """
    key = _get_key()
    iv = bytes.fromhex(iv_hex)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(encrypted_data) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def encrypt_text(text: str) -> tuple[str, str]:
    """Encrypt a text string, return (encrypted_b64, iv_hex)."""
    encrypted, iv_hex = encrypt_file(text.encode("utf-8"))
    return base64.b64encode(encrypted).decode(), iv_hex


def decrypt_text(encrypted_b64: str, iv_hex: str) -> str:
    """Decrypt an encrypted text string."""
    encrypted = base64.b64decode(encrypted_b64)
    return decrypt_file(encrypted, iv_hex).decode("utf-8")

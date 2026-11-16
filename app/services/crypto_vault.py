import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from app.config import FILE_KEY

AAD = b"secure-docvault:v1"


def encrypt(data: bytes) -> bytes:
    """Container layout: 12-byte IV | ciphertext | 16-byte GCM authentication tag."""
    nonce = os.urandom(12)
    return nonce + AESGCM(FILE_KEY).encrypt(nonce, data, AAD)


def decrypt(container: bytes) -> bytes:
    if len(container) < 28:
        raise ValueError("Пошкоджений або закороткий шифроконтейнер")
    return AESGCM(FILE_KEY).decrypt(container[:12], container[12:], AAD)


__all__ = ["encrypt", "decrypt", "InvalidTag"]

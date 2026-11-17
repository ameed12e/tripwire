"""Fernet encryption for incident reports at rest."""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken


class DecryptionError(Exception):
    """Raised when a stored payload cannot be decrypted (wrong key or tampering)."""


def generate_key() -> str:
    return Fernet.generate_key().decode("ascii")


class Cipher:
    def __init__(self, key: str | bytes) -> None:
        raw = key.encode("ascii") if isinstance(key, str) else key
        try:
            self._fernet = Fernet(raw)
        except (ValueError, TypeError) as exc:
            raise ValueError("invalid Fernet key (expected 32 url-safe base64 bytes)") from exc

    def encrypt(self, data: bytes) -> bytes:
        return self._fernet.encrypt(data)

    def decrypt(self, token: bytes) -> bytes:
        try:
            return self._fernet.decrypt(token)
        except InvalidToken as exc:
            raise DecryptionError("cannot decrypt payload: wrong key or corrupted data") from exc

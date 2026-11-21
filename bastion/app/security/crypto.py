"""
Encryption of sensitive data at rest.

Fernet (from the `cryptography` package) is authenticated symmetric
encryption: AES-128 in CBC mode for confidentiality plus HMAC-SHA256 for
integrity, with a random IV per message and a timestamp. If a single byte of
the ciphertext is changed, decryption fails instead of returning garbage.
It was chosen over hand-assembling AES because it removes the usual mistakes
(IV reuse, missing MAC, padding-oracle bugs).
"""
from cryptography.fernet import Fernet, InvalidToken


class FieldCipher:
    """SECURE: encrypts individual database fields (e.g. email addresses)."""

    def __init__(self, fernet: Fernet):
        self._fernet = fernet

    def encrypt(self, plaintext):
        if not plaintext:
            return plaintext
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, token):
        if not token:
            return token
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError):
            return "[cannot be decrypted with the current key]"


class PlaintextCipher:
    """VULNERABLE: stores fields as plain text (anyone with the .db file reads them)."""

    def encrypt(self, plaintext):
        return plaintext

    def decrypt(self, value):
        return value

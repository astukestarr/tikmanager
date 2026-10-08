"""Encrypts stored router configurations (they include passwords and keys) with AES-256-GCM.

Uses Ubuntu's python3-cryptography package (installed by deploy/install.sh). The key is derived from the master key in
/etc/tikmanager, so the database alone reveals nothing. In dev mode without the package, data is stored unencrypted and
marked as such.
"""
import hashlib
import hmac
import os

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:   # dev machines without the package
    AESGCM = None

MAGIC = b"TMv1"


class Vault:
    def __init__(self, master_key: bytes, dev=False):
        self.key = hmac.new(master_key, b"tikmanager:backup-encryption", hashlib.sha256).digest()
        self.dev = dev
        if AESGCM is None and not dev:
            raise RuntimeError("python3-cryptography is required to store router configurations (sudo apt install python3-cryptography).")

    @property
    def available(self):
        return AESGCM is not None

    def seal(self, data: bytes, context: str) -> tuple[bytes, str]:
        """Returns (blob, method). The context (e.g. 'device:12') is bound to the ciphertext so blobs can't be swapped."""
        if AESGCM is None:
            return data, "none"
        nonce = os.urandom(12)
        return MAGIC + nonce + AESGCM(self.key).encrypt(nonce, data, context.encode()), "aes-gcm"

    def open(self, blob: bytes, method: str, context: str) -> bytes:
        if method == "none":
            return blob
        if AESGCM is None:
            raise RuntimeError("This configuration is encrypted and python3-cryptography isn't installed.")
        if not blob.startswith(MAGIC):
            raise ValueError("Not a TikManager encrypted blob.")
        return AESGCM(self.key).decrypt(blob[4:16], blob[16:], context.encode())

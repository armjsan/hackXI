"""
key_manager.py
SHA-256 based key derivation for Password B.

Produces a 12-character digest (truncated base64 of first 16 bytes of SHA-256)
with a randomly-sized salt (1-12 bytes). Verification uses hmac.compare_digest
for timing-safe comparison.
"""

import os
import random
import base64
import hashlib
import hmac


_HASH_BYTES = 16    # take first 16 bytes of SHA-256 digest
_DIGEST_LEN = 12    # truncated base64 characters


def generate_salt():
    """Generate a random salt with length randomly chosen between 1 and 12 bytes."""
    length = random.randint(1, 12)
    return os.urandom(length)


def derive_key(password, salt):
    """
    Derive a 12-character digest from password + salt using SHA-256.

    1. SHA-256(salt + password)
    2. Take first 16 bytes
    3. Base64 encode
    4. Truncate to 12 characters

    Returns the 12-char key string.
    """
    raw_hash = hashlib.sha256(salt + password.encode('utf-8')).digest()
    key_buffer = raw_hash[:_HASH_BYTES]
    b64_full = base64.b64encode(key_buffer).decode('ascii')
    return b64_full[:_DIGEST_LEN]


def encode_salt(salt):
    """Base64 encode the salt for database storage."""
    return base64.b64encode(salt).decode('ascii')


def decode_salt(salt_b64):
    """Decode a base64-encoded salt from the database."""
    return base64.b64decode(salt_b64)


def create_key(password):
    """
    Generate salt, derive key, return (key, salt_b64) for storage.

    Returns:
        Tuple of (key, salt_b64) where key is the 12-char digest
        and salt_b64 is the base64-encoded salt.
    """
    salt = generate_salt()
    key = derive_key(password, salt)
    salt_b64 = encode_salt(salt)
    return key, salt_b64


def verify_key(password, stored_key, stored_salt_b64):
    """
    Verify a password against stored key and salt using timing-safe comparison.

    Returns True if the password matches, False otherwise.
    """
    salt = decode_salt(stored_salt_b64)
    candidate_key = derive_key(password, salt)
    return hmac.compare_digest(candidate_key, stored_key)

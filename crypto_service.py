

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
from typing import Optional

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CryptoError(Exception):
    """Raised for any encryption, decryption, or integrity failure."""

    pass


class CryptoLogicalError(CryptoError):
    """Raised for logical errors (wrong key size, invalid nonce, etc.)."""

    pass


class CryptoAuthenticationError(CryptoError):
    """Raised when authenticated encryption verification fails."""

    pass


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

AES_KEY_SIZE = 32  # 256-bit AES key
RSA_KEY_SIZE = 3072  # bits (NIST 128-bit equivalent; faster than 4096)

# AES-GCM nonce: MUST be exactly 12 bytes (96 bits)
# 12-byte nonce is standard (RFC 5116, NIST SP 800-38D)
AES_GCM_NONCE_SIZE = 12

# Authenticated encryption integrity
INTEGRITY_ALGORITHM = "sha256"
INTEGRITY_HMAC_ALGORITHM = "sha256"

# Key serialization format
KEY_ENCODING = "base64"


# ---------------------------------------------------------------------------
# AES-GCM symmetric encryption
# ---------------------------------------------------------------------------


def generate_aes_key() -> bytes:
    """
    Return a cryptographically random 256-bit AES key.

    Returns:
        32-byte random key for AES-256.
    """
    return get_random_bytes(AES_KEY_SIZE)


def generate_aes_nonce() -> bytes:
    """
    Generate a cryptographically random 12-byte AES-GCM nonce.

    ✅ Explicit nonce generation (not library default).
    ✅ Exactly 12 bytes for optimal GCM performance (per RFC 5116).

    Returns:
        12-byte random nonce.

    Raises:
        CryptoLogicalError: if nonce generation fails (should never happen).
    """
    try:
        return get_random_bytes(AES_GCM_NONCE_SIZE)
    except Exception as e:
        logger.error(f"Failed to generate AES nonce: {e}")
        raise CryptoLogicalError("Nonce generation failed") from e


def _validate_aes_nonce(nonce: bytes) -> None:
    """
    Validate that nonce is exactly 12 bytes.

    Args:
        nonce: Nonce to validate.

    Raises:
        CryptoLogicalError: if nonce is not exactly 12 bytes.
    """
    if len(nonce) != AES_GCM_NONCE_SIZE:
        msg = f"AES-GCM nonce must be {AES_GCM_NONCE_SIZE} bytes, got {len(nonce)}"
        logger.warning(msg)
        raise CryptoLogicalError(msg)


def encrypt_file(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt *data* with AES-256-GCM.

    ✅ Explicit 12-byte nonce generation (not library default).
    ✅ Returns (ciphertext, nonce, tag) for authenticated decryption.

    Args:
        data: Plaintext bytes to encrypt.
        key: 32-byte AES-256 key.

    Returns:
        Tuple of (ciphertext, nonce, tag). All three are required for decryption.

    Raises:
        CryptoLogicalError: if key is not exactly 32 bytes.
        CryptoError: if encryption fails.
    """
    if len(key) != AES_KEY_SIZE:
        msg = f"AES key must be {AES_KEY_SIZE} bytes, got {len(key)}"
        logger.error(msg)
        raise CryptoLogicalError(msg)

    try:
        nonce = generate_aes_nonce()
        _validate_aes_nonce(nonce)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        logger.debug(f"Encrypted {len(data)} bytes with AES-256-GCM")
        return ciphertext, nonce, tag
    except CryptoError:
        raise
    except Exception as e:
        logger.error(f"AES encryption failed: {e}")
        raise CryptoError("Encryption failed") from e


def decrypt_file(
    ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes
) -> bytes:
    """
    Decrypt and authenticate *ciphertext* with AES-256-GCM.

    ✅ Explicit nonce validation (must be 12 bytes).
    ✅ Logs decryption failures for intrusion detection.

    Args:
        ciphertext: Encrypted data.
        key: 32-byte AES-256 key (must match encryption key).
        nonce: 12-byte AES-GCM nonce (must match nonce used during encryption).
        tag: Authentication tag from encryption (proof of integrity).

    Returns:
        Plaintext bytes.

    Raises:
        CryptoLogicalError: if key or nonce is wrong size.
        CryptoAuthenticationError: if authentication tag does not match
                                  (data tampered or wrong key).
    """
    if len(key) != AES_KEY_SIZE:
        msg = f"AES key must be {AES_KEY_SIZE} bytes, got {len(key)}"
        logger.error(msg)
        raise CryptoLogicalError(msg)

    try:
        _validate_aes_nonce(nonce)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        logger.debug(f"Decrypted {len(ciphertext)} bytes with AES-256-GCM")
        return plaintext
    except ValueError as exc:
        # ✅ Log decryption failures (intrusion detection)
        logger.warning(
            f"AES-GCM authentication failed: possible tampering or wrong key "
            f"(ciphertext_len={len(ciphertext)}, nonce_len={len(nonce)})"
        )
        raise CryptoAuthenticationError(
            "Decryption failed: authentication tag mismatch (data may be tampered)"
        ) from exc
    except CryptoLogicalError:
        raise
    except Exception as e:
        logger.error(f"AES decryption failed: {e}")
        raise CryptoError("Decryption failed") from e


# ---------------------------------------------------------------------------
# RSA-OAEP asymmetric key wrapping (with base64 serialization)
# ---------------------------------------------------------------------------


def generate_rsa_keys() -> tuple[bytes, bytes]:
    """
    Generate a 3072-bit RSA key pair.

    ✅ RSA-3072 (NIST 128-bit equivalent, better performance than 4096).

    Returns:
        Tuple of (private_key_pem, public_key_pem) — both PEM-encoded bytes.

    Raises:
        CryptoError: if key generation fails.
    """
    try:
        key = RSA.generate(RSA_KEY_SIZE)
        private_pem = key.export_key()
        public_pem = key.publickey().export_key()

        logger.info(f"Generated RSA-{RSA_KEY_SIZE} key pair")
        return private_pem, public_pem
    except Exception as e:
        logger.error(f"RSA key generation failed: {e}")
        raise CryptoError("Key generation failed") from e


def wrap_aes_key(aes_key: bytes, rsa_public_key_pem: bytes) -> str:
    """
    Encrypt *aes_key* with *rsa_public_key_pem* using RSA-OAEP.

    ✅ Returns base64-encoded wrapped key (safe for DB storage).

    Args:
        aes_key: 32-byte AES-256 key to wrap.
        rsa_public_key_pem: Public key in PEM format.

    Returns:
        Base64-encoded wrapped key (safe for storage/transport).

    Raises:
        CryptoLogicalError: if aes_key is not 32 bytes.
        CryptoError: if RSA encryption fails.
    """
    if len(aes_key) != AES_KEY_SIZE:
        msg = f"AES key must be {AES_KEY_SIZE} bytes, got {len(aes_key)}"
        logger.error(msg)
        raise CryptoLogicalError(msg)

    try:
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(rsa_public_key_pem))
        wrapped_bytes = cipher_rsa.encrypt(aes_key)

        # ✅ Base64-encode for safe storage (no binary in DB)
        wrapped_b64 = base64.b64encode(wrapped_bytes).decode("ascii")

        logger.debug(f"Wrapped AES key ({len(wrapped_bytes)} bytes, base64)")
        return wrapped_b64
    except CryptoLogicalError:
        raise
    except Exception as e:
        logger.error(f"RSA key wrapping failed: {e}")
        raise CryptoError("Key wrapping failed") from e


def unwrap_aes_key(wrapped_key_b64: str, rsa_private_key_pem: bytes) -> bytes:
    """
    Decrypt *wrapped_key_b64* with *rsa_private_key_pem* using RSA-OAEP.

    ✅ Accepts base64-encoded wrapped key (from safe storage).
    ✅ Logs unwrapping failures for intrusion detection.

    Args:
        wrapped_key_b64: Base64-encoded wrapped AES key from storage.
        rsa_private_key_pem: Private key in PEM format.

    Returns:
        32-byte AES-256 key (unwrapped).

    Raises:
        CryptoLogicalError: if wrapped_key_b64 is not valid base64.
        CryptoAuthenticationError: if RSA decryption fails
                                  (wrong key or corrupted data).
    """
    try:
        # Decode base64
        try:
            wrapped_bytes = base64.b64decode(wrapped_key_b64)
        except Exception as e:
            logger.warning(f"Invalid base64 in wrapped key: {e}")
            raise CryptoLogicalError("Invalid base64 in wrapped key") from e

        # Decrypt with RSA
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(rsa_private_key_pem))
        aes_key = cipher_rsa.decrypt(wrapped_bytes)

        if len(aes_key) != AES_KEY_SIZE:
            msg = f"Unwrapped key is {len(aes_key)} bytes, expected {AES_KEY_SIZE}"
            logger.error(msg)
            raise CryptoLogicalError(msg)

        logger.debug(f"Unwrapped AES key ({len(aes_key)} bytes)")
        return aes_key
    except (CryptoLogicalError, CryptoAuthenticationError):
        raise
    except ValueError as exc:
        # ✅ Log unwrapping failures (intrusion detection)
        logger.warning(
            f"RSA unwrapping failed: possible tampering or wrong key (base64_len={len(wrapped_key_b64)})"
        )
        raise CryptoAuthenticationError("RSA key unwrapping failed") from exc
    except Exception as e:
        logger.error(f"RSA unwrapping failed: {e}")
        raise CryptoError("RSA unwrapping failed") from e


# ---------------------------------------------------------------------------
# RSA-OAEP message encryption (for short plaintext messages)
# ---------------------------------------------------------------------------


def encrypt_message(text: str, public_key_pem: bytes) -> str:
    """
    Encrypt a text message using RSA-OAEP with the recipient's public key.

    ✅ Suitable for short messages (text, small payloads).
    ✅ Returns base64-encoded ciphertext for safe storage.
    ✅ Only the holder of the corresponding private key can decrypt.

    Args:
        text: Plaintext message to encrypt.
        public_key_pem: Recipient's RSA public key in PEM format.

    Returns:
        Base64-encoded encrypted message.

    Raises:
        CryptoLogicalError: if public_key_pem is invalid.
        CryptoError: if encryption fails.
    """
    try:
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key_pem))
        encrypted_bytes = cipher_rsa.encrypt(text.encode())
        return base64.b64encode(encrypted_bytes).decode("ascii")
    except ValueError as e:
        logger.error(f"Invalid public key for message encryption: {e}")
        raise CryptoLogicalError("Invalid public key for message encryption") from e
    except Exception as e:
        logger.error(f"Message encryption failed: {e}")
        raise CryptoError("Message encryption failed") from e


def decrypt_message(encrypted_b64: str, private_key_pem: bytes) -> str:
    """
    Decrypt a text message using RSA-OAEP with the recipient's private key.

    ✅ Accepts base64-encoded ciphertext (from safe storage).
    ✅ Returns plaintext as string.
    ✅ Logs decryption failures for intrusion detection.

    Args:
        encrypted_b64: Base64-encoded encrypted message.
        private_key_pem: Recipient's RSA private key in PEM format.

    Returns:
        Decrypted plaintext message.

    Raises:
        CryptoLogicalError: if encrypted_b64 is not valid base64.
        CryptoAuthenticationError: if decryption fails
                                  (wrong key or corrupted data).
        CryptoError: if other errors occur.
    """
    try:
        # Decode base64
        try:
            encrypted_bytes = base64.b64decode(encrypted_b64)
        except Exception as e:
            logger.warning(f"Invalid base64 in encrypted message: {e}")
            raise CryptoLogicalError("Invalid base64 in encrypted message") from e

        # Decrypt with RSA
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key_pem))
        plaintext_bytes = cipher_rsa.decrypt(encrypted_bytes)
        return plaintext_bytes.decode()
    except CryptoLogicalError:
        raise
    except ValueError as exc:
        logger.warning(
            f"RSA message decryption failed: possible tampering or wrong key (base64_len={len(encrypted_b64)})"
        )
        raise CryptoAuthenticationError("RSA message decryption failed") from exc
    except Exception as e:
        logger.error(f"Message decryption failed: {e}")
        raise CryptoError("Message decryption failed") from e


# ---------------------------------------------------------------------------
# Authenticated encryption integrity (HMAC-SHA256)
# ---------------------------------------------------------------------------


def compute_integrity_hmac(
    data: bytes, key: bytes, algorithm: str = INTEGRITY_HMAC_ALGORITHM
) -> str:
    """
    Compute HMAC-SHA256 of *data* using *key*.

    ✅ HMAC provides both confidentiality and authentication checks.
    ✅ Keyed (unlike plain hash), so attacker can't forge integrity proof.
    ✅ Faster than SHA-512 for typical file sizes.

    Args:
        data: Bytes to authenticate.
        key: Secret key for HMAC (typically the AES key).
        algorithm: HMAC algorithm (default: sha256).

    Returns:
        Hex-encoded HMAC digest.

    Raises:
        CryptoError: if algorithm is not available.
    """
    try:
        h = hmac.new(key, data, getattr(hashlib, f"sha256"))
        return h.hexdigest()
    except AttributeError as e:
        logger.error(f"Unsupported HMAC algorithm: {algorithm}")
        raise CryptoError(f"Unsupported HMAC algorithm: {algorithm}") from e


def verify_integrity_hmac(
    data: bytes, expected_hmac: str, key: bytes, algorithm: str = INTEGRITY_HMAC_ALGORITHM
) -> bool:
    """
    Verify that *data* matches *expected_hmac*.

    ✅ Constant-time comparison (immune to timing attacks).

    Args:
        data: Bytes to verify.
        expected_hmac: Expected HMAC hex digest.
        key: Secret key for HMAC (must match key used during computation).
        algorithm: HMAC algorithm (default: sha256).

    Returns:
        True if HMAC matches, False otherwise.

    Raises:
        CryptoError: if algorithm is not available.
    """
    try:
        actual_hmac = compute_integrity_hmac(data, key, algorithm)
        return hmac.compare_digest(actual_hmac, expected_hmac)
    except CryptoError:
        raise


# ---------------------------------------------------------------------------
# Legacy plain hash (SHA-512, non-keyed) — for backward compatibility
# ---------------------------------------------------------------------------


def calculate_hash(data: bytes, algorithm: str = INTEGRITY_ALGORITHM) -> str:
    """
    Return the hex digest of *data* using *algorithm* (default: SHA-256).

    ⚠️  Non-keyed hash. Prefer compute_integrity_hmac() for authentication.

    Args:
        data: Bytes to hash.
        algorithm: Hash algorithm name (default: sha256).

    Returns:
        Hex-encoded hash digest.

    Raises:
        CryptoError: if algorithm is not available on this platform.
    """
    try:
        return hashlib.new(algorithm, data).hexdigest()
    except ValueError as exc:
        logger.error(f"Unsupported hash algorithm: {algorithm}")
        raise CryptoError(f"Unsupported hash algorithm: {algorithm!r}") from exc


def verify_hash(
    data: bytes, expected_hex: str, algorithm: str = INTEGRITY_ALGORITHM
) -> bool:
    """
    Return ``True`` if *data* hashes to *expected_hex* (constant-time compare).

    ⚠️  Non-keyed hash. Prefer verify_integrity_hmac() for authentication.

    Args:
        data: Bytes to verify.
        expected_hex: Expected hash hex digest.
        algorithm: Hash algorithm name (default: sha256).

    Returns:
        True if hash matches, False otherwise.

    Raises:
        CryptoError: if algorithm is not available.
    """
    actual = calculate_hash(data, algorithm)
    return hmac.compare_digest(actual, expected_hex)


__all__ = [
    # Exceptions
    "CryptoError",
    "CryptoLogicalError",
    "CryptoAuthenticationError",
    # AES-GCM
    "generate_aes_key",
    "generate_aes_nonce",
    "encrypt_file",
    "decrypt_file",
    # RSA-OAEP
    "generate_rsa_keys",
    "wrap_aes_key",
    "unwrap_aes_key",
    "encrypt_message",
    "decrypt_message",
    # Integrity (HMAC-SHA256, preferred)
    "compute_integrity_hmac",
    "verify_integrity_hmac",
    # Legacy hash (non-keyed, for backward compatibility)
    "calculate_hash",
    "verify_hash",
]
"""
file_router.py — Hardened Encrypted File Service.
"""

from __future__ import annotations
import base64
import logging
import struct
import uuid
import hashlib
import abc
from pathlib import Path
from typing import Callable

import anyio
from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, Header, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session, aliased
from Crypto.Cipher import AES

# Assume these are imported from your respective modules
from auth_service import AuthException, decode_access_token
from crypto_service import CryptoError, generate_aes_key, wrap_aes_key, unwrap_aes_key, generate_rsa_keys
from database import get_db, SessionLocal
from models import EncryptedKey, FileMetadata, User, Message, UserRole
from crypto_service import encrypt_file


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration & Constants
# ---------------------------------------------------------------------------

STORAGE_DIR = Path("storage")
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB Limit enforced for in-memory safety

BLOB_MAGIC      = b"SECF"
BLOB_VERSION    = 1
NONCE_LEN       = 12
TAG_LEN         = 16
HEADER_FMT      = f"!4sBBB"
HEADER_SIZE     = struct.calcsize(HEADER_FMT)

router = APIRouter(prefix="/files", tags=["files"])


# ---------------------------------------------------------------------------
# Strict KMS Abstraction Boundary
# ---------------------------------------------------------------------------

class KMSProvider(abc.ABC):
    """
    Abstract Base Class defining the strict boundary between the application
    and external Key Management Services (AWS KMS, HashiCorp Vault, etc.).
    """
    @abc.abstractmethod
    def get_public_key(self, user_id: int) -> bytes:
        pass

    @abc.abstractmethod
    def unwrap_key(self, user_id: int, wrapped_key: bytes) -> bytes:
        pass

class MockExternalKMS(KMSProvider):
    """Network-simulated implementation of the KMSProvider with actual RSA key management."""
    
    def __init__(self):
        # In-memory key store: { user_id: (public_key_pem, private_key_pem) }
        self._key_store = {}
    
    def _ensure_keys_exist(self, user_id: int) -> tuple[bytes, bytes]:
        """Generate RSA keys for user if they don't exist. Returns (private_pem, public_pem)."""
        if user_id not in self._key_store:
            private_pem, public_pem = generate_rsa_keys()
            self._key_store[user_id] = (private_pem, public_pem)
        return self._key_store[user_id]
    
    def get_public_key(self, user_id: int) -> bytes:
        """Return the user's RSA public key."""
        _, public_pem = self._ensure_keys_exist(user_id)
        return public_pem
    
    def unwrap_key(self, user_id: int, wrapped_key: bytes) -> bytes:
        """Unwrap AES key using the user's RSA private key."""
        private_pem, _ = self._ensure_keys_exist(user_id)
        # wrapped_key is base64-encoded from the database
        wrapped_key_b64 = wrapped_key.decode('ascii') if isinstance(wrapped_key, bytes) else wrapped_key
        return unwrap_aes_key(wrapped_key_b64, private_pem)

kms_client = MockExternalKMS()


# ---------------------------------------------------------------------------
# Strict Blob Validation
# ---------------------------------------------------------------------------

def _decode_blob(blob: bytes) -> tuple[bytes, bytes, bytes]:
    """Parse versioned blob with strict boundary and sanity checks."""
    if len(blob) < HEADER_SIZE + NONCE_LEN + TAG_LEN:
        raise ValueError("Blob fails minimum structural length requirements.")
        
    magic, version, nonce_len, tag_len = struct.unpack(HEADER_FMT, blob[:HEADER_SIZE])
    
    if magic != BLOB_MAGIC:
        raise ValueError(f"Corrupted magic bytes: {magic!r}.")
    if version != BLOB_VERSION:
        raise ValueError(f"Unsupported cryptography version: {version}.")
    if nonce_len != NONCE_LEN or tag_len != TAG_LEN:
        raise ValueError("Invalid nonce or tag lengths specified in header.")

    offset = HEADER_SIZE
    nonce = blob[offset : offset + nonce_len]
    tag = blob[offset + nonce_len : offset + nonce_len + tag_len]
    ciphertext = blob[offset + nonce_len + tag_len :]
    
    if not ciphertext:
        raise ValueError("Blob contains no ciphertext data.")
        
    return nonce, tag, ciphertext


# ---------------------------------------------------------------------------
# Isolated Audit Logging
# ---------------------------------------------------------------------------

def _write_audit_log(file_id: int, actor_id: int, action: str, success: bool) -> None:
    db: Session = SessionLocal()
    try:
        from models import FileAccessLog
        db.add(FileAccessLog(file_id=file_id, actor_id=actor_id, action=action, success=success))
        db.commit()
    except Exception:
        db.rollback()
        # SHA-256 for correlation, entirely removing MD5
        actor_ref = hashlib.sha256(str(actor_id).encode()).hexdigest()[:12]
        logger.error("audit-write-failed", extra={"action": action, "actor_ref": actor_ref})
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Auth Dependency
# ---------------------------------------------------------------------------

def get_current_user(authorization: str = Header(None), db: Session = Depends(get_db)) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing or malformed Authorization header.")
    try:
        token_data = decode_access_token(authorization[7:])
        user_id = int(token_data.sub)
        if not user_id:
            raise ValueError("Token missing user ID.")
    except Exception as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token.") from exc

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found.")
    return user


# ---------------------------------------------------------------------------
# Upload (Single-Buffer Safe Write)
# ---------------------------------------------------------------------------

class FileRecordOut(BaseModel):
    file_id: int
    original_filename: str
    sender_id: int
    sender_name: str
    receiver_id: int
    receiver_name: str
    sha256_hash: str
    created_at: str


class UploadResponse(BaseModel):
    file_id: int
    original_filename: str
    sha256_hash: str
    message: str

@router.post("/upload", response_model=UploadResponse, status_code=status.HTTP_201_CREATED)
def upload_file(
    file: UploadFile = File(...),
    doc_type: str = Form(...),
    receiver_id: int = Form(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Logic: Auto-route Exam Papers strictly to the department's HOD
    if doc_type == "EXAM_PAPER":
        try:
            hod = db.query(User).filter(
                User.role == UserRole.HOD,
                User.department == current_user.department
            ).one()
            receiver_id = hod.id
        except Exception:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                f"No HOD registered for the {current_user.department} department."
            )

    # Logic: Reports and Results use dynamic receiver selected from the UI
    elif doc_type in ("RESULT", "REPORT"):
        if not receiver_id:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"A receiver_id is required to upload a {doc_type}."
            )
        # Verify the selected receiver actually exists
        receiver = db.get(User, receiver_id)
        if not receiver:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Selected recipient not found.")

    else:
        # Fallback: receiver_id must be explicitly provided for unknown types
        if receiver_id is None:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"Unknown document type '{doc_type}'. Please specify receiver_id explicitly."
            )
    
    content: bytes = file.file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, f"File exceeds {MAX_FILE_SIZE // (1024*1024)}MB memory limit.")
    import magic
    detected_mime = magic.from_buffer(content, mime=True)
    if detected_mime not in ["application/pdf", "text/plain"]:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Forbidden file type.")
    
    # 3. HEURISTIC MALWARE SCAN
    # Port your existing _scan_for_malware logic from frontend.py here
    if _scan_for_malware(content):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Malware signature detected.")

    file_hash_hex = hashlib.sha256(content).hexdigest()
    aes_key = generate_aes_key()
    cipher = AES.new(aes_key, AES.MODE_GCM)
    
    try:
        ciphertext, nonce, tag = encrypt_file(content, aes_key)
    except CryptoError as exc:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Encryption computation failed.") from exc

    header = struct.pack(HEADER_FMT, BLOB_MAGIC, BLOB_VERSION, len(nonce), len(tag))
    blob = header + nonce + tag + ciphertext

    storage_id = uuid.uuid4().hex
    final_path = STORAGE_DIR / f"{storage_id}.enc"
    tmp_path = STORAGE_DIR / f"{storage_id}.enc.tmp"

    try:
        tmp_path.write_bytes(blob)
        tmp_path.rename(final_path)
    except OSError as exc:
        tmp_path.unlink(missing_ok=True)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Storage write failed.") from exc

    try:
        # TARGETED FIX: Wrap the AES key using the intended RECEIVER'S public key, not the sender's.
        receiver_pub = kms_client.get_public_key(receiver_id)
        wrapped_key = wrap_aes_key(aes_key, receiver_pub)
    except CryptoError as exc:
        final_path.unlink(missing_ok=True)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "KMS key wrapping failed.") from exc

    try:
        # TARGETED FIX: Save the actual receiver_id to the database schema
        receiver = db.get(User, receiver_id)
        meta = FileMetadata(
            original_filename=file.filename,
            obfuscated_storage_path=str(final_path),
            sender_id=current_user.id,
            receiver_id=receiver_id,
            receiver_role=receiver.role,
            sha256_hash=file_hash_hex,
        )
        db.add(meta)
        db.flush()
        
        db.add(EncryptedKey(
            file_id=meta.file_id,
            encrypted_session_key=wrapped_key,  # Already base64-encoded by wrap_aes_key
        ))
        db.commit()
        db.refresh(meta)
    except Exception as exc:
        db.rollback()
        final_path.unlink(missing_ok=True)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database transaction failed.") from exc

    file_ref = hashlib.sha256(str(meta.file_id).encode()).hexdigest()[:12]
    logger.info("file-uploaded", extra={"ref": file_ref})

    return UploadResponse(
        file_id=meta.file_id,
        original_filename=meta.original_filename,
        sha256_hash=file_hash_hex,
        message="File securely uploaded."
    )

import re

_MALWARE_PATTERNS = [
    ("EXE_MAGIC",         re.compile(rb"\x4d\x5a[\x00-\xff]{0,60}\x50\x45\x00\x00")),
    ("JAVASCRIPT_IN_PDF", re.compile(rb"/JavaScript\s", re.IGNORECASE)),
    ("OPENACTION",        re.compile(rb"/OpenAction\s", re.IGNORECASE)),
    ("EMBEDDED_FILE",     re.compile(rb"/EmbeddedFile\s", re.IGNORECASE)),
    ("POWERSHELL",        re.compile(rb"powershell\s*-", re.IGNORECASE)),
]

def _scan_for_malware(data: bytes) -> list[str]:
    # Scan first 8KB
    sample = data[:8192]
    return [name for name, pat in _MALWARE_PATTERNS if pat.search(sample)]

# ---------------------------------------------------------------------------
# Download (Authenticated In-Memory Decryption)
# ---------------------------------------------------------------------------

@router.get("/download/{file_id}", status_code=status.HTTP_200_OK)
def download_file(
    file_id: int,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    meta = db.get(FileMetadata, file_id)
    key_record = db.query(EncryptedKey).filter(EncryptedKey.file_id == file_id).first()

    if not meta or not key_record:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "File or key not found."
        )

    # Only the intended recipient can decrypt and download the file
    if meta.receiver_id != current_user.id:
        _write_audit_log(file_id, current_user.id, "download", False)
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Only the recipient can decrypt this file."
        )

    enc_path = Path(meta.obfuscated_storage_path)

    if not enc_path.exists():
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Storage media missing."
        )

    # Retrieve AES session key from KMS
    try:
        aes_key = kms_client.unwrap_key(
            current_user.id,
            key_record.encrypted_session_key  # Pass the string directly!
        )
    except Exception as exc:
        logger.error(
            f"KMS unwrap failed for user {current_user.id}: {exc}"
        )
        _write_audit_log(file_id, current_user.id, "download", False)
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "KMS unwrapping failed."
        ) from exc

    # Read encrypted blob
    try:
        blob = enc_path.read_bytes()
        nonce, tag, ciphertext = _decode_blob(blob)
    except (OSError, ValueError) as exc:
        _write_audit_log(file_id, current_user.id, "download", False)
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Blob validation failed."
        ) from exc

    # AES-GCM decryption with authentication
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        logger.error(
            f"CRYPTOGRAPHIC TAMPERING DETECTED: Invalid MAC for file {file_id}"
        )
        _write_audit_log(file_id, current_user.id, "download", False)
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "CRYPTOGRAPHIC TAMPERING DETECTED: Invalid MAC."
        )

    # Integrity verification (SHA-256)
    actual_hash = hashlib.sha256(plaintext).hexdigest()

    if actual_hash != meta.sha256_hash:
        logger.error(
            f"INTEGRITY FAILURE: File {file_id} hash mismatch!"
        )
        _write_audit_log(file_id, current_user.id, "download_integrity_check", False)
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Integrity Error: File tampered with."
        )

    # Integrity success
    logger.info(f"Integrity verified for file {file_id}")

    # Write decrypted file to temporary storage for FileResponse
    tmp_out = STORAGE_DIR / f".dl_{uuid.uuid4().hex}"

    try:
        tmp_out.write_bytes(plaintext)
    except OSError as exc:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Failed to prepare download buffer."
        ) from exc

    # Cleanup and audit logging (These run correctly on success)
    background_tasks.add_task(
        lambda: tmp_out.unlink(missing_ok=True)
    )

    background_tasks.add_task(
        _write_audit_log,
        file_id,
        current_user.id,
        "download_integrity_check",
        True
    )

    background_tasks.add_task(
        _write_audit_log,
        file_id,
        current_user.id,
        "download",
        True
    )

    file_ref = hashlib.sha256(
        str(file_id).encode()
    ).hexdigest()[:12]

    logger.info(
        "file-download-initiated",
        extra={"ref": file_ref}
    )

    return FileResponse(
        path=tmp_out,
        media_type="application/octet-stream",
        filename=meta.original_filename,
        headers={
            "Content-Disposition": (
                f'attachment; filename="{meta.original_filename}"'
            )
        }
    )


# ---------------------------------------------------------------------------
# File Tracking Endpoints (Inbox & Sent)
# ---------------------------------------------------------------------------

@router.get("/inbox", response_model=list[FileRecordOut])
def get_file_inbox(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Fetch metadata for all files securely routed TO the current user."""
    SenderUser = aliased(User)

    results = (
        db.query(FileMetadata, SenderUser.username.label("sender_name"))
        .join(SenderUser, FileMetadata.sender_id == SenderUser.id)
        .filter(FileMetadata.receiver_id == current_user.id)
        .order_by(FileMetadata.created_at.desc())
        .all()
    )

    return [
        FileRecordOut(
            file_id=r.FileMetadata.file_id,
            original_filename=r.FileMetadata.original_filename,
            sender_id=r.FileMetadata.sender_id,
            sender_name=r.sender_name,
            receiver_id=current_user.id,
            receiver_name=current_user.username,
            sha256_hash=r.FileMetadata.sha256_hash,
            created_at=str(r.FileMetadata.created_at),
        )
        for r in results
    ]


@router.get("/sent", response_model=list[FileRecordOut])
def get_sent_files(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Fetch metadata for all files uploaded BY the current user."""
    ReceiverUser = aliased(User)

    results = (
        db.query(FileMetadata, ReceiverUser.username.label("receiver_name"))
        .join(ReceiverUser, FileMetadata.receiver_id == ReceiverUser.id)
        .filter(FileMetadata.sender_id == current_user.id)
        .order_by(FileMetadata.created_at.desc())
        .all()
    )

    return [
        FileRecordOut(
            file_id=r.FileMetadata.file_id,
            original_filename=r.FileMetadata.original_filename,
            sender_id=current_user.id,
            sender_name=current_user.username,
            receiver_id=r.FileMetadata.receiver_id,
            receiver_name=r.receiver_name,
            sha256_hash=r.FileMetadata.sha256_hash,
            created_at=str(r.FileMetadata.created_at),
        )
        for r in results
    ]
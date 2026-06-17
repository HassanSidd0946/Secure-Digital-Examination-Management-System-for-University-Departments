from __future__ import annotations
from sqlalchemy.orm import aliased
import base64
import json
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from auth_service import decode_access_token
from crypto_service import (
    CryptoError,
    calculate_hash,
    decrypt_file as aes_decrypt,
    encrypt_file as aes_encrypt,
    generate_aes_key,
    unwrap_aes_key,
    verify_hash,
    wrap_aes_key,
)
from database import get_db
from models import User, Message
from routers.files import get_current_user          # reuse the JWT dependency

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/comm", tags=["Communication"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class SendMessageRequest(BaseModel):
    receiver_id: int  = Field(gt=0)
    text:        str  = Field(min_length=1, max_length=10_000)


class MessageOut(BaseModel):
    message_id:  int
    sender_id:   int
    receiver_id: int
    created_at:  str


class MessageDecrypted(MessageOut):
    plaintext: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_user_or_404(user_id: int, db: Session) -> User:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"User {user_id} not found.")
    return user


def _get_message_or_404(message_id: int, db: Session) -> Message:
    msg = db.get(Message, message_id)
    if not msg or msg.is_deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Message not found.")
    return msg


def _kms_public_key(user: User) -> bytes:
    """Retrieve RSA public key from KMS. Convert DB string to bytes."""
    key = getattr(user, "public_key_pem", None)
    if not key:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"User {user.id} has no registered public key.")
    # Fix: Ensure key is bytes for the cryptography library
    return key.encode('utf-8') if isinstance(key, str) else key


def _kms_private_key(user: User) -> bytes:
    """Retrieve RSA private key from KMS. Convert DB string to bytes."""
    key = getattr(user, "private_key_pem", None)
    if not key:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No private key available.")
    # Fix: Ensure key is bytes for the cryptography library
    return key.encode('utf-8') if isinstance(key, str) else key


def _audit(db: Session, *, message_id: int, actor_id: int, action: str, success: bool) -> None:
    """Append-only audit; never raises so it can't break the main flow."""
    try:
        from models import FileAccessLog
        db.add(FileAccessLog(file_id=message_id, actor_id=actor_id, action=action, success=success))
        db.commit()
    except Exception as exc:
        logger.error(f"Audit failed: {exc}")
        db.rollback()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/send", response_model=MessageOut, status_code=status.HTTP_201_CREATED)
def send_message(
    payload:      SendMessageRequest,
    current_user: User    = Depends(get_current_user),
    db:           Session = Depends(get_db),
):
    """
    Encrypt *text* for *receiver_id* and persist to the messages table.
    """
    if payload.receiver_id == current_user.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cannot send a message to yourself.")

    receiver = _get_user_or_404(payload.receiver_id, db)
    receiver_pub = _kms_public_key(receiver)

    plaintext_bytes = payload.text.encode()
    aes_key = generate_aes_key()

    try:
        ciphertext, nonce, tag = aes_encrypt(plaintext_bytes, aes_key)
        wrapped_key            = wrap_aes_key(aes_key, receiver_pub)
    except CryptoError as exc:
        logger.error(f"Encryption failed: {exc}")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Encryption failed.") from exc

    # Robust b64 encoder: handles both str and bytes
    def b64(data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.b64encode(data).decode('utf-8')
    
    # Fix: Pack the encryption artifacts into a JSON payload
    # to match the single 'encrypted_content' column in models.py
    payload_data = {
        "ciphertext_b64": b64(ciphertext),
        "nonce_b64": b64(nonce),
        "tag_b64": b64(tag),
        "wrapped_key_b64": b64(wrapped_key), # Now safe even if wrapped_key is a string
        "sha512_hash": calculate_hash(plaintext_bytes)
    }

    try:
        msg = Message(
            sender_id         = current_user.id,
            receiver_id       = receiver.id,
            encrypted_content = json.dumps(payload_data) # Store as JSON string
        )
        db.add(msg)
        db.commit()
        db.refresh(msg)
    except Exception as exc:
        db.rollback()
        logger.error(f"Database insertion failed: {exc}")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Failed to store message.") from exc

    logger.info("message-sent", extra={"ref": msg.id})
    return MessageOut(
        message_id=msg.id, sender_id=msg.sender_id,
        receiver_id=msg.receiver_id, created_at=str(msg.created_at),
    )


@router.get("/inbox", response_model=list[dict])
def get_inbox(
    current_user: User    = Depends(get_current_user),
    db:           Session = Depends(get_db),
):
    """Return metadata along with resolved sender names for the inbox."""
    SenderUser = aliased(User)
    results = (
        db.query(Message, SenderUser.username.label("sender_name"))
        .join(SenderUser, Message.sender_id == SenderUser.id)
        .filter(Message.receiver_id == current_user.id, Message.is_deleted == False)
        .order_by(Message.created_at.desc())
        .all()
    )
    return [
        {
            "message_id": r.Message.id,
            "sender_id": r.Message.sender_id,
            "sender_name": r.sender_name,
            "receiver_id": r.Message.receiver_id,
            "receiver_name": current_user.username,
            "created_at": str(r.Message.created_at),
            "encrypted_content": r.Message.encrypted_content
        }
        for r in results
    ]


@router.get("/messages/{message_id}", response_model=MessageDecrypted)
def read_message(
    message_id:   int,
    current_user: User    = Depends(get_current_user),
    db:           Session = Depends(get_db),
):
    """
    Decrypt and return a single message.
    """
    msg = _get_message_or_404(message_id, db)

    if msg.receiver_id != current_user.id:
        _audit(db, message_id=message_id, actor_id=current_user.id, action="read", success=False)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Access denied.")

    priv_key = _kms_private_key(current_user)
    
    # Fix: Unpack the JSON payload from encrypted_content
    try:
        payload_data = json.loads(msg.encrypted_content)
    except json.JSONDecodeError:
        _audit(db, message_id=message_id, actor_id=current_user.id, action="read", success=False)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Message data is corrupted.")

    b64dec = lambda s: base64.b64decode(s)

    try:
        aes_key   = unwrap_aes_key(b64dec(payload_data["wrapped_key_b64"]), priv_key)
        plaintext = aes_decrypt(
            b64dec(payload_data["ciphertext_b64"]), 
            aes_key,
            b64dec(payload_data["nonce_b64"]), 
            b64dec(payload_data["tag_b64"])
        )
    except CryptoError as exc:
        _audit(db, message_id=message_id, actor_id=current_user.id, action="read", success=False)
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Decryption failed.") from exc

    if not verify_hash(plaintext, payload_data["sha512_hash"]):
        _audit(db, message_id=message_id, actor_id=current_user.id, action="read", success=False)
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Integrity check failed.")

    _audit(db, message_id=message_id, actor_id=current_user.id, action="read", success=True)
    logger.info("message-read", extra={"ref": message_id})

    return MessageDecrypted(
        message_id=msg.id, sender_id=msg.sender_id,
        receiver_id=msg.receiver_id, created_at=str(msg.created_at),
        plaintext=plaintext.decode(),
    )


@router.delete("/messages/{message_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_message(
    message_id:   int,
    current_user: User    = Depends(get_current_user),
    db:           Session = Depends(get_db),
):
    """
    Soft-delete a message.  Only sender or receiver may delete.
    """
    msg = _get_message_or_404(message_id, db)

    if current_user.id not in (msg.sender_id, msg.receiver_id):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Access denied.")

    msg.is_deleted = True
    db.commit()
    logger.info("message-deleted", extra={"ref": message_id})

@router.get("/sent", response_model=list[dict])
def get_sent_messages(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return metadata along with resolved receiver names for sent messages."""
    ReceiverUser = aliased(User)
    results = (
        db.query(Message, ReceiverUser.username.label("receiver_name"))
        .join(ReceiverUser, Message.receiver_id == ReceiverUser.id)
        .filter(Message.sender_id == current_user.id)
        .order_by(Message.created_at.desc())
        .all()
    )
    return [
        {
            "message_id": r.Message.id,
            "sender_id": r.Message.sender_id,
            "sender_name": current_user.username,
            "receiver_id": r.Message.receiver_id,
            "receiver_name": r.receiver_name,
            "created_at": str(r.Message.created_at),
            "encrypted_content": r.Message.encrypted_content
        }
        for r in results
    ]
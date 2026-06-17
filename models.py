

from __future__ import annotations

import enum
from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)


# ---------------------------------------------------------------------------
# 1.  Shared base — single source of truth for metadata
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    """
    Project-wide declarative base.

    Uses the modern SQLAlchemy 2.x class-based form instead of the
    deprecated `declarative_base()` factory. Both produce identical
    metadata; the class form is forward-compatible.
    """
    __allow_unmapped__ = True


# ---------------------------------------------------------------------------
# 2.  Enumerations — replaces unconstrained role strings
# ---------------------------------------------------------------------------

class UserRole(str, enum.Enum):
    """
    Valid roles within the system.

    Inheriting from `str` means SQLAlchemy stores the value as a plain
    string, so existing data is unaffected when migrating. It also
    makes JSON serialisation trivial.
    """
    ADMIN      = "admin"
    FACULTY    = "faculty"
    HOD        = "hod"
    DEPARTMENT = "department"


# ---------------------------------------------------------------------------
# 3.  Shared Enum — reused across all tables
# ---------------------------------------------------------------------------

# Define the Enum type once to reuse it in multiple columns, avoiding
# duplicate database constraints and ensuring consistency.
USER_ROLE_ENUM = Enum(UserRole, name="user_role_enum", create_constraint=True)


# ---------------------------------------------------------------------------
# 4.  Timestamp mixin — reused across all tables
# ---------------------------------------------------------------------------

class TimestampMixin:
    """
    Adds `created_at` / `updated_at` to any model that inherits this mixin.

    `server_default=func.now()` delegates the default to the database
    engine, making it reliable even for bulk inserts that bypass the ORM.
    `onupdate=func.now()` automatically refreshes `updated_at` on every
    UPDATE statement.
    """
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


# ---------------------------------------------------------------------------
# 5.  Constants
# ---------------------------------------------------------------------------

# SHA-256 hex digest is always 64 characters; pin the column length so the
# DB engine can use a fixed-length type instead of an unbounded TEXT column.
SHA256_HEX_LENGTH: int = 64

# A hex-encoded 16-byte (128-bit) salt is 32 chars; allow up to 64 for
# larger salts without a schema migration.
SALT_HEX_MAX_LENGTH: int = 64

# Bcrypt/Argon2 hashes are longer than SHA-256. Bcrypt produces 60-char hashes
# with fixed format; Argon2 can be 80+ chars. Use 255 for flexibility.
PASSWORD_HASH_MAX_LENGTH: int = 255


# ---------------------------------------------------------------------------
# 5.  Models
# ---------------------------------------------------------------------------

class User(TimestampMixin, Base):
    """
    Application user — human actor identified by a unique username.

    Security notes
    --------------
    * `password_hash`  — store a *salted* bcrypt/argon2 digest (SHA-256 alone is
                         too fast for password hashing in 2024+).
    * `salt_hex`       — per-user random salt, hex-encoded.
    * `role`           — constrained by the UserRole enum; the DB will
                         reject any out-of-range value at the storage layer.

    Indexes
    -------
    * `username` — frequently queried for authentication and duplicate prevention
    """

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("username", name="uq_users_username"),
        UniqueConstraint("role", "department", name="uq_one_hod_per_department"),
    )

    # --- identity ---
    id:       Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(150), nullable=False, index=True)
    department: Mapped[str] = mapped_column(String(100), nullable=False, default="General")
    # --- credentials ---
    password_hash: Mapped[str] = mapped_column(String(PASSWORD_HASH_MAX_LENGTH), nullable=False)
    salt_hex:      Mapped[str] = mapped_column(String(SALT_HEX_MAX_LENGTH), nullable=False)

    # --- authorisation ---
    role: Mapped[UserRole] = mapped_column(USER_ROLE_ENUM, nullable=False)

    public_key_pem: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    private_key_pem: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)

    # --- relationships ---
    sent_files: List["FileMetadata"] = relationship(
        "FileMetadata",
        back_populates="sender",
        foreign_keys="[FileMetadata.sender_id]",
        cascade="all, delete-orphan",
        lazy="select",
    )

    def __repr__(self) -> str:
        return (
            f"<User id={self.id!r} username={self.username!r} "
            f"role={self.role!r}>"
        )


class FileMetadata(TimestampMixin, Base):
    """
    Metadata record for every file processed by the system.

    The actual file content lives on disk at `obfuscated_storage_path`; the
    `sha256_hash` column lets the application verify integrity without
    re-reading the file from storage.

    Column notes
    ------------
    * `original_filename`       — user-supplied name; NEVER used as a path.
    * `obfuscated_storage_path` — server-generated UUID-based path; NEVER
                                  derived from `original_filename`.
    * `receiver_role`           — the UserRole that may download this file.

    Indexes
    -------
    * `sender_id`         — foreign key, frequently filtered in list queries
    * `obfuscated_storage_path` — unique, already indexed
    """

    __tablename__ = "file_metadata"

    # --- identity ---
    file_id:                 Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    original_filename:       Mapped[str] = mapped_column(String(255), nullable=False)
    obfuscated_storage_path: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)

    # --- ownership / access ---
    sender_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,  # frequently filtered in user file queries
    )
    receiver_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,  # frequently filtered for access control
    )
    receiver_role: Mapped[UserRole] = mapped_column(USER_ROLE_ENUM, nullable=False)

    # --- integrity ---
    sha256_hash: Mapped[str] = mapped_column(String(SHA256_HEX_LENGTH), nullable=False)

    # --- relationships ---
    sender: "User" = relationship("User", back_populates="sent_files", foreign_keys=[sender_id])
    encrypted_key: Optional["EncryptedKey"] = relationship(
        "EncryptedKey",
        back_populates="file_metadata",
        uselist=False,           # enforces one-to-one at ORM level
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return (
            f"<FileMetadata file_id={self.file_id!r} "
            f"filename={self.original_filename!r} "
            f"sender_id={self.sender_id!r}>"
        )


class EncryptedKey(TimestampMixin, Base):
    """
    RSA-wrapped AES session key for a single FileMetadata record.

    Architecture note
    -----------------
    Each file is encrypted with a one-time AES session key (hybrid
    encryption). That session key is itself RSA-encrypted with the
    receiver's public key and stored here. This table therefore holds
    *exactly one* row per FileMetadata row (enforced by the UNIQUE
    constraint on `file_id` and `uselist=False` in the relationship).
    """

    __tablename__ = "encrypted_keys"

    # --- identity ---
    id:      Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    file_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("file_metadata.file_id", ondelete="CASCADE"),
        nullable=False,
        unique=True,    # enforces the one-to-one relationship at DB level
    )

    # --- key material ---
    # RSA-2048 produces 256-byte ciphertext → 344-char base64; allow 512
    # to accommodate RSA-4096 or other future key-wrapping schemes.
    encrypted_session_key: Mapped[str] = mapped_column(String(512), nullable=False)

    # --- relationships ---
    file_metadata: "FileMetadata" = relationship(
        "FileMetadata",
        back_populates="encrypted_key",
    )

    def __repr__(self) -> str:
        return f"<EncryptedKey id={self.id!r} file_id={self.file_id!r}>"


class Message(TimestampMixin, Base):
    """
    Encrypted message model for communication between users.

    Architecture note
    -----------------
    Allows users to send encrypted messages to each other. The message content
    is stored encrypted and can only be decrypted by the intended receiver using
    their private key. This provides secure inter-department communication.

    Column notes
    -----------
    * `sender_id`          — user sending the message
    * `receiver_id`        — user receiving the message
    * `encrypted_content`  — RSA-encrypted message content (base64-encoded)

    Indexes
    -------
    * `sender_id`   — frequently filtered to fetch sent messages
    * `receiver_id` — frequently filtered to fetch received messages
    """

    __tablename__ = "messages"

    # --- identity ---
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    # --- ownership / access ---
    sender_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    receiver_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # --- content ---
    encrypted_content: Mapped[str] = mapped_column(String(2048), nullable=False)

    def __repr__(self) -> str:
        return (
            f"<Message id={self.id!r} sender_id={self.sender_id!r} "
            f"receiver_id={self.receiver_id!r}>"
        )
    
class FileAccessLog(TimestampMixin, Base):
    __tablename__ = "file_access_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    file_id: Mapped[int] = mapped_column(ForeignKey("file_metadata.file_id"))
    actor_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String(50))
    success: Mapped[bool] = mapped_column(Boolean)
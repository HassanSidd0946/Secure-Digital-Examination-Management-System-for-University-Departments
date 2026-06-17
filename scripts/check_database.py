#!/usr/bin/env python
"""Check database encryption key storage"""
import sys
sys.path.insert(0, 'D:\\Desktop\\CS\\CS\\Crypto\\Project_crypto')

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import FileMetadata, EncryptedKey, Base
from config import settings
import base64

# Connect to database using the same URL as the FastAPI server
engine = create_engine(settings.DATABASE_URL)
Session = sessionmaker(bind=engine)
db = Session()

# Query latest uploaded file
file_metadata = db.query(FileMetadata).order_by(FileMetadata.file_id.desc()).first()
if not file_metadata:
    print("No files found")
    exit(1)

print("Latest uploaded file:")
print(f"  File ID: {file_metadata.file_id}")
print(f"  Sender ID: {file_metadata.sender_id}")
print(f"  Receiver ID: {file_metadata.receiver_id}")
print(f"  SHA256: {file_metadata.sha256_hash[:20]}...")
print()

# Query encrypted key
encrypted_key = db.query(EncryptedKey).filter(EncryptedKey.file_id == file_metadata.file_id).first()
if not encrypted_key:
    print("No encrypted key found")
    exit(1)

print("Encrypted key record:")
print(f"  File ID: {encrypted_key.file_id}")
print(f"  Encrypted Key Type: {type(encrypted_key.encrypted_session_key)}")
print(f"  Encrypted Key Length: {len(encrypted_key.encrypted_session_key)} bytes")
print(f"  Encrypted Key (first 100 chars): {str(encrypted_key.encrypted_session_key)[:100]}")
print()

# Try to decode as base64
try:
    decoded = base64.b64decode(encrypted_key.encrypted_session_key)
    print(f"✓ Successfully decoded as base64: {len(decoded)} bytes")
except Exception as e:
    print(f"✗ Failed to decode as base64: {e}")

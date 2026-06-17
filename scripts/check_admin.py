#!/usr/bin/env python
"""Check admin receiver"""
import sys
sys.path.insert(0, 'D:\\Desktop\\CS\\CS\\Crypto\\Project_crypto')

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import FileMetadata, User
from config import settings

engine = create_engine(settings.DATABASE_URL)
Session = sessionmaker(bind=engine)
db = Session()

# Get latest file
file_meta = db.query(FileMetadata).filter(FileMetadata.file_id == 15).first()
if file_meta:
    print(f"File 15:")
    print(f"  Receiver ID: {file_meta.receiver_id}")
    receiver = db.get(User, file_meta.receiver_id)
    print(f"  Receiver: {receiver.username} (ID: {receiver.id})")
    print()

# Get all admin users
admins = db.query(User).filter(User.role == 'admin').all()
print(f"All Admin users:")
for admin in admins:
    print(f"  - {admin.username} (ID: {admin.id})")

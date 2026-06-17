#!/usr/bin/env python
"""Debug receiver_id issue"""
import sys
sys.path.insert(0, 'D:\\Desktop\\CS\\CS\\Crypto\\Project_crypto')

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import FileMetadata, User
from config import settings

# Connect to database
engine = create_engine(settings.DATABASE_URL)
Session = sessionmaker(bind=engine)
db = Session()

# Get latest file
file_meta = db.query(FileMetadata).order_by(FileMetadata.file_id.desc()).first()
print(f"Latest file ID: {file_meta.file_id}")
print(f"Sender ID: {file_meta.sender_id}")
print(f"Receiver ID: {file_meta.receiver_id}")
print(f"Receiver role: {file_meta.receiver_role}")
print()

# Get sender
sender = db.get(User, file_meta.sender_id)
print(f"Sender: {sender.username} (ID: {sender.id}, role: {sender.role})")

# Get receiver
receiver = db.get(User, file_meta.receiver_id)
print(f"Receiver: {receiver.username} (ID: {receiver.id}, role: {receiver.role})")
print()

# Get all HOD users
hods = db.query(User).filter(User.role == 'hod').all()
print(f"All HOD users:")
for hod in hods:
    print(f"  - {hod.username} (ID: {hod.id})")

#!/usr/bin/env python
"""Check admin_user password"""
import sys
sys.path.insert(0, 'D:\\Desktop\\CS\\CS\\Crypto\\Project_crypto')

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import User
from config import settings

engine = create_engine(settings.DATABASE_URL)
Session = sessionmaker(bind=engine)
db = Session()

# Get admin_user
admin = db.query(User).filter(User.username == 'admin_user').first()
if admin:
    print(f"admin_user found (ID: {admin.id})")
    print(f"  Password hash: {admin.password_hash[:50]}...")
else:
    print("admin_user not found")

# Try common passwords
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

passwords_to_try = ['admin', 'AdminPass123', 'password', 'Admin@123', 'admin123', 'test123']
print("\nTrying to verify passwords:")
for pwd in passwords_to_try:
    if admin:
        try:
            if pwd_context.verify(pwd, admin.password_hash):
                print(f"  ✓ Password matches: {pwd}")
            else:
                print(f"  ✗ {pwd}")
        except:
            print(f"  ✗ {pwd} (error)")

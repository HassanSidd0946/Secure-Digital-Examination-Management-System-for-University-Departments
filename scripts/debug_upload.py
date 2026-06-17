#!/usr/bin/env python
"""Debug file upload endpoint"""
import requests
import io
import json
import time

BASE_URL = 'http://127.0.0.1:8000'
timestamp = str(int(time.time()))

# Step 1: Register user with specific role (HOD or ADMIN)
print("[Step 1] Registering HOD user...")
r = requests.post(f'{BASE_URL}/auth/register', json={
    'username': f'hod_{timestamp}',
    'password': 'TestPass123',
    'role': 'hod'  # Try HOD role
}, timeout=5)
print(f"  Status: {r.status_code}")
if r.status_code != 201:
    print(f"  Error: {r.text}")
    exit(1)

# Step 2: Register faculty user
print("[Step 2] Registering faculty user...")
r = requests.post(f'{BASE_URL}/auth/register', json={
    'username': f'faculty_{timestamp}',
    'password': 'TestPass123',
    'role': 'faculty'
}, timeout=5)
print(f"  Status: {r.status_code}")
if r.status_code != 201 and r.status_code != 409:
    print(f"  Error: {r.text}")
    exit(1)

# Step 3: Login as faculty
print("[Step 3] Logging in as faculty...")
r = requests.post(f'{BASE_URL}/auth/login', json={
    'username': f'faculty_{timestamp}',
    'password': 'TestPass123'
}, timeout=5)
print(f"  Status: {r.status_code}")
if r.status_code != 200:
    print(f"  Error: {r.text}")
    exit(1)
token = r.json()['access_token']
print(f"  Token: {token[:20]}...")

# Step 4: Upload file with EXAM_PAPER doc type (should route to HOD)
print("[Step 4] Uploading file with EXAM_PAPER doc_type...")
headers = {'Authorization': f'Bearer {token}'}
files = {'file': ('exam.txt', io.BytesIO(b'Exam confidential data'))}
data = {'doc_type': 'EXAM_PAPER'}

r = requests.post(f'{BASE_URL}/files/upload', files=files, data=data, headers=headers, timeout=10)
print(f"  Status: {r.status_code}")
print(f"  Response: {r.text}")

if r.status_code != 201:
    print("\n[DEBUG] Checking what routes are available...")
    r = requests.get(f'{BASE_URL}/docs', timeout=5)
    if r.status_code == 200:
        print("  OpenAPI docs endpoint is available")
    
    print("\n[DEBUG] Checking file router directly...")
    r = requests.options(f'{BASE_URL}/files/upload', timeout=5)
    print(f"  OPTIONS /files/upload: {r.status_code}")

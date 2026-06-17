#!/usr/bin/env python
"""Quick test of file upload"""
import requests
import io

BASE_URL = 'http://127.0.0.1:8000'

# Register 2 users
print('[1] Registering user 1 (faculty)...')
r1 = requests.post(f'{BASE_URL}/auth/register', json={
    'username': 'faculty_user',
    'password': 'Password123',
    'role': 'faculty'
}, timeout=5)
print(f'    Status: {r1.status_code}')

print('[2] Registering user 2 (admin)...')
r2 = requests.post(f'{BASE_URL}/auth/register', json={
    'username': 'admin_user',
    'password': 'Password123',
    'role': 'admin'
}, timeout=5)
print(f'    Status: {r2.status_code}')

print('[3] Logging in as faculty...')
r = requests.post(f'{BASE_URL}/auth/login', json={
    'username': 'faculty_user',
    'password': 'Password123'
}, timeout=5)
token = r.json()['access_token']
print(f'    Status: {r.status_code}')

# Test file upload with RESULT (auto-routes to admin)
print('[4] Uploading file as RESULT...')
data = {'doc_type': 'RESULT'}
files = {'file': ('results.txt', io.BytesIO(b'Student results data'))}
headers = {'Authorization': f'Bearer {token}'}
r = requests.post(f'{BASE_URL}/files/upload', data=data, files=files, headers=headers, timeout=10)
print(f'    Status: {r.status_code}')
if r.status_code in [200, 201]:
    print(f'    SUCCESS: {r.json().get("message")}')
    print(f'    File ID: {r.json().get("file_id")}')
else:
    print(f'    ERROR: {r.json()}')

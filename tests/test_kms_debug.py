#!/usr/bin/env python
"""Test file upload and download with KMS debugging"""
import requests
import io
import time
import json

BASE_URL = 'http://127.0.0.1:8000'
timestamp = str(int(time.time()))

print("=" * 70)
print("KMS DEBUGGING - UPLOAD & DOWNLOAD")
print("=" * 70)
print()

try:
    # [1] Register HOD
    print("[1] Registering HOD user...")
    r = requests.post(f'{BASE_URL}/auth/register', json={
        'username': f'hod_debug_{timestamp}',
        'password': 'TestPass123',
        'role': 'hod'
    }, timeout=5)
    print(f"    Status: {r.status_code}")
    if r.status_code != 201:
        print(f"    Error: {r.text}")
        exit(1)
    hod_id = r.json().get('user_id')
    print(f"    HOD ID: {hod_id}")
    
    # [2] Register Faculty
    print("[2] Registering faculty user...")
    r = requests.post(f'{BASE_URL}/auth/register', json={
        'username': f'faculty_debug_{timestamp}',
        'password': 'TestPass123',
        'role': 'faculty'
    }, timeout=5)
    faculty_id = r.json().get('user_id')
    print(f"    Faculty ID: {faculty_id}")
    
    # [3] Faculty login
    print("[3] Faculty login...")
    r = requests.post(f'{BASE_URL}/auth/login', json={
        'username': f'faculty_debug_{timestamp}',
        'password': 'TestPass123'
    }, timeout=5)
    token = r.json()['access_token']
    print(f"    Token obtained")
    
    headers = {'Authorization': f'Bearer {token}'}
    
    # [4] Upload file
    print("[4] Uploading EXAM_PAPER...")
    test_content = b'Test exam content'
    files = {'file': ('exam.txt', io.BytesIO(test_content))}
    data = {'doc_type': 'EXAM_PAPER'}
    
    r = requests.post(f'{BASE_URL}/files/upload', files=files, data=data, headers=headers, timeout=10)
    print(f"    Upload Status: {r.status_code}")
    if r.status_code != 201:
        print(f"    Error: {r.text}")
        exit(1)
    upload_response = r.json()
    file_id = upload_response['file_id']
    print(f"    File ID: {file_id}")
    print(f"    Response: {json.dumps(upload_response, indent=2)}")
    
    # [5] Download file (will fail but let's see the error)
    print("[5] Attempting download...")
    r = requests.get(f'{BASE_URL}/files/download/{file_id}', headers=headers, timeout=10)
    print(f"    Download Status: {r.status_code}")
    print(f"    Response: {r.text}")
    
except Exception as e:
    print(f"[ERROR] {e}")
    import traceback
    traceback.print_exc()

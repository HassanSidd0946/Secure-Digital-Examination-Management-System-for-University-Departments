#!/usr/bin/env python
"""Test complete workflow by querying API for user IDs"""
import requests
import io
import hashlib
import time

BASE_URL = 'http://127.0.0.1:8000'
timestamp = str(int(time.time()))

print("=" * 70)
print("SIMPLIFIED FILE WORKFLOW TEST")
print("=" * 70)
print()

try:
    # [1] Create Admin user
    print("[1] Creating Admin user...")
    r = requests.post(f'{BASE_URL}/auth/register', json={
        'username': f'admin_final_{timestamp}',
        'password': 'TestPass123',
        'role': 'admin'
    }, timeout=5)
    print(f"    Status: {r.status_code}")
    
    # [2] Create Faculty
    print("[2] Creating Faculty user...")
    r = requests.post(f'{BASE_URL}/auth/register', json={
        'username': f'faculty_test_{timestamp}',
        'password': 'TestPass123',
        'role': 'faculty'
    }, timeout=5)
    print(f"    Status: {r.status_code}")
    
    # [3] Faculty login
    print("[3] Faculty login...")
    r = requests.post(f'{BASE_URL}/auth/login', json={
        'username': f'faculty_test_{timestamp}',
        'password': 'TestPass123'
    }, timeout=5)
    assert r.status_code == 200
    faculty_token = r.json()['access_token']
    faculty_headers = {'Authorization': f'Bearer {faculty_token}'}
    print(f"    ✓ Logged in\n")
    
    # [4] Upload as RESULT doc_type (routes to Admin)
    print("[4] Upload RESULT document...")
    test_content = b'Student Results - Confidential'
    files = {'file': ('results.txt', io.BytesIO(test_content))}
    data = {'doc_type': 'RESULT'}
    
    r = requests.post(f'{BASE_URL}/files/upload', files=files, data=data, headers=faculty_headers, timeout=15)
    if r.status_code != 201:
        print(f"    ✗ Upload failed: {r.status_code}")
        print(f"       {r.text}")
        exit(1)
    
    upload_resp = r.json()
    file_id = upload_resp['file_id']
    original_hash = upload_resp['sha256_hash']
    print(f"    ✓ Uploaded (ID: {file_id})")
    print(f"    ✓ Original SHA-256: {original_hash}\n")
    
    # [5] Admin login
    print("[5] Admin login...")
    r = requests.post(f'{BASE_URL}/auth/login', json={
        'username': f'admin_final_{timestamp}',
        'password': 'TestPass123'
    }, timeout=5)
    if r.status_code != 200:
        print(f"    ✗ Admin login failed: {r.status_code}")
        exit(1)
    admin_token = r.json()['access_token']
    admin_headers = {'Authorization': f'Bearer {admin_token}'}
    print(f"    ✓ Logged in\n")
    
    # [6] Admin downloads file
    print("[6] Admin downloads file...")
    print(f"    ⏳ Downloading (RSA decryption takes ~5-10s)...")
    r = requests.get(f'{BASE_URL}/files/download/{file_id}', headers=admin_headers, timeout=60)
    
    if r.status_code == 200:
        print(f"    ✓ Download successful (200)")
        downloaded_content = r.content
        download_hash = hashlib.sha256(downloaded_content).hexdigest()
        print(f"    ✓ Downloaded SHA-256: {download_hash}")
        
        if download_hash == original_hash:
            print(f"    ✓ INTEGRITY CHECK PASSED")
        
        if downloaded_content == test_content:
            print(f"    ✓ Content decrypted correctly\n")
            print("=" * 70)
            print("✓ ALL TESTS PASSED - SYSTEM IS OPERATIONAL")
            print("=" * 70)
        else:
            print(f"    ✗ Content mismatch\n")
    elif r.status_code == 403:
        print(f"    ✗ Access denied (403) - receiver mismatch\n")
    else:
        print(f"    ✗ Download failed: {r.status_code}")
        print(f"       {r.text}\n")
    
except Exception as e:
    print(f"[ERROR] {e}")
    import traceback
    traceback.print_exc()

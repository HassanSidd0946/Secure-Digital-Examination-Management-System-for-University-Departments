#!/usr/bin/env python
"""Test complete workflow using existing admin_user"""
import requests
import io
import hashlib
import time

BASE_URL = 'http://127.0.0.1:8000'
timestamp = str(int(time.time()))

print("=" * 70)
print("FILE WORKFLOW TEST (Using Existing admin_user)")
print("=" * 70)
print()

try:
    # [1] Create Faculty
    print("[1] Creating Faculty user...")
    r = requests.post(f'{BASE_URL}/auth/register', json={
        'username': f'faculty_test_{timestamp}',
        'password': 'TestPass123',
        'role': 'faculty'
    }, timeout=5)
    print(f"    Status: {r.status_code}")
    
    # [2] Faculty login
    print("[2] Faculty login...")
    r = requests.post(f'{BASE_URL}/auth/login', json={
        'username': f'faculty_test_{timestamp}',
        'password': 'TestPass123'
    }, timeout=5)
    assert r.status_code == 200
    faculty_token = r.json()['access_token']
    faculty_headers = {'Authorization': f'Bearer {faculty_token}'}
    print(f"    ✓ Logged in\n")
    
    # [3] Upload RESULT document (routes to admin_user)
    print("[3] Upload RESULT document...")
    test_content = b'Student Results - Confidential Data'
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
    
    # [4] admin_user login (the receiver)
    print("[4] admin_user login...")
    r = requests.post(f'{BASE_URL}/auth/login', json={
        'username': 'admin_user',
        'password': 'AdminPass123'
    }, timeout=5)
    if r.status_code != 200:
        print(f"    ✗ admin_user login failed: {r.status_code}")
        print(f"       Trying 'admin' as password...")
        r = requests.post(f'{BASE_URL}/auth/login', json={
            'username': 'admin_user',
            'password': 'admin'
        }, timeout=5)
        if r.status_code != 200:
            print(f"    ✗ admin_user login still failed")
            exit(1)
    admin_token = r.json()['access_token']
    admin_headers = {'Authorization': f'Bearer {admin_token}'}
    print(f"    ✓ Logged in\n")
    
    # [5] admin_user downloads file
    print("[5] admin_user downloads file...")
    print(f"    ⏳ Downloading (RSA decryption takes ~5-10s)...")
    r = requests.get(f'{BASE_URL}/files/download/{file_id}', headers=admin_headers, timeout=60)
    
    if r.status_code == 200:
        print(f"    ✓ Download successful (200)")
        downloaded_content = r.content
        download_hash = hashlib.sha256(downloaded_content).hexdigest()
        print(f"    ✓ Downloaded SHA-256: {download_hash}")
        
        if download_hash == original_hash:
            print(f"    ✓ INTEGRITY CHECK PASSED")
        else:
            print(f"    ✗ Hash mismatch!")
            print(f"       Original:   {original_hash}")
            print(f"       Downloaded: {download_hash}")
        
        if downloaded_content == test_content:
            print(f"    ✓ Content decrypted correctly\n")
            print("=" * 70)
            print("✓✓✓ ALL TESTS PASSED - FILE ENCRYPTION SYSTEM OPERATIONAL ✓✓✓")
            print("=" * 70)
        else:
            print(f"    ✗ Content mismatch")
            print(f"       Original:   {test_content}")
            print(f"       Downloaded: {downloaded_content}\n")
    elif r.status_code == 403:
        print(f"    ✗ Access denied (403) - incorrect receiver\n")
    else:
        print(f"    ✗ Download failed: {r.status_code}")
        print(f"       {r.text}\n")
    
except Exception as e:
    print(f"[ERROR] {e}")
    import traceback
    traceback.print_exc()

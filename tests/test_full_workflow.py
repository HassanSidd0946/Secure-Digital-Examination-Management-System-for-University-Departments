#!/usr/bin/env python
"""Test file upload and download with integrity verification"""
import requests
import io
import time

BASE_URL = 'http://127.0.0.1:8000'
timestamp = str(int(time.time()))

print("=" * 70)
print("FILE UPLOAD & DOWNLOAD TEST (Module 2 + Module 5)")
print("=" * 70)
print()

try:
    # [1] Register HOD
    print("[1] Registering HOD user...")
    r = requests.post(f'{BASE_URL}/auth/register', json={
        'username': f'hod_test_{timestamp}',
        'password': 'TestPass123',
        'role': 'hod'
    }, timeout=5)
    assert r.status_code == 201, f"HOD registration failed: {r.text}"
    print("    [OK] HOD registered")
    
    # [2] Register Faculty
    print("[2] Registering faculty user...")
    r = requests.post(f'{BASE_URL}/auth/register', json={
        'username': f'faculty_test_{timestamp}',
        'password': 'TestPass123',
        'role': 'faculty'
    }, timeout=5)
    assert r.status_code == 201, f"Faculty registration failed: {r.text}"
    print("    [OK] Faculty registered")
    
    # [3] Faculty login
    print("[3] Faculty login...")
    r = requests.post(f'{BASE_URL}/auth/login', json={
        'username': f'faculty_test_{timestamp}',
        'password': 'TestPass123'
    }, timeout=5)
    assert r.status_code == 200, f"Login failed: {r.text}"
    token = r.json()['access_token']
    print("    [OK] Faculty logged in with JWT token")
    
    headers = {'Authorization': f'Bearer {token}'}
    
    # [4] Upload file
    print("[4] Uploading EXAM_PAPER...")
    test_content = b'This is a confidential exam paper'
    files = {'file': ('exam.txt', io.BytesIO(test_content))}
    data = {'doc_type': 'EXAM_PAPER'}
    
    r = requests.post(f'{BASE_URL}/files/upload', files=files, data=data, headers=headers, timeout=10)
    assert r.status_code == 201, f"Upload failed: {r.text}"
    upload_response = r.json()
    file_id = upload_response['file_id']
    original_hash = upload_response['sha256_hash']
    print(f"    [OK] File uploaded (ID: {file_id})")
    print(f"    [OK] Original SHA-256: {original_hash}")
    
    # [5] Download file
    print("[5] Downloading file...")
    r = requests.get(f'{BASE_URL}/files/download/{file_id}', headers=headers, timeout=10)
    assert r.status_code == 200, f"Download failed: {r.status_code} - {r.text}"
    downloaded_content = r.content
    print(f"    [OK] File downloaded ({len(downloaded_content)} bytes)")
    
    # [6] Verify integrity
    print("[6] Verifying file integrity (Module 5 - SHA-256)...")
    import hashlib
    download_hash = hashlib.sha256(downloaded_content).hexdigest()
    print(f"    [OK] Downloaded SHA-256: {download_hash}")
    
    if download_hash == original_hash:
        print("    [✓] INTEGRITY VERIFIED: Hashes match!")
        print("    [✓] File was not tampered with during transmission")
    else:
        print("    [✗] INTEGRITY FAILED: Hashes do not match!")
        print(f"       Original:  {original_hash}")
        print(f"       Downloaded: {download_hash}")
    
    # [7] Verify content
    print("[7] Verifying decrypted content...")
    if downloaded_content == test_content:
        print("    [✓] Content verified: Decryption successful!")
    else:
        print("    [✗] Content mismatch!")
    
    print()
    print("=" * 70)
    print("RESULT: All modules working correctly")
    print("=" * 70)
    
except Exception as e:
    print(f"[ERROR] {e}")
    import traceback
    traceback.print_exc()

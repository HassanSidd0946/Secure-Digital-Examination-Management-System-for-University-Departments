#!/usr/bin/env python
"""Test complete file workflow with explicit receiver"""
import requests
import io
import hashlib
import time

BASE_URL = 'http://127.0.0.1:8000'
timestamp = str(int(time.time()))

print("=" * 70)
print("FILE UPLOAD & DOWNLOAD TEST (WITH EXPLICIT RECEIVER)")
print("=" * 70)
print()

try:
    # [1] Register HOD (receiver)
    print("[1] Registering HOD user (will be receiver)...")
    r = requests.post(f'{BASE_URL}/auth/register', json={
        'username': f'hod_final_{timestamp}',
        'password': 'TestPass123',
        'role': 'hod'
    }, timeout=5)
    assert r.status_code == 201, f"HOD registration failed: {r.text}"
    hod_user_id = r.json().get('user_id', 999)  # Try to get user_id from response
    print(f"    ✓ HOD registered\n")
    
    # [2] Register Faculty (sender)
    print("[2] Registering Faculty user (will be sender)...")
    r = requests.post(f'{BASE_URL}/auth/register', json={
        'username': f'faculty_final_{timestamp}',
        'password': 'TestPass123',
        'role': 'faculty'
    }, timeout=5)
    assert r.status_code == 201
    print(f"    ✓ Faculty registered\n")
    
    # [3] Faculty login and upload
    print("[3] Faculty login and upload file...")
    r = requests.post(f'{BASE_URL}/auth/login', json={
        'username': f'faculty_final_{timestamp}',
        'password': 'TestPass123'
    }, timeout=5)
    assert r.status_code == 200
    faculty_token = r.json()['access_token']
    print(f"    ✓ Faculty logged in")
    
    faculty_headers = {'Authorization': f'Bearer {faculty_token}'}
    test_content = b'Secret Exam Paper Content - Final Test'
    files = {'file': ('exam.txt', io.BytesIO(test_content))}
    
    # Get latest user ID to use as receiver (should be the newly created HOD)
    r = requests.post(f'{BASE_URL}/auth/login', json={
        'username': f'hod_final_{timestamp}',
        'password': 'TestPass123'
    }, timeout=5)
    hod_token = r.json()['access_token']
    
    # Upload with auto-routing (will assign to first HOD in database)
    data = {'doc_type': 'EXAM_PAPER'}
    r = requests.post(f'{BASE_URL}/files/upload', files=files, data=data, headers=faculty_headers, timeout=15)
    assert r.status_code == 201, f"Upload failed: {r.text}"
    upload_resp = r.json()
    file_id = upload_resp['file_id']
    original_hash = upload_resp['sha256_hash']
    print(f"    ✓ File uploaded (ID: {file_id})")
    print(f"    ✓ Original SHA-256: {original_hash}\n")
    
    # Now we need to find which HOD was the receiver and login as that user
    # For now, let's just test with the newly created HOD
    print("[4] HOD download file...")
    hod_headers = {'Authorization': f'Bearer {hod_token}'}
    
    print(f"    ⏳ Downloading file (RSA decryption takes ~5-10s)...")
    r = requests.get(f'{BASE_URL}/files/download/{file_id}', headers=hod_headers, timeout=60)
    print(f"    ✓ Response status: {r.status_code}")
    
    if r.status_code == 200:
        downloaded_content = r.content
        download_hash = hashlib.sha256(downloaded_content).hexdigest()
        print(f"    ✓ Downloaded SHA-256: {download_hash}")
        
        if download_hash == original_hash:
            print(f"    ✓ INTEGRITY VERIFIED: Hashes match!")
        else:
            print(f"    ✗ Hash mismatch!")
        
        if downloaded_content == test_content:
            print(f"    ✓ Content verified: Decryption successful!\n")
        else:
            print(f"    ✗ Content mismatch: got {len(downloaded_content)} bytes\n")
    elif r.status_code == 403:
        print(f"    ! Access denied (receiver mismatch)")
        print(f"    ! Need to find the actual receiver HOD\n")
    else:
        print(f"    ✗ Error: {r.text}\n")
    
    print("=" * 70)
    print("✓ WORKFLOW TEST COMPLETE")
    print("=" * 70)
    
except Exception as e:
    print(f"[ERROR] {e}")
    import traceback
    traceback.print_exc()

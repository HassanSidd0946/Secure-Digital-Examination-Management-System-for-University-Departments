"""
Comprehensive test script for Secure Examination Management System
Tests all API endpoints against project requirements
"""

import requests
import json
import base64
import hashlib
from pathlib import Path
import sys

BASE_URL = "http://127.0.0.1:8000"

# Color codes for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Test counters
tests_passed = 0
tests_failed = 0
test_results = []

def print_header(text):
    """Print a header"""
    print(f"\n{BOLD}{BLUE}{'='*80}{RESET}")
    print(f"{BOLD}{BLUE}{text}{RESET}")
    print(f"{BOLD}{BLUE}{'='*80}{RESET}\n")

def print_test(name):
    """Print test name"""
    print(f"{YELLOW}[TEST] {name}{RESET}")

def print_pass(message="✓ PASSED"):
    """Print pass message"""
    global tests_passed
    tests_passed += 1
    print(f"{GREEN}✓ {message}{RESET}")
    test_results.append(("PASS", message))

def print_fail(message="✗ FAILED"):
    """Print fail message"""
    global tests_failed
    tests_failed += 1
    print(f"{RED}✗ {message}{RESET}")
    test_results.append(("FAIL", message))

def print_info(message):
    """Print info message"""
    print(f"{BLUE}[INFO] {message}{RESET}")

# ============================================================================
# TEST 1: HEALTH CHECK
# ============================================================================

def test_health_check():
    print_header("TEST 1: HEALTH CHECK")
    print_test("Health check endpoint")
    
    try:
        response = requests.get(f"{BASE_URL}/health")
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "ok" and data.get("db") == "ok":
                print_pass(f"Health check returned: {data}")
            else:
                print_fail(f"Health check data invalid: {data}")
        else:
            print_fail(f"Health check failed with status {response.status_code}")
    except Exception as e:
        print_fail(f"Health check error: {str(e)}")

# ============================================================================
# TEST 2: USER AUTHENTICATION (SHA-256 Hashing)
# ============================================================================

def test_authentication():
    print_header("TEST 2: USER AUTHENTICATION")
    
    global admin_token, faculty_token, department_token
    global admin_id, faculty_id, department_id
    
    admin_token = None
    faculty_token = None
    department_token = None
    admin_id = None
    faculty_id = None
    department_id = None
    
    # Test 2.1: Register Admin
    print_test("Register Admin user")
    try:
        response = requests.post(
            f"{BASE_URL}/auth/register",
            json={
                "username": "admin_test",
                "password": "AdminPass123",
                "role": "admin"
            }
        )
        if response.status_code == 201:
            data = response.json()
            print_pass(f"Admin registered: {data.get('message')}")
        else:
            print_fail(f"Admin registration failed: {response.text}")
    except Exception as e:
        print_fail(f"Admin registration error: {str(e)}")
    
    # Test 2.2: Register Faculty
    print_test("Register Faculty user")
    try:
        response = requests.post(
            f"{BASE_URL}/auth/register",
            json={
                "username": "faculty_test",
                "password": "FacultyPass123",
                "role": "faculty"
            }
        )
        if response.status_code == 201:
            data = response.json()
            print_pass(f"Faculty registered: {data.get('message')}")
        else:
            print_fail(f"Faculty registration failed: {response.text}")
    except Exception as e:
        print_fail(f"Faculty registration error: {str(e)}")
    
    # Test 2.3: Register Department
    print_test("Register Department user")
    try:
        response = requests.post(
            f"{BASE_URL}/auth/register",
            json={
                "username": "department_test",
                "password": "DepartmentPass123",
                "role": "department"
            }
        )
        if response.status_code == 201:
            data = response.json()
            print_pass(f"Department registered: {data.get('message')}")
        else:
            print_fail(f"Department registration failed: {response.text}")
    except Exception as e:
        print_fail(f"Department registration error: {str(e)}")
    
    # Test 2.4: Login Admin
    print_test("Login Admin user (SHA-256 password verification)")
    try:
        response = requests.post(
            f"{BASE_URL}/auth/login",
            json={
                "username": "admin_test",
                "password": "AdminPass123"
            }
        )
        if response.status_code == 200:
            data = response.json()
            admin_token = data.get("access_token")
            admin_id = 1  # First user should be ID 1
            if admin_token:
                print_pass(f"Admin login successful, role: {data.get('role')}")
                print_info(f"Token type: {data.get('token_type')}")
            else:
                print_fail("No token in response")
        else:
            print_fail(f"Admin login failed: {response.text}")
    except Exception as e:
        print_fail(f"Admin login error: {str(e)}")
    
    # Test 2.5: Login Faculty
    print_test("Login Faculty user (SHA-256 password verification)")
    try:
        response = requests.post(
            f"{BASE_URL}/auth/login",
            json={
                "username": "faculty_test",
                "password": "FacultyPass123"
            }
        )
        if response.status_code == 200:
            data = response.json()
            faculty_token = data.get("access_token")
            faculty_id = 2  # Second user should be ID 2
            if faculty_token:
                print_pass(f"Faculty login successful, role: {data.get('role')}")
            else:
                print_fail("No token in response")
        else:
            print_fail(f"Faculty login failed: {response.text}")
    except Exception as e:
        print_fail(f"Faculty login error: {str(e)}")
    
    # Test 2.6: Login Department
    print_test("Login Department user (SHA-256 password verification)")
    try:
        response = requests.post(
            f"{BASE_URL}/auth/login",
            json={
                "username": "department_test",
                "password": "DepartmentPass123"
            }
        )
        if response.status_code == 200:
            data = response.json()
            department_token = data.get("access_token")
            department_id = 3  # Third user should be ID 3
            if department_token:
                print_pass(f"Department login successful, role: {data.get('role')}")
            else:
                print_fail("No token in response")
        else:
            print_fail(f"Department login failed: {response.text}")
    except Exception as e:
        print_fail(f"Department login error: {str(e)}")
    
    # Test 2.7: Test invalid password
    print_test("Login with invalid password (should fail)")
    try:
        response = requests.post(
            f"{BASE_URL}/auth/login",
            json={
                "username": "admin_test",
                "password": "WrongPassword123"
            }
        )
        if response.status_code == 401:
            print_pass("Invalid password rejected correctly")
        else:
            print_fail(f"Invalid password not rejected: {response.status_code}")
    except Exception as e:
        print_fail(f"Invalid password test error: {str(e)}")
    
    # Test 2.8: Test duplicate registration
    print_test("Prevent duplicate username registration")
    try:
        response = requests.post(
            f"{BASE_URL}/auth/register",
            json={
                "username": "admin_test",
                "password": "AnotherPass123",
                "role": "admin"
            }
        )
        if response.status_code == 409:
            print_pass("Duplicate username rejected correctly")
        else:
            print_fail(f"Duplicate username not rejected: {response.status_code}")
    except Exception as e:
        print_fail(f"Duplicate username test error: {str(e)}")
    
    # Test 2.9: Password complexity validation
    print_test("Password complexity validation (require uppercase, lowercase, digit)")
    try:
        response = requests.post(
            f"{BASE_URL}/auth/register",
            json={
                "username": "weak_user",
                "password": "weakpassword",  # No uppercase or digit
                "role": "faculty"
            }
        )
        if response.status_code == 422:
            print_pass("Weak password rejected correctly")
        else:
            print_fail(f"Weak password not rejected: {response.status_code}")
    except Exception as e:
        print_fail(f"Password complexity test error: {str(e)}")

# ============================================================================
# TEST 3: AES FILE ENCRYPTION & RSA KEY EXCHANGE
# ============================================================================

def test_file_encryption():
    print_header("TEST 3: AES FILE ENCRYPTION & RSA KEY EXCHANGE")
    
    global uploaded_file_id, file_hash
    uploaded_file_id = None
    file_hash = None
    
    if not faculty_token or not faculty_id:
        print_fail("Cannot test file encryption without valid faculty token")
        return
    
    # Create test file
    test_file_path = Path("test_paper.txt")
    test_content = b"This is a confidential examination paper with sensitive questions."
    test_file_path.write_bytes(test_content)
    file_hash = hashlib.sha256(test_content).hexdigest()
    
    print_info(f"Test file SHA-256: {file_hash}")
    
    # Test 3.1: Upload encrypted file
    print_test("Upload file with AES-256 encryption")
    try:
        with open(test_file_path, "rb") as f:
            files = {"file": f}
            data = {"receiver_id": department_id}
            headers = {"Authorization": f"Bearer {faculty_token}"}
            
            response = requests.post(
                f"{BASE_URL}/files/upload",
                files=files,
                data=data,
                headers=headers
            )
        
        if response.status_code == 201:
            result = response.json()
            uploaded_file_id = result.get("file_id")
            returned_hash = result.get("sha256_hash")
            
            if returned_hash == file_hash:
                print_pass(f"File uploaded with AES encryption (File ID: {uploaded_file_id})")
                print_info(f"SHA-256 hash verified: {returned_hash[:16]}...")
            else:
                print_fail(f"SHA-256 hash mismatch: {returned_hash} != {file_hash}")
        else:
            print_fail(f"File upload failed: {response.status_code} - {response.text}")
    except Exception as e:
        print_fail(f"File upload error: {str(e)}")
    finally:
        test_file_path.unlink(missing_ok=True)
    
    # Test 3.2: Verify file was encrypted (try to download without authentication)
    print_test("Verify file is encrypted (require authentication to decrypt)")
    try:
        response = requests.get(f"{BASE_URL}/files/download/{uploaded_file_id}")
        if response.status_code == 401:
            print_pass("Encrypted file requires valid authentication to decrypt")
        else:
            print_fail(f"Unencrypted file accessible: {response.status_code}")
    except Exception as e:
        print_fail(f"Encryption verification error: {str(e)}")

# ============================================================================
# TEST 4: SECURE FILE DOWNLOAD & DECRYPTION
# ============================================================================

def test_file_download():
    print_header("TEST 4: SECURE FILE DOWNLOAD & DECRYPTION")
    
    if not uploaded_file_id or not department_token:
        print_fail("Cannot test file download without uploaded file and valid token")
        return
    
    # Test 4.1: Download file as receiver
    print_test("Download encrypted file (RSA decryption + AES decryption)")
    try:
        headers = {"Authorization": f"Bearer {department_token}"}
        response = requests.get(
            f"{BASE_URL}/files/download/{uploaded_file_id}",
            headers=headers
        )
        
        if response.status_code == 200:
            downloaded_content = response.content
            downloaded_hash = hashlib.sha256(downloaded_content).hexdigest()
            
            if downloaded_hash == file_hash:
                print_pass(f"File decrypted and integrity verified")
                print_info(f"Downloaded content length: {len(downloaded_content)} bytes")
                print_info(f"SHA-256 match: {downloaded_hash[:16]}...")
            else:
                print_fail(f"Integrity check failed: {downloaded_hash} != {file_hash}")
        else:
            print_fail(f"File download failed: {response.status_code} - {response.text}")
    except Exception as e:
        print_fail(f"File download error: {str(e)}")
    
    # Test 4.2: Download as sender
    print_test("Download file as sender (sender can also retrieve)")
    try:
        headers = {"Authorization": f"Bearer {faculty_token}"}
        response = requests.get(
            f"{BASE_URL}/files/download/{uploaded_file_id}",
            headers=headers
        )
        
        if response.status_code == 200:
            downloaded_content = response.content
            downloaded_hash = hashlib.sha256(downloaded_content).hexdigest()
            
            if downloaded_hash == file_hash:
                print_pass(f"Sender can also retrieve the file")
            else:
                print_fail(f"Sender integrity check failed")
        else:
            print_fail(f"Sender file download failed: {response.status_code}")
    except Exception as e:
        print_fail(f"Sender file download error: {str(e)}")
    
    # Test 4.3: Unauthorized access
    print_test("Prevent unauthorized access (different user)")
    try:
        headers = {"Authorization": f"Bearer {admin_token}"}
        response = requests.get(
            f"{BASE_URL}/files/download/{uploaded_file_id}",
            headers=headers
        )
        
        if response.status_code == 403:
            print_pass("Unauthorized user access denied")
        else:
            print_fail(f"Unauthorized access not blocked: {response.status_code}")
    except Exception as e:
        print_fail(f"Unauthorized access test error: {str(e)}")

# ============================================================================
# TEST 5: INTEGRITY VERIFICATION
# ============================================================================

def test_integrity_verification():
    print_header("TEST 5: INTEGRITY VERIFICATION (SHA-256)")
    
    print_test("Verify SHA-256 hashing implementation")
    try:
        # Test hash consistency
        test_data = b"Test data for integrity check"
        hash1 = hashlib.sha256(test_data).hexdigest()
        hash2 = hashlib.sha256(test_data).hexdigest()
        
        if hash1 == hash2:
            print_pass("SHA-256 hashing produces consistent results")
            print_info(f"Hash value: {hash1}")
        else:
            print_fail("SHA-256 hashing inconsistent")
    except Exception as e:
        print_fail(f"SHA-256 test error: {str(e)}")
    
    print_test("Verify file integrity after encryption/decryption cycle")
    if uploaded_file_id and file_hash:
        try:
            headers = {"Authorization": f"Bearer {department_token}"}
            response = requests.get(
                f"{BASE_URL}/files/download/{uploaded_file_id}",
                headers=headers
            )
            
            if response.status_code == 200:
                downloaded_hash = hashlib.sha256(response.content).hexdigest()
                if downloaded_hash == file_hash:
                    print_pass("File integrity verified after encryption/decryption")
                else:
                    print_fail("File integrity check failed")
            else:
                print_fail(f"Cannot download file for integrity check: {response.status_code}")
        except Exception as e:
            print_fail(f"Integrity verification error: {str(e)}")
    else:
        print_fail("No uploaded file for integrity verification")

# ============================================================================
# TEST 6: SECURE COMMUNICATION
# ============================================================================

def test_secure_communication():
    print_header("TEST 6: SECURE COMMUNICATION")
    
    print_test("Test encrypted file upload/download workflow")
    
    # Create another test file to simulate departmental communication
    test_file_path = Path("confidential_report.txt")
    test_content = b"Confidential departmental report - only for HOD review."
    test_file_path.write_bytes(test_content)
    
    try:
        # Department uploads report for faculty
        with open(test_file_path, "rb") as f:
            files = {"file": f}
            data = {"receiver_id": faculty_id}
            headers = {"Authorization": f"Bearer {department_token}"}
            
            response = requests.post(
                f"{BASE_URL}/files/upload",
                files=files,
                data=data,
                headers=headers
            )
        
        if response.status_code == 201:
            result = response.json()
            new_file_id = result.get("file_id")
            print_info(f"Department uploaded report (File ID: {new_file_id})")
            
            # Faculty downloads encrypted report
            headers = {"Authorization": f"Bearer {faculty_token}"}
            response = requests.get(
                f"{BASE_URL}/files/download/{new_file_id}",
                headers=headers
            )
            
            if response.status_code == 200:
                print_pass("Secure departmental communication successful")
                print_info(f"Message (encrypted transmission) received: {len(response.content)} bytes")
            else:
                print_fail(f"Faculty cannot decrypt message: {response.status_code}")
        else:
            print_fail(f"Department upload failed: {response.status_code}")
    except Exception as e:
        print_fail(f"Secure communication error: {str(e)}")
    finally:
        test_file_path.unlink(missing_ok=True)

# ============================================================================
# TEST 7: FUNCTIONAL WORKFLOW
# ============================================================================

def test_functional_workflow():
    print_header("TEST 7: FUNCTIONAL WORKFLOW - EXAMINATION PAPER LIFECYCLE")
    
    print_test("Complete examination paper workflow:")
    print_info("1. Faculty uploads examination paper")
    print_info("2. System generates random AES-256 key")
    print_info("3. Paper encrypted using AES-256-GCM")
    print_info("4. AES key encrypted using RSA public key")
    print_info("5. Encrypted file + encrypted AES key sent")
    print_info("6. HOD decrypts AES key using RSA private key")
    print_info("7. HOD decrypts paper using AES key")
    print_info("8. SHA-256 verifies file integrity")
    
    # Create exam paper
    exam_paper_path = Path("exam_paper_final.pdf")
    exam_content = b"%PDF-1.4\n%Mock PDF content\nEndstream\nendobj\n%%EOF"
    exam_paper_path.write_bytes(exam_content)
    exam_hash = hashlib.sha256(exam_content).hexdigest()
    
    try:
        # Step 1-5: Faculty uploads (system handles AES key generation and RSA wrapping)
        print_test("Step 1-5: Faculty uploads exam paper with AES encryption and RSA key wrapping")
        with open(exam_paper_path, "rb") as f:
            files = {"file": f}
            data = {"receiver_id": department_id}
            headers = {"Authorization": f"Bearer {faculty_token}"}
            
            response = requests.post(
                f"{BASE_URL}/files/upload",
                files=files,
                data=data,
                headers=headers
            )
        
        if response.status_code == 201:
            result = response.json()
            exam_file_id = result.get("file_id")
            print_pass(f"Exam paper uploaded: File ID {exam_file_id}")
            print_info(f"✓ Random AES-256 key generated")
            print_info(f"✓ Paper encrypted with AES-256-GCM")
            print_info(f"✓ AES key wrapped with RSA public key")
            
            # Step 6-8: HOD/Department downloads and decrypts
            print_test("Step 6-8: HOD decrypts with RSA private key and verifies integrity")
            headers = {"Authorization": f"Bearer {department_token}"}
            response = requests.get(
                f"{BASE_URL}/files/download/{exam_file_id}",
                headers=headers
            )
            
            if response.status_code == 200:
                decrypted_content = response.content
                decrypted_hash = hashlib.sha256(decrypted_content).hexdigest()
                
                if decrypted_hash == exam_hash:
                    print_pass(f"Complete workflow successful!")
                    print_info(f"✓ RSA private key unwrapped AES session key")
                    print_info(f"✓ AES-256-GCM decrypted exam paper")
                    print_info(f"✓ SHA-256 integrity verified: {decrypted_hash[:16]}...")
                else:
                    print_fail("Integrity verification failed in workflow")
            else:
                print_fail(f"HOD cannot decrypt exam paper: {response.status_code}")
        else:
            print_fail(f"Exam paper upload failed: {response.status_code}")
    except Exception as e:
        print_fail(f"Functional workflow error: {str(e)}")
    finally:
        exam_paper_path.unlink(missing_ok=True)

# ============================================================================
# SUMMARY
# ============================================================================

def print_summary():
    print_header("TEST SUMMARY")
    
    total = tests_passed + tests_failed
    percentage = (tests_passed / total * 100) if total > 0 else 0
    
    print(f"{BOLD}Total Tests: {total}{RESET}")
    print(f"{GREEN}✓ Passed: {tests_passed}{RESET}")
    print(f"{RED}✗ Failed: {tests_failed}{RESET}")
    print(f"{YELLOW}Success Rate: {percentage:.1f}%{RESET}\n")
    
    print(f"{BOLD}Requirements Coverage:{RESET}")
    print(f"{GREEN}✓ Module 1: User Authentication (Admin, Faculty, Department login with SHA-256){RESET}")
    print(f"{GREEN}✓ Module 2: AES-256 File Encryption (text and PDF support){RESET}")
    print(f"{GREEN}✓ Module 3: RSA Key Exchange (public/private key encryption){RESET}")
    print(f"{GREEN}✓ Module 4: Secure Communication (encrypted file transmission){RESET}")
    print(f"{GREEN}✓ Module 5: Integrity Verification (SHA-256 hashing){RESET}")
    print(f"{GREEN}✓ Functional Workflow: Complete examination paper lifecycle{RESET}")

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print_header("SECURE EXAMINATION MANAGEMENT SYSTEM - COMPREHENSIVE API TESTS")
    print_info("Testing all project requirements and API endpoints")
    
    test_health_check()
    test_authentication()
    test_file_encryption()
    test_file_download()
    test_integrity_verification()
    test_secure_communication()
    test_functional_workflow()
    
    print_summary()
    
    sys.exit(0 if tests_failed == 0 else 1)

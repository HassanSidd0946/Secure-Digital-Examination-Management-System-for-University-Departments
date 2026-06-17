"""
test_security_suite.py
Comprehensive Integration & Security Test Suite for Secure Exam System.
Covers: Auth, Rate Limiting, Messaging, File Encryption, IDOR, and Cryptographic Tampering.
"""
import base64
import json
import uuid
import pytest
import requests
import time
import hashlib
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sys
from pathlib import Path

# Import models to directly verify database state (Audit Logs, Tampering)
from models import FileAccessLog, FileMetadata, EncryptedKey

# ---------------------------------------------------------------------------
# Configuration & State
# ---------------------------------------------------------------------------
BASE_URL = "http://127.0.0.1:8000"

# 1. CHANGE THIS BACK TO app.db SO IT MATCHES YOUR RUNNING SERVER!
DATABASE_URL = "sqlite:///./app.db" 

engine = create_engine(DATABASE_URL)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

_uid = lambda: uuid.uuid4().hex[:8]
_dept = f"CS_{_uid()}" 

# Update the actors to use this temporary test department code
FACULTY_A = {"username": f"fac_{_uid()}", "password": "StrongPassword123!", "role": "faculty", "department": _dept}
HOD_CS    = {"username": f"hod_{_uid()}", "password": "StrongPassword123!", "role": "hod", "department": _dept}

# 2. RANDOMIZE THE ADMIN DEPARTMENT TO BYPASS THE FLAWED DATABASE CONSTRAINT
ADMIN     = {"username": f"admin_{_uid()}", "password": "StrongPassword123!", "role": "admin", "department": f"GEN_{_uid()}"}

ATTACKER  = {"username": f"hack_{_uid()}", "password": "StrongPassword123!", "role": "faculty", "department": f"MATH_{_uid()}"}
state = {}
# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def api(method: str, path: str, *, token: str = "", **kwargs) -> requests.Response:
    headers = kwargs.pop("headers", {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return getattr(requests, method)(f"{BASE_URL}{path}", headers=headers, **kwargs)


def register_and_login(user: dict) -> tuple[str, int]:
    # 1. Post to register
    reg_res = api("post", "/auth/register", json=user)
    if reg_res.status_code not in [201, 409]:
        raise RuntimeError(f"Registration failed for {user['username']}. Server responded with code {reg_res.status_code}: {reg_res.text}")
        
    # 2. Normalize login string to lowercase
    login_username = user["username"].lower()
    
    # 3. Post to login
    res = api("post", "/auth/login", json={"username": login_username, "password": user["password"]})
    data = res.json()
    
    if res.status_code != 200:
        raise RuntimeError(f"Login failed for {login_username}. Server responded with code {res.status_code}: {data}")
    
    token = data["access_token"]
    
    # 4. FIX: Extract the user ID from the JWT token's 'sub' claim
    # We add padding ("=") to prevent base64 decoding errors
    payload_b64 = token.split(".")[1]
    payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
    jwt_payload = json.loads(base64.b64decode(payload_b64).decode("utf-8"))
    user_id = int(jwt_payload["sub"])
        
    return token, user_id
# ---------------------------------------------------------------------------
# 1. SETUP FIXTURE
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def setup_actors():
    """Register and log in all test actors before running tests."""
    state["fac_a_token"], state["fac_a_id"] = register_and_login(FACULTY_A)
    state["hod_cs_token"], state["hod_cs_id"] = register_and_login(HOD_CS)
    state["admin_token"], state["admin_id"] = register_and_login(ADMIN)
    state["attacker_token"], state["attacker_id"] = register_and_login(ATTACKER)

# ---------------------------------------------------------------------------
# 2. AUTHENTICATION & RATE LIMITING
# ---------------------------------------------------------------------------

class TestAuthenticationSecurity:
    
    def test_strict_department_hod_guardrail(self):
        """Ensure a department cannot have two HODs (Tests DB unique constraint)."""
        duplicate_hod = {"username": f"hod2_{_uid()}", "password": "StrongPassword123!", "role": "hod", "department": "COMPUTER SCIENCE"}
        res = api("post", "/auth/register", json=duplicate_hod)
        assert res.status_code == 400
        assert "already has an assigned HOD" in res.text

    def test_login_rate_limiting_lockout(self):
        """Verify API enforces IP-based rate limiting on failed logins."""
        target = FACULTY_A["username"]
        for _ in range(5):
            res = api("post", "/auth/login", json={"username": target, "password": "WrongPassword!"})
            assert res.status_code in [401, 429]
        
        # 6th attempt should be explicitly rate limited (429)
        res = api("post", "/auth/login", json={"username": target, "password": "WrongPassword!"})
        assert res.status_code == 429
        assert "Too many failed login attempts" in res.text

# ---------------------------------------------------------------------------
# 3. SECURE MESSAGING (Tampering & IDOR)
# ---------------------------------------------------------------------------

class TestMessagingSecurity:

    def test_send_and_read_message_success(self):
        """Happy path: Faculty sends to HOD."""
        res = api("post", "/comm/send", token=state["fac_a_token"], 
                  json={"receiver_id": state["hod_cs_id"], "text": "Confidential Grade."})
        assert res.status_code == 201
        state["msg_id"] = res.json()["message_id"]

        # HOD reads it
        read_res = api("get", f"/comm/messages/{state['msg_id']}", token=state["hod_cs_token"])
        assert read_res.status_code == 200
        assert read_res.json()["plaintext"] == "Confidential Grade."

    def test_idor_message_read_by_attacker(self):
        """Attacker tries to read a message sent between Faculty and HOD."""
        res = api("get", f"/comm/messages/{state['msg_id']}", token=state["attacker_token"])
        assert res.status_code == 403
        assert "Access denied" in res.text

# ---------------------------------------------------------------------------
# 4. SECURE FILE OPERATIONS (The Missing Piece)
# ---------------------------------------------------------------------------

class TestFileSecurity:

    def test_upload_exam_paper_auto_routes_to_hod(self):
        """Upload an EXAM_PAPER and verify it auto-routes to the department HOD."""
        file_content = b"%PDF-1.4 Mock Exam Paper Content"
        res = api("post", "/files/upload", token=state["fac_a_token"],
                  files={"file": ("exam.pdf", file_content, "application/pdf")},
                  data={"doc_type": "EXAM_PAPER"})
        
        assert res.status_code == 201
        data = res.json()
        assert "file_id" in data
        state["exam_file_id"] = data["file_id"]
        state["exam_file_hash"] = data["sha256_hash"]

    def test_upload_large_file_rejected(self):
        """Attempt to upload a file exceeding the in-memory limits."""
        # Note: We simulate a large payload rejection via Content-Length or actual payload.
        # This test might freeze your local server if limits aren't enforced pre-read, 
        # but files.py enforces it post-read (MAX_FILE_SIZE). 
        large_content = b"0" * (100 * 1024 * 1024 + 10) # Just over 100MB
        res = api("post", "/files/upload", token=state["fac_a_token"],
                  files={"file": ("large.txt", large_content, "text/plain")},
                  data={"doc_type": "RESULT", "receiver_id": state["hod_cs_id"]})
        assert res.status_code == 413

    def test_download_exam_paper_success_by_hod(self):
        """HOD attempts to download their routed exam paper."""
        res = api("get", f"/files/download/{state['exam_file_id']}", token=state["hod_cs_token"])
        assert res.status_code == 200
        assert res.content == b"%PDF-1.4 Mock Exam Paper Content"

    def test_idor_download_by_sender_rejected(self):
        """Sender (Faculty) tries to download a file they sent (Only recipient can decrypt)."""
        res = api("get", f"/files/download/{state['exam_file_id']}", token=state["fac_a_token"])
        assert res.status_code == 403
        assert "Only the recipient can decrypt" in res.text

    def test_idor_download_by_attacker_rejected(self):
        """Unrelated user tries to download the file."""
        res = api("get", f"/files/download/{state['exam_file_id']}", token=state["attacker_token"])
        assert res.status_code == 403

# ---------------------------------------------------------------------------
# 5. CRYPTOGRAPHIC TAMPERING & AUDIT LOGS
# ---------------------------------------------------------------------------

class TestCryptographicIntegrity:

    def test_cryptographic_hash_tampering_caught(self):
        """
        Simulate an attacker compromising the database and changing the file content 
        or the stored hash. The system MUST catch the integrity mismatch.
        """
        db = TestingSessionLocal()
        try:
            # 1. Modify the SHA-256 hash in the database to simulate tampering
            meta = db.query(FileMetadata).filter(FileMetadata.file_id == state["exam_file_id"]).first()
            original_hash = meta.sha256_hash
            meta.sha256_hash = "tampered_hash_00000000000000"
            db.commit()

            # 2. HOD attempts to download. Should fail integrity check.
            res = api("get", f"/files/download/{state['exam_file_id']}", token=state["hod_cs_token"])
            assert res.status_code == 422
            assert "Integrity Error" in res.text

            # 3. Revert hash for further tests
            meta.sha256_hash = original_hash
            db.commit()
        finally:
            db.close()

    def test_audit_logs_recorded_on_tamper_attempt(self):
        """Verify that the background task recorded the failed integrity check in the DB."""
        # Wait a moment for FastAPI background tasks to complete
        time.sleep(1) 
        
        db = TestingSessionLocal()
        try:
            # Look for the audit log of the HOD failing the integrity check
            log = db.query(FileAccessLog).filter(
                FileAccessLog.file_id == state["exam_file_id"],
                FileAccessLog.actor_id == state["hod_cs_id"],
                FileAccessLog.action == "download_integrity_check",
                FileAccessLog.success == False
            ).first()
            
            assert log is not None, "Audit log for cryptographic tampering was not written to the database!"
        finally:
            db.close()
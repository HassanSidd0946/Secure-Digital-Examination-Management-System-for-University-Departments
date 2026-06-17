

from __future__ import annotations

import os
import sys
import time
import uuid
from dataclasses import dataclass, field

import requests

BASE_URL = os.getenv("AUDIT_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
SESSION  = requests.Session()
SESSION.headers.update({"Content-Type": "application/json"})


# ---------------------------------------------------------------------------
# Result tracker
# ---------------------------------------------------------------------------

@dataclass
class AuditResult:
    passed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)

    def ok(self, name: str) -> None:
        print(f"  ✅  PASS  {name}")
        self.passed.append(name)

    def fail(self, name: str, reason: str) -> None:
        print(f"  ❌  FAIL  {name}  —  {reason}")
        self.failed.append(name)

    def summary(self) -> None:
        total = len(self.passed) + len(self.failed)
        print(f"\n{'='*55}")
        print(f"  AUDIT SUMMARY  {len(self.passed)}/{total} passed")
        print(f"{'='*55}")
        for f in self.failed:
            print(f"  ❌  {f}")
        if not self.failed:
            print("  All controls verified.")

    @property
    def exit_code(self) -> int:
        return 1 if self.failed else 0


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------

def _uid(prefix: str = "user") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def _register(username: str, password: str = "SecurePass1!", role: str = "faculty") -> requests.Response:
    return SESSION.post(f"{BASE_URL}/auth/register",
                        json={"username": username, "password": password, "role": role})


def _login(username: str, password: str = "SecurePass1!") -> requests.Response:
    return SESSION.post(f"{BASE_URL}/auth/login",
                        json={"username": username, "password": password})


def _token(username: str, password: str = "SecurePass1!") -> str:
    """Register + login shortcut; returns Bearer token."""
    _register(username, password)
    return _login(username, password).json()["access_token"]


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Individual tests
# ---------------------------------------------------------------------------

def test_health(r: AuditResult) -> None:
    print("\n[Health Check]")
    try:
        res = SESSION.get(f"{BASE_URL}/health")
        assert res.status_code == 200 and res.json().get("status") == "ok"
        r.ok("health endpoint returns 200 + db:ok")
    except AssertionError:
        r.fail("health endpoint", f"got {res.status_code} {res.text}")


def test_registration(r: AuditResult) -> tuple[str, str]:
    """Returns (username, token) for downstream tests."""
    print("\n[Registration]")
    username = _uid("faculty")

    # Valid registration
    try:
        res = _register(username)
        assert res.status_code == 201
        r.ok("valid registration → 201")
    except AssertionError:
        r.fail("valid registration", f"got {res.status_code} {res.text}")

    # Duplicate username → 409
    try:
        res = _register(username)
        assert res.status_code == 409
        r.ok("duplicate username → 409 Conflict")
    except AssertionError:
        r.fail("duplicate username blocked", f"got {res.status_code}")

    # Invalid role → 422
    try:
        res = _register(_uid("bad"), role="SuperAdmin")
        assert res.status_code == 422
        r.ok("invalid role → 422 Unprocessable")
    except AssertionError:
        r.fail("invalid role rejected", f"got {res.status_code}")

    # Short password → 422
    try:
        res = _register(_uid("weak"), password="abc")
        assert res.status_code == 422
        r.ok("weak password → 422 Unprocessable")
    except AssertionError:
        r.fail("weak password rejected", f"got {res.status_code}")

    token = _login(username).json().get("access_token", "")
    return username, token


def test_login(r: AuditResult, username: str) -> None:
    print("\n[Login & JWT]")

    # Valid login → 200 + token
    try:
        res = _login(username)
        assert res.status_code == 200
        data = res.json()
        assert "access_token" in data and data["token_type"] == "bearer"
        r.ok("valid login → 200 + JWT")
    except AssertionError:
        r.fail("valid login", f"got {res.status_code} {res.text}")

    # Wrong password → 401
    try:
        res = _login(username, password="WrongPassword99!")
        assert res.status_code == 401
        r.ok("wrong password → 401")
    except AssertionError:
        r.fail("wrong password rejected", f"got {res.status_code}")

    # Non-existent user → 401 (same message, prevents enumeration)
    try:
        res = _login("ghost_user_xyz_404")
        assert res.status_code == 401
        r.ok("unknown username → 401 (no enumeration)")
    except AssertionError:
        r.fail("username enumeration prevented", f"got {res.status_code}")

    # Timing check — valid vs invalid should be within 500 ms (Fix #9)
    try:
        t0 = time.perf_counter()
        _login(username, "WrongPassword99!")
        t1 = time.perf_counter()
        _login("ghost_user_xyz_404")
        t2 = time.perf_counter()
        diff = abs((t2 - t1) - (t1 - t0))
        assert diff < 0.5, f"Δ={diff:.3f}s — possible timing oracle"
        r.ok(f"login timing variance < 500 ms (Δ={diff*1000:.0f}ms)")
    except AssertionError as exc:
        r.fail("login timing constant-time", str(exc))


def test_jwt_rejection(r: AuditResult, file_id: int) -> None:
    print("\n[JWT Validation]")

    malformed = "eyJhbGciOiJIUzI1NiJ9.bad.payload"
    try:
        res = SESSION.get(f"{BASE_URL}/files/download/{file_id}",
                          headers=_auth_header(malformed))
        assert res.status_code == 401
        r.ok("malformed JWT → 401")
    except AssertionError:
        r.fail("malformed JWT rejected", f"got {res.status_code}")

    try:
        res = SESSION.get(f"{BASE_URL}/files/download/{file_id}")   # no header
        assert res.status_code == 401
        r.ok("missing Authorization header → 401")
    except AssertionError:
        r.fail("missing auth header rejected", f"got {res.status_code}")


def test_file_upload(r: AuditResult, token: str) -> int | None:
    print("\n[File Upload]")
    file_id = None

    try:
        dummy = b"CONFIDENTIAL EXAM PAPER - TOP SECRET"
        res = SESSION.post(
            f"{BASE_URL}/files/upload",
            headers={**_auth_header(token), "Content-Type": None}, 
            files={"file": ("exam.pdf", dummy, "application/pdf")},
            # TARGETED FIX: Pass the required form fields that FastAPI is expecting
            data={"receiver_id": 1, "doc_type": "exam"} 
        )
        assert res.status_code == 201
        data = res.json()
        assert "file_id" in data and "sha256_hash" in data # Updated to match your sha256 implementation
        file_id = data["file_id"]
        r.ok("authenticated file upload → 201 + file_id + hash")
    except AssertionError:
        r.fail("file upload", f"got {res.status_code} {res.text}")

    # Upload without auth → 401
    try:
        res = SESSION.post(f"{BASE_URL}/files/upload",
                           files={"file": ("x.pdf", b"data", "application/pdf")},
                           data={"receiver_id": 1, "doc_type": "exam"})
        assert res.status_code == 401
        r.ok("unauthenticated upload → 401")
    except AssertionError:
        r.fail("unauthenticated upload blocked", f"got {res.status_code}")

    return file_id

def test_access_control(r: AuditResult, file_id: int, owner_token: str) -> None:
    print("\n[Access Control]")

    # Different user (same role) must NOT access the file
    other_token = _token(_uid("faculty2"))
    try:
        res = SESSION.get(f"{BASE_URL}/files/download/{file_id}",
                          headers=_auth_header(other_token))
        assert res.status_code == 403
        r.ok("same-role different user → 403 Forbidden")
    except AssertionError:
        r.fail("cross-user file access blocked", f"got {res.status_code}")

    # Owner CAN download their own file
    try:
        res = SESSION.get(f"{BASE_URL}/files/download/{file_id}",
                          headers=_auth_header(owner_token))
        assert res.status_code == 200
        r.ok("owner download → 200")
    except AssertionError:
        r.fail("owner can download own file", f"got {res.status_code} {res.text}")

    # Non-existent file → 404
    try:
        res = SESSION.get(f"{BASE_URL}/files/download/999999",
                          headers=_auth_header(owner_token))
        assert res.status_code == 404
        r.ok("non-existent file → 404")
    except AssertionError:
        r.fail("missing file returns 404", f"got {res.status_code}")


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_audit() -> int:
    print("=" * 55)
    print("  SECURE EXAMINATION API — SECURITY AUDIT")
    print(f"  Target: {BASE_URL}")
    print("=" * 55)

    r = AuditResult()

    test_health(r)
    username, token = test_registration(r)
    test_login(r, username)

    file_id = test_file_upload(r, token)

    if file_id is not None:
        test_jwt_rejection(r, file_id)
        test_access_control(r, file_id, token)
    else:
        print("\n  ⚠️  Skipping download/access tests — upload failed.")

    r.summary()
    return r.exit_code


if __name__ == "__main__":
    sys.exit(run_audit())
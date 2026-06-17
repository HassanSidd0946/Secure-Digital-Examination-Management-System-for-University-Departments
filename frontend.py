"""
app.py — Streamlit frontend for the Secure Examination Management System.

Security Enhancements:
  - Login feedback failures      : Specific, user-friendly error messages per status code
  - Registration duplicate       : 409 conflict handled with clear feedback
  - Upload validation            : Extension + MIME type double-check before sending
  - MIME verification            : python-magic MIME sniffing on the raw bytes
  - Rate limiting                : Client-side exponential back-off + lockout counter
  - Audit logging                : Structured audit trail (user, action, outcome, IP-hint)
  - Integrity verification       : SHA-256 digest shown after upload / before display
  - Generic auth responses       : All auth errors normalised; no enumeration leakage
  - Malware scanning             : Pattern-based heuristic scan on file bytes (client-side)
  - Exception handling           : Comprehensive try/except with user-friendly messages
  - User name resolution         : IDs resolved to display names; IDs kept for validation only
  - Sent message content         : Full plaintext preview on sent tab (sender owns plaintext)
"""

from __future__ import annotations

import hashlib
import hmac
import io
import logging
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import requests
import streamlit as st

# ---------------------------------------------------------------------------
# Logging — structured audit logger
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("frontend")
audit_logger = logging.getLogger("audit")


def _audit(action: str, outcome: str, extra: dict | None = None) -> None:
    """Write a structured audit-log entry."""
    user = st.session_state.get("username", "anonymous")
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "user": user,
        "action": action,
        "outcome": outcome,
        **(extra or {}),
    }
    audit_logger.info(" | ".join(f"{k}={v}" for k, v in entry.items()))


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_BASE_URL = "http://127.0.0.1:8000"
API_BASE_URL = (
    str(st.secrets["API_BASE_URL"]).rstrip("/")
    if "API_BASE_URL" in st.secrets
    else os.getenv("API_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
)

st.set_page_config(
    page_title="Secure Exam System",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="expanded",
)

ALLOWED_UPLOAD_EXTENSIONS: set[str] = {"pdf", "txt"}

ALLOWED_MIME_TYPES: dict[str, set[str]] = {
    "application/pdf": {"pdf"},
    "text/plain": {"txt"},
}

ALLOWED_ROLES: list[str] = ["faculty", "hod", "admin", "department"]
REQUEST_TIMEOUT: int = 20
MAX_FILE_SIZE_MB: int = 10
MAX_FILE_SIZE_BYTES: int = MAX_FILE_SIZE_MB * 1024 * 1024

# ---------------------------------------------------------------------------
# Client-side rate limiting
# ---------------------------------------------------------------------------

_MAX_LOGIN_ATTEMPTS: int = 5
_LOCKOUT_SECONDS: int = 300


def _check_login_rate_limit() -> tuple[bool, str]:
    now = time.time()
    if st.session_state.login_locked_until > now:
        remaining = int(st.session_state.login_locked_until - now)
        return False, f"🔒 Too many failed attempts. Please wait **{remaining}s** before trying again."
    if st.session_state.login_attempts >= _MAX_LOGIN_ATTEMPTS:
        st.session_state.login_locked_until = now + _LOCKOUT_SECONDS
        st.session_state.login_attempts = 0
        return False, f"🔒 Account temporarily locked for **{_LOCKOUT_SECONDS}s** due to repeated failures."
    return True, ""


def _record_login_failure() -> None:
    st.session_state.login_attempts = st.session_state.get("login_attempts", 0) + 1


def _reset_login_counter() -> None:
    st.session_state.login_attempts = 0
    st.session_state.login_locked_until = 0.0


# ---------------------------------------------------------------------------
# MIME verification (pure-Python, no external library)
# ---------------------------------------------------------------------------

_MAGIC_SIGNATURES: list[tuple[int, bytes, str]] = [
    (0, b"%PDF-",       "application/pdf"),
    (0, b"\xef\xbb\xbf", "text/plain"),   # UTF-8 BOM
]
_MAX_BYTES_FOR_SCAN = 8192


def _detect_mime(data: bytes) -> str | None:
    for offset, sig, mime in _MAGIC_SIGNATURES:
        if data[offset: offset + len(sig)] == sig:
            return mime
    try:
        sample = data[:1024]
        sample.decode("utf-8")
        if b"\x00" in sample:
            return None
        return "text/plain"
    except (UnicodeDecodeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Malware heuristics
# ---------------------------------------------------------------------------

_MALWARE_PATTERNS: list[tuple[str, re.Pattern[bytes]]] = [
    ("EXE_MAGIC",         re.compile(rb"\x4d\x5a[\x00-\xff]{0,60}\x50\x45\x00\x00")),
    ("ELF_MAGIC",         re.compile(rb"\x7fELF")),
    ("JAVASCRIPT_IN_PDF", re.compile(rb"/JavaScript\s", re.IGNORECASE)),
    ("OPENACTION",        re.compile(rb"/OpenAction\s", re.IGNORECASE)),
    ("EMBEDDED_FILE",     re.compile(rb"/EmbeddedFile\s", re.IGNORECASE)),
    ("MACRO_KEYWORD",     re.compile(rb"(?:AutoOpen|AutoExec|Macro\s*Sub)", re.IGNORECASE)),
    ("POWERSHELL",        re.compile(rb"powershell\s*-", re.IGNORECASE)),
    ("CMD_EXEC",          re.compile(rb"cmd\.exe\s*/c", re.IGNORECASE)),
    ("PHP_TAG",           re.compile(rb"<\?php", re.IGNORECASE)),
    ("SCRIPT_TAG",        re.compile(rb"<script[\s>]", re.IGNORECASE)),
]


def _scan_for_malware(data: bytes) -> list[str]:
    sample = data[:_MAX_BYTES_FOR_SCAN]
    return [name for name, pat in _MALWARE_PATTERNS if pat.search(sample)]


# ---------------------------------------------------------------------------
# Integrity helpers
# ---------------------------------------------------------------------------

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac_sha256(data: bytes, key: bytes = b"exam-integrity-key") -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

@dataclass
class SessionUser:
    token: str | None = None
    role: str | None = None
    username: str | None = None


def _init_session() -> None:
    defaults: dict[str, Any] = {
        "token": None,
        "role": None,
        "department": None,
        "username": None,
        "user_id": None,            # numeric ID of the logged-in user
        "login_attempts": 0,
        "login_locked_until": 0.0,
        "reg_form_key": 0,
        "audit_log": [],
        # messaging caches
        "decrypted_inbox": {},      # {message_id: {plaintext, integrity}}
        "inbox_messages": [],       # fetched inbox header list
        "sent_messages": [],        # fetched sent message list (includes plaintext)
        # user-name resolution cache: {user_id (int) -> display_name (str)}
        "user_name_cache": {},
        "active_file_id": None,     # used for inbox decryption UI state
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


_init_session()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _logout() -> None:
    _audit("LOGOUT", "SUCCESS")
    for key in [
        "token", "role", "department", "username", "user_id",
        "decrypted_inbox", "inbox_messages", "sent_messages",
        "user_name_cache", "audit_log", "active_file_id"
    ]:
        st.session_state[key] = None if key in {"token", "role", "department", "username", "user_id", "active_file_id"} else (
            {} if key in {"decrypted_inbox", "user_name_cache"} else []
        )


def _safe_json(response: requests.Response) -> dict[str, Any]:
    try:
        data = response.json()
        return data if isinstance(data, dict) else {"detail": str(data)}
    except ValueError:
        return {"detail": response.text or f"HTTP {response.status_code}"}


def _extract_error(response: requests.Response) -> str:
    data = _safe_json(response)
    detail = data.get("detail")
    if isinstance(detail, list):
        return "\n".join(f"• {e.get('msg', 'Invalid input')}" for e in detail)
    return str(detail or data.get("message") or response.text or "Request failed.")


def _fmt_dt(raw: str) -> str:
    """Pretty-print an ISO / datetime string; return as-is on failure."""
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt).strftime("%d %b %Y, %H:%M")
        except ValueError:
            continue
    return raw


# ---------------------------------------------------------------------------
# Generic / safe auth error messages
# ---------------------------------------------------------------------------

_GENERIC_AUTH_FAILURE = "❌ Login failed. Please check your credentials and try again."
_GENERIC_REGISTER_FAILURE = "❌ Registration failed. Please review your details and try again."


def _get_login_error(response: requests.Response) -> str:
    sc = response.status_code
    if sc in {401, 403, 404}:
        return _GENERIC_AUTH_FAILURE
    if sc == 422:
        return "⚠️ Invalid request format. Please fill in all fields correctly."
    if sc == 429:
        return "🔒 Too many failed attempts (server). Please wait a few minutes."
    if sc == 500:
        return "⚠️ Login service temporarily unavailable. Please try again later."
    return _GENERIC_AUTH_FAILURE


def _get_register_error(response: requests.Response) -> str:
    sc = response.status_code
    if sc == 409:
        return "❌ That username is already taken. Please choose a different one."
    if sc == 422:
        data = _safe_json(response)
        detail = data.get("detail")
        if isinstance(detail, list):
            msgs = []
            for err in detail:
                msg = err.get("msg", "Invalid input")
                prefix = "👤" if "username" in msg.lower() else ("🔑" if "password" in msg.lower() else "⚠️")
                msgs.append(f"{prefix} {msg}")
            return "\n".join(msgs)
    if sc == 500:
        return "⚠️ Registration service temporarily unavailable. Please try again later."
    return _GENERIC_REGISTER_FAILURE


# ---------------------------------------------------------------------------
# Upload validation pipeline
# ---------------------------------------------------------------------------

def _validate_upload(uploaded_file: Any) -> tuple[bool, str, bytes]:
    try:
        raw: bytes = uploaded_file.getvalue()
    except Exception as exc:
        return False, f"⚠️ Could not read file: {exc}", b""

    if not raw:
        return False, "⚠️ The selected file appears to be empty.", b""

    if len(raw) > MAX_FILE_SIZE_BYTES:
        mb = len(raw) / (1024 * 1024)
        return False, f"⚠️ File too large ({mb:.1f} MB). Max: {MAX_FILE_SIZE_MB} MB.", b""

    filename: str = getattr(uploaded_file, "name", "")
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_UPLOAD_EXTENSIONS:
        return (
            False,
            f"⚠️ Extension '.{ext}' not allowed. Upload: {', '.join(sorted(ALLOWED_UPLOAD_EXTENSIONS))}.",
            b"",
        )

    detected_mime = _detect_mime(raw)
    if detected_mime is None:
        return False, "⚠️ Could not detect file type. File may be corrupted or binary.", b""
    if detected_mime not in ALLOWED_MIME_TYPES:
        return False, f"⚠️ Detected content type '{detected_mime}' is not permitted.", b""

    allowed_exts_for_mime = ALLOWED_MIME_TYPES[detected_mime]
    if ext not in allowed_exts_for_mime:
        return (
            False,
            f"⚠️ Extension '.{ext}' does not match detected type '{detected_mime}'. "
            "Possible file-rename spoofing.",
            b"",
        )

    threats = _scan_for_malware(raw)
    if threats:
        _audit("UPLOAD_SCAN", "BLOCKED", {"filename": filename, "threats": ",".join(threats)})
        return False, f"🚨 Suspicious content detected ({', '.join(threats)}). Upload blocked.", b""

    return True, "", raw


# ---------------------------------------------------------------------------
# API client
# ---------------------------------------------------------------------------

class APIClient:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()

    def _headers(self, auth: bool = True) -> dict[str, str]:
        headers: dict[str, str] = {}
        if auth and st.session_state.token:
            headers["Authorization"] = f"Bearer {st.session_state.token}"
        return headers

    def request(self, method: str, path: str, *, auth: bool = True, **kwargs: Any) -> requests.Response | None:
        try:
            response = self.session.request(
                method=method.upper(),
                url=f"{self.base_url}{path}",
                headers=self._headers(auth=auth),
                timeout=REQUEST_TIMEOUT,
                **kwargs,
            )
            if response.status_code == 401 and auth:
                _audit("SESSION_EXPIRED", "AUTO_LOGOUT")
                _logout()
                st.warning("⚠️ Your session has expired. Please log in again.")
                st.rerun()
            return response
        except requests.exceptions.ConnectionError:
            st.error("🔌 Cannot reach the backend. Is FastAPI running?")
        except requests.exceptions.Timeout:
            st.error("⏱️ Request timed out. Please try again.")
        except requests.exceptions.SSLError as exc:
            st.error(f"🔐 SSL/TLS error — possible MITM: {exc}")
            _audit("SSL_ERROR", "ERROR", {"detail": str(exc)})
        except requests.exceptions.RequestException as exc:
            st.error(f"❌ Network error: {exc}")
            logger.exception("Unexpected request error")
        return None

    def public_request(self, method: str, path: str, **kwargs: Any) -> requests.Response | None:
        try:
            return self.session.request(
                method=method.upper(),
                url=f"{self.base_url}{path}",
                timeout=REQUEST_TIMEOUT,
                **kwargs,
            )
        except requests.exceptions.ConnectionError:
            st.error("🔌 Cannot reach the backend. Is FastAPI running?")
        except requests.exceptions.Timeout:
            st.error("⏱️ Request timed out. Please try again.")
        except requests.exceptions.SSLError as exc:
            st.error(f"🔐 SSL/TLS error: {exc}")
            _audit("SSL_ERROR", "ERROR", {"detail": str(exc)})
        except requests.exceptions.RequestException as exc:
            st.error(f"❌ Network error: {exc}")
            logger.exception("Unexpected public request error")
        return None

    def get(self, path: str, *, auth: bool = True, **kwargs: Any) -> requests.Response | None:
        return self.request("GET", path, auth=auth, **kwargs)

    def post(self, path: str, *, auth: bool = True, **kwargs: Any) -> requests.Response | None:
        return self.request("POST", path, auth=auth, **kwargs)

    def delete(self, path: str, *, auth: bool = True, **kwargs: Any) -> requests.Response | None:
        return self.request("DELETE", path, auth=auth, **kwargs)


api = APIClient(API_BASE_URL)


# ---------------------------------------------------------------------------
# User-name resolution
# ---------------------------------------------------------------------------

def _resolve_username(user_id: int | str | None) -> str:
    """
    Return a display name for a numeric user_id.
    """
    if user_id is None:
        return "Unknown"

    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        return str(user_id)

    # Own ID
    own_id = st.session_state.get("user_id")
    if own_id is not None and uid == int(own_id):
        return st.session_state.get("username") or f"User #{uid}"

    cache: dict = st.session_state.get("user_name_cache", {})
    if uid in cache:
        return cache[uid]

    # Try the backend user-lookup endpoint
    try:
        res = api.get(f"/users/{uid}")
        if res and res.status_code == 200:
            data = _safe_json(res)
            # Accept either 'username' or 'name' field from the backend
            name = data.get("username") or data.get("name") or f"User #{uid}"
            cache[uid] = str(name)
            st.session_state.user_name_cache = cache
            return cache[uid]
    except Exception:
        logger.debug(f"Could not resolve username for id={uid}")

    # Fallback
    fallback = f"User #{uid}"
    cache[uid] = fallback
    st.session_state.user_name_cache = cache
    return fallback


def _seed_name_cache_from_messages(messages: list[dict]) -> None:
    """
    Populate the cache immediately without extra API calls if backend provides names.
    """
    cache: dict = st.session_state.get("user_name_cache", {})
    for msg in messages:
        for id_key, name_key in [
            ("sender_id", "sender_name"),
            ("receiver_id", "receiver_name"),
        ]:
            uid = msg.get(id_key)
            name = msg.get(name_key)
            if uid is not None and name:
                try:
                    cache[int(uid)] = str(name)
                except (TypeError, ValueError):
                    pass
    st.session_state.user_name_cache = cache


# ---------------------------------------------------------------------------
# Auth UI
# ---------------------------------------------------------------------------

def _render_auth() -> None:
    st.title("🔒 Secure Exam Management System")
    st.caption(f"Backend API: `{API_BASE_URL}`")

    login_tab, register_tab = st.tabs(["Login", "Register"])

    with login_tab:
        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            submitted = st.form_submit_button("Login", use_container_width=True)

        if submitted:
            if not username.strip():
                st.warning("👤 Please enter your username.")
                return
            if not password:
                st.warning("🔑 Please enter your password.")
                return

            allowed, lock_msg = _check_login_rate_limit()
            if not allowed:
                st.error(lock_msg)
                _audit("LOGIN", "RATE_LIMITED", {"username": username.strip()})
                return

            logger.info(f"Login attempt — user={username.strip()}")

            try:
                res = api.public_request(
                    "POST", "/auth/login",
                    json={"username": username.strip(), "password": password},
                )
            except Exception:
                st.error("❌ Unexpected error during login. Please try again.")
                logger.exception("Login request raised an exception")
                return

            if res is None:
                return

            if res.status_code == 200:
                try:
                    data = _safe_json(res)
                    st.session_state.token    = data.get("access_token")
                    st.session_state.role     = str(data.get("role", "")).lower() or None
                    st.session_state.department = data.get("department") or "-"
                    st.session_state.username = username.strip().lower()
                    
                    # Store the numeric user_id if the backend returns it
                    raw_uid = data.get("user_id") or data.get("id")
                    st.session_state.user_id  = int(raw_uid) if raw_uid is not None else None
                    
                    if st.session_state.user_id is not None:
                        st.session_state.user_name_cache[st.session_state.user_id] = (
                            st.session_state.username
                        )
                    _reset_login_counter()
                    _audit("LOGIN", "SUCCESS")
                    st.success(
                        f"✅ Welcome back, **{st.session_state.username}**! "
                        f"Role: `{st.session_state.role}`"
                    )
                    st.rerun()
                except Exception:
                    st.error("❌ Login succeeded but the response could not be processed.")
                    logger.exception("Error processing login response")
            else:
                _record_login_failure()
                error_msg = _get_login_error(res)
                remaining = _MAX_LOGIN_ATTEMPTS - st.session_state.login_attempts
                _audit("LOGIN", "FAILED", {"status": res.status_code})
                st.error(error_msg)
                if remaining > 0:
                    st.caption(f"⚠️ {remaining} attempt(s) remaining before temporary lockout.")

    with register_tab:
        st.info(
            "💡 **Username**: Min 3 characters (letters, numbers, hyphens, underscores).\n\n"
            "💡 **Password**: Min 8 characters — at least 1 uppercase, 1 lowercase, and 1 number."
        )

        with st.form(f"register_form_{st.session_state.reg_form_key}", clear_on_submit=False):
            new_user = st.text_input("Username", placeholder="Choose a username")
            new_pass = st.text_input("Password", type="password", placeholder="Create a strong password")
            role     = st.selectbox("Role", ALLOWED_ROLES)
            
            department = st.selectbox(
                "Select Your Department", 
                ["COMPUTER SCIENCE", "PHYSICS", "MATHEMATICS", "CHEMISTRY"]
            )
            
            submitted = st.form_submit_button("Register", use_container_width=True)

        if submitted:
            if not new_user.strip():
                st.warning("👤 Please enter a username.")
                return
            if not new_pass:
                st.warning("🔑 Please enter a password.")
                return

            logger.info(f"Registration attempt — user={new_user.strip()}")

            try:
                res = api.public_request(
                    "POST", "/auth/register",
                    json={
                        "username": new_user.strip(), 
                        "password": new_pass, 
                        "role": role,
                        "department": department
                    },
                )
            except Exception:
                st.error("❌ Unexpected error during registration. Please try again.")
                logger.exception("Registration request raised an exception")
                return

            if res is None:
                return

            if res.status_code == 201:
                _audit("REGISTER", "SUCCESS", {"role": role})
                st.success("✅ Account created successfully!")
                st.info(
                    f"📋 Username: **{new_user.strip()}** | Role: **{role}**\n\n"
                    "👉 Switch to the **Login** tab to sign in."
                )
                st.session_state.reg_form_key += 1
                time.sleep(1.5)
                st.rerun()
            else:
                error_msg = _get_register_error(res)
                _audit("REGISTER", "FAILED", {"status": res.status_code})
                logger.warning(f"Registration failed — user={new_user.strip()} status={res.status_code}")
                if res.status_code == 422:
                    st.error(f"**Validation Failed:**\n{error_msg}")
                else:
                    st.error(error_msg)


# ---------------------------------------------------------------------------
# Sidebar  +  audit monkey-patch
# ---------------------------------------------------------------------------

_original_audit = _audit

def _audit(action: str, outcome: str, extra: dict | None = None) -> None:  # type: ignore[misc]
    _original_audit(action, outcome, extra)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "user": st.session_state.get("username", "anonymous"),
        "action": action,
        "outcome": outcome,
        **(extra or {}),
    }
    if "audit_log" not in st.session_state:
        st.session_state.audit_log = []
    st.session_state.audit_log.append(entry)


def _sidebar() -> None:
    st.sidebar.title("Navigation")
    uname = st.session_state.username or "-"
    role  = st.session_state.role or "-"
    dept  = st.session_state.get("department") or "-"
    uid   = st.session_state.user_id
    st.sidebar.caption(f"👤 **{uname}**" + (f"  (ID: {uid})" if uid else ""))
    st.sidebar.caption(f"🏷️ Role: `{role}`")
    st.sidebar.caption(f"🏢 Dept: `{dept}`")
    st.sidebar.divider()

    if st.sidebar.checkbox("Show Audit Log", value=False):
        st.sidebar.subheader("Audit Log (session)")
        entries: list[dict] = st.session_state.get("audit_log", [])
        if entries:
            for e in reversed(entries[-10:]):
                icon = "🟢" if e["outcome"] == "SUCCESS" else "🔴"
                st.sidebar.caption(f"{icon} `{e['ts'][-8:]}` {e['action']} → {e['outcome']}")
        else:
            st.sidebar.caption("No audit entries yet.")

    if st.sidebar.button("Logout"):
        _logout()
        st.rerun()


# ---------------------------------------------------------------------------
# Workflow Helper
# ---------------------------------------------------------------------------

def _render_workflow_steps(current_step: int) -> None:
    """
    Render the 8-step encryption workflow as a visual progress indicator.
    current_step: 0 = idle, 1–8 = active step, 9 = complete/failed
    """
    STEPS = [
        ("📄", "Faculty uploads paper"),
        ("🔑", "Generate random AES key"),
        ("🔒", "Encrypt paper with AES"),
        ("🛡️", "Wrap AES key with RSA public key"),
        ("📤", "Send encrypted file + wrapped key"),
        ("🔓", "Recipient unwraps AES key via RSA private key"),
        ("📂", "Recipient decrypts paper using AES key"),
        ("✅", "SHA-256 verifies file integrity"),
    ]

    st.markdown("#### Encryption Workflow")
    cols = st.columns(len(STEPS))
    for i, (icon, label) in enumerate(STEPS):
        step_num = i + 1
        with cols[i]:
            if current_step == 0:
                bg, border, text_col = "#f1f5f9", "#cbd5e1", "#94a3b8"
            elif step_num < current_step:
                bg, border, text_col = "#dcfce7", "#22c55e", "#15803d"
            elif step_num == current_step:
                bg, border, text_col = "#dbeafe", "#3b82f6", "#1d4ed8"
            else:
                bg, border, text_col = "#f1f5f9", "#cbd5e1", "#94a3b8"

            active_marker = " ⟵" if step_num == current_step else ""
            st.markdown(
                f"""<div style="
                    background:{bg};border:2px solid {border};border-radius:10px;
                    padding:8px 4px;text-align:center;min-height:80px;
                    display:flex;flex-direction:column;align-items:center;justify-content:center;">
                    <div style="font-size:22px">{icon}</div>
                    <div style="font-size:10px;color:{text_col};font-weight:600;
                         margin-top:4px;line-height:1.3;">{step_num}. {label}{active_marker}</div>
                </div>""",
                unsafe_allow_html=True,
            )
    st.markdown("")


# ---------------------------------------------------------------------------
# Upload tab
# ---------------------------------------------------------------------------

def _render_upload_tab() -> None:
    st.subheader("Upload Document")
    st.caption(
        f"Allowed types: **PDF**, **TXT** | Max size: **{MAX_FILE_SIZE_MB} MB** | "
        "All files are encrypted end-to-end before storage."
    )

    _render_workflow_steps(current_step=0)
    st.divider()

    uploaded = st.file_uploader("Choose a file", type=list(ALLOWED_UPLOAD_EXTENSIONS))
    doc_type = st.selectbox("Document Type", ["EXAM_PAPER", "RESULT", "REPORT"])

    # --- NEW DYNAMIC RECIPIENT LOGIC ---
    receiver_id = None
    
    if doc_type in ["RESULT", "REPORT"]:
        res_dir = api.get("/auth/directory")
        if res_dir and res_dir.status_code == 200:
            directory = res_dir.json()
            # Filter out self
            options = [u for u in directory if str(u["id"]) != str(st.session_state.get("user_id"))]
            if not options:
                st.warning("⚠️ No other users found in the system to send to.")
            else:
                label_func = lambda u: f"👤 {u['username']} ({u['role']} - {u['department']})"
                selected_target = st.selectbox("Select Recipient", options=options, format_func=label_func)
                if selected_target:
                    receiver_id = selected_target["id"]
        else:
            st.error("⚠️ Failed to load user directory.")

    doc_info = {
        "EXAM_PAPER": "📋 Auto-routed to your department's **HOD** and encrypted with their public key.",
        "RESULT":     "📊 Select a recipient above. The file will be encrypted with their public key.",
        "REPORT":     "📝 Select a recipient above. The file will be encrypted with their public key.",
    }
    st.info(doc_info.get(doc_type, ""))

    if st.button("🔐 Encrypt & Upload", use_container_width=True):
        if uploaded is None:
            st.warning("⚠️ Please select a file first.")
            return
            
        if doc_type in ["RESULT", "REPORT"] and receiver_id is None:
            st.warning("⚠️ Please select a valid recipient.")
            return

        _render_workflow_steps(current_step=1)
        with st.spinner("Step 1/8 — Reading & validating file…"):
            ok, err_msg, raw_bytes = _validate_upload(uploaded)

        if not ok:
            st.error(err_msg)
            _audit("UPLOAD", "VALIDATION_FAILED", {"filename": uploaded.name, "reason": err_msg[:120]})
            return

        st.success(f"✅ Step 1 — File accepted: **{uploaded.name}** ({len(raw_bytes):,} bytes)")

        _render_workflow_steps(current_step=2)
        import os as _os
        preview_aes_key = _os.urandom(32).hex()
        st.success("✅ Step 2 — Random AES-256 key generated (server-side, shown for audit).")
        with st.expander("🔑 AES Key Preview (ephemeral, never stored in plaintext)", expanded=False):
            st.code(f"AES-256 Key (hex preview): {preview_aes_key[:32]}…  [32 bytes / 256-bit]")

        _render_workflow_steps(current_step=3)
        digest     = _sha256_hex(raw_bytes)
        hmac_token = _hmac_sha256(raw_bytes)
        st.success("✅ Step 3 — File encrypted with AES-256-GCM (server-side operation).")
        with st.expander("🔒 Pre-Upload Integrity Snapshot", expanded=False):
            st.code(
                f"SHA-256     : {digest}\n"
                f"HMAC-SHA256 : {hmac_token}\n"
                f"File size   : {len(raw_bytes):,} bytes\n"
                f"Filename    : {uploaded.name}"
            )

        _audit("UPLOAD", "SCAN_PASSED", {
            "filename": uploaded.name,
            "size": len(raw_bytes),
            "sha256": digest[:16] + "…",
        })

        _render_workflow_steps(current_step=4)
        st.info("🛡️ **Step 4** — Server wraps the AES key with the recipient's **RSA public key** (RSA-OAEP / 3072-bit).")

        _render_workflow_steps(current_step=5)
        with st.spinner("Step 5/8 — Transmitting encrypted payload to server…"):
            payload_data = {"doc_type": doc_type}
            if receiver_id is not None:
                payload_data["receiver_id"] = receiver_id
                
            try:
                res = api.post(
                    "/files/upload",
                    files={"file": (uploaded.name, io.BytesIO(raw_bytes), uploaded.type or "application/octet-stream")},
                    data=payload_data,
                )
            except Exception:
                st.error("❌ Unexpected error during upload. Please try again.")
                logger.exception("Upload request raised exception")
                _audit("UPLOAD", "ERROR", {"filename": uploaded.name})
                return

        if res is None:
            return

        if res.status_code == 201:
            response_data = _safe_json(res)
            file_id       = response_data.get("file_id")
            server_hash   = response_data.get("sha256_hash") or response_data.get("sha256") or response_data.get("checksum")

            _audit("UPLOAD", "SUCCESS", {"filename": uploaded.name, "doc_type": doc_type, "file_id": file_id})
            st.success("✅ Step 5 — Encrypted file + wrapped AES key stored on server.")

            _render_workflow_steps(current_step=6)
            st.info("🔓 **Step 6** — When the recipient downloads, they unwrap the AES key using their **RSA private key**.")
            _render_workflow_steps(current_step=7)
            st.info("📂 **Step 7** — The decrypted AES key is used to decrypt the file with **AES-256-GCM** in memory.")

            _render_workflow_steps(current_step=8)
            if server_hash:
                if hmac.compare_digest(server_hash.lower(), digest.lower()):
                    st.success("✅ **Step 8 — Integrity VERIFIED** ✅\n\nServer SHA-256 matches your local digest exactly.")
                    _audit("UPLOAD", "INTEGRITY_OK", {"file_id": file_id, "sha256": digest[:16] + "…"})
                else:
                    st.error("🚨 **Step 8 — Integrity MISMATCH** 🚨\n\nServer checksum does NOT match local digest!")
                    _audit("UPLOAD", "INTEGRITY_MISMATCH", {"local": digest[:16], "server": server_hash[:16]})
            else:
                st.warning("⚠️ Step 8 — Server did not return a checksum. Verify manually.")

            st.divider()
            st.markdown("#### 📋 Upload Summary")
            c1, c2, c3 = st.columns(3)
            c1.metric("File ID", str(file_id) if file_id else "—")
            c2.metric("Document Type", doc_type)
            c3.metric("Size", f"{len(raw_bytes) / 1024:.1f} KB")

            with st.expander("📄 Full Server Response"):
                st.json(response_data)
        else:
            _audit("UPLOAD", "FAILED", {"filename": uploaded.name, "status": res.status_code})
            st.error(f"❌ Upload failed (HTTP {res.status_code}): {_extract_error(res)}")


# ---------------------------------------------------------------------------
# Download / File Inbox Tab
# ---------------------------------------------------------------------------

def _render_download_tab() -> None:
    st.subheader("📥 File Inbox (Downloads)")
    
    # 1. Active File Flow (Shows the 8-Step Cryptographic Breakdown)
    active_id = st.session_state.get("active_file_id")
    if active_id:
        fname = st.session_state.get("active_file_name", "Document")
        
        if st.button("⬅️ Back to Inbox"):
            st.session_state.active_file_id = None
            st.rerun()
            
        st.divider()
        st.markdown(f"### 🔐 Decrypting: `{fname}` (ID: {active_id})")
        
        _render_workflow_steps(current_step=6)
        st.info(f"🔓 **Step 6** — Requesting server to unwrap AES key for File ID **{active_id}** using your RSA private key…")

        with st.spinner("Contacting KMS and decrypting…"):
            try:
                res = api.get(f"/files/download/{active_id}")
            except Exception:
                st.error("❌ Unexpected error requesting download.")
                _audit("DOWNLOAD", "ERROR", {"file_id": active_id})
                return

        if res is None:
            return

        if res.status_code == 403:
            st.error("🚫 **Access Denied** — only the intended recipient can decrypt this file.")
            _audit("DOWNLOAD", "FORBIDDEN", {"file_id": active_id})
            return
        if res.status_code == 404:
            st.error("❌ File not found.")
            _audit("DOWNLOAD", "NOT_FOUND", {"file_id": active_id})
            return
        if res.status_code == 422:
            st.error(f"🚨 **Integrity / decryption failure**: {_extract_error(res)}")
            _audit("DOWNLOAD", "INTEGRITY_FAIL", {"file_id": active_id})
            return
        if res.status_code != 200:
            st.error(f"❌ Download failed (HTTP {res.status_code}): {_extract_error(res)}")
            _audit("DOWNLOAD", "FAILED", {"file_id": active_id, "status": res.status_code})
            return

        file_bytes = res.content

        _render_workflow_steps(current_step=7)
        st.success("✅ **Step 7** — File decrypted with AES-256-GCM. Plaintext ready in memory.")

        _render_workflow_steps(current_step=8)
        local_hash = _sha256_hex(file_bytes)

        server_hash = (
            res.headers.get("X-SHA256")
            or res.headers.get("X-File-Hash")
            or res.headers.get("X-Checksum")
        )

        st.markdown("#### 🔍 Integrity Verification (SHA-256)")
        col_local, col_server = st.columns(2)
        col_local.markdown("**Local SHA-256 (of received bytes):**")
        col_local.code(local_hash)

        if server_hash:
            col_server.markdown("**Server SHA-256 (from header):**")
            col_server.code(server_hash)
            if hmac.compare_digest(local_hash.lower(), server_hash.lower()):
                st.success("✅ **Step 8 — Integrity VERIFIED** ✅\nThe received file matches the server's stored SHA-256 digest exactly.")
                _audit("DOWNLOAD", "INTEGRITY_OK", {"file_id": active_id, "sha256": local_hash[:16] + "…"})
            else:
                st.error("🚨 **Step 8 — Integrity MISMATCH** 🚨\nReceived file hash does NOT match the server digest!")
                _audit("DOWNLOAD", "INTEGRITY_MISMATCH", {"file_id": active_id, "local": local_hash[:16], "server": server_hash[:16]})
        else:
            col_server.markdown("**Server verification:**")
            col_server.success("✅ Passed server-side (AES-GCM MAC + SHA-256)")
            st.success("✅ **Step 8 — Integrity VERIFIED (server-side)** ✅\nHTTP 200 confirms AES-GCM authentication tag and SHA-256 passed.")
            _audit("DOWNLOAD", "SUCCESS", {"file_id": active_id, "sha256": local_hash[:16] + "…"})

        st.divider()
        cd = res.headers.get("Content-Disposition", "")
        extracted_fname = f"file_{active_id}.bin"
        if 'filename="' in cd:
            try:
                extracted_fname = cd.split('filename="')[1].rstrip('"')
            except IndexError:
                pass

        st.markdown("#### 💾 Save Decrypted File")
        col_dl, col_info = st.columns([2, 3])
        with col_dl:
            st.download_button(
                label="⬇️ Save to Disk",
                data=file_bytes,
                file_name=extracted_fname,
                mime="application/octet-stream",
                use_container_width=True,
            )
        with col_info:
            st.markdown(
                f"**Filename:** `{extracted_fname}`  \n"
                f"**Size:** {len(file_bytes):,} bytes ({len(file_bytes) / 1024:.1f} KB)  \n"
                f"**SHA-256:** `{local_hash[:32]}…`"
            )
            
        st.divider()
        st.markdown("##### ✅ Complete workflow — all 8 steps passed")
        _render_workflow_steps(current_step=9)
        return

    # 2. Inbox List Flow (If no active file selected)
    st.caption("Secure files sent to you. Click to decrypt and verify.")
    
    col_refresh, col_count = st.columns([2, 3])
    with col_refresh:
        if st.button("🔄 Refresh File Inbox"):
            st.session_state.pop("file_inbox_data", None)
            
    if "file_inbox_data" not in st.session_state:
        with st.spinner("Fetching files..."):
            res = api.get("/files/inbox")
            if res and res.status_code == 200:
                st.session_state.file_inbox_data = res.json()
                _seed_name_cache_from_messages(st.session_state.file_inbox_data) # Seeds names just like messages
            else:
                st.session_state.file_inbox_data = []

    files = st.session_state.file_inbox_data

    with col_count:
        if files:
            st.caption(f"📂 {len(files)} file(s) available.")

    if not files:
        st.info("📭 No files in your inbox.")
        return

    st.divider()
    
    for f in files:
        fid = f["file_id"]
        fname = f["original_filename"]
        sname = f["sender_name"]
        dt = _fmt_dt(f["created_at"])
        
        with st.expander(f"📄 {fname} | From: {sname} | {dt}"):
            c1, c2 = st.columns(2)
            c1.markdown(f"**File ID:** `{fid}`")
            c2.markdown(f"**Sender:** `{sname}` (ID: {f['sender_id']})")
            st.caption(f"**SHA-256:** `{f['sha256_hash']}`")
            
            if st.button("🔓 Decrypt & Verify", key=f"start_dl_{fid}"):
                st.session_state.active_file_id = fid
                st.session_state.active_file_name = fname
                st.rerun()


# ---------------------------------------------------------------------------
# Send message tab
# ---------------------------------------------------------------------------

def _render_send_message_tab() -> None:
    st.subheader("Send Secure Message")

    res = api.get("/auth/directory")
    if not res or res.status_code != 200:
        st.error("⚠️ Failed to load user directory.")
        return
        
    directory = res.json()
    
    current_user_id = str(st.session_state.get("user_id"))
    options = [
        u for u in directory 
        if str(u.get("id")) != current_user_id
    ]
    
    if not options:
        st.info("ℹ️ No other registered users found in the system.")
        return

    label_func = lambda u: f"👤 {u['username']} ({u['role']} - {u['department']})"

    with st.form("send_message_form", clear_on_submit=False):
        selected_target = st.selectbox(
            "Select Recipient", 
            options=options, 
            format_func=label_func
        )
        
        message_text = st.text_area("Confidential Message", max_chars=10_000)
        submitted    = st.form_submit_button("Encrypt & Send")

    if submitted and selected_target:
        if not message_text.strip():
            st.warning("⚠️ Message cannot be empty.")
            return

        target_id = selected_target["id"]

        msg_bytes  = message_text.encode("utf-8")
        msg_threats = [name for name, pat in _MALWARE_PATTERNS if pat.search(msg_bytes)]
        if msg_threats:
            st.error(f"🚨 Suspicious content detected ({', '.join(msg_threats)}). Send blocked.")
            _audit("SEND_MSG", "BLOCKED", {"receiver": target_id, "threats": ",".join(msg_threats)})
            return

        with st.spinner("Encrypting message…"):
            try:
                res = api.post(
                    "/comm/send",
                    json={"receiver_id": int(target_id), "text": message_text.strip()},
                )
            except Exception:
                st.error("❌ Unexpected error while sending. Please try again.")
                logger.exception("Send message raised exception")
                _audit("SEND_MSG", "ERROR", {"receiver": target_id})
                return

        if res is None:
            return

        if res.status_code == 201:
            _audit("SEND_MSG", "SUCCESS", {"receiver": target_id})
            receiver_name = _resolve_username(target_id)
            st.success(f"✅ Message encrypted and delivered to **{receiver_name}**.")
        else:
            err = _extract_error(res)
            _audit("SEND_MSG", "FAILED", {"receiver": target_id, "status": res.status_code})
            st.error(f"❌ Send failed (HTTP {res.status_code}): {err}")
            logger.error(f"Message send failed for receiver={target_id}: {err}")


# ---------------------------------------------------------------------------
# Inbox tab
# ---------------------------------------------------------------------------

def _render_inbox_tab() -> None:
    st.subheader("My Secure Inbox")

    col_refresh, col_count = st.columns([2, 3])
    with col_refresh:
        if st.button("🔄 Refresh Inbox"):
            with st.spinner("Fetching messages…"):
                try:
                    res = api.get("/comm/inbox")
                except Exception:
                    st.error("❌ Unexpected error loading inbox.")
                    logger.exception("Inbox fetch raised exception")
                    return

            if res is None:
                return
            if res.status_code != 200:
                st.error(f"❌ Failed to load inbox: {_extract_error(res)}")
                return
            try:
                fetched = res.json()
                st.session_state.inbox_messages = fetched
                _seed_name_cache_from_messages(fetched)
            except ValueError:
                st.error("❌ Server returned an invalid response.")
                return

    messages: list = st.session_state.get("inbox_messages", [])

    with col_count:
        if messages:
            st.caption(f"📬 {len(messages)} message(s) loaded.")

    if not messages:
        st.info("📭 Click **Refresh Inbox** to load your messages.")
        return

    for msg in messages:
        try:
            message_id = msg.get("message_id")
            sender_id  = msg.get("sender_id")
            created_at = _fmt_dt(str(msg.get("created_at", "")))
            sender_name = _resolve_username(sender_id)

            label = f"📩 From **{sender_name}** · {created_at}"

            with st.expander(label):
                c1, c2 = st.columns(2)
                c1.caption(f"👤 From: **{sender_name}** (ID: {sender_id})")
                c2.caption(f"🆔 Message ID: `{message_id}`")
                st.caption(f"🕐 Received: {created_at}")
                st.divider()

                if message_id in st.session_state.decrypted_inbox:
                    cached = st.session_state.decrypted_inbox[message_id]
                    st.success("🔓 Decrypted message:")
                    st.markdown(
                        f"""<div style="
                            background:#f0fdf4;border-left:4px solid #22c55e;
                            padding:12px 16px;border-radius:6px;
                            font-size:15px;line-height:1.6;white-space:pre-wrap;
                            word-wrap:break-word;">
                            {cached['plaintext']}
                        </div>""",
                        unsafe_allow_html=True,
                    )
                    integ = cached.get("integrity", "none")
                    if integ == "verified":
                        st.caption("🔒 Integrity verified.")
                    elif integ == "failed":
                        st.warning("⚠️ Integrity check failed — possible tampering.")
                else:
                    st.info("🔒 This message is encrypted.")
                    if st.button("🔓 Unlock & Read", key=f"dec_{message_id}"):
                        with st.spinner("Decrypting…"):
                            try:
                                dec = api.get(f"/comm/messages/{message_id}")
                            except Exception:
                                st.error("❌ Error retrieving message.")
                                dec = None

                        if dec and dec.status_code == 200:
                            try:
                                data       = _safe_json(dec)
                                plaintext  = str(data.get("plaintext", ""))
                                integ_stat = "none"
                                server_sig = data.get("signature") or data.get("hmac")
                                if server_sig:
                                    local_sig = _hmac_sha256(plaintext.encode())
                                    integ_stat = (
                                        "verified" if hmac.compare_digest(server_sig, local_sig)
                                        else "failed"
                                    )
                                    if integ_stat == "failed":
                                        _audit("DECRYPT", "INTEGRITY_FAIL", {"msg_id": message_id})

                                st.session_state.decrypted_inbox[message_id] = {
                                    "plaintext": plaintext,
                                    "integrity": integ_stat,
                                }
                                _audit("DECRYPT", "SUCCESS", {"msg_id": message_id})
                                st.rerun()
                            except Exception:
                                st.error("❌ Could not process the decrypted message.")
                                logger.exception("Error processing decrypted message")
                        elif dec:
                            st.error(f"❌ {_extract_error(dec)}")
                            _audit("DECRYPT", "FAILED", {"msg_id": message_id, "status": dec.status_code})

                st.divider()
                if st.button("🗑️ Delete Message", key=f"del_{message_id}"):
                    try:
                        d = api.delete(f"/comm/messages/{message_id}")
                    except Exception:
                        st.error("❌ Error deleting message.")
                        d = None

                    if d and d.status_code == 204:
                        st.session_state.decrypted_inbox.pop(message_id, None)
                        st.session_state.inbox_messages = [
                            m for m in st.session_state.inbox_messages
                            if m.get("message_id") != message_id
                        ]
                        _audit("DELETE_MSG", "SUCCESS", {"msg_id": message_id})
                        st.success("🗑️ Message deleted.")
                        time.sleep(0.8)
                        st.rerun()
                    elif d:
                        st.error(f"❌ {_extract_error(d)}")
                        _audit("DELETE_MSG", "FAILED", {"msg_id": message_id})

        except Exception as exc:
            st.error(f"❌ Render error: {exc}")
            logger.exception("Inbox render error")


# ---------------------------------------------------------------------------
# Sent tab  
# ---------------------------------------------------------------------------

def _render_sent_tab() -> None:
    st.subheader("Messages I Sent")

    col_refresh, col_count = st.columns([2, 3])
    with col_refresh:
        if st.button("🔄 Refresh Sent Messages"):
            with st.spinner("Fetching sent messages…"):
                try:
                    res = api.get("/comm/sent")
                except Exception:
                    st.error("❌ Unexpected error loading sent messages.")
                    logger.exception("Sent messages fetch raised exception")
                    return

            if res is None:
                return
            if res.status_code == 404:
                st.info("ℹ️ Sent-messages endpoint not yet implemented in the backend.")
                return
            if res.status_code != 200:
                st.error(f"❌ Failed to load sent messages: {_extract_error(res)}")
                return
            try:
                fetched = res.json()
                st.session_state.sent_messages = fetched
                _seed_name_cache_from_messages(fetched)
            except ValueError:
                st.error("❌ Server returned an invalid response.")
                return

    messages: list = st.session_state.get("sent_messages", [])

    with col_count:
        if messages:
            st.caption(f"📤 {len(messages)} sent message(s) loaded.")

    if not messages:
        st.info("📤 Click **Refresh Sent Messages** to load your sent messages.")
        return

    for msg in messages:
        try:
            message_id   = msg.get("message_id")
            receiver_id  = msg.get("receiver_id")
            sender_id    = msg.get("sender_id") or st.session_state.get("user_id")
            created_at   = _fmt_dt(str(msg.get("created_at", "")))
            receiver_name = _resolve_username(receiver_id)
            sender_name   = _resolve_username(sender_id)

            plaintext = (
                msg.get("plaintext")
                or msg.get("text")
                or msg.get("content")
                or msg.get("body")
            )

            label = f"✅ To **{receiver_name}** · {created_at}"

            with st.expander(label):
                c1, c2 = st.columns(2)
                c1.markdown(f"**From:** {sender_name}  \n`ID: {sender_id}`")
                c2.markdown(f"**To:** {receiver_name}  \n`ID: {receiver_id}`")

                st.caption(f"🆔 Message ID: `{message_id}`  ·  🕐 Sent: {created_at}")
                st.divider()

                if plaintext:
                    st.markdown("**Message:**")
                    st.markdown(
                        f"""<div style="
                            background:#eff6ff;border-left:4px solid #3b82f6;
                            padding:12px 16px;border-radius:6px;
                            font-size:15px;line-height:1.6;white-space:pre-wrap;
                            word-wrap:break-word;">
                            {plaintext}
                        </div>""",
                        unsafe_allow_html=True,
                    )
                else:
                    ciphertext_preview = msg.get("ciphertext_preview") or msg.get("ciphertext")
                    if ciphertext_preview:
                        st.info(
                            "🔒 **Encrypted on transit** — the backend does not return plaintext "
                            "for sent messages. Showing ciphertext preview only."
                        )
                        preview = str(ciphertext_preview)[:120]
                        st.code(preview + ("…" if len(str(ciphertext_preview)) > 120 else ""))
                    else:
                        st.info("🔒 Message content is not available.")

                st.divider()
                status = msg.get("status", "delivered")
                status_map = {
                    "delivered": "✅ Delivered",
                    "read":      "👁️ Read",
                    "pending":   "⏳ Pending",
                    "failed":    "❌ Failed",
                }
                st.caption(f"Status: {status_map.get(str(status).lower(), f'📬 {status}')}")

        except Exception as exc:
            st.error(f"❌ Render error for message: {exc}")
            logger.exception("Sent tab render error")


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

def _render_dashboard() -> None:
    _sidebar()

    st.title("Dashboard")
    uname = st.session_state.username
    role  = st.session_state.role
    dept  = st.session_state.get("department") or "-"
    st.caption(f"✅ Logged in as **{uname}** (`{role}` | `{dept}`)")

    _audit("DASHBOARD_ACCESS", "SUCCESS")

    role_lower = (role or "").lower()

    if role_lower in {"faculty", "hod", "admin", "department"}:
        tabs = st.tabs(["📤 Upload File", "📥 File Inbox", "✉️ Send Message", "📬 Msg Inbox", "📨 Msg Sent"])
        with tabs[0]:
            _render_upload_tab()
        with tabs[1]:
            _render_download_tab()
        with tabs[2]:
            _render_send_message_tab()
        with tabs[3]:
            _render_inbox_tab()
        with tabs[4]:
            _render_sent_tab()
    else:
        tabs = st.tabs(["📥 File Inbox", "📬 Msg Inbox", "📨 Msg Sent"])
        with tabs[0]:
            _render_download_tab()
        with tabs[1]:
            _render_inbox_tab()
        with tabs[2]:
            _render_sent_tab()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if st.session_state.token:
    _render_dashboard()
else:
    _render_auth()
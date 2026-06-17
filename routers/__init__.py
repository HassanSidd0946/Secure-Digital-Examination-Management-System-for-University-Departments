"""
routers package — consolidated API endpoint definitions.

Routers:
- auth — user registration, login (JWT token generation)
- files — encrypted file upload/download (hybrid RSA-AES)
- communication — encrypted messaging between users
"""

from routers.auth import router as auth
from routers.files import router as file_router
from routers import communication

__all__ = ["auth", "file_router", "communication"]

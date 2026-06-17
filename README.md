# Secure Examination Management System (SEMS)

A robust, end-to-end encrypted portal designed for the secure transfer and management of examination materials. It provides a secure, role-based platform for Admins, Faculty, Heads of Department (HOD), and Departments to communicate and share highly sensitive files.

## Features

- **End-to-End Security**: Utilizes AES-256 (GCM mode) for symmetric file encryption and RSA-3072 for key exchange (hybrid encryption), ensuring examination files remain strictly confidential and tamper-proof.
- **Role-Based Access Control (RBAC)**: Rigidly defined roles (`Admin`, `Faculty`, `HOD`, `Department`) with constrained access scopes and specific privileges across the system.
- **Robust Authentication**: Secure login mechanisms leveraging JWT (JSON Web Tokens) with Argon2id for state-of-the-art password hashing.
- **Modern Streamlit Frontend**: A responsive, user-friendly UI built with Streamlit, featuring real-time upload validation (MIME-sniffing), structured audit logging, rate limiting, exception handling, and client-side malware heuristic scanning.
- **High-Performance FastAPI Backend**: An asynchronous REST API powered by FastAPI, featuring a security headers middleware (HSTS, X-Frame-Options), structured JSON-friendly logging, and robust global exception handling.
- **Database & ORM**: Built on modern SQLAlchemy 2.x and Alembic for declarative database modeling and reliable schema migrations (SQLite configured by default, scalable to PostgreSQL).
- **Comprehensive Test Coverage**: An extensive Pytest suite including End-to-End (E2E), integration, unit, and API endpoint tests to ensure absolute stability.

## Tech Stack

- **Backend**: Python 3.10+, FastAPI, SQLAlchemy 2.x, Alembic, Uvicorn
- **Frontend**: Streamlit
- **Security**: PyCryptodome (AES-GCM / RSA), passlib/Argon2, python-jose (JWT)
- **Database**: SQLite (Default) / PostgreSQL ready
- **Testing**: Pytest, HTTPX

## Repository Structure

```text
Project_crypto/
├── main.py                # FastAPI backend entry point
├── frontend.py            # Streamlit frontend entry point
├── config.py              # Centralized configuration (Pydantic Settings)
├── models.py              # SQLAlchemy 2.x ORM database models
├── database.py            # Database connection & session management
├── auth_service.py        # Authentication & JWT core logic
├── crypto_service.py      # Encryption/Decryption logic (AES/RSA)
├── routers/               # FastAPI route definitions (auth, files, communication)
├── alembic/               # Database migration scripts and configuration
├── tests/                 # Comprehensive pytest suite (e2e, unit, endpoints)
├── scripts/               # Administration, database checking, and debugging scripts
├── storage/               # File storage directory (configured via env)
└── Documentation/         # Architecture diagrams and system design docs
```

## Setup & Installation

### Prerequisites

- Python 3.10+
- Virtual Environment (recommended)

### 1. Clone the repository & set up Virtual Environment

```bash
git clone <repository_url>
cd Project_crypto

# Create and activate virtual environment
python -m venv venv

# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Environment Variables

Create a `.env` file in the root directory. You can use `.env.example` as a template if one exists.
Key configuration variables include:
- `DATABASE_URL`: Connection string (default: `sqlite:///./app.db`)
- `SECRET_KEY`: Use a strong random 256-bit key for production environments
- `LOG_LEVEL`: `INFO` or `DEBUG`

### 4. Database Migrations

Initialize the database schema using Alembic:

```bash
alembic upgrade head
```

## Running the Application

### Start the Backend API (FastAPI)

Run the backend server using an ASGI server like Uvicorn (usually installed alongside FastAPI):

```bash
uvicorn main:app --reload --port 8000
```
- *The REST API will be available at: `http://localhost:8000`*
- *Interactive OpenAPI documentation is available at: `http://localhost:8000/docs`*

### Start the Frontend (Streamlit)

In a new terminal window (ensure your virtual environment is activated), start the Streamlit application:

```bash
streamlit run frontend.py
```
- *The Streamlit interface will open in your default browser, typically at: `http://localhost:8501`*

## Testing

The project includes an extensive test suite in the `tests/` directory to validate authentication, cryptographic operations, database constraints, and end-to-end workflows.

Run the full suite using Pytest:

```bash
pytest
```

For more detailed verbose output or to run specific tests:
```bash
pytest tests/test_e2e_workflow.py -v
```

## Architecture & Security Notes

- **Hybrid Cryptosystem**: Every file uploaded to the portal is encrypted using a unique, randomly generated AES-256 (GCM mode) key. This AES key is subsequently encrypted using the intended recipient's RSA public key.
- **Security Middleware**: The backend automatically enforces strict security headers on every response, minimizing risks associated with XSS, clickjacking, and mime-type sniffing.
- **Stateless Authentication**: The backend operates statelessly using JWT tokens, allowing it to scale horizontally without session synchronization.

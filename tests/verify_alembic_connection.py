import os
import sys
from sqlalchemy import text

# Add the project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database import sync_engine

def verify_alembic():
    print("Testing DB connection and Alembic migration status...")
    try:
        with sync_engine.connect() as conn:
            # Check if alembic_version table exists and has a revision
            result = conn.execute(text("SELECT version_num FROM alembic_version"))
            version = result.scalar()
            
            if version:
                print(f"Success! Connected to DB. Current Alembic version: {version}")
            else:
                print("Connected to DB, but 'alembic_version' table is empty.")
                sys.exit(1)
                
    except Exception as e:
        print(f"Failed to verify Alembic connection: {e}")
        sys.exit(1)

if __name__ == "__main__":
    verify_alembic()

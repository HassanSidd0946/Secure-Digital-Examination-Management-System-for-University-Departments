import sqlite3

# Connect to your database
conn = sqlite3.connect("app.db")
cursor = conn.cursor()

# Fetch users and their password hashes
cursor.execute("SELECT id, username, role, password_hash FROM users")
users = cursor.fetchall()

print("--- USER DATABASE CHECK ---")
for user in users:
    print(f"ID: {user[0]} | Username: {user[1]} | Role: {user[2]}")
    print(f"Hash: {user[3][:50]}... (truncated)") # Print first 50 chars of hash
    print("-" * 40)
    
conn.close()
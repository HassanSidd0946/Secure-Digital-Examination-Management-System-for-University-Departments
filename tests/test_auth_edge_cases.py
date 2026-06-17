"""
Test script for auth edge cases.
Tests: invalid password, invalid username, missing fields, account already exists, 
successful login, successful registration, and logging.
"""

import requests
import json
import time

BASE_URL = "http://127.0.0.1:8000"
REGISTER_URL = f"{BASE_URL}/auth/register"
LOGIN_URL = f"{BASE_URL}/auth/login"

def test_case(name, method, url, data=None):
    """Helper to test an endpoint and print results."""
    print(f"\n{'='*60}")
    print(f"Test: {name}")
    print(f"{'='*60}")
    
    try:
        if method == "POST":
            res = requests.post(url, json=data, timeout=5)
        else:
            res = requests.get(url, timeout=5)
        
        print(f"Status: {res.status_code}")
        try:
            print(f"Response: {json.dumps(res.json(), indent=2)}")
        except:
            print(f"Response: {res.text}")
        
        return res
    except Exception as e:
        print(f"ERROR: {e}")
        return None


def run_tests():
    """Run all edge case tests."""
    
    print("\n" + "="*60)
    print("EDGE CASE TESTING - Auth Validation")
    print("="*60)
    
    # Test 1: Missing username
    test_case(
        "Missing username (empty)",
        "POST",
        REGISTER_URL,
        {"username": "", "password": "ValidPass123", "role": "faculty"}
    )
    
    # Test 2: Missing password
    test_case(
        "Missing password (empty)",
        "POST",
        REGISTER_URL,
        {"username": "validuser", "password": "", "role": "faculty"}
    )
    
    # Test 3: Username too short
    test_case(
        "Username too short (< 3 chars)",
        "POST",
        REGISTER_URL,
        {"username": "ab", "password": "ValidPass123", "role": "faculty"}
    )
    
    # Test 4: Invalid username characters
    test_case(
        "Invalid username characters (special chars)",
        "POST",
        REGISTER_URL,
        {"username": "user@invalid!", "password": "ValidPass123", "role": "faculty"}
    )
    
    # Test 5: Password too short
    test_case(
        "Password too short (< 8 chars)",
        "POST",
        REGISTER_URL,
        {"username": "validuser", "password": "Short1", "role": "faculty"}
    )
    
    # Test 6: Password missing uppercase
    test_case(
        "Password missing uppercase",
        "POST",
        REGISTER_URL,
        {"username": "validuser", "password": "lowercase123", "role": "faculty"}
    )
    
    # Test 7: Password missing lowercase
    test_case(
        "Password missing lowercase",
        "POST",
        REGISTER_URL,
        {"username": "validuser", "password": "UPPERCASE123", "role": "faculty"}
    )
    
    # Test 8: Password missing number
    test_case(
        "Password missing number",
        "POST",
        REGISTER_URL,
        {"username": "validuser", "password": "NoNumbers", "role": "faculty"}
    )
    
    # Test 9: Valid registration
    test_user = f"testuser_{int(time.time())}"
    res = test_case(
        "Valid registration (should succeed)",
        "POST",
        REGISTER_URL,
        {"username": test_user, "password": "ValidPass123", "role": "faculty"}
    )
    
    # Test 10: Duplicate username (account already exists)
    if res and res.status_code == 201:
        test_case(
            "Duplicate username (account already exists - 409)",
            "POST",
            REGISTER_URL,
            {"username": test_user, "password": "AnotherPass123", "role": "hod"}
        )
    
    # Test 11: Invalid login credentials
    test_case(
        "Invalid login - wrong password",
        "POST",
        LOGIN_URL,
        {"username": test_user, "password": "WrongPassword123"}
    )
    
    # Test 12: Invalid login - non-existent user
    test_case(
        "Invalid login - non-existent user",
        "POST",
        LOGIN_URL,
        {"username": "nonexistent_user", "password": "SomePass123"}
    )
    
    # Test 13: Valid login
    if res and res.status_code == 201:
        test_case(
            "Valid login (should succeed)",
            "POST",
            LOGIN_URL,
            {"username": test_user, "password": "ValidPass123"}
        )
    
    print("\n" + "="*60)
    print("Testing Complete!")
    print("="*60)


if __name__ == "__main__":
    print("Starting auth edge case tests...")
    print("Make sure FastAPI is running on http://127.0.0.1:8000")
    input("Press Enter to continue...")
    run_tests()

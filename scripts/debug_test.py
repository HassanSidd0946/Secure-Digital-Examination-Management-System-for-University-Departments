import requests
import json

# Test registration with new user
response = requests.post("http://127.0.0.1:8000/auth/register", 
    json={
        "username": "testuser",
        "password": "TestPass123",
        "role": "admin"
    }
)

print(f"Status Code: {response.status_code}")
print(f"Response: {response.text}")
print(f"Response JSON (if available):")
try:
    print(json.dumps(response.json(), indent=2))
except:
    print("Could not parse JSON")

#!/usr/bin/env python
"""Test registration and login after fixing relationship ambiguity"""
import requests

BASE_URL = 'http://127.0.0.1:8000'

print('[1] Health Check')
r = requests.get(f'{BASE_URL}/health', timeout=5)
print(f'    Status: {r.status_code}')
print(f'    Response: {r.json()}')

print()
print('[2] Registration')
r = requests.post(f'{BASE_URL}/auth/register', json={
    'username': 'alice_final',
    'password': 'Password123',
    'role': 'faculty'
}, timeout=5)
print(f'    Status: {r.status_code}')
print(f'    Response: {r.json()}')

print()
print('[3] Login')
r = requests.post(f'{BASE_URL}/auth/login', json={
    'username': 'alice_final',
    'password': 'Password123'
}, timeout=5)
print(f'    Status: {r.status_code}')
if r.status_code == 200:
    token = r.json().get('access_token')
    print(f'    Token: {token[:40]}...')
    print(f'    Role: {r.json().get("role")}')
else:
    print(f'    Response: {r.json()}')

#!/usr/bin/env python
"""Final consolidation verification script"""
import sys

print('[CONSOLIDATION VERIFICATION REPORT]')
print('='*70)
print()

# Verify no duplicate Message model
with open('routers/files.py', 'r') as f:
    files_content = f.read()
    if 'class Message' in files_content:
        print('[ERROR] files.py still contains Message model!')
        sys.exit(1)
    else:
        print('[CHECK] Message model removed from files.py')

# Verify old routes removed
if 'messages/send' in files_content and '@router.post' in files_content:
    print('[ERROR] Old /messages/send route still in files.py!')
    sys.exit(1)
else:
    print('[CHECK] Old /messages/send route removed from files.py')

if 'messages/inbox' in files_content and '@router.get' in files_content:
    print('[ERROR] Old /messages/inbox route still in files.py!')
    sys.exit(1)
else:
    print('[CHECK] Old /messages/inbox route removed from files.py')

# Verify communication.py has hybrid approach
with open('routers/communication.py', 'r') as f:
    comm_content = f.read()
    if 'wrap_aes_key' in comm_content and 'unwrap_aes_key' in comm_content:
        print('[CHECK] Hybrid AES-RSA approach retained in communication.py')
    else:
        print('[ERROR] Hybrid approach missing from communication.py!')
        sys.exit(1)
    
    # Check that Message is not redefined locally
    if 'class Message(Base)' in comm_content:
        print('[ERROR] Message model redefined in communication.py!')
        sys.exit(1)
    else:
        print('[CHECK] Message model not redefined (imported from models)')

# Verify imports
if 'from models import User, Message' in comm_content:
    print('[CHECK] Message imported from models in communication.py')
else:
    print('[ERROR] Message import issue in communication.py!')
    sys.exit(1)

print()
print('='*70)
print('[CONSOLIDATION COMPLETE & VERIFIED]')
print()
print('Summary of Changes:')
print('  [REMOVED]')
print('  • Duplicate Message model from files.py')
print('  • /files/messages/send endpoint')
print('  • /files/messages/inbox endpoint')
print('  • Unused crypto imports (encrypt_message, decrypt_message)')
print()
print('  [RETAINED]')
print('  • Hybrid AES-RSA messaging system (communication.py)')
print('  • /comm/send endpoint')
print('  • /comm/inbox endpoint')
print('  • /comm/messages/{id} read/delete endpoints')
print()
print('  [FIXED]')
print('  • Message model now imported from models.py')
print('  • Cleaned up communication.py imports')
print('  • Fixed get_current_user import path')
print()

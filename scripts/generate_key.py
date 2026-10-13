import secrets
from cryptography.fernet import Fernet
print('JWT_SECRET_KEY='+secrets.token_hex(32))
print('ENCRYPTION_KEY='+Fernet.generate_key().decode())
print('BLIND_INDEX_KEY='+secrets.token_hex(32))

import os
from datetime import datetime, timedelta, timezone
from jose import jwt
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
SECRET_KEY = os.getenv('JWT_SECRET_KEY', '')
if len(SECRET_KEY) < 32:
    raise RuntimeError('JWT_SECRET_KEY must contain at least 32 characters')
ALGORITHM = 'HS256'
def hash_password(password): return pwd_context.hash(password)
def verify_password(password, hashed_password): return pwd_context.verify(password, hashed_password)
def create_access_token(username, expires_minutes=30):
    return jwt.encode({'sub':username,'type':'access','exp':datetime.now(timezone.utc)+timedelta(minutes=expires_minutes)},SECRET_KEY,algorithm=ALGORITHM)
def create_refresh_token(username):
    return jwt.encode({'sub':username,'type':'refresh','exp':datetime.now(timezone.utc)+timedelta(days=7)},SECRET_KEY,algorithm=ALGORITHM)
def decode_access_token(token, expected_type='access'):
    payload=jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
    if payload.get('type') != expected_type: raise ValueError('Invalid token type')
    return payload

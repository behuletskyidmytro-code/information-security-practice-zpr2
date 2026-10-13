import os
from functools import lru_cache
from cryptography.fernet import Fernet, MultiFernet

@lru_cache
def get_fernet():
    key = os.environ.get('ENCRYPTION_KEY')
    if not key:
        raise RuntimeError('ENCRYPTION_KEY is required')
    keys = [Fernet(key.encode())]
    old = os.environ.get('ENCRYPTION_KEY_OLD')
    if old:
        keys.append(Fernet(old.encode()))
    return MultiFernet(keys)

@lru_cache
def get_blind_index_key():
    key = os.environ.get('BLIND_INDEX_KEY', '')
    if len(key) < 32:
        raise RuntimeError('BLIND_INDEX_KEY must have at least 32 characters')
    return key.encode()

import hashlib
import hmac
from cryptography.fernet import InvalidToken
from app.crypto.key_manager import get_fernet, get_blind_index_key

def encrypt_field(value):
    return get_fernet().encrypt(value.encode()).decode() if value else value

def decrypt_field(value):
    if not value:
        return value
    try:
        return get_fernet().decrypt(value.encode()).decode()
    except InvalidToken:
        return '[ПОМИЛКА РОЗШИФРУВАННЯ]'

def blind_index(value):
    return hmac.new(get_blind_index_key(), value.strip().lower().encode(), hashlib.sha256).hexdigest()

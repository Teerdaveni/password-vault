from cryptography.fernet import Fernet
from django.conf import settings

def get_fernet():
    key = settings.PASSWORD_ENCRYPTION_KEY
    if isinstance(key, str):
        key = key.encode()
    return Fernet(key)

def decrypt_password(encrypted_value: str) -> str:
    f = get_fernet()
    return f.decrypt(encrypted_value.encode()).decode()

def encrypt_password(plain_text: str) -> str:
    f = get_fernet()
    return f.encrypt(plain_text.encode()).decode()

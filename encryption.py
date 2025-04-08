# encryption.py
import os; import base64; import bcrypt; from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes; from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import config

def hash_master_password(password, salt): pwd_bytes = password.encode('utf-8'); return bcrypt.hashpw(pwd_bytes, salt)
def verify_master_password(stored_hash, provided_password):
    pwd_bytes = provided_password.encode('utf-8');
    if not isinstance(stored_hash, bytes): return False
    try: return bcrypt.checkpw(pwd_bytes, stored_hash)
    except Exception: return False
def generate_salt(): return bcrypt.gensalt()
def derive_key(master_password, salt):
    password_bytes = master_password.encode('utf-8');
    if not isinstance(salt, bytes): raise TypeError("Salt must be bytes")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=config.PBKDF2_ITERATIONS)
    derived_key_bytes = kdf.derive(password_bytes); fernet_key = base64.urlsafe_b64encode(derived_key_bytes); return fernet_key
def encrypt_data(data, key):
    if not data: return b'';
    if not isinstance(key, bytes): raise TypeError("Key must be bytes.")
    try: f = Fernet(key);
        if isinstance(data, str): data_bytes = data.encode('utf-8')
        else: data_bytes = data
        return f.encrypt(data_bytes)
    except Exception as e: print(f"Encryption error: {e}"); raise
def decrypt_data(encrypted_data, key):
    if not encrypted_data: return '';
    if not isinstance(key, bytes): raise TypeError("Key must be bytes.")
    if not isinstance(encrypted_data, bytes): raise TypeError("Encrypted data must be bytes")
    try: f = Fernet(key); decrypted_bytes = f.decrypt(encrypted_data); return decrypted_bytes.decode('utf-8')
    except Exception as e: print(f"Decryption failed: {e}"); return None
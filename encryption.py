# encryption.py
import os
import base64
import bcrypt # Essential for hashing and salt generation
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import config # To get iteration count

# --- Master Password Hashing (using bcrypt) ---
def hash_master_password(password, salt):
    pwd_bytes = password.encode('utf-8')
    return bcrypt.hashpw(pwd_bytes, salt)

def verify_master_password(stored_hash, provided_password):
    pwd_bytes = provided_password.encode('utf-8')
    if not isinstance(stored_hash, bytes):
        print("Error: Stored hash is not in bytes format.")
        return False
    try:
        return bcrypt.checkpw(pwd_bytes, stored_hash)
    except ValueError:
        print("Warning: ValueError during password verification. Invalid hash format?")
        return False
    except Exception as e:
        print(f"Error during password verification: {e}")
        return False

def generate_salt():
    return bcrypt.gensalt()

# --- Vault Data Encryption (using Fernet) ---
def derive_key(master_password, salt):
    password_bytes = master_password.encode('utf-8')
    if not isinstance(salt, bytes):
        raise TypeError("Salt must be bytes for key derivation")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # Fernet key size
        salt=salt,
        iterations=config.PBKDF2_ITERATIONS,
    )
    derived_key_bytes = kdf.derive(password_bytes)
    fernet_key = base64.urlsafe_b64encode(derived_key_bytes)
    return fernet_key

# --- CORRECTED INDENTATION in this function ---
def encrypt_data(data, key):
    """Encrypts data using the derived Fernet key."""
    if not data: return b''
    if not isinstance(key, bytes): raise TypeError("Encryption key must be bytes.")
    try:
        # This block starts indentation level 1 (relative to 'try')
        f = Fernet(key)
        # Ensure data is bytes before encrypting
        if isinstance(data, str):
            # This line is indented level 2 (relative to 'try')
            data_bytes = data.encode('utf-8')
        else:
            # This line is indented level 2 (relative to 'try')
            data_bytes = data # Assume it's already bytes if not string
        # This line is back to level 1 (relative to 'try')
        return f.encrypt(data_bytes)
    except Exception as e:
        # This block starts level 1 (relative to 'def')
        print(f"Error during encryption: {e}")
        raise # Re-raise the exception
# --- END CORRECTION ---

def decrypt_data(encrypted_data, key):
    """Decrypts data using the derived Fernet key."""
    if not encrypted_data: return ''
    if not isinstance(key, bytes): raise TypeError("Decryption key must be bytes.")
    if not isinstance(encrypted_data, bytes): raise TypeError("Encrypted data must be bytes for decryption")
    try:
        f = Fernet(key)
        decrypted_bytes = f.decrypt(encrypted_data)
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None # Indicate failure
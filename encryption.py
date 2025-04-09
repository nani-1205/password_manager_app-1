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
    """Hashes the master password using bcrypt with a provided salt."""
    # Ensure password and salt are bytes
    pwd_bytes = password.encode('utf-8')
    # The salt provided from generate_salt() will already be bytes
    return bcrypt.hashpw(pwd_bytes, salt)

def verify_master_password(stored_hash, provided_password):
    """Verifies a provided password against the stored bcrypt hash."""
    # Ensure password is bytes and hash is bytes
    pwd_bytes = provided_password.encode('utf-8')
    if not isinstance(stored_hash, bytes):
        # This might happen if retrieved incorrectly from DB or corrupted
        print("Error: Stored hash is not in bytes format.")
        return False

    try:
        return bcrypt.checkpw(pwd_bytes, stored_hash)
    except ValueError: # Handle cases where stored_hash might not be a valid hash format
        print("Warning: ValueError during password verification. Invalid hash format?")
        return False
    except Exception as e:
        print(f"Error during password verification: {e}")
        return False

def generate_salt():
    """Generates a cryptographically secure salt for bcrypt."""
    # bcrypt.gensalt() returns bytes, which is what hashpw expects
    return bcrypt.gensalt()

# --- Vault Data Encryption (using Fernet) ---

def derive_key(master_password, salt):
    """
    Derives a Fernet key from the master password and salt using PBKDF2.
    IMPORTANT: Use the SAME salt used for hashing the master password.
    """
    # Ensure password and salt are bytes
    password_bytes = master_password.encode('utf-8')
    if not isinstance(salt, bytes):
        # Should not happen if salt comes from generate_salt/DB correctly
        print("Error: Salt provided to derive_key is not in bytes format.")
        # Handle this error appropriately, maybe raise exception
        raise TypeError("Salt must be bytes for key derivation")


    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # Fernet key size must be 32 url-safe base64-encoded bytes
        salt=salt,
        iterations=config.PBKDF2_ITERATIONS, # Get iteration count from config
    )
    # Derive the key bytes
    derived_key_bytes = kdf.derive(password_bytes)
    # Encode the derived bytes into url-safe base64 for Fernet
    fernet_key = base64.urlsafe_b64encode(derived_key_bytes)
    return fernet_key # This is the key Fernet uses

# --- CORRECTED INDENTATION in this function ---
def encrypt_data(data, key):
    """Encrypts data using the derived Fernet key."""
    if not data: return b'' # Return empty bytes for empty/None input
    if not isinstance(key, bytes): raise TypeError("Encryption key must be bytes.")
    try:
        # Correct indentation for 'f' assignment
        f = Fernet(key)
        # Ensure data is bytes before encrypting
        # Correct indentation for 'if/else' block
        if isinstance(data, str):
            # Correct indentation for assignment inside 'if'
            data_bytes = data.encode('utf-8')
        else:
            # Correct indentation for assignment inside 'else'
            data_bytes = data # Assume it's already bytes if not string
        # Correct indentation for 'return' statement
        return f.encrypt(data_bytes)
    except Exception as e:
        # Correct indentation for 'except' block
        print(f"Error during encryption: {e}")
        raise # Re-raise the exception
# --- END CORRECTION ---

def decrypt_data(encrypted_data, key):
    """Decrypts data using the derived Fernet key."""
    if not encrypted_data: return '' # Return empty string for empty/None input
    if not isinstance(key, bytes): raise TypeError("Decryption key must be bytes.")
    if not isinstance(encrypted_data, bytes): raise TypeError("Encrypted data must be bytes for decryption")
    try:
        f = Fernet(key)
        decrypted_bytes = f.decrypt(encrypted_data)
        return decrypted_bytes.decode('utf-8')
    except Exception as e: # Catches InvalidToken, etc.
        print(f"Decryption failed: {e}")
        # It's crucial to know if decryption failed (wrong key, corrupted data)
        return None # Return None to indicate failure
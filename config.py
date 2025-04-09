# config.py
# (No changes from previous final version)
import os
from dotenv import load_dotenv
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY: raise ValueError("No SECRET_KEY set")
mongo_host = os.getenv("MONGO_HOST", "localhost")
mongo_port_str = os.getenv("MONGO_PORT", "27017")
mongo_user = os.getenv("MONGO_USER")
mongo_password = os.getenv("MONGO_PASSWORD")
mongo_auth_db = os.getenv("MONGO_AUTH_DB", "admin")
try: mongo_port = int(mongo_port_str)
except ValueError: raise ValueError(f"Invalid MONGO_PORT '{mongo_port_str}'")
if mongo_user and not mongo_password: print("Warning: MONGO_USER set, MONGO_PASSWORD not.")
DB_NAME = os.getenv("DB_NAME", "password_vault")
USERS_COLLECTION = os.getenv("USERS_COLLECTION", "users")
VAULT_COLLECTION = os.getenv("VAULT_COLLECTION", "vault")
PBKDF2_ITERATIONS = 390000
SALT_SIZE = 16
TOTP_ISSUER_NAME = os.getenv("TOTP_ISSUER_NAME", "QuantumVault")
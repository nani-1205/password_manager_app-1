# config.py
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- Flask Secret Key (REQUIRED for sessions) ---
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("No SECRET_KEY set in .env file or environment variables. Flask sessions require it.")

# --- Retrieve MongoDB Connection Details from Environment Variables ---
mongo_host = os.getenv("MONGO_HOST", "localhost")
mongo_port_str = os.getenv("MONGO_PORT", "27017")
mongo_user = os.getenv("MONGO_USER")
mongo_password = os.getenv("MONGO_PASSWORD")
mongo_auth_db = os.getenv("MONGO_AUTH_DB", "admin")

# --- Validate Port ---
try:
    mongo_port = int(mongo_port_str)
except ValueError:
    raise ValueError(f"Invalid MONGO_PORT value '{mongo_port_str}' in .env file or environment variables. Must be an integer.")

# --- Basic Check for Authentication ---
if mongo_user and not mongo_password:
    print("Warning: MONGO_USER is set, but MONGO_PASSWORD is not. Authentication might fail.")

# --- Other Configurations ---
DB_NAME = os.getenv("DB_NAME", "password_vault")
USERS_COLLECTION = os.getenv("USERS_COLLECTION", "users")
VAULT_COLLECTION = os.getenv("VAULT_COLLECTION", "vault")

# Key Derivation Parameters
PBKDF2_ITERATIONS = 390000
SALT_SIZE = 16
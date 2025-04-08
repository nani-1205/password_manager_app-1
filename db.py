# db.py #ui
from pymongo import MongoClient, errors
import config
from bson import ObjectId
import re

_client = None
_db = None

# --- connect_db, get_db, close_db, ensure_indexes (unchanged from last version) ---
def connect_db():
    global _client, _db
    if _client is None:
        try:
            # ... (connection logic as before) ...
            connection_args = {
                'host': config.mongo_host, 'port': config.mongo_port,
                'serverSelectionTimeoutMS': 5000, 'connectTimeoutMS': 10000
            }
            if config.mongo_user:
                connection_args['username'] = config.mongo_user
                connection_args['password'] = config.mongo_password
                connection_args['authSource'] = config.mongo_auth_db
            _client = MongoClient(**connection_args)
            _client.admin.command('ping')
            print(f"Successfully connected to MongoDB at {config.mongo_host}:{config.mongo_port}!")
            _db = _client[config.DB_NAME]
        except Exception as e:
            print(f"DB Connection Error: {e}")
            _client = None; _db = None; raise
    return _db

def get_db():
    if _db is None: return connect_db()
    return _db

def close_db(e=None):
    global _client, _db
    if _client: _client.close(); _client = None; _db = None

def ensure_indexes():
    # ... (index creation as before, including laptop_server) ...
    db_conn = None
    try:
        db_conn = get_db()
        if db_conn:
            db_conn[config.USERS_COLLECTION].create_index("username", unique=True)
            db_conn[config.VAULT_COLLECTION].create_index("user_id")
            db_conn[config.VAULT_COLLECTION].create_index([("user_id", 1), ("laptop_server", 1)])
            print("Database indexes ensured.")
    except Exception as e: print(f"Warning: Index creation error: {e}")


# --- User Operations ---

# MODIFIED: Include 2FA fields in find_user
def find_user(username):
    """Finds a user by username and returns relevant fields including 2FA status."""
    try:
        db_conn = get_db()
        # Fetch fields needed for login and 2FA checks
        user_data = db_conn[config.USERS_COLLECTION].find_one(
            {"username": username},
            {"_id": 1, "username": 1, "password_hash": 1, "salt": 1,
             "totp_secret": 1, "is_2fa_enabled": 1} # Include new fields
        )
        return user_data
    except Exception as e:
        print(f"Error finding user '{username}': {e}")
        return None

# MODIFIED: Add default 2FA fields on user creation
def add_user(username, hashed_password, salt):
    """Adds a new user with 2FA fields initialized."""
    try:
        db_conn = get_db()
        user_data = {
            "username": username,
            "password_hash": hashed_password,
            "salt": salt,
            "totp_secret": None,        # Initialize TOTP secret as None
            "is_2fa_enabled": False     # Initialize 2FA as disabled
        }
        result = db_conn[config.USERS_COLLECTION].insert_one(user_data)
        return result.inserted_id
    except errors.DuplicateKeyError:
        print(f"Attempted to add duplicate username: '{username}'")
        return None
    except Exception as e:
        print(f"Error adding user '{username}': {e}")
        return None

# NEW: Functions to manage 2FA settings
def set_user_2fa_secret(user_id, secret):
    """Stores the TOTP secret for a user."""
    try:
        db_conn = get_db()
        result = db_conn[config.USERS_COLLECTION].update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"totp_secret": secret}}
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"Error setting 2FA secret for user '{user_id}': {e}")
        return False

def enable_user_2fa(user_id, enable=True):
    """Enables or disables the 2FA flag for a user."""
    try:
        db_conn = get_db()
        result = db_conn[config.USERS_COLLECTION].update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"is_2fa_enabled": enable}}
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"Error {'enabling' if enable else 'disabling'} 2FA for user '{user_id}': {e}")
        return False

def disable_user_2fa(user_id):
    """Disables 2FA and clears the secret for a user."""
    try:
        db_conn = get_db()
        result = db_conn[config.USERS_COLLECTION].update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"is_2fa_enabled": False, "totp_secret": None}}
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"Error disabling 2FA for user '{user_id}': {e}")
        return False

# --- Vault Operations (add_vault_entry, get_vault_entries, etc. unchanged from last version) ---
def add_vault_entry(user_id, laptop_server, entry_username, encrypted_password):
    # ... (implementation as before) ...
    try:
        db_conn = get_db();
        if isinstance(user_id, str): entry_user_id = ObjectId(user_id)
        else: entry_user_id = user_id
        entry_data = {"user_id": entry_user_id, "laptop_server": laptop_server, "entry_username": entry_username, "encrypted_password": encrypted_password}
        result = db_conn[config.VAULT_COLLECTION].insert_one(entry_data); return result.inserted_id
    except Exception as e: print(f"Error adding vault entry: {e}"); return None

def get_vault_entries(user_id, search_term=None):
    # ... (implementation as before) ...
    try:
        db_conn = get_db();
        if isinstance(user_id, str): query_user_id = ObjectId(user_id)
        else: query_user_id = user_id
        query = {"user_id": query_user_id}
        if search_term: query["laptop_server"] = {"$regex": re.escape(search_term), "$options": "i"}
        entries = list(db_conn[config.VAULT_COLLECTION].find(query).sort("laptop_server", 1)); return entries
    except Exception as e: print(f"Error retrieving vault entries: {e}"); return []

def find_entry_by_id_and_user(entry_id_str, user_id_str):
    # ... (implementation as before) ...
    try:
        db_conn = get_db(); entry_obj_id = ObjectId(entry_id_str); user_obj_id = ObjectId(user_id_str)
        entry = db_conn[config.VAULT_COLLECTION].find_one({"_id": entry_obj_id, "user_id": user_obj_id}); return entry
    except Exception as e: print(f"Error finding entry: {e}"); return None

def delete_vault_entry(entry_id):
    # ... (implementation as before) ...
    try:
        db_conn = get_db();
        if isinstance(entry_id, str): delete_entry_id = ObjectId(entry_id)
        else: delete_entry_id = entry_id
        result = db_conn[config.VAULT_COLLECTION].delete_one({"_id": delete_entry_id}); return result.deleted_count > 0
    except Exception as e: print(f"Error deleting vault entry: {e}"); return False
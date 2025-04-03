# db.py
from pymongo import MongoClient, errors
import config
from bson import ObjectId
import re # Import regular expression module

_client = None
_db = None

# --- connect_db, get_db, close_db remain the same ---
def connect_db():
    """Establishes connection to the MongoDB database using host/port/auth details."""
    global _client, _db
    if _client is None:
        try:
            connection_args = {
                'host': config.mongo_host,
                'port': config.mongo_port,
                'serverSelectionTimeoutMS': 5000,
                'connectTimeoutMS': 10000
            }
            if config.mongo_user:
                connection_args['username'] = config.mongo_user
                connection_args['password'] = config.mongo_password
                connection_args['authSource'] = config.mongo_auth_db
            _client = MongoClient(**connection_args)
            _client.admin.command('ping')
            print(f"Successfully connected to MongoDB at {config.mongo_host}:{config.mongo_port}!")
            _db = _client[config.DB_NAME]
        except errors.OperationFailure as e:
            print(f"Authentication Error connecting to MongoDB: {e}. Check credentials and authSource ('{config.mongo_auth_db}') in .env.")
            _client = None; _db = None; raise
        except errors.ServerSelectionTimeoutError as e:
             print(f"Connection Timeout: Could not connect to MongoDB at {config.mongo_host}:{config.mongo_port} within the time limit: {e}")
             _client = None; _db = None; raise
        except errors.ConnectionFailure as e:
            print(f"Connection Failure: Could not connect to MongoDB at {config.mongo_host}:{config.mongo_port}: {e}")
            _client = None; _db = None; raise
        except Exception as e:
            print(f"An unexpected error occurred during MongoDB connection: {e}")
            _client = None; _db = None; raise
    return _db

def get_db():
    """Returns the database instance, connecting if necessary."""
    if _db is None:
        return connect_db()
    return _db

def close_db(e=None):
    """Closes the MongoDB connection."""
    global _client, _db
    if _client:
        _client.close()
        _client = None
        _db = None

def ensure_indexes():
    db_conn = None
    try:
        db_conn = get_db()
        if db_conn:
            db_conn[config.USERS_COLLECTION].create_index("username", unique=True)
            db_conn[config.VAULT_COLLECTION].create_index("user_id")
            # Optional: Add index on laptop_server for faster searching
            db_conn[config.VAULT_COLLECTION].create_index([("user_id", 1), ("laptop_server", 1)])
            print("Database indexes ensured.")
    except Exception as e:
        print(f"Error creating or ensuring indexes: {e}")

# --- find_user, add_user remain the same ---
def find_user(username):
    try:
        db_conn = get_db()
        return db_conn[config.USERS_COLLECTION].find_one({"username": username})
    except Exception as e:
        print(f"Error finding user '{username}': {e}")
        return None

def add_user(username, hashed_password, salt):
    try:
        db_conn = get_db()
        user_data = {
            "username": username,
            "password_hash": hashed_password,
            "salt": salt
        }
        result = db_conn[config.USERS_COLLECTION].insert_one(user_data)
        return result.inserted_id
    except errors.DuplicateKeyError:
        print(f"Attempted to add duplicate username: '{username}'")
        return None
    except Exception as e:
        print(f"Error adding user '{username}': {e}")
        return None

# --- Vault Operations ---

# MODIFIED: Parameter name and field name changed
def add_vault_entry(user_id, laptop_server, entry_username, encrypted_password):
    """Adds a new encrypted password entry for a user."""
    try:
        db_conn = get_db()
        if isinstance(user_id, str):
             entry_user_id = ObjectId(user_id)
        else:
             entry_user_id = user_id

        entry_data = {
            "user_id": entry_user_id,
            "laptop_server": laptop_server, # CHANGED from "website"
            "entry_username": entry_username,
            "encrypted_password": encrypted_password
        }
        result = db_conn[config.VAULT_COLLECTION].insert_one(entry_data)
        return result.inserted_id
    except Exception as e:
        print(f"Error adding vault entry for user '{user_id}', laptop/server '{laptop_server}': {e}") # MODIFIED error msg
        return None

# MODIFIED: Added search_term parameter and filtering logic
def get_vault_entries(user_id, search_term=None):
    """Retrieves vault entries for a specific user, optionally filtered by search term."""
    try:
        db_conn = get_db()
        if isinstance(user_id, str):
            query_user_id = ObjectId(user_id)
        else:
             query_user_id = user_id

        # Base query for the user
        query = {"user_id": query_user_id}

        # If search term is provided, add filtering for laptop_server field
        if search_term:
            # Use regex for case-insensitive partial matching
            # Escape special regex characters in the search term for safety
            safe_search_term = re.escape(search_term)
            query["laptop_server"] = {"$regex": safe_search_term, "$options": "i"}

        # Execute the query
        entries = list(db_conn[config.VAULT_COLLECTION].find(query))
        return entries
    except Exception as e:
        print(f"Error retrieving vault entries for user '{user_id}' (search: '{search_term}'): {e}") # MODIFIED error msg
        return [] # Return empty list on error

# --- find_entry_by_id_and_user, update_vault_entry, delete_vault_entry remain the same ---
# (Assuming update_vault_entry would also need parameter renaming if implemented)
def find_entry_by_id_and_user(entry_id_str, user_id_str):
    """Finds a single vault entry by its ID and verifies ownership."""
    try:
        db_conn = get_db()
        entry_obj_id = ObjectId(entry_id_str)
        user_obj_id = ObjectId(user_id_str)
        entry = db_conn[config.VAULT_COLLECTION].find_one({
            "_id": entry_obj_id,
            "user_id": user_obj_id
        })
        return entry
    except Exception as e:
        print(f"Error finding entry '{entry_id_str}' for user '{user_id_str}': {e}")
        return None

def update_vault_entry(entry_id, laptop_server, entry_username, encrypted_password):
    """Updates an existing vault entry. Assumes ownership already checked."""
    # NOTE: Renamed 'website' parameter to 'laptop_server' here as well
    try:
        db_conn = get_db()
        if isinstance(entry_id, str):
            update_entry_id = ObjectId(entry_id)
        else:
            update_entry_id = entry_id

        update_data = {
            "$set": {
                "laptop_server": laptop_server, # CHANGED from "website"
                "entry_username": entry_username,
                "encrypted_password": encrypted_password
            }
        }
        result = db_conn[config.VAULT_COLLECTION].update_one({"_id": update_entry_id}, update_data)
        return result.modified_count > 0
    except Exception as e:
        print(f"Error updating vault entry '{entry_id}': {e}")
        return False

def delete_vault_entry(entry_id):
    """Deletes a vault entry by its ID. Assumes ownership already checked."""
    try:
        db_conn = get_db()
        if isinstance(entry_id, str):
            delete_entry_id = ObjectId(entry_id)
        else:
             delete_entry_id = entry_id
        result = db_conn[config.VAULT_COLLECTION].delete_one({"_id": delete_entry_id})
        return result.deleted_count > 0
    except Exception as e:
        print(f"Error deleting vault entry '{entry_id}': {e}")
        return False
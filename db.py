# db.py
from pymongo import MongoClient, errors
import config # For DB connection details and collection names
from bson import ObjectId # For converting string IDs to MongoDB ObjectIds
import re # For regular expression searches

# Global variables to hold the client and database connections
_client = None
_db = None

# --- Database Connection Functions ---

def connect_db():
    """
    Establishes a connection to the MongoDB database using settings from config.py.
    Returns the database object upon successful connection.
    Raises exceptions on connection failure.
    """
    global _client, _db
    # Connect only if the client instance hasn't been created yet
    if _client is None:
        try:
            # Build connection arguments dictionary from config
            connection_args = {
                'host': config.mongo_host,
                'port': config.mongo_port,
                'serverSelectionTimeoutMS': 5000, # Wait 5 seconds for server selection
                'connectTimeoutMS': 10000         # Wait 10 seconds for initial connection
            }
            # Add authentication if username is provided in config
            if config.mongo_user:
                connection_args.update({ # Use update for cleaner conditional additions
                    'username': config.mongo_user,
                    'password': config.mongo_password,
                    'authSource': config.mongo_auth_db # DB where the user is defined
                })
                # Optional: Specify authentication mechanism if required by your MongoDB setup
                # connection_args['authMechanism'] = 'SCRAM-SHA-256'

            # Create the MongoDB client instance using keyword argument unpacking
            _client = MongoClient(**connection_args)

            # Verify connection by pinging the admin database
            _client.admin.command('ping')
            print(f"Successfully connected to MongoDB at {config.mongo_host}:{config.mongo_port}!")
            # Get the database object using the name from config
            _db = _client[config.DB_NAME]

        # --- Error Handling for Connection ---
        except errors.OperationFailure as e:
            # Authentication errors (wrong user/pass, incorrect authSource)
            print(f"Authentication Error connecting to MongoDB: {e}. Check credentials and authSource ('{config.mongo_auth_db}') in .env.")
            _client = None; _db = None; raise # Re-raise after printing details
        except errors.ServerSelectionTimeoutError as e:
             # Server not found or unreachable within timeout
             print(f"Connection Timeout: Could not connect to MongoDB at {config.mongo_host}:{config.mongo_port} within the time limit: {e}")
             _client = None; _db = None; raise # Re-raise
        except errors.ConnectionFailure as e:
            # Other connection failures (network issues, etc.)
            print(f"Connection Failure: Could not connect to MongoDB at {config.mongo_host}:{config.mongo_port}: {e}")
            _client = None; _db = None; raise # Re-raise
        except Exception as e:
            # Catch any other unexpected errors during connection
            print(f"An unexpected error occurred during MongoDB connection: {e}")
            _client = None; _db = None; raise # Re-raise
    # Return the database object (will be None if connection failed and wasn't re-raised)
    return _db

def get_db():
    """Returns the database instance, attempting to connect if it doesn't exist."""
    if _db is None:
        # connect_db() will either return the db object or raise an exception
        return connect_db()
    return _db

def close_db(e=None):
    """Closes the MongoDB client connection if it's currently open."""
    global _client, _db
    if _client:
        _client.close()
        _client = None
        _db = None
        # print("MongoDB connection closed.") # Optional: uncomment for debugging

def ensure_indexes():
    """Creates necessary indexes on collections for performance and uniqueness if they don't already exist."""
    db_conn = None # Use local variable for safety
    try:
        db_conn = get_db() # Get database connection
        if db_conn:
            # Ensure a unique index on the 'username' field in the users collection
            db_conn[config.USERS_COLLECTION].create_index("username", unique=True)
            # Ensure an index on 'user_id' in the vault collection for faster lookups of user's entries
            db_conn[config.VAULT_COLLECTION].create_index("user_id")
            # Ensure a compound index for sorting/filtering vault entries efficiently by user
            db_conn[config.VAULT_COLLECTION].create_index([
                ("user_id", 1),         # Filter by user first
                ("brand_label", 1),     # Then sort/filter by brand
                ("laptop_server", 1)    # Then sort/filter by ID
            ], name="user_brand_laptop_idx") # Optional: Give index a name
            print("Database indexes ensured.")
    except Exception as e:
        # Log a warning if index creation fails, but don't crash the application startup
        print(f"Warning: Error creating or ensuring indexes: {e}")

# --- User Operations ---

def find_user(username):
    """Finds a user by username. Returns the user document or None."""
    try:
        db_conn = get_db()
        # Projection specifies which fields to return
        user_data = db_conn[config.USERS_COLLECTION].find_one(
            {"username": username},
            {"_id": 1, "username": 1, "password_hash": 1, "salt": 1,
             "totp_secret": 1, "is_2fa_enabled": 1,
             "role": 1, "is_active": 1 }
        )
        return user_data
    except Exception as e:
        print(f"Error finding user '{username}': {e}")
        return None

def add_user(username, hashed_password, salt, role='user', is_active=True):
    """Adds a new user document to the database. Sets first user as admin."""
    try:
        db_conn = get_db()
        user_data = {
            "username": username, "password_hash": hashed_password, "salt": salt,
            "totp_secret": None, "is_2fa_enabled": False,
            "role": role, "is_active": is_active
        }
        # Check if this is the very first user being added
        # Use count_documents for accuracy on non-sharded or small collections
        if db_conn[config.USERS_COLLECTION].count_documents({}, limit=1) == 0:
            user_data["role"] = "admin" # Promote first user to admin
            print("INFO: First user created, setting role to 'admin'.")

        # Insert the new user document
        result = db_conn[config.USERS_COLLECTION].insert_one(user_data)
        return result.inserted_id # Return the new user's ObjectId
    except errors.DuplicateKeyError:
        # Handle error if username already exists (due to unique index)
        print(f"Attempted to add duplicate username: '{username}'")
        return None
    except Exception as e:
        print(f"Error adding user '{username}': {e}")
        return None

def set_user_2fa_secret(user_id, secret):
    """Updates the TOTP secret for a specific user."""
    try:
        db_conn = get_db()
        result = db_conn[config.USERS_COLLECTION].update_one(
            {"_id": ObjectId(user_id)}, # Find user by ID
            {"$set": {"totp_secret": secret}} # Set the secret field
        )
        return result.modified_count > 0 # Return True if updated
    except Exception as e:
        print(f"Error setting 2FA secret user '{user_id}': {e}")
        return False

def enable_user_2fa(user_id, enable=True):
    """Sets the 'is_2fa_enabled' flag for a user."""
    try:
        db_conn = get_db()
        result = db_conn[config.USERS_COLLECTION].update_one(
            {"_id": ObjectId(user_id)}, {"$set": {"is_2fa_enabled": bool(enable)}} # Ensure boolean value
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"Error {'enabling' if enable else 'disabling'} 2FA user '{user_id}': {e}")
        return False

def disable_user_2fa(user_id):
    """Disables 2FA and clears the stored TOTP secret for security."""
    try:
        db_conn = get_db()
        result = db_conn[config.USERS_COLLECTION].update_one(
            {"_id": ObjectId(user_id)}, {"$set": {"is_2fa_enabled": False, "totp_secret": None}} # Clear secret
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"Error disabling 2FA user '{user_id}': {e}")
        return False

# --- Admin Specific User Functions ---

def get_all_users():
    """Retrieves a list of all users (excluding sensitive fields) for admin display."""
    try:
        db_conn = get_db()
        users = list(db_conn[config.USERS_COLLECTION].find(
            {}, {"password_hash": 0, "salt": 0, "totp_secret": 0} # Projection
        ).sort("username", 1))
        return users
    except Exception as e:
        print(f"Error getting all users: {e}")
        return []

def set_user_status(user_id, is_active):
    """Admin function to set the active status for a user (enable/disable login)."""
    try:
        db_conn = get_db()
        result = db_conn[config.USERS_COLLECTION].update_one(
            {"_id": ObjectId(user_id)}, {"$set": {"is_active": bool(is_active)}} # Ensure boolean
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"Error setting user status for '{user_id}': {e}")
        return False

def set_user_role(user_id, role):
    """Admin function to set the 'role' for a user ('admin' or 'user')."""
    if role not in ['admin', 'user']: # Validate role
        print(f"Invalid role specified for update: {role}")
        return False
    try:
        db_conn = get_db()
        result = db_conn[config.USERS_COLLECTION].update_one(
            {"_id": ObjectId(user_id)}, {"$set": {"role": role}}
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"Error setting user role for '{user_id}': {e}")
        return False

def delete_user_by_id(user_id):
    """Admin function to delete a user document and ALL their associated vault entries."""
    try:
        db_conn = get_db(); user_obj_id = ObjectId(user_id)
        # Delete associated vault entries FIRST
        delete_result = db_conn[config.VAULT_COLLECTION].delete_many({"user_id": user_obj_id})
        print(f"Deleted {delete_result.deleted_count} vault entries for user {user_id}")
        # THEN delete the user document
        result = db_conn[config.USERS_COLLECTION].delete_one({"_id": user_obj_id})
        return result.deleted_count > 0 # True if user document was deleted
    except Exception as e:
        print(f"Error deleting user '{user_id}' and their entries: {e}")
        return False

# --- Vault Operations ---

def add_vault_entry(user_id, laptop_server, brand_label, entry_username, encrypted_password):
    """Adds a new encrypted vault entry including brand/label for a user."""
    try:
        db_conn = get_db(); entry_user_id = ObjectId(user_id) if isinstance(user_id, str) else user_id
        entry_data = {
            "user_id": entry_user_id, "laptop_server": laptop_server,
            "brand_label": brand_label, "entry_username": entry_username,
            "encrypted_password": encrypted_password # Expecting bytes
        }
        result = db_conn[config.VAULT_COLLECTION].insert_one(entry_data)
        return result.inserted_id
    except Exception as e:
        print(f"Error adding vault entry user '{user_id}', id '{laptop_server}': {e}")
        return None

def get_vault_entries(user_id, search_term=None): # For user's own vault view
    """Retrieves vault entries for the specified user, optionally filtered and sorted."""
    try:
        db_conn = get_db(); query_user_id = ObjectId(user_id) if isinstance(user_id, str) else user_id
        query = {"user_id": query_user_id} # Base filter for user
        if search_term: # Add search filter if term provided
            safe_search_term = re.escape(search_term) # Escape regex special chars
            query["$or"] = [ # Case-insensitive regex search on multiple fields
                {"laptop_server": {"$regex": safe_search_term, "$options": "i"}},
                {"brand_label": {"$regex": safe_search_term, "$options": "i"}},
                {"entry_username": {"$regex": safe_search_term, "$options": "i"}}
             ]
        # Find matching entries and sort them
        entries = list(db_conn[config.VAULT_COLLECTION].find(query).sort([
            ("brand_label", 1), ("laptop_server", 1)
        ]));
        return entries
    except Exception as e:
        print(f"Error retrieving own vault entries user '{user_id}' (search: '{search_term}'): {e}")
        return [] # Return empty list on error

def get_vault_entries_for_user(target_user_id): # Admin view metadata
     """Admin function to get METADATA (no password) of another user's entries."""
     try:
        db_conn = get_db(); query_user_id = ObjectId(target_user_id) if isinstance(target_user_id, str) else target_user_id
        # Find entries for the target user, excluding the encrypted password
        entries = list(db_conn[config.VAULT_COLLECTION].find(
            {"user_id": query_user_id},
            {"encrypted_password": 0} # Projection excludes password
        ).sort([("brand_label", 1), ("laptop_server", 1)]));
        return entries
     except Exception as e:
         print(f"Error admin retrieving vault entries for user '{target_user_id}': {e}")
         return []

def find_entry_by_id_and_user(entry_id_str, user_id_str): # Checks ownership
    """Finds a single vault entry only if it belongs to the specified user."""
    try:
        db_conn = get_db(); entry_obj_id = ObjectId(entry_id_str); user_obj_id = ObjectId(user_id_str)
        entry = db_conn[config.VAULT_COLLECTION].find_one({"_id": entry_obj_id, "user_id": user_obj_id})
        return entry
    except Exception as e:
        print(f"Error finding entry '{entry_id_str}' user '{user_id_str}': {e}")
        return None

def find_entry_by_id(entry_id_str): # Finds entry regardless of owner
    """Finds a single vault entry by its ID, without checking ownership."""
    try:
        db_conn = get_db(); entry_obj_id = ObjectId(entry_id_str)
        entry = db_conn[config.VAULT_COLLECTION].find_one({"_id": entry_obj_id})
        return entry
    except Exception as e:
        print(f"Error finding entry by ID '{entry_id_str}': {e}")
        return None

def update_vault_entry(entry_id, laptop_server, brand_label, entry_username, encrypted_password): # Assumes owner check done by caller
    """Updates an existing vault entry. Assumes ownership checked by caller."""
    try:
        db_conn = get_db(); update_entry_id = ObjectId(entry_id) if isinstance(entry_id, str) else entry_id
        update_data = {"$set": {
            "laptop_server": laptop_server, "brand_label": brand_label,
            "entry_username": entry_username, "encrypted_password": encrypted_password
        }}
        result = db_conn[config.VAULT_COLLECTION].update_one({"_id": update_entry_id}, update_data)
        return result.modified_count > 0
    except Exception as e:
        print(f"Error updating vault entry '{entry_id}': {e}")
        return False

def delete_vault_entry(entry_id): # Generic delete by ID
    """Deletes a vault entry by its ID. Permissions must be checked by caller."""
    try:
        db_conn = get_db()
        delete_entry_id = ObjectId(entry_id) if isinstance(entry_id, str) else entry_id
        result = db_conn[config.VAULT_COLLECTION].delete_one({"_id": delete_entry_id})
        return result.deleted_count > 0
    except Exception as e:
        print(f"Error deleting vault entry '{entry_id}': {e}")
        return False
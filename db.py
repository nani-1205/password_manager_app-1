# db.py
from pymongo import MongoClient, errors
import config
from bson import ObjectId
import re

# Global variables for connection and db object
_client = None
_db = None

# --- Database Connection Functions ---

def connect_db():
    """Establishes connection to the MongoDB database using host/port/auth details."""
    global _client, _db
    # Connect only if not already connected
    if _client is None:
        try:
            # Build connection arguments from config
            connection_args = {
                'host': config.mongo_host,
                'port': config.mongo_port,
                'serverSelectionTimeoutMS': 5000, # Timeout for finding a server
                'connectTimeoutMS': 10000         # Timeout for initial connection
            }
            # Add authentication if username is provided in config
            if config.mongo_user:
                connection_args['username'] = config.mongo_user
                connection_args['password'] = config.mongo_password
                connection_args['authSource'] = config.mongo_auth_db
                # Optional: Specify auth mechanism if needed (e.g., 'SCRAM-SHA-256')
                # connection_args['authMechanism'] = 'SCRAM-SHA-256'

            # Create the MongoDB client instance
            _client = MongoClient(**connection_args)

            # Verify connection by pinging the admin database
            _client.admin.command('ping')
            print(f"Successfully connected to MongoDB at {config.mongo_host}:{config.mongo_port}!")
            # Get the database object
            _db = _client[config.DB_NAME]

        # --- Error Handling for Connection ---
        except errors.OperationFailure as e:
            print(f"Authentication Error connecting to MongoDB: {e}. Check credentials and authSource ('{config.mongo_auth_db}') in .env.")
            _client = None; _db = None; raise # Re-raise after printing
        except errors.ServerSelectionTimeoutError as e:
             print(f"Connection Timeout: Could not connect to MongoDB at {config.mongo_host}:{config.mongo_port} within the time limit: {e}")
             _client = None; _db = None; raise # Re-raise
        except errors.ConnectionFailure as e:
            print(f"Connection Failure: Could not connect to MongoDB at {config.mongo_host}:{config.mongo_port}: {e}")
            _client = None; _db = None; raise # Re-raise
        except Exception as e:
            print(f"An unexpected error occurred during MongoDB connection: {e}")
            _client = None; _db = None; raise # Re-raise
    # Return the database object (or None if connection failed and wasn't re-raised)
    return _db

def get_db():
    """Returns the database instance, connecting if necessary."""
    # If global _db object is not set, call connect_db()
    if _db is None:
        # connect_db() will return the db object or raise an exception
        return connect_db()
    # Return the existing db object
    return _db

def close_db(e=None):
    """Closes the MongoDB connection if it's open."""
    global _client, _db
    if _client:
        _client.close()
        _client = None
        _db = None
        # print("MongoDB connection closed.") # Usually noisy, keep commented unless debugging

def ensure_indexes():
    """Creates necessary indexes if they don't exist."""
    db_conn = None # Use a local variable for safety
    try:
        db_conn = get_db() # Get the database connection
        if db_conn:
            # Create unique index on username in the users collection
            db_conn[config.USERS_COLLECTION].create_index("username", unique=True)
            # Create index on user_id in the vault collection for efficient lookup
            db_conn[config.VAULT_COLLECTION].create_index("user_id")
            # Create compound index including fields used for sorting/filtering vault entries
            db_conn[config.VAULT_COLLECTION].create_index([
                ("user_id", 1),         # Filter by user first
                ("brand_label", 1),     # Then sort/filter by brand
                ("laptop_server", 1)    # Then sort/filter by ID
            ])
            print("Database indexes ensured.")
    except Exception as e:
        # Log a warning if index creation fails (e.g., permissions issue)
        # Don't necessarily crash the app, but log the problem.
        print(f"Warning: Error creating or ensuring indexes: {e}")

# --- User Operations ---

def find_user(username):
    """Finds a user by username and returns relevant fields including role/active/2FA status."""
    try:
        db_conn = get_db()
        # Specify the fields to return (projection) to avoid fetching sensitive data unnecessarily elsewhere
        user_data = db_conn[config.USERS_COLLECTION].find_one(
            {"username": username},
            {"_id": 1, "username": 1, "password_hash": 1, "salt": 1,
             "totp_secret": 1, "is_2fa_enabled": 1,
             "role": 1, "is_active": 1 }
        )
        return user_data # Returns the document or None if not found
    except Exception as e:
        print(f"Error finding user '{username}': {e}")
        return None # Return None on error

def add_user(username, hashed_password, salt, role='user', is_active=True):
    """Adds a new user with role, active status, and initialized 2FA fields."""
    try:
        db_conn = get_db()
        user_data = {
            "username": username,
            "password_hash": hashed_password,
            "salt": salt,
            "totp_secret": None,        # Initialize 2FA fields
            "is_2fa_enabled": False,
            "role": role,             # Set role (defaults to 'user')
            "is_active": is_active      # Set active status (defaults to True)
        }
        # Logic to make the very first user an admin
        user_count = db_conn[config.USERS_COLLECTION].count_documents({})
        if user_count == 0:
             print("INFO: First user created, setting role to 'admin'.")
             user_data["role"] = "admin"

        # Insert the new user document
        result = db_conn[config.USERS_COLLECTION].insert_one(user_data)
        return result.inserted_id # Return the ID of the newly created user
    except errors.DuplicateKeyError:
        # Handle case where username already exists (due to unique index)
        print(f"Attempted to add duplicate username: '{username}'")
        return None
    except Exception as e:
        print(f"Error adding user '{username}': {e}")
        return None

def set_user_2fa_secret(user_id, secret):
    """Stores the TOTP secret for a user (typically during 2FA setup)."""
    try:
        db_conn = get_db()
        # Update the user document matching the ID, setting the totp_secret
        result = db_conn[config.USERS_COLLECTION].update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"totp_secret": secret}}
        )
        # Return True if the update was successful (at least one doc modified)
        return result.modified_count > 0
    except Exception as e:
        print(f"Error setting 2FA secret for user '{user_id}': {e}")
        return False

def enable_user_2fa(user_id, enable=True):
    """Enables or disables the 2FA flag for a user."""
    try:
        db_conn = get_db()
        # Update the user document matching the ID, setting the is_2fa_enabled flag
        result = db_conn[config.USERS_COLLECTION].update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"is_2fa_enabled": bool(enable)}} # Ensure boolean value
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"Error {'enabling' if enable else 'disabling'} 2FA for user '{user_id}': {e}")
        return False

def disable_user_2fa(user_id):
    """Disables 2FA and clears the secret for a user for security."""
    try:
        db_conn = get_db()
        # Update the user, setting flag to False and clearing the secret
        result = db_conn[config.USERS_COLLECTION].update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"is_2fa_enabled": False, "totp_secret": None}}
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"Error disabling 2FA for user '{user_id}': {e}")
        return False

# --- Admin Specific User Functions ---

def get_all_users():
    """Retrieves basic info for all users (for admin listing)."""
    try:
        db_conn = get_db()
        # Projection excludes sensitive fields
        users = list(db_conn[config.USERS_COLLECTION].find(
            {},
            {"password_hash": 0, "salt": 0, "totp_secret": 0}
        ).sort("username", 1)) # Sort alphabetically by username
        return users
    except Exception as e:
        print(f"Error getting all users: {e}")
        return []

def set_user_status(user_id, is_active):
    """Admin function to set the active status for a user."""
    try:
        db_conn = get_db()
        result = db_conn[config.USERS_COLLECTION].update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"is_active": bool(is_active)}} # Ensure boolean
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"Error setting user status for '{user_id}': {e}")
        return False

def set_user_role(user_id, role):
    """Admin function to set the role for a user ('admin' or 'user')."""
    # Validate role input
    if role not in ['admin', 'user']:
        print(f"Invalid role specified for update: {role}")
        return False
    try:
        db_conn = get_db()
        result = db_conn[config.USERS_COLLECTION].update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"role": role}}
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"Error setting user role for '{user_id}': {e}")
        return False

def delete_user_by_id(user_id):
    """Admin function to delete a user and ALL their associated vault entries."""
    # WARNING: Destructive operation!
    try:
        db_conn = get_db()
        user_obj_id = ObjectId(user_id)

        # Step 1: Delete all vault entries associated with this user
        delete_result = db_conn[config.VAULT_COLLECTION].delete_many({"user_id": user_obj_id})
        print(f"Deleted {delete_result.deleted_count} vault entries for user {user_id}")

        # Step 2: Delete the user document itself
        result = db_conn[config.USERS_COLLECTION].delete_one({"_id": user_obj_id})

        # Return True if the user document was deleted
        return result.deleted_count > 0
    except Exception as e:
        print(f"Error deleting user '{user_id}' and their entries: {e}")
        return False


# --- Vault Operations ---

def add_vault_entry(user_id, laptop_server, brand_label, entry_username, encrypted_password):
    """Adds a new encrypted password entry including brand/label for a user."""
    try:
        db_conn = get_db()
        # Convert user_id string (from session) to ObjectId
        if isinstance(user_id, str): entry_user_id = ObjectId(user_id)
        else: entry_user_id = user_id

        entry_data = {
            "user_id": entry_user_id,
            "laptop_server": laptop_server,
            "brand_label": brand_label, # Include brand/label
            "entry_username": entry_username,
            "encrypted_password": encrypted_password # Expecting bytes
        }
        result = db_conn[config.VAULT_COLLECTION].insert_one(entry_data)
        return result.inserted_id # Return ID of the new vault entry
    except Exception as e:
        print(f"Error adding vault entry user '{user_id}', id '{laptop_server}': {e}")
        return None

def get_vault_entries(user_id, search_term=None):
    """Retrieves vault entries for the logged-in user, optionally filtered and sorted."""
    try:
        db_conn = get_db()
        if isinstance(user_id, str): query_user_id = ObjectId(user_id)
        else: query_user_id = user_id

        # Base query for the current user
        query = {"user_id": query_user_id}

        # Add search filter if search_term is provided
        if search_term:
            safe_search_term = re.escape(search_term) # Escape regex special chars
            # Case-insensitive search across multiple fields
            query["$or"] = [
                {"laptop_server": {"$regex": safe_search_term, "$options": "i"}},
                {"brand_label": {"$regex": safe_search_term, "$options": "i"}},
                {"entry_username": {"$regex": safe_search_term, "$options": "i"}}
             ]

        # Fetch entries and sort them
        entries = list(db_conn[config.VAULT_COLLECTION].find(query).sort([
            ("brand_label", 1), # Primary sort by brand/label
            ("laptop_server", 1) # Secondary sort by laptop/server ID
        ]))
        return entries
    except Exception as e:
        print(f"Error retrieving own vault entries user '{user_id}' (search: '{search_term}'): {e}")
        return [] # Return empty list on error

# Admin function to view metadata (no passwords)
def get_vault_entries_for_user(target_user_id):
     """Admin function to get METADATA of another user's entries."""
     try:
        db_conn = get_db()
        if isinstance(target_user_id, str): query_user_id = ObjectId(target_user_id)
        else: query_user_id = target_user_id

        # Projection excludes the encrypted password field
        entries = list(db_conn[config.VAULT_COLLECTION].find(
            {"user_id": query_user_id},
            {"encrypted_password": 0} # <-- Exclude sensitive data
        ).sort([("brand_label", 1), ("laptop_server", 1)]))
        return entries
     except Exception as e:
         print(f"Error admin retrieving vault entries for user '{target_user_id}': {e}")
         return []

def find_entry_by_id_and_user(entry_id_str, user_id_str):
    """Finds a single vault entry by its ID and verifies ownership by user ID."""
    try:
        db_conn = get_db()
        entry_obj_id = ObjectId(entry_id_str)
        user_obj_id = ObjectId(user_id_str)
        # Query for document matching both _id and user_id
        entry = db_conn[config.VAULT_COLLECTION].find_one({
            "_id": entry_obj_id,
            "user_id": user_obj_id
        })
        return entry # Returns document or None
    except Exception as e:
        print(f"Error finding entry '{entry_id_str}' user '{user_id_str}': {e}")
        return None

def update_vault_entry(entry_id, laptop_server, brand_label, entry_username, encrypted_password):
    """Updates an existing vault entry. Assumes ownership checked by caller."""
    try:
        db_conn = get_db()
        # Convert entry_id string to ObjectId
        if isinstance(entry_id, str): update_entry_id = ObjectId(entry_id)
        else: update_entry_id = entry_id

        # Prepare the update operation using $set
        update_data = {"$set": {
            "laptop_server": laptop_server,
            "brand_label": brand_label, # Include brand/label update
            "entry_username": entry_username,
            "encrypted_password": encrypted_password # Pass the (potentially new) encrypted password
        }}
        # Perform the update on the specific document
        result = db_conn[config.VAULT_COLLECTION].update_one({"_id": update_entry_id}, update_data)
        # Check if any document was actually modified
        return result.modified_count > 0
    except Exception as e:
        print(f"Error updating vault entry '{entry_id}': {e}")
        return False

def delete_vault_entry(entry_id):
    """Deletes a vault entry by its ID. Assumes ownership checked by caller."""
    # Renamed from delete_vault_entry_by_id for consistency if only called via web_app wrapper
    try:
        db_conn = get_db()
        # Ensure entry_id is an ObjectId
        if isinstance(entry_id, str):
            delete_entry_id = ObjectId(entry_id)
        else:
            delete_entry_id = entry_id
        # Delete the single document matching the _id
        result = db_conn[config.VAULT_COLLECTION].delete_one({"_id": delete_entry_id})
        # Return True if a document was deleted
        return result.deleted_count > 0
    except Exception as e:
        print(f"Error deleting vault entry '{entry_id}': {e}")
        return False
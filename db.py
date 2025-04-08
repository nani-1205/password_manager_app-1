# db.py
from pymongo import MongoClient, errors
import config
from bson import ObjectId
import re # Import regular expression module

_client = None
_db = None

# --- Database Connection Functions ---
def connect_db():
    """Establishes connection to the MongoDB database using host/port/auth details."""
    global _client, _db
    if _client is None:
        try:
            connection_args = {
                'host': config.mongo_host,
                'port': config.mongo_port,
                'serverSelectionTimeoutMS': 5000, # Wait 5 seconds for server selection
                'connectTimeoutMS': 10000 # Wait 10 seconds for initial connection
            }
            # Add authentication details ONLY if username is provided
            if config.mongo_user:
                connection_args['username'] = config.mongo_user
                connection_args['password'] = config.mongo_password
                connection_args['authSource'] = config.mongo_auth_db
                # Optional: Specify auth mechanism if needed
                # connection_args['authMechanism'] = 'SCRAM-SHA-256'

            # Create a new client and connect to the server
            _client = MongoClient(**connection_args) # Use keyword argument unpacking
            # Send a ping to confirm a successful connection
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
        # Will raise exception if connection fails
        return connect_db()
    return _db

def close_db(e=None):
    """Closes the MongoDB connection."""
    global _client, _db
    if _client:
        _client.close()
        _client = None
        _db = None
        # print("MongoDB connection closed.") # Uncomment for debugging if needed

def ensure_indexes():
    """Creates necessary indexes if they don't exist."""
    db_conn = None
    try:
        db_conn = get_db()
        if db_conn:
            # Unique index on username
            db_conn[config.USERS_COLLECTION].create_index("username", unique=True)
            # Index on user_id for vault entries
            db_conn[config.VAULT_COLLECTION].create_index("user_id")
            # Compound index including laptop_server and brand_label for faster searching by user
            db_conn[config.VAULT_COLLECTION].create_index([
                ("user_id", 1),
                ("laptop_server", 1),
                ("brand_label", 1) # Add brand_label to index
            ])
            print("Database indexes ensured.")
    except Exception as e:
        # Log warning but don't crash the app if index creation fails (might be permission issue)
        print(f"Warning: Error creating or ensuring indexes: {e}")

# --- User Operations ---
def find_user(username):
    """Finds a user by username and returns relevant fields including 2FA status."""
    try:
        db_conn = get_db()
        # Fetch fields needed for login and 2FA checks
        user_data = db_conn[config.USERS_COLLECTION].find_one(
            {"username": username},
            # Projection: specify fields to return
            {"_id": 1, "username": 1, "password_hash": 1, "salt": 1,
             "totp_secret": 1, "is_2fa_enabled": 1}
        )
        return user_data
    except Exception as e:
        print(f"Error finding user '{username}': {e}")
        return None

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
        # Username already exists
        print(f"Attempted to add duplicate username: '{username}'")
        return None
    except Exception as e:
        print(f"Error adding user '{username}': {e}")
        return None

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
            {"$set": {"is_2fa_enabled": False, "totp_secret": None}} # Clear secret on disable
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"Error disabling 2FA for user '{user_id}': {e}")
        return False

# --- Vault Operations ---
def add_vault_entry(user_id, laptop_server, brand_label, entry_username, encrypted_password):
    """Adds a new encrypted password entry including brand/label."""
    try:
        db_conn = get_db()
        # Convert user_id string from session to ObjectId for query
        if isinstance(user_id, str):
            entry_user_id = ObjectId(user_id)
        else:
            entry_user_id = user_id # Assume it's already ObjectId

        entry_data = {
            "user_id": entry_user_id,
            "laptop_server": laptop_server,
            "brand_label": brand_label, # Added field
            "entry_username": entry_username,
            "encrypted_password": encrypted_password # Should be bytes from encryption
        }
        result = db_conn[config.VAULT_COLLECTION].insert_one(entry_data)
        return result.inserted_id
    except Exception as e:
        print(f"Error adding vault entry user '{user_id}', laptop/server '{laptop_server}': {e}")
        return None

def get_vault_entries(user_id, search_term=None):
    """Retrieves vault entries for a specific user, optionally filtered and sorted."""
    try:
        db_conn = get_db()
        # Convert user_id string from session to ObjectId for query
        if isinstance(user_id, str):
            query_user_id = ObjectId(user_id)
        else:
            query_user_id = user_id # Assume it's already ObjectId

        # Base query to get entries only for the logged-in user
        query = {"user_id": query_user_id}

        # If search term is provided, add filtering logic
        if search_term:
            # Escape special characters in search term to prevent regex errors
            safe_search_term = re.escape(search_term)
            # Create case-insensitive regex search across multiple relevant fields
            query["$or"] = [
                {"laptop_server": {"$regex": safe_search_term, "$options": "i"}},
                {"brand_label": {"$regex": safe_search_term, "$options": "i"}},
                {"entry_username": {"$regex": safe_search_term, "$options": "i"}}
             ]

        # Execute the query and sort the results
        entries = list(db_conn[config.VAULT_COLLECTION].find(query).sort([
            ("brand_label", 1), # Sort primarily by brand/label
            ("laptop_server", 1) # Then by laptop/server ID
        ]))
        return entries
    except Exception as e:
        print(f"Error retrieving vault entries user '{user_id}' (search: '{search_term}'): {e}")
        return [] # Return empty list on error

def find_entry_by_id_and_user(entry_id_str, user_id_str):
    """Finds a single vault entry by its ID and verifies ownership."""
    try:
        db_conn = get_db()
        # Convert string IDs to ObjectIds for the query
        entry_obj_id = ObjectId(entry_id_str)
        user_obj_id = ObjectId(user_id_str)
        # Find document matching both entry ID and user ID
        entry = db_conn[config.VAULT_COLLECTION].find_one({
            "_id": entry_obj_id,
            "user_id": user_obj_id
        })
        return entry # Returns document if found and owned, None otherwise
    except Exception as e:
        print(f"Error finding entry '{entry_id_str}' user '{user_id_str}': {e}")
        return None

def update_vault_entry(entry_id, laptop_server, brand_label, entry_username, encrypted_password):
    """Updates an existing vault entry including brand/label. Assumes ownership checked by caller."""
    try:
        db_conn = get_db()
        # Convert entry_id string to ObjectId
        if isinstance(entry_id, str):
            update_entry_id = ObjectId(entry_id)
        else:
            update_entry_id = entry_id

        # Data to set in the update operation
        update_data = {"$set": {
            "laptop_server": laptop_server,
            "brand_label": brand_label, # Include updated brand/label
            "entry_username": entry_username,
            "encrypted_password": encrypted_password
        }}
        # Update the single document matching the _id
        result = db_conn[config.VAULT_COLLECTION].update_one({"_id": update_entry_id}, update_data)
        # Return True if a document was modified, False otherwise
        return result.modified_count > 0
    except Exception as e:
        print(f"Error updating vault entry '{entry_id}': {e}")
        return False

def delete_vault_entry(entry_id):
    """Deletes a vault entry by its ID. Assumes ownership checked by caller."""
    try:
        # Standard indentation for the try block
        db_conn = get_db()
        # Ensure entry_id is an ObjectId
        if isinstance(entry_id, str):
            # Indentation level for the if block
            delete_entry_id = ObjectId(entry_id)
        else:
            # Indentation level for the else block
            delete_entry_id = entry_id
        # Back to the try block's indentation level
        result = db_conn[config.VAULT_COLLECTION].delete_one({"_id": delete_entry_id})
        # Return True if a document was deleted
        return result.deleted_count > 0
    except Exception as e:
        # Standard indentation for the except block
        print(f"Error deleting vault entry '{entry_id}': {e}")
        return False
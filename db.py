# db.py
from pymongo import MongoClient, errors
# Removed ServerApi import as it's mainly for Atlas SRV interaction stability checks
import config  # Imports the individual config variables now
from bson import ObjectId

_client = None
_db = None

def connect_db():
    """Establishes connection to the MongoDB database using host/port/auth details."""
    global _client, _db
    if _client is None:
        try:
            # Construct connection arguments
            connection_args = {
                'host': config.mongo_host,
                'port': config.mongo_port, # Use the integer port from config
                # Add reasonable timeouts (optional but recommended)
                'serverSelectionTimeoutMS': 5000, # Wait 5 seconds for server selection
                'connectTimeoutMS': 10000 # Wait 10 seconds for initial connection
            }

            # Add authentication details ONLY if username is provided
            if config.mongo_user:
                connection_args['username'] = config.mongo_user
                connection_args['password'] = config.mongo_password
                connection_args['authSource'] = config.mongo_auth_db
                # Add authMechanism if needed (e.g., 'SCRAM-SHA-256')
                # connection_args['authMechanism'] = 'SCRAM-SHA-256'

            # Create a new client and connect to the server
            _client = MongoClient(**connection_args) # Use keyword argument unpacking

            # Send a ping to confirm a successful connection
            _client.admin.command('ping')
            print(f"Successfully connected to MongoDB at {config.mongo_host}:{config.mongo_port}!")
            _db = _client[config.DB_NAME]

        except errors.OperationFailure as e:
            # Handle authentication errors specifically
            print(f"Authentication Error connecting to MongoDB: {e}. Check credentials and authSource ('{config.mongo_auth_db}') in .env.")
            _client = None
            _db = None
            raise # Re-raise to be caught by the startup check
        except errors.ServerSelectionTimeoutError as e:
             print(f"Connection Timeout: Could not connect to MongoDB at {config.mongo_host}:{config.mongo_port} within the time limit. Check host/port, network access, and if MongoDB is running: {e}")
             _client = None
             _db = None
             raise # Re-raise
        except errors.ConnectionFailure as e:
            print(f"Connection Failure: Could not connect to MongoDB at {config.mongo_host}:{config.mongo_port}: {e}")
            _client = None
            _db = None
            raise # Re-raise
        except Exception as e:
            print(f"An unexpected error occurred during MongoDB connection: {e}")
            _client = None
            _db = None
            raise # Re-raise
    return _db

# --- Database Interaction Functions ---

def get_db():
    """Returns the database instance, connecting if necessary."""
    if _db is None:
        # This will raise an exception if connection fails, handled by caller or Flask
        return connect_db()
    return _db

def close_db(e=None):
    """Closes the MongoDB connection."""
    global _client, _db
    if _client:
        _client.close()
        _client = None
        _db = None
        # print("MongoDB connection closed.") # Can be noisy, uncomment if needed

# Ensure indexes for performance and uniqueness
def ensure_indexes():
    db_conn = None # Use separate variable to avoid issues with global _db state
    try:
        db_conn = get_db()
        if db_conn:
            # Unique index on username
            db_conn[config.USERS_COLLECTION].create_index("username", unique=True)
            # Index on user_id for vault entries
            db_conn[config.VAULT_COLLECTION].create_index("user_id")
            print("Database indexes ensured.")
    except Exception as e:
        print(f"Error creating or ensuring indexes: {e}")
        # Don't necessarily raise here, maybe the app can run without indexes initially
        # Although the unique username index is important for signup logic.

# --- User Operations ---

def find_user(username):
    """Finds a user by username."""
    try:
        db_conn = get_db()
        return db_conn[config.USERS_COLLECTION].find_one({"username": username})
    except Exception as e:
        print(f"Error finding user '{username}': {e}")
        return None # Return None on error

def add_user(username, hashed_password, salt):
    """Adds a new user to the database."""
    try:
        db_conn = get_db()
        user_data = {
            "username": username,
            "password_hash": hashed_password, # Store the hash, not the plain password
            "salt": salt # Store the unique salt for this user
        }
        result = db_conn[config.USERS_COLLECTION].insert_one(user_data)
        return result.inserted_id
    except errors.DuplicateKeyError:
        print(f"Attempted to add duplicate username: '{username}'")
        return None # Indicate failure due to duplicate
    except Exception as e:
        print(f"Error adding user '{username}': {e}")
        return None # Return None on other errors

# --- Vault Operations ---

def add_vault_entry(user_id, website, entry_username, encrypted_password):
    """Adds a new encrypted password entry for a user."""
    try:
        db_conn = get_db()
        # Ensure user_id is ObjectId if needed, though Flask session stores string usually
        if isinstance(user_id, str):
             entry_user_id = ObjectId(user_id)
        else:
             entry_user_id = user_id # Assume it's already ObjectId if not string

        entry_data = {
            "user_id": entry_user_id, # Link to the user document
            "website": website,
            "entry_username": entry_username,
            "encrypted_password": encrypted_password # Store the encrypted data
        }
        result = db_conn[config.VAULT_COLLECTION].insert_one(entry_data)
        return result.inserted_id
    except Exception as e:
        print(f"Error adding vault entry for user '{user_id}': {e}")
        return None

def get_vault_entries(user_id):
    """Retrieves all vault entries for a specific user."""
    try:
        db_conn = get_db()
        # Ensure user_id is an ObjectId if it's passed as a string
        if isinstance(user_id, str):
            query_user_id = ObjectId(user_id)
        else:
             query_user_id = user_id # Assume it's already ObjectId if not string

        entries = list(db_conn[config.VAULT_COLLECTION].find({"user_id": query_user_id}))
        return entries
    except Exception as e:
        print(f"Error retrieving vault entries for user '{user_id}': {e}")
        return [] # Return empty list on error

# Optional: Function to get a single entry and check ownership (more efficient)
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
        return entry # Returns document if found and owned, None otherwise
    except Exception as e:
        print(f"Error finding entry '{entry_id_str}' for user '{user_id_str}': {e}")
        return None


def update_vault_entry(entry_id, website, entry_username, encrypted_password):
    """Updates an existing vault entry. Assumes ownership already checked."""
    # Note: This function assumes the caller (Flask route) has verified
    # that the logged-in user owns this entry_id.
    try:
        db_conn = get_db()
        # Ensure entry_id is an ObjectId
        if isinstance(entry_id, str):
            update_entry_id = ObjectId(entry_id)
        else:
            update_entry_id = entry_id

        update_data = {
            "$set": {
                "website": website,
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
     # Note: This function assumes the caller (Flask route) has verified
    # that the logged-in user owns this entry_id.
    try:
        db_conn = get_db()
        # Ensure entry_id is an ObjectId
        if isinstance(entry_id, str):
            delete_entry_id = ObjectId(entry_id)
        else:
             delete_entry_id = entry_id
        result = db_conn[config.VAULT_COLLECTION].delete_one({"_id": delete_entry_id})
        return result.deleted_count > 0
    except Exception as e:
        print(f"Error deleting vault entry '{entry_id}': {e}")
        return False
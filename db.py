# db.py (Illustrative Changes)

# Modify add_user to include role and active status
def add_user(username, hashed_password, salt, role='user', is_active=True): # Add role/active params
    """Adds a new user with role and active status."""
    try:
        db_conn = get_db()
        user_data = {
            "username": username,
            "password_hash": hashed_password,
            "salt": salt,
            "totp_secret": None,
            "is_2fa_enabled": False,
            "role": role,             # <-- ADDED
            "is_active": is_active      # <-- ADDED
        }
        # Ensure first user created is an admin (Example logic)
        user_count = db_conn[config.USERS_COLLECTION].count_documents({})
        if user_count == 0:
             print("INFO: First user created, setting role to 'admin'.")
             user_data["role"] = "admin"

        result = db_conn[config.USERS_COLLECTION].insert_one(user_data)
        return result.inserted_id
    # ... (rest of add_user)

# Modify find_user to fetch role/active status
def find_user(username):
    """Finds a user by username and returns relevant fields including role/active status."""
    try:
        db_conn = get_db()
        user_data = db_conn[config.USERS_COLLECTION].find_one(
            {"username": username},
            {"_id": 1, "username": 1, "password_hash": 1, "salt": 1,
             "totp_secret": 1, "is_2fa_enabled": 1,
             "role": 1, "is_active": 1 } # <-- ADDED
        )
        return user_data
    # ... (rest of find_user)

# --- NEW Admin DB Functions ---
def get_all_users():
    """Retrieves basic info for all users (for admin listing)."""
    try:
        db_conn = get_db()
        # Exclude sensitive fields like password_hash, salt, totp_secret
        users = list(db_conn[config.USERS_COLLECTION].find(
            {},
            {"password_hash": 0, "salt": 0, "totp_secret": 0}
        ).sort("username", 1))
        return users
    except Exception as e:
        print(f"Error getting all users: {e}")
        return []

def set_user_status(user_id, is_active):
    """Sets the active status for a user."""
    try:
        db_conn = get_db()
        result = db_conn[config.USERS_COLLECTION].update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"is_active": bool(is_active)}}
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"Error setting user status for '{user_id}': {e}")
        return False

def set_user_role(user_id, role):
    """Sets the role for a user ('admin' or 'user')."""
    if role not in ['admin', 'user']:
        print(f"Invalid role specified: {role}")
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
    """Deletes a user and their associated vault entries."""
    # WARNING: This is destructive. Ensure proper confirmation.
    try:
        db_conn = get_db()
        user_obj_id = ObjectId(user_id)
        # Check if admin is trying to delete themselves (optional prevention)
        # if str(session.get('user_id')) == user_id: return False

        # Delete vault entries first
        db_conn[config.VAULT_COLLECTION].delete_many({"user_id": user_obj_id})
        # Then delete the user
        result = db_conn[config.USERS_COLLECTION].delete_one({"_id": user_obj_id})
        return result.deleted_count > 0
    except Exception as e:
        print(f"Error deleting user '{user_id}' and their entries: {e}")
        return False

# get_vault_entries needs modification if admin can view other's entries
# THIS VERSION LETS ADMIN SEE METADATA ONLY
def get_vault_entries_for_user(target_user_id):
     """Admin function to get METADATA of another user's entries."""
     try:
        db_conn = get_db()
        if isinstance(target_user_id, str): query_user_id = ObjectId(target_user_id)
        else: query_user_id = target_user_id

        # Projection excludes the encrypted password
        entries = list(db_conn[config.VAULT_COLLECTION].find(
            {"user_id": query_user_id},
            {"encrypted_password": 0} # <-- Exclude sensitive data
        ).sort([("brand_label", 1), ("laptop_server", 1)]))
        return entries
     except Exception as e:
         print(f"Error admin retrieving vault entries for user '{target_user_id}': {e}")
         return []

# Original function for logged-in user's own vault
def get_vault_entries(user_id, search_term=None):
    # ... (Keep the original function as is) ...
    try:
        db_conn = get_db()
        if isinstance(user_id, str): query_user_id = ObjectId(user_id)
        else: query_user_id = user_id
        query = {"user_id": query_user_id}
        if search_term:
            safe_search_term = re.escape(search_term)
            query["$or"] = [ {"laptop_server": {"$regex": safe_search_term, "$options": "i"}}, {"brand_label": {"$regex": safe_search_term, "$options": "i"}}, {"entry_username": {"$regex": safe_search_term, "$options": "i"}} ]
        entries = list(db_conn[config.VAULT_COLLECTION].find(query).sort([("brand_label", 1), ("laptop_server", 1)])); return entries
    except Exception as e: print(f"Error retrieving own vault entries user '{user_id}' (search: '{search_term}'): {e}"); return []

# --- Other vault functions (find_entry_by_id_and_user, update_vault_entry, add_vault_entry unchanged) ---
# Delete needs slight modification if admin can delete others' entries
def delete_vault_entry_by_id(entry_id):
     """Admin/Owner function to delete a specific entry by ID."""
     try:
         db_conn = get_db()
         if isinstance(entry_id, str): delete_entry_id = ObjectId(entry_id)
         else: delete_entry_id = entry_id
         result = db_conn[config.VAULT_COLLECTION].delete_one({"_id": delete_entry_id})
         return result.deleted_count > 0
     except Exception as e:
         print(f"Error deleting vault entry '{entry_id}': {e}")
         return False
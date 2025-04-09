# db.py
# (No changes from previous final version - includes brand_label, search, 2FA, admin functions)
from pymongo import MongoClient, errors; import config; from bson import ObjectId; import re
_client = None; _db = None
def connect_db():
    global _client, _db
    if _client is None:
        try: connection_args = {'host': config.mongo_host, 'port': config.mongo_port, 'serverSelectionTimeoutMS': 5000, 'connectTimeoutMS': 10000};
            if config.mongo_user: connection_args.update({'username': config.mongo_user, 'password': config.mongo_password, 'authSource': config.mongo_auth_db})
            _client = MongoClient(**connection_args); _client.admin.command('ping'); print(f"Successfully connected to MongoDB at {config.mongo_host}:{config.mongo_port}!"); _db = _client[config.DB_NAME]
        except Exception as e: print(f"DB Connection Error: {e}"); _client = None; _db = None; raise
    return _db
def get_db():
    if _db is None: return connect_db()
    return _db
def close_db(e=None):
    global _client, _db
    if _client: _client.close(); _client = None; _db = None
def ensure_indexes():
    db_conn = None
    try: db_conn = get_db();
        if db_conn: db_conn[config.USERS_COLLECTION].create_index("username", unique=True); db_conn[config.VAULT_COLLECTION].create_index("user_id"); db_conn[config.VAULT_COLLECTION].create_index([("user_id", 1), ("laptop_server", 1), ("brand_label", 1)]); print("Database indexes ensured.")
    except Exception as e: print(f"Warning: Error creating indexes: {e}")
def find_user(username):
    try: db_conn = get_db(); return db_conn[config.USERS_COLLECTION].find_one({"username": username},{"_id": 1, "username": 1, "password_hash": 1, "salt": 1, "totp_secret": 1, "is_2fa_enabled": 1, "role": 1, "is_active": 1})
    except Exception as e: print(f"Error finding user '{username}': {e}"); return None
def add_user(username, hashed_password, salt, role='user', is_active=True):
    try: db_conn = get_db(); user_data = {"username": username, "password_hash": hashed_password, "salt": salt, "totp_secret": None, "is_2fa_enabled": False, "role": role, "is_active": is_active};
        if db_conn[config.USERS_COLLECTION].count_documents({}) == 0: user_data["role"] = "admin"; print("INFO: First user set as admin.")
        result = db_conn[config.USERS_COLLECTION].insert_one(user_data); return result.inserted_id
    except errors.DuplicateKeyError: print(f"Duplicate username: '{username}'"); return None
    except Exception as e: print(f"Error adding user '{username}': {e}"); return None
def set_user_2fa_secret(user_id, secret):
    try: db_conn = get_db(); result = db_conn[config.USERS_COLLECTION].update_one({"_id": ObjectId(user_id)},{"$set": {"totp_secret": secret}}); return result.modified_count > 0
    except Exception as e: print(f"Error setting 2FA secret user '{user_id}': {e}"); return False
def enable_user_2fa(user_id, enable=True):
    try: db_conn = get_db(); result = db_conn[config.USERS_COLLECTION].update_one({"_id": ObjectId(user_id)},{"$set": {"is_2fa_enabled": bool(enable)}}); return result.modified_count > 0
    except Exception as e: print(f"Error {'enabling' if enable else 'disabling'} 2FA user '{user_id}': {e}"); return False
def disable_user_2fa(user_id):
    try: db_conn = get_db(); result = db_conn[config.USERS_COLLECTION].update_one({"_id": ObjectId(user_id)},{"$set": {"is_2fa_enabled": False, "totp_secret": None}}); return result.modified_count > 0
    except Exception as e: print(f"Error disabling 2FA user '{user_id}': {e}"); return False
def get_all_users():
    try: db_conn = get_db(); users = list(db_conn[config.USERS_COLLECTION].find({},{"password_hash": 0, "salt": 0, "totp_secret": 0}).sort("username", 1)); return users
    except Exception as e: print(f"Error getting all users: {e}"); return []
def set_user_status(user_id, is_active):
    try: db_conn = get_db(); result = db_conn[config.USERS_COLLECTION].update_one({"_id": ObjectId(user_id)},{"$set": {"is_active": bool(is_active)}}); return result.modified_count > 0
    except Exception as e: print(f"Error setting user status for '{user_id}': {e}"); return False
def set_user_role(user_id, role):
    if role not in ['admin', 'user']: print(f"Invalid role: {role}"); return False
    try: db_conn = get_db(); result = db_conn[config.USERS_COLLECTION].update_one({"_id": ObjectId(user_id)},{"$set": {"role": role}}); return result.modified_count > 0
    except Exception as e: print(f"Error setting user role for '{user_id}': {e}"); return False
def delete_user_by_id(user_id):
    try: db_conn = get_db(); user_obj_id = ObjectId(user_id); delete_result = db_conn[config.VAULT_COLLECTION].delete_many({"user_id": user_obj_id}); print(f"Deleted {delete_result.deleted_count} vault entries for user {user_id}"); result = db_conn[config.USERS_COLLECTION].delete_one({"_id": user_obj_id}); return result.deleted_count > 0
    except Exception as e: print(f"Error deleting user '{user_id}': {e}"); return False
def add_vault_entry(user_id, laptop_server, brand_label, entry_username, encrypted_password):
    try: db_conn = get_db(); entry_user_id = ObjectId(user_id) if isinstance(user_id, str) else user_id; entry_data = {"user_id": entry_user_id, "laptop_server": laptop_server, "brand_label": brand_label, "entry_username": entry_username, "encrypted_password": encrypted_password}; result = db_conn[config.VAULT_COLLECTION].insert_one(entry_data); return result.inserted_id
    except Exception as e: print(f"Error adding vault entry user '{user_id}': {e}"); return None
def get_vault_entries(user_id, search_term=None):
    try: db_conn = get_db(); query_user_id = ObjectId(user_id) if isinstance(user_id, str) else user_id; query = {"user_id": query_user_id};
        if search_term: safe_search_term = re.escape(search_term); query["$or"] = [ {"laptop_server": {"$regex": safe_search_term, "$options": "i"}}, {"brand_label": {"$regex": safe_search_term, "$options": "i"}}, {"entry_username": {"$regex": safe_search_term, "$options": "i"}} ]
        entries = list(db_conn[config.VAULT_COLLECTION].find(query).sort([("brand_label", 1), ("laptop_server", 1)])); return entries
    except Exception as e: print(f"Error retrieving own vault entries user '{user_id}' (search: '{search_term}'): {e}"); return []
def get_vault_entries_for_user(target_user_id):
     try: db_conn = get_db(); query_user_id = ObjectId(target_user_id) if isinstance(target_user_id, str) else target_user_id; entries = list(db_conn[config.VAULT_COLLECTION].find({"user_id": query_user_id}, {"encrypted_password": 0}).sort([("brand_label", 1), ("laptop_server", 1)])); return entries
     except Exception as e: print(f"Error admin retrieving vault entries for user '{target_user_id}': {e}"); return []
def find_entry_by_id_and_user(entry_id_str, user_id_str):
    try: db_conn = get_db(); entry_obj_id = ObjectId(entry_id_str); user_obj_id = ObjectId(user_id_str); entry = db_conn[config.VAULT_COLLECTION].find_one({"_id": entry_obj_id, "user_id": user_obj_id}); return entry
    except Exception as e: print(f"Error finding entry '{entry_id_str}' user '{user_id_str}': {e}"); return None
def find_entry_by_id(entry_id_str):
    try: db_conn = get_db(); entry_obj_id = ObjectId(entry_id_str); entry = db_conn[config.VAULT_COLLECTION].find_one({"_id": entry_obj_id}); return entry
    except Exception as e: print(f"Error finding entry '{entry_id_str}': {e}"); return None
def update_vault_entry(entry_id, laptop_server, brand_label, entry_username, encrypted_password):
    try: db_conn = get_db(); update_entry_id = ObjectId(entry_id) if isinstance(entry_id, str) else entry_id; update_data = {"$set": {"laptop_server": laptop_server, "brand_label": brand_label, "entry_username": entry_username, "encrypted_password": encrypted_password}}; result = db_conn[config.VAULT_COLLECTION].update_one({"_id": update_entry_id}, update_data); return result.modified_count > 0
    except Exception as e: print(f"Error updating vault entry '{entry_id}': {e}"); return False
def delete_vault_entry(entry_id):
    try: db_conn = get_db(); delete_entry_id = ObjectId(entry_id) if isinstance(entry_id, str) else entry_id; result = db_conn[config.VAULT_COLLECTION].delete_one({"_id": delete_entry_id}); return result.deleted_count > 0
    except Exception as e: print(f"Error deleting vault entry '{entry_id}': {e}"); return False
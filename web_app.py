# web_app.py
import os
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify, abort)
from functools import wraps
import config; import db; import encryption; import utils; import pyotp
import traceback

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
if not app.secret_key: raise ValueError("FLASK_SECRET_KEY not set")

@app.teardown_appcontext
def shutdown_session(exception=None): db.close_db()

# --- Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session: flash('Please log in.', 'warning'); return redirect(url_for('login'))
        if session.get('2fa_required') and not session.get('2fa_passed'):
            if request.endpoint != 'login_2fa': flash('2FA required.', 'warning'); return redirect(url_for('login_2fa'))
        needs_key = request.endpoint not in ['login', 'signup', 'logout', 'login_2fa', 'index', 'setup_2fa', 'disable_2fa', 'admin_users', 'admin_toggle_user_status', 'admin_change_user_role', 'admin_delete_user', 'admin_view_user_vault', 'static']
        if needs_key and 'encryption_key' not in session:
             flash('Session invalid or key missing. Please log in again.', 'error')
             session.clear(); return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin': flash('Admin access required.', 'error'); return redirect(url_for('vault'))
        return f(*args, **kwargs)
    return decorated_function

# --- Standard Routes ---
@app.route('/')
def index():
    if 'user_id' in session: return redirect(url_for('vault'))
    return redirect(url_for('login'))
@app.route('/logout')
def logout(): session.clear(); flash('Logged out.', 'success'); return redirect(url_for('login'))

# --- Auth Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session and not session.get('2fa_required'): return redirect(url_for('vault'))
    if request.method == 'POST':
        username = request.form.get('username'); password = request.form.get('password')
        if not username or not password: flash('Username and password required.', 'error'); return render_template('quantum_login_v3.html')
        user_data = db.find_user(username)
        if user_data and encryption.verify_master_password(user_data['password_hash'], password):
             if not user_data.get('is_active', True): flash('Account disabled.', 'error'); return render_template('quantum_login_v3.html')
             session['_2fa_user_id'] = str(user_data['_id']); session['_2fa_username'] = user_data['username']; session['_2fa_salt'] = user_data['salt']; session['_2fa_role'] = user_data.get('role', 'user')
             if user_data.get('is_2fa_enabled'):
                 session['2fa_required'] = True; session.pop('_2fa_passed', None); return redirect(url_for('login_2fa'))
             else:
                 try:
                     key = encryption.derive_key(password, user_data['salt'])
                     session['user_id'] = session.pop('_2fa_user_id'); session['username'] = session.pop('_2fa_username'); session['salt'] = session.pop('_2fa_salt'); session['role'] = session.pop('_2fa_role')
                     session['encryption_key'] = key; session['is_2fa_enabled'] = False; session.pop('2fa_required', None); session.pop('_2fa_passed', None)
                     flash('Login successful!', 'success'); return redirect(url_for('vault'))
                 except Exception as e: print(f"DEBUG Login Err (no 2FA): {e}"); traceback.print_exc(); flash(f'Login process error: {e}', 'error'); session.clear(); return render_template('quantum_login_v3.html')
        else: flash('Invalid username or password.', 'error'); session.clear()
    session.pop('_2fa_user_id', None); session.pop('_2fa_username', None); session.pop('_2fa_salt', None); session.pop('2fa_required', None); session.pop('_2fa_passed', None)
    return render_template('quantum_login_v3.html')

@app.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    if '_2fa_user_id' not in session: flash('Please log in first.', 'warning'); return redirect(url_for('login'))
    user_id = session['_2fa_user_id']
    if request.method == 'POST':
        password = request.form.get('password'); totp_code = request.form.get('totp_code')
        if not password or not totp_code: flash('Password and code required.', 'error'); return render_template('quantum_login_2fa_v3.html')
        user_data = db.find_user(session['_2fa_username'])
        if not user_data or str(user_data['_id']) != user_id: flash('User validation error.', 'error'); session.clear(); return redirect(url_for('login'))
        if not encryption.verify_master_password(user_data['password_hash'], password): flash('Invalid password.', 'error'); return render_template('quantum_login_2fa_v3.html')
        totp_secret = user_data.get('totp_secret')
        if not totp_secret: flash('2FA secret not found.', 'error'); session.clear(); return redirect(url_for('login'))
        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(totp_code, valid_window=1): flash('Invalid authenticator code.', 'error'); return render_template('quantum_login_2fa_v3.html')
        try:
            key = encryption.derive_key(password, user_data['salt'])
            session['user_id'] = session.pop('_2fa_user_id'); session['username'] = session.pop('_2fa_username'); session['salt'] = session.pop('_2fa_salt'); session['role'] = session.pop('_2fa_role')
            session['encryption_key'] = key; session['is_2fa_enabled'] = True; session.pop('2fa_required', None); session['2fa_passed'] = True
            flash('Login successful!', 'success'); return redirect(url_for('vault'))
        except Exception as e: print(f"DEBUG Login Err (2FA): {e}"); traceback.print_exc(); flash(f'Login process error after 2FA: {e}', 'error'); session.clear(); return redirect(url_for('login'))
    return render_template('quantum_login_2fa_v3.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user_id' in session: return redirect(url_for('vault'))
    if request.method == 'POST':
        username = request.form.get('username'); password = request.form.get('password'); confirm_password = request.form.get('confirm_password')
        error = None
        if not username or not password or not confirm_password: error = 'All fields required.'
        elif password != confirm_password: error = 'Passwords do not match.'
        elif len(password) < 8: error = 'Password min 8 characters.'
        elif db.find_user(username): error = 'Username exists.'
        if error: flash(error, 'error')
        else:
            try:
                salt = encryption.generate_salt(); hashed_password = encryption.hash_master_password(password, salt)
                user_id = db.add_user(username, hashed_password, salt)
                if user_id:
                    flash('Account created! Please log in.', 'success');
                    try: db.ensure_indexes()
                    except Exception as idx_e: print(f"Warning: Signup index error: {idx_e}")
                    return redirect(url_for('login'))
                else: flash('Failed to create account.', 'error')
            except Exception as e: print(f"Signup Error: {e}"); traceback.print_exc(); flash(f'Signup error: {e}', 'error')
    return render_template('quantum_signup_v3.html')

# --- 2FA Management ---
@app.route('/setup_2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    user_id = session['user_id']; username = session['username']
    if request.method == 'POST':
        secret_key = request.form.get('secret_key'); totp_code = request.form.get('totp_code')
        if not secret_key or not totp_code: flash('Code and secret required.', 'error'); return redirect(url_for('setup_2fa'))
        totp = pyotp.TOTP(secret_key)
        if totp.verify(totp_code, valid_window=1):
            if db.set_user_2fa_secret(user_id, secret_key) and db.enable_user_2fa(user_id, enable=True):
                flash('2FA enabled successfully!', 'success'); session['is_2fa_enabled'] = True; return redirect(url_for('vault'))
            else: flash('Failed to save 2FA settings.', 'error'); return redirect(url_for('setup_2fa'))
        else:
            flash('Invalid verification code.', 'error')
            provisioning_uri = pyotp.totp.TOTP(secret_key).provisioning_uri(name=username, issuer_name=config.TOTP_ISSUER_NAME)
            qr_code_data = utils.generate_qr_code_base64(provisioning_uri)
            if not qr_code_data: flash('Error generating QR code.', 'error'); return redirect(url_for('vault'))
            return render_template('quantum_setup_2fa_v3.html', secret_key=secret_key, qr_code_data=qr_code_data)
    secret_key = pyotp.random_base32(); provisioning_uri = pyotp.totp.TOTP(secret_key).provisioning_uri(name=username, issuer_name=config.TOTP_ISSUER_NAME)
    qr_code_data = utils.generate_qr_code_base64(provisioning_uri)
    if not qr_code_data: flash('Error generating QR code.', 'error'); return redirect(url_for('vault'))
    return render_template('quantum_setup_2fa_v3.html', secret_key=secret_key, qr_code_data=qr_code_data)

@app.route('/disable_2fa', methods=['POST'])
@login_required
def disable_2fa():
    user_id = session['user_id']
    if db.disable_user_2fa(user_id): flash('2FA disabled.', 'success'); session['is_2fa_enabled'] = False
    else: flash('Failed to disable 2FA.', 'error')
    return redirect(url_for('vault'))

# --- Admin Routes ---
@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    all_users = db.get_all_users(); return render_template('quantum_admin_users.html', users=all_users)

@app.route('/admin/user/status/<user_id>', methods=['POST'])
@login_required
@admin_required
def admin_toggle_user_status(user_id):
    all_users = db.get_all_users(); target_user_data = next((u for u in all_users if str(u['_id']) == user_id), None)
    if not target_user_data: flash('User not found.', 'error'); return redirect(url_for('admin_users'))
    if str(target_user_data['_id']) == session.get('user_id'): flash('Cannot disable self.', 'error'); return redirect(url_for('admin_users'))
    new_status = not target_user_data.get('is_active', True)
    if db.set_user_status(user_id, new_status): flash(f"User '{target_user_data['username']}' status set to {'Active' if new_status else 'Disabled'}.", 'success')
    else: flash('Failed to update status.', 'error')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/role/<user_id>', methods=['POST'])
@login_required
@admin_required
def admin_change_user_role(user_id):
    new_role = request.form.get('role')
    if not new_role or new_role not in ['admin', 'user']: flash('Invalid role.', 'error'); return redirect(url_for('admin_users'))
    if str(user_id) == session.get('user_id') and new_role == 'user': flash('Cannot demote self.', 'error'); return redirect(url_for('admin_users'))
    if db.set_user_role(user_id, new_role): flash(f"User role updated.", 'success')
    else: flash('Failed to update role.', 'error')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/delete/<user_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    if str(user_id) == session.get('user_id'): flash('Cannot delete self.', 'error'); return redirect(url_for('admin_users'))
    if db.delete_user_by_id(user_id): flash(f"User deleted.", 'success')
    else: flash('Failed to delete user.', 'error')
    return redirect(url_for('admin_users'))

@app.route('/admin/view_vault/<user_id>')
@login_required
@admin_required
def admin_view_user_vault(user_id):
     all_users = db.get_all_users(); target_user = next((u for u in all_users if str(u['_id']) == user_id), None)
     if not target_user: flash('Target user not found.', 'error'); return redirect(url_for('admin_users'))
     entries = db.get_vault_entries_for_user(user_id); return render_template('quantum_admin_view_vault.html', entries=entries, target_user=target_user)

# --- Vault ---
@app.route('/vault')
@login_required
def vault():
    user_id = session['user_id']
    search_term = request.args.get('search_term', '')
    # Make sure this function fetches full entries for the owner
    entries = db.get_vault_entries(user_id, search_term=search_term)

    # Debugging statement
    print(f"DEBUG: Rendering vault for {session.get('username')}, found {len(entries)} entries.")
    # print(f"DEBUG: First entry sample: {entries[0] if entries else 'None'}")

    return render_template(
        'quantum_vault_v3.html', # Ensure using V3 template
        entries=entries,
        search_term=search_term,
        is_2fa_enabled=session.get('is_2fa_enabled'),
        current_username=session.get('username')
    )

@app.route('/add_entry', methods=['POST'])
@login_required
def add_entry():
    laptop_server = request.form.get('laptop_server'); brand_label = request.form.get('brand_label')
    entry_username = request.form.get('entry_username'); password = request.form.get('entry_password')
    user_id = session['user_id']; encryption_key = session.get('encryption_key')
    if not laptop_server or not entry_username or not password: flash('Laptop/Server ID, Username, Password required.', 'error')
    elif not encryption_key: flash('Session error: Key missing.', 'error'); session.clear(); return redirect(url_for('login'))
    else:
        try:
            encrypted_password = encryption.encrypt_data(password, encryption_key)
            entry_id = db.add_vault_entry(user_id, laptop_server, brand_label, entry_username, encrypted_password)
            if entry_id: flash('Entry added!', 'success')
            else: flash('Failed to add entry.', 'error')
        except Exception as e: flash(f'Error adding entry: {e}', 'error')
    return redirect(url_for('vault'))

# Edit route removed - handled by modal

@app.route('/update_entry/<entry_id>', methods=['POST'])
@login_required
def update_entry(entry_id):
    user_id = session['user_id']; encryption_key = session.get('encryption_key')
    if not encryption_key: flash('Session error.', 'error'); session.clear(); return redirect(url_for('login'))
    new_laptop_server = request.form.get('laptop_server'); new_brand_label = request.form.get('brand_label')
    new_entry_username = request.form.get('entry_username'); new_plain_password = request.form.get('password')
    if not new_laptop_server or not new_entry_username: flash('Laptop/Server ID and Username required.', 'error'); return redirect(url_for('vault'))
    original_entry_data = db.find_entry_by_id_and_user(entry_id, user_id) # Verify ownership
    if not original_entry_data: flash('Permission denied or entry not found.', 'error'); return redirect(url_for('vault'))
    if new_plain_password: # Only update password if provided
        try: new_encrypted_password = encryption.encrypt_data(new_plain_password, encryption_key)
        except Exception as e: flash(f'Error encrypting: {e}', 'error'); return redirect(url_for('vault'))
    else: new_encrypted_password = original_entry_data.get('encrypted_password', b'') # Keep existing
    success = db.update_vault_entry(entry_id, new_laptop_server, new_brand_label, new_entry_username, new_encrypted_password)
    if success: flash('Entry updated!', 'success')
    else: flash('Failed update (or no changes).', 'warning')
    return redirect(url_for('vault'))

@app.route('/delete_entry/<entry_id>', methods=['POST'])
@login_required
def delete_entry(entry_id):
     user_id = session['user_id']; user_role = session.get('role')
     can_delete = False; entry_data = db.find_entry_by_id_and_user(entry_id, user_id) # Check owner
     if entry_data: can_delete = True
     elif user_role == 'admin':
         entry_exists = db.find_entry_by_id(entry_id) # Admin check if entry exists
         if entry_exists: can_delete = True
         else: print(f"Admin {session.get('username')} tried deleting non-existent entry {entry_id}.")
     if can_delete:
         try:
             success = db.delete_vault_entry(entry_id);
             if success: flash('Entry deleted.', 'success')
             else: flash('Failed to delete.', 'error')
         except Exception as e: flash(f'Error deleting: {e}', 'error')
     else: flash('Cannot delete (not found/permission denied).', 'error')
     return redirect(url_for('vault'))

# --- APIs ---
@app.route('/generate_password')
@login_required
def generate_password_api():
    try: return jsonify({'password': utils.generate_password(16)})
    except Exception as e: print(f"Gen pass error: {e}"); return jsonify({'error': 'Failed'}), 500

@app.route('/get_password/<entry_id>') # For card show/copy
@login_required
def get_password_api(entry_id):
    user_id = session['user_id']; encryption_key = session.get('encryption_key')
    if not encryption_key: return jsonify({'error': 'Key missing'}), 401
    try:
        entry_data = db.find_entry_by_id_and_user(entry_id, user_id)
        if entry_data:
            encrypted_pass = entry_data.get('encrypted_password')
            if encrypted_pass:
                decrypted_pass = encryption.decrypt_data(encrypted_pass, encryption_key)
                if decrypted_pass is not None:
                    return jsonify({'password': decrypted_pass})
                else:
                    return jsonify({'error': 'Decryption failed'}), 500
            else:
                return jsonify({'password': ''})
        else:
            return jsonify({'error': 'Not found/denied'}), 404
    except Exception as e:
        print(f"Get pass error for entry '{entry_id}': {e}")
        return jsonify({'error': 'Internal error'}), 500

@app.route('/get_entry_details/<entry_id>') # For edit modal
@login_required
def get_entry_details_api(entry_id):
    user_id = session['user_id']; encryption_key = session.get('encryption_key')
    if not encryption_key: return jsonify({'error': 'Key missing'}), 401
    try:
        entry_data = db.find_entry_by_id_and_user(entry_id, user_id);
        if not entry_data:
             return jsonify({'error': 'Not found/denied'}), 404
        decrypted_password = "";
        encrypted_pass = entry_data.get('encrypted_password')
        if encrypted_pass:
            decrypted_password = encryption.decrypt_data(encrypted_pass, encryption_key)
            if decrypted_password is None:
                 decrypted_password = "" # Return empty on decrypt fail
        details = {
            'laptop_server': entry_data.get('laptop_server', ''),
            'brand_label': entry_data.get('brand_label', ''),
            'entry_username': entry_data.get('entry_username', ''),
            'password': decrypted_password # Decrypted password
        }
        return jsonify(details)
    except Exception as e:
        print(f"Get entry details error for entry '{entry_id}': {e}")
        return jsonify({'error': 'Internal error'}), 500

# --- Main Execution ---
if __name__ == '__main__':
    try:
        print("Attempting initial database connection check...")
        db_conn_check = db.connect_db()
        if db_conn_check is not None:
            print("Initial connection successful. Checking indexes...")
            db.ensure_indexes(); db.close_db()
            print("Database connection checked and indexes ensured.")
        else:
             raise ConnectionError("DB check returned None.")
    except Exception as e:
        print(f"\nCRITICAL: DB setup failed: {e}\n");
        import sys;
        sys.exit(1)

    print("Starting Flask dev server (Debug Mode)...");
    app.run(host='0.0.0.0', port=5000, debug=True)
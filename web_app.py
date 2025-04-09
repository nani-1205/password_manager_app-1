# web_app.py
import os
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify, abort)
from functools import wraps
import config  # Reads .env for settings
import db      # Database interaction functions
import encryption # Hashing and encryption functions
import utils    # Utility functions (password gen, QR code)
import pyotp    # For TOTP 2FA generation/verification
import traceback # For detailed error logging

# --- Flask App Initialization ---
app = Flask(__name__)
app.secret_key = config.SECRET_KEY # Load secret key from config (read from .env)
if not app.secret_key:
     # Critical: App cannot run securely without a secret key for sessions
     raise ValueError("FLASK_SECRET_KEY is not set in config or environment variables!")

# --- App Context Teardown ---
@app.teardown_appcontext
def shutdown_session(exception=None):
    """Closes the database connection at the end of each request/app context."""
    db.close_db()

# --- Decorators ---
def login_required(f):
    """Decorator to ensure user is logged in and 2FA is passed (if required)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Basic Login Check: Is user_id in session?
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))

        # 2. 2FA Check: If 2FA is required for this session, has it been passed?
        if session.get('2fa_required') and not session.get('2fa_passed'):
            # Allow access only to the 2FA verification page itself to prevent loops
            if request.endpoint != 'login_2fa':
                flash('Two-factor authentication is required.', 'warning')
                return redirect(url_for('login_2fa'))

        # 3. Encryption Key Check: Does the route need the decryption key, and is it present?
        # Routes that manipulate or view decrypted vault data need the key.
        # Admin routes viewing metadata might not need the *user's* key.
        needs_key = request.endpoint in [
            'vault', 'add_entry', 'update_entry', 'delete_entry', # Vault operations
            'get_password_api', 'get_entry_details_api' # APIs needing decryption
            # Add other routes here if they perform encryption/decryption
        ]
        if needs_key and 'encryption_key' not in session:
             print(f"DEBUG: Encryption key missing for endpoint '{request.endpoint}'. Session: {session}") # Debug log
             flash('Session invalid or encryption key missing. Please log in again.', 'error')
             session.clear(); # Clear invalid session
             return redirect(url_for('login'))

        # If all checks pass, execute the original route function
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to ensure the logged-in user has the 'admin' role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check the role stored in the session
        if session.get('role') != 'admin':
            flash('Administrator access is required for this page.', 'error')
            return redirect(url_for('vault')) # Redirect non-admins to their vault
        # If admin, proceed
        return f(*args, **kwargs)
    return decorated_function

# --- Standard Routes ---
@app.route('/')
def index():
    """Redirects authenticated users to vault, others to login."""
    if 'user_id' in session:
        return redirect(url_for('vault'))
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    """Logs the user out by clearing the session."""
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

# --- Authentication Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login (Stage 1: Password Check)."""
    # Redirect if already fully logged in
    if 'user_id' in session and not session.get('2fa_required'):
        return redirect(url_for('vault'))

    if request.method == 'POST':
        username = request.form.get('username'); password = request.form.get('password')
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('quantum_login_v3.html')

        user_data = db.find_user(username) # Fetches all necessary fields

        # Verify user exists and password matches hash
        if user_data and encryption.verify_master_password(user_data['password_hash'], password):
            # Check if the account is marked as active
             if not user_data.get('is_active', True): # Default to active if field missing
                  flash('Your account is disabled. Please contact an administrator.', 'error')
                  return render_template('quantum_login_v3.html')

             # Password correct! Store temporary info before 2FA check or final login
             session['_2fa_user_id'] = str(user_data['_id'])
             session['_2fa_username'] = user_data['username']
             session['_2fa_salt'] = user_data['salt']
             session['_2fa_role'] = user_data.get('role', 'user') # Get role

             # Check if 2FA is enabled for this user in the database
             if user_data.get('is_2fa_enabled'):
                 session['2fa_required'] = True # Mark session as needing 2FA step
                 session.pop('_2fa_passed', None) # Clear previous 2FA pass status
                 return redirect(url_for('login_2fa')) # Redirect to 2FA input page
             else:
                 # No 2FA required, complete login process now
                 try:
                     # Derive the encryption key using the verified password and salt
                     key = encryption.derive_key(password, user_data['salt'])
                     # Promote temporary session vars to final session vars
                     session['user_id'] = session.pop('_2fa_user_id')
                     session['username'] = session.pop('_2fa_username')
                     session['salt'] = session.pop('_2fa_salt')
                     session['role'] = session.pop('_2fa_role')
                     session['encryption_key'] = key # Store the derived key
                     session['is_2fa_enabled'] = False # Reflect current status
                     session.pop('2fa_required', None); session.pop('_2fa_passed', None) # Clean up flags
                     flash('Login successful!', 'success')
                     return redirect(url_for('vault')) # Redirect to the main vault page
                 except Exception as e:
                     # Catch errors during key derivation or final session setting
                     print(f"ERROR Login (no 2FA) key derivation/session set: {e}"); traceback.print_exc()
                     flash(f'Login process error: {e}', 'error')
                     session.clear(); return render_template('quantum_login_v3.html')
        else:
            # Invalid username or password provided
            flash('Invalid username or password.', 'error')
            session.clear() # Clear any temporary data

    # Clear temporary flags if user visits login page via GET
    session.pop('_2fa_user_id', None); session.pop('_2fa_username', None); session.pop('_2fa_salt', None)
    session.pop('2fa_required', None); session.pop('_2fa_passed', None)
    return render_template('quantum_login_v3.html')

@app.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    """Handles user login (Stage 2: 2FA Verification)."""
    # Ensure user passed Stage 1 (password check)
    if '_2fa_user_id' not in session:
        flash('Please enter your username and password first.', 'warning')
        return redirect(url_for('login'))

    user_id = session['_2fa_user_id'] # Use temp ID for consistency check

    if request.method == 'POST':
        password = request.form.get('password'); totp_code = request.form.get('totp_code')
        if not password or not totp_code:
            flash('Password and authenticator code are required.', 'error')
            return render_template('quantum_login_2fa_v3.html')

        # Re-fetch user data to get hash, salt, TOTP secret
        user_data = db.find_user(session['_2fa_username']) # Find by temp username
        # Verify consistency and user exists
        if not user_data or str(user_data['_id']) != user_id:
            flash('User validation error. Please try logging in again.', 'error')
            session.clear(); return redirect(url_for('login'))

        # 1. Verify password AGAIN (security measure against session fixation/timing issues)
        if not encryption.verify_master_password(user_data['password_hash'], password):
            flash('Invalid password provided.', 'error')
            return render_template('quantum_login_2fa_v3.html') # Stay on 2FA page

        # 2. Verify TOTP code
        totp_secret = user_data.get('totp_secret')
        if not totp_secret: # Should not happen if is_2fa_enabled was true
            flash('2FA secret not found for user. Cannot verify code.', 'error')
            session.clear(); return redirect(url_for('login'))

        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(totp_code, valid_window=1): # Allow 1 time step tolerance (30-60s)
            flash('Invalid authenticator code.', 'error')
            return render_template('quantum_login_2fa_v3.html') # Stay on 2FA page

        # --- Both factors verified ---
        try:
            # Derive encryption key *now* using the verified password
            key = encryption.derive_key(password, user_data['salt'])
            # Set final session variables, removing temporary ones
            session['user_id'] = session.pop('_2fa_user_id')
            session['username'] = session.pop('_2fa_username')
            session['salt'] = session.pop('_2fa_salt')
            session['role'] = session.pop('_2fa_role')
            session['encryption_key'] = key
            session['is_2fa_enabled'] = True # Reflect actual status
            session.pop('2fa_required', None) # Remove requirement flag
            session['2fa_passed'] = True # Mark 2FA as passed for this session
            flash('Login successful!', 'success')
            return redirect(url_for('vault'))
        except Exception as e:
            print(f"DEBUG Login Err (2FA): {e}"); traceback.print_exc()
            flash(f'Login process error after 2FA: {e}', 'error')
            session.clear(); return redirect(url_for('login'))

    # Render 2FA input page on GET request
    return render_template('quantum_login_2fa_v3.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handles new user registration."""
    if 'user_id' in session: return redirect(url_for('vault')) # Redirect if already logged in
    if request.method == 'POST':
        username = request.form.get('username'); password = request.form.get('password'); confirm_password = request.form.get('confirm_password')
        error = None # Validation flag
        if not username or not password or not confirm_password: error = 'All fields are required.'
        elif password != confirm_password: error = 'Passwords do not match.'
        elif len(password) < 8: error = 'Password must be at least 8 characters.'
        elif db.find_user(username): error = 'Username already exists.' # Check uniqueness

        if error: # If any validation error occurred
            flash(error, 'error')
        else:
            # Validation passed, proceed with account creation
            try:
                salt = encryption.generate_salt(); hashed_password = encryption.hash_master_password(password, salt)
                # db.add_user defaults role to 'user', but promotes the first user to 'admin'
                user_id = db.add_user(username, hashed_password, salt)
                if user_id: # If user was added successfully
                    flash('Account created successfully! Please log in.', 'success')
                    try: db.ensure_indexes() # Attempt to ensure indexes exist
                    except Exception as idx_e: print(f"Warning: Could not ensure indexes after signup for user {username}: {idx_e}")
                    return redirect(url_for('login')) # Redirect to login page
                else: flash('Failed to create account (database issue or unexpected error).', 'error')
            except Exception as e:
                # Catch any other errors during hashing/DB interaction
                print(f"Signup Error: {e}"); traceback.print_exc()
                flash(f'An error occurred during signup: {e}', 'error')
    # Render signup page for GET requests or if POST validation failed
    return render_template('quantum_signup_v3.html')

# --- 2FA Management ---
@app.route('/setup_2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    """Handles setup and verification of 2FA for the logged-in user."""
    user_id = session['user_id']; username = session['username'] # Needed for provisioning URI

    if request.method == 'POST': # User submitted verification code
        secret_key = request.form.get('secret_key') # Secret generated during GET request
        totp_code = request.form.get('totp_code') # Code entered by user

        if not secret_key or not totp_code:
            flash('Verification code and secret key are required.', 'error')
            return redirect(url_for('setup_2fa')) # Redirect back to generate new QR

        # Verify the submitted code against the temp secret
        totp = pyotp.TOTP(secret_key)
        if totp.verify(totp_code, valid_window=1): # Allow 1 time step tolerance
            # Code is valid! Save secret and enable 2FA flag in the database.
            if db.set_user_2fa_secret(user_id, secret_key) and db.enable_user_2fa(user_id, enable=True):
                flash('2FA enabled successfully!', 'success')
                session['is_2fa_enabled'] = True # Update session state immediately
                return redirect(url_for('vault'))
            else:
                flash('Failed to save 2FA settings in the database. Please try again.', 'error')
                return redirect(url_for('setup_2fa')) # Redirect to try again
        else:
            # Invalid code entered by user
            flash('Invalid verification code. Please check your authenticator app and try again.', 'error')
            # Re-render the setup page WITH THE SAME secret/QR so they can retry verification
            provisioning_uri = pyotp.totp.TOTP(secret_key).provisioning_uri(name=username, issuer_name=config.TOTP_ISSUER_NAME)
            qr_code_data = utils.generate_qr_code_base64(provisioning_uri)
            if not qr_code_data: flash('Error re-generating QR code.', 'error'); return redirect(url_for('vault'))
            return render_template('quantum_setup_2fa_v3.html', secret_key=secret_key, qr_code_data=qr_code_data)

    # --- GET Request Logic: Generate new secret and display QR ---
    secret_key = pyotp.random_base32() # Generate new secure secret
    # Create the otpauth:// URI
    provisioning_uri = pyotp.totp.TOTP(secret_key).provisioning_uri(
        name=username, issuer_name=config.TOTP_ISSUER_NAME
    )
    # Generate QR code image data from the URI
    qr_code_data = utils.generate_qr_code_base64(provisioning_uri)
    if not qr_code_data: # Handle QR generation failure
        flash('Error generating QR code for 2FA setup.', 'error')
        return redirect(url_for('vault'))
    # Render the setup page, passing the secret (for manual entry/form submission) and QR data
    return render_template('quantum_setup_2fa_v3.html', secret_key=secret_key, qr_code_data=qr_code_data)

@app.route('/disable_2fa', methods=['POST'])
@login_required
def disable_2fa():
    """Disables 2FA for the logged-in user."""
    # SECURITY ENHANCEMENT: Add password/TOTP verification before disabling
    user_id = session['user_id']
    if db.disable_user_2fa(user_id): # Clears secret and sets flag to False
        flash('Two-factor authentication disabled.', 'success')
        session['is_2fa_enabled'] = False # Update session state
    else:
        flash('Failed to disable 2FA in database.', 'error')
    return redirect(url_for('vault'))

# --- Admin Routes ---
@app.route('/admin/users')
@login_required
@admin_required # Ensures only admins can access
def admin_users():
    """Displays the user management page."""
    all_users = db.get_all_users(); return render_template('quantum_admin_users.html', users=all_users)

@app.route('/admin/user/status/<user_id>', methods=['POST'])
@login_required
@admin_required
def admin_toggle_user_status(user_id):
    """Admin action to enable/disable a user account."""
    all_users = db.get_all_users(); target_user_data = next((u for u in all_users if str(u['_id']) == user_id), None)
    if not target_user_data: flash('User not found.', 'error'); return redirect(url_for('admin_users'))
    # Prevent admin disabling themselves
    if str(target_user_data['_id']) == session.get('user_id'): flash('Cannot disable own account.', 'error'); return redirect(url_for('admin_users'))
    new_status = not target_user_data.get('is_active', True) # Toggle current status
    if db.set_user_status(user_id, new_status): flash(f"User '{target_user_data['username']}' status set to {'Active' if new_status else 'Disabled'}.", 'success')
    else: flash('Failed to update user status.', 'error')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/role/<user_id>', methods=['POST'])
@login_required
@admin_required
def admin_change_user_role(user_id):
    """Admin action to change a user's role."""
    new_role = request.form.get('role')
    if not new_role or new_role not in ['admin', 'user']: flash('Invalid role specified.', 'error'); return redirect(url_for('admin_users'))
    # Prevent admin demoting themselves
    if str(user_id) == session.get('user_id') and new_role == 'user': flash('Cannot demote own account.', 'error'); return redirect(url_for('admin_users'))
    # Optional: Add check here to prevent removing the last admin
    if db.set_user_role(user_id, new_role): flash(f"User role updated successfully.", 'success')
    else: flash('Failed to update user role.', 'error')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/delete/<user_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    """Admin action to delete a user and all their data."""
    # Prevent admin deleting themselves
    if str(user_id) == session.get('user_id'): flash('Cannot delete own account.', 'error'); return redirect(url_for('admin_users'))
    # SECURITY: Consider adding admin password confirmation here
    if db.delete_user_by_id(user_id): flash(f"User and all associated vault entries deleted.", 'success')
    else: flash('Failed to delete user.', 'error')
    return redirect(url_for('admin_users'))

@app.route('/admin/view_vault/<user_id>')
@login_required
@admin_required
def admin_view_user_vault(user_id):
     """Admin page to view METADATA of another user's vault."""
     all_users = db.get_all_users(); target_user = next((u for u in all_users if str(u['_id']) == user_id), None)
     if not target_user: flash('Target user not found.', 'error'); return redirect(url_for('admin_users'))
     entries = db.get_vault_entries_for_user(user_id) # Gets metadata only
     return render_template('quantum_admin_view_vault.html', entries=entries, target_user=target_user)

# --- Vault Routes ---
@app.route('/vault')
@login_required
def vault():
    """Displays the main vault page with user's entries."""
    user_id = session['user_id']; search_term = request.args.get('search_term', '')
    entries = db.get_vault_entries(user_id, search_term=search_term) # Gets own entries
    return render_template('quantum_vault_v3.html', entries=entries, search_term=search_term, is_2fa_enabled=session.get('is_2fa_enabled'), current_username=session.get('username'))

@app.route('/add_entry', methods=['POST'])
@login_required
def add_entry():
    """Handles submission for adding a new vault entry."""
    laptop_server = request.form.get('laptop_server'); brand_label = request.form.get('brand_label')
    entry_username = request.form.get('entry_username'); password = request.form.get('entry_password')
    user_id = session['user_id']; encryption_key = session.get('encryption_key')
    if not laptop_server or not entry_username or not password: flash('Laptop/Server ID, Username, Password required.', 'error')
    elif not encryption_key: flash('Session error: Key missing.', 'error'); session.clear(); return redirect(url_for('login'))
    else:
        try:
            encrypted_password = encryption.encrypt_data(password, encryption_key)
            entry_id = db.add_vault_entry(user_id, laptop_server, brand_label, entry_username, encrypted_password)
            if entry_id: flash('Entry added successfully!', 'success')
            else: flash('Failed to add entry to database.', 'error')
        except Exception as e: flash(f'Error adding entry: {e}', 'error')
    return redirect(url_for('vault'))

# Edit route removed - Now handled by Edit Modal + update_entry route

@app.route('/update_entry/<entry_id>', methods=['POST'])
@login_required
def update_entry(entry_id):
    """Handles submission from the Edit Entry modal."""
    user_id = session['user_id']; encryption_key = session.get('encryption_key')
    if not encryption_key: flash('Session error.', 'error'); session.clear(); return redirect(url_for('login'))
    # Get data from submitted form
    new_laptop_server = request.form.get('laptop_server'); new_brand_label = request.form.get('brand_label')
    new_entry_username = request.form.get('entry_username'); new_plain_password = request.form.get('password') # Password field might be empty

    if not new_laptop_server or not new_entry_username: flash('Laptop/Server ID and Username required.', 'error'); return redirect(url_for('vault')) # Redirect to vault

    # Verify ownership before proceeding
    original_entry_data = db.find_entry_by_id_and_user(entry_id, user_id)
    if not original_entry_data: flash('Permission denied or entry not found.', 'error'); return redirect(url_for('vault'))

    # Handle password update conditionally
    if new_plain_password: # Only encrypt and update if user entered a new password
        try: new_encrypted_password = encryption.encrypt_data(new_plain_password, encryption_key)
        except Exception as e: flash(f'Error encrypting new password: {e}', 'error'); return redirect(url_for('vault'))
    else: # If password field was left blank, reuse the existing encrypted password
        new_encrypted_password = original_entry_data.get('encrypted_password', b'') # Use existing or default to empty bytes

    # Call DB function to update the document
    success = db.update_vault_entry(entry_id, new_laptop_server, new_brand_label, new_entry_username, new_encrypted_password)
    if success: flash('Entry updated successfully!', 'success')
    else: flash('Failed to update entry (or no changes were made).', 'warning') # Use warning if nothing changed
    return redirect(url_for('vault')) # Redirect back to the main vault page

@app.route('/delete_entry/<entry_id>', methods=['POST'])
@login_required
def delete_entry(entry_id):
     """Handles deletion of a vault entry by owner or admin."""
     user_id = session['user_id']; user_role = session.get('role')
     can_delete = False
     # Check if current user owns the entry
     entry_data = db.find_entry_by_id_and_user(entry_id, user_id)
     if entry_data:
         can_delete = True
     # If not owner, check if current user is admin AND if entry exists
     elif user_role == 'admin':
         entry_exists = db.find_entry_by_id(entry_id)
         if entry_exists:
             can_delete = True
         else:
             print(f"Admin {session.get('username')} tried deleting non-existent entry {entry_id}.")

     if can_delete:
         try:
             success = db.delete_vault_entry(entry_id);
             if success:
                 flash('Entry deleted successfully.', 'success')
             else:
                 flash('Failed to delete entry from database.', 'error')
         except Exception as e:
             flash(f'Error occurred during deletion: {e}', 'error')
     else:
         # User is not owner and not admin, or entry doesn't exist
         flash('Cannot delete entry (not found or permission denied).', 'error')
     return redirect(url_for('vault'))

# --- APIs ---
@app.route('/generate_password')
@login_required
def generate_password_api():
    """API: Generates a random password."""
    try: return jsonify({'password': utils.generate_password(16)})
    except Exception as e: print(f"Gen pass error: {e}"); return jsonify({'error': 'Failed'}), 500

@app.route('/get_password/<entry_id>') # For card show/copy
@login_required
def get_password_api(entry_id):
    """API: Gets decrypted password for a specific entry owned by the user."""
    user_id = session['user_id']; encryption_key = session.get('encryption_key')
    if not encryption_key: return jsonify({'error': 'Key missing'}), 401
    try:
        entry_data = db.find_entry_by_id_and_user(entry_id, user_id) # Checks ownership
        if entry_data:
            encrypted_pass = entry_data.get('encrypted_password')
            if encrypted_pass:
                decrypted_pass = encryption.decrypt_data(encrypted_pass, encryption_key)
                if decrypted_pass is not None: return jsonify({'password': decrypted_pass})
                else: return jsonify({'error': 'Decryption failed'}), 500 # Internal error if decrypt fails
            else: return jsonify({'password': ''}) # No password stored
        else: return jsonify({'error': 'Not found/denied'}), 404 # Not found or not owner
    except Exception as e: print(f"Get pass error for entry '{entry_id}': {e}"); return jsonify({'error': 'Internal error'}), 500

@app.route('/get_entry_details/<entry_id>') # For edit modal
@login_required
def get_entry_details_api(entry_id):
    """API: Gets all relevant entry details (including decrypted password) for editing."""
    user_id = session['user_id']; encryption_key = session.get('encryption_key')
    if not encryption_key: return jsonify({'error': 'Key missing'}), 401
    try:
        entry_data = db.find_entry_by_id_and_user(entry_id, user_id); # Checks ownership
        if not entry_data: return jsonify({'error': 'Not found/denied'}), 404
        decrypted_password = ""; encrypted_pass = entry_data.get('encrypted_password')
        if encrypted_pass:
            decrypted_password = encryption.decrypt_data(encrypted_pass, encryption_key)
            if decrypted_password is None: decrypted_password = "" # Return empty string on decrypt fail for form
        details = {
            'laptop_server': entry_data.get('laptop_server', ''),
            'brand_label': entry_data.get('brand_label', ''),
            'entry_username': entry_data.get('entry_username', ''),
            'password': decrypted_password # Decrypted password or ""
        }
        return jsonify(details)
    except Exception as e: print(f"Get entry details error for entry '{entry_id}': {e}"); return jsonify({'error': 'Internal error'}), 500

# --- Main Execution ---
if __name__ == '__main__':
    try:
        print("Attempting initial database connection check...")
        db_conn_check = db.connect_db()
        if db_conn_check is not None:
            print("Initial connection successful. Checking indexes...")
            db.ensure_indexes(); db.close_db() # Ensure indexes then close initial connection
            print("Database connection checked and indexes ensured.")
        else: raise ConnectionError("DB check returned None.")
    except Exception as e: print(f"\nCRITICAL: DB setup failed: {e}\n"); import sys; sys.exit(1)
    print("Starting Flask dev server (Debug Mode)...");
    app.run(host='0.0.0.0', port=5000, debug=True) # debug=True is ONLY for development!
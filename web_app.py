# web_app.py
import os
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify)
from functools import wraps
import config
import db
import encryption
import utils
import pyotp # <--- Add TOTP library import

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
if not app.secret_key:
     raise ValueError("FLASK_SECRET_KEY is not set")

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.close_db()

# --- Decorator for Login Required ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check base login
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))

        # Check if 2FA verification is pending OR required but not passed
        if session.get('2fa_required') and not session.get('2fa_passed'):
             # Check if we are already going to the 2FA page to avoid redirect loop
             if request.endpoint != 'login_2fa':
                 flash('Two-factor authentication is required.', 'warning')
                 return redirect(url_for('login_2fa'))

        # Check if essential encryption info is present *after* potential 2FA pass
        # (Encryption key is set only after FULL login including 2FA if needed)
        if not session.get('2fa_required') and ('encryption_key' not in session or 'user_salt' not in session):
             # This case happens if user logged in WITHOUT 2FA but key is missing
             flash('Session error: Encryption info missing. Please log in again.', 'error')
             session.clear()
             return redirect(url_for('login'))

        # Allow access if basic login is done AND (2FA not required OR 2FA passed)
        return f(*args, **kwargs)
    return decorated_function

# --- Standard Routes (Index, Logout - unchanged) ---
@app.route('/')
def index():
    if 'user_id' in session: return redirect(url_for('vault'))
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# --- Authentication Routes ---

# MODIFIED: Login Stage 1 (Password Check)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session and not session.get('2fa_required'):
         return redirect(url_for('vault')) # Already fully logged in

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password') # Get password submitted here

        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('login.html')

        user_data = db.find_user(username) # Fetches 2FA fields too

        if user_data and encryption.verify_master_password(user_data['password_hash'], password):
            # Password is Correct! Now check 2FA status

            # Store basic info needed for next step or final login
            session['_2fa_user_id'] = str(user_data['_id']) # Temp store ID for 2FA step
            session['_2fa_username'] = user_data['username'] # Temp store username
            session['_2fa_salt'] = user_data['salt'] # Temp store salt

            if user_data.get('is_2fa_enabled'):
                # 2FA is enabled, redirect to 2FA verification page
                session['2fa_required'] = True
                session.pop('_2fa_passed', None) # Ensure previous pass state is cleared
                print(f"User {username} passed password, requires 2FA.") # Debugging
                return redirect(url_for('login_2fa'))
            else:
                # 2FA is NOT enabled, proceed with full login directly
                print(f"User {username} passed password, 2FA not enabled.") # Debugging
                try:
                    # Derive key using the password submitted in THIS request
                    key = encryption.derive_key(password, user_data['salt'])
                    # Set final session variables
                    session['user_id'] = session.pop('_2fa_user_id')
                    session['username'] = session.pop('_2fa_username')
                    session['salt'] = session.pop('_2fa_salt')
                    session['encryption_key'] = key
                    session['is_2fa_enabled'] = False # Store status for UI
                    session.pop('2fa_required', None)
                    session.pop('_2fa_passed', None)

                    flash('Login successful!', 'success')
                    return redirect(url_for('vault'))
                except Exception as e:
                     flash(f'Failed to derive encryption key during login: {e}', 'error')
                     session.clear() # Clear potentially inconsistent session
                     return render_template('login.html')
        else:
            # Invalid username or password
            flash('Invalid username or password.', 'error')
            session.clear() # Clear any temporary session data on failure

    # Clear temporary 2FA data if just visiting the login page
    session.pop('_2fa_user_id', None)
    session.pop('_2fa_username', None)
    session.pop('_2fa_salt', None)
    session.pop('2fa_required', None)
    session.pop('_2fa_passed', None)
    return render_template('login.html')

# NEW: Login Stage 2 (2FA Verification)
@app.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    # Ensure user passed password check first
    if '_2fa_user_id' not in session:
        flash('Please enter your username and password first.', 'warning')
        return redirect(url_for('login'))

    user_id = session['_2fa_user_id'] # Get user ID from temporary session store

    if request.method == 'POST':
        password = request.form.get('password') # Get password AGAIN
        totp_code = request.form.get('totp_code')

        if not password or not totp_code:
             flash('Password and authenticator code are required.', 'error')
             return render_template('login_2fa.html')

        # Fetch full user data again using the stored ID
        # We need hash, salt, and TOTP secret
        user_data = db.find_user(session['_2fa_username']) # Find by username stored temporarily
        if not user_data or str(user_data['_id']) != user_id:
             # Should not happen if session is consistent, but check
             flash('User validation error. Please try logging in again.', 'error')
             session.clear()
             return redirect(url_for('login'))

        # 1. Verify password AGAIN
        if not encryption.verify_master_password(user_data['password_hash'], password):
             flash('Invalid password provided.', 'error')
             # DO NOT clear _2fa_user_id here, let them retry the 2FA page
             return render_template('login_2fa.html')

        # 2. Verify TOTP code
        totp_secret = user_data.get('totp_secret')
        if not totp_secret:
            flash('2FA secret not found for user. Please contact support or disable 2FA.', 'error')
            session.clear() # Clear session as state is inconsistent
            return redirect(url_for('login'))

        totp = pyotp.TOTP(totp_secret)
        # Verify the code, allowing for a 1-step window (30-60 seconds) for clock drift
        if not totp.verify(totp_code, valid_window=1):
            flash('Invalid authenticator code.', 'error')
            # DO NOT clear _2fa_user_id here, let them retry the 2FA page
            return render_template('login_2fa.html')

        # --- BOTH Password and TOTP are verified ---
        print(f"User {session['_2fa_username']} passed 2FA.") # Debugging
        try:
            # Derive encryption key using the password submitted in THIS request
            key = encryption.derive_key(password, user_data['salt'])

            # Set final session variables
            session['user_id'] = session.pop('_2fa_user_id')
            session['username'] = session.pop('_2fa_username')
            session['salt'] = session.pop('_2fa_salt')
            session['encryption_key'] = key
            session['is_2fa_enabled'] = True # Store status for UI
            session.pop('2fa_required', None) # Clean up temp flags
            session['2fa_passed'] = True # Mark 2FA as passed for this session

            flash('Login successful!', 'success')
            return redirect(url_for('vault')) # Redirect to vault

        except Exception as e:
             flash(f'Failed to derive encryption key after 2FA: {e}', 'error')
             session.clear() # Clear session on final step failure
             return redirect(url_for('login'))

    # Render the 2FA form for GET request
    return render_template('login_2fa.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # ... (Signup logic remains the same - adds user with 2FA disabled by default) ...
    if 'user_id' in session: return redirect(url_for('vault'))
    if request.method == 'POST':
        username = request.form.get('username'); password = request.form.get('password'); confirm_password = request.form.get('confirm_password')
        error = None
        if not username or not password or not confirm_password: error = 'All fields are required.'
        elif password != confirm_password: error = 'Passwords do not match.'
        elif len(password) < 8: error = 'Password must be at least 8 characters.'
        elif db.find_user(username): error = 'Username already exists.'
        if error: flash(error, 'error')
        else:
            try:
                salt = encryption.generate_salt(); hashed_password = encryption.hash_master_password(password, salt)
                user_id = db.add_user(username, hashed_password, salt) # Adds user with 2FA disabled
                if user_id:
                    flash('Account created successfully! Please log in.', 'success')
                    try: db.ensure_indexes()
                    except Exception as idx_e: print(f"Warning: Signup index error: {idx_e}")
                    return redirect(url_for('login'))
                else: flash('Failed to create account.', 'error')
            except Exception as e: flash(f'Signup error: {e}', 'error')
    return render_template('signup.html')

# --- 2FA Management Routes ---

# NEW: Route to setup 2FA
@app.route('/setup_2fa', methods=['GET', 'POST'])
@login_required # Must be logged in to set up 2FA
def setup_2fa():
    user_id = session['user_id']
    username = session['username']

    if request.method == 'POST':
        # Verify the code entered by the user against the secret we generated
        secret_key = request.form.get('secret_key') # Get secret from hidden form field
        totp_code = request.form.get('totp_code')

        if not secret_key or not totp_code:
             flash('Verification code and secret key are required.', 'error')
             # Need to regenerate and show page again if secret is missing
             return redirect(url_for('setup_2fa')) # Simplest is redirect back to GET

        totp = pyotp.TOTP(secret_key)
        if totp.verify(totp_code, valid_window=1):
            # Code is valid, save the secret and enable 2FA in DB
            if db.set_user_2fa_secret(user_id, secret_key) and \
               db.enable_user_2fa(user_id, enable=True):
                flash('Two-factor authentication enabled successfully!', 'success')
                session['is_2fa_enabled'] = True # Update session status
                return redirect(url_for('vault'))
            else:
                flash('Failed to save 2FA settings in database.', 'error')
                # Stay on setup page, user might need to retry verification
        else:
            flash('Invalid verification code. Please try again.', 'error')
            # Re-render the setup page WITH THE SAME secret and QR code
            # We need to generate these again if we redirect, so let's pass them back
            provisioning_uri = pyotp.totp.TOTP(secret_key).provisioning_uri(
                name=username, issuer_name=config.TOTP_ISSUER_NAME
            )
            qr_code_data = utils.generate_qr_code_base64(provisioning_uri)
            return render_template('setup_2fa.html', secret_key=secret_key, qr_code_data=qr_code_data)

    # --- GET Request Logic ---
    # Generate a new secret for the user
    secret_key = pyotp.random_base32()

    # Generate provisioning URI for authenticator app
    # Format: otpauth://totp/Issuer:Username?secret=SECRETKEY&issuer=Issuer
    provisioning_uri = pyotp.totp.TOTP(secret_key).provisioning_uri(
        name=username, issuer_name=config.TOTP_ISSUER_NAME
    )

    # Generate QR code image data (base64 PNG)
    qr_code_data = utils.generate_qr_code_base64(provisioning_uri)

    if not qr_code_data:
        flash('Error generating QR code for 2FA setup.', 'error')
        # Handle error appropriately, maybe redirect back or show error message

    # Render the setup page, passing the secret and QR data
    return render_template('setup_2fa.html', secret_key=secret_key, qr_code_data=qr_code_data)


# NEW: Route to disable 2FA
@app.route('/disable_2fa', methods=['POST'])
@login_required
def disable_2fa():
    user_id = session['user_id']

    # SECURITY NOTE: Add password or current TOTP verification here for real app
    # For simplicity now, we just disable directly.

    if db.disable_user_2fa(user_id):
        flash('Two-factor authentication disabled.', 'success')
        session['is_2fa_enabled'] = False # Update session status
    else:
        flash('Failed to disable two-factor authentication.', 'error')

    return redirect(url_for('vault'))


# --- Vault and API Routes (Unchanged from last provided version) ---

@app.route('/vault')
@login_required
def vault():
    # ... (Vault display logic with search as before) ...
    user_id = session['user_id']; search_term = request.args.get('search_term', '')
    entries = db.get_vault_entries(user_id, search_term=search_term)
    # Pass 2FA status from session to template for display
    return render_template('vault.html', entries=entries, search_term=search_term, is_2fa_enabled=session.get('is_2fa_enabled'))


@app.route('/add_entry', methods=['POST'])
@login_required
def add_entry():
    # ... (Add entry logic as before) ...
    laptop_server = request.form.get('laptop_server'); entry_username = request.form.get('entry_username'); password = request.form.get('entry_password')
    user_id = session['user_id']; encryption_key = session.get('encryption_key')
    if not laptop_server or not entry_username or not password: flash('Laptop/Server ID, Username, and Password are required.', 'error')
    elif not encryption_key: flash('Session error: Encryption key missing.', 'error'); session.clear(); return redirect(url_for('login'))
    else:
        try:
            encrypted_password = encryption.encrypt_data(password, encryption_key)
            entry_id = db.add_vault_entry(user_id, laptop_server, entry_username, encrypted_password)
            if entry_id: flash('Entry added successfully!', 'success')
            else: flash('Failed to add entry.', 'error')
        except Exception as e: flash(f'Error adding entry: {e}', 'error')
    return redirect(url_for('vault'))

@app.route('/delete_entry/<entry_id>', methods=['POST'])
@login_required
def delete_entry(entry_id):
    # ... (Delete entry logic as before) ...
     user_id = session['user_id']; entry_data = db.find_entry_by_id_and_user(entry_id, user_id)
     if entry_data:
         try:
             success = db.delete_vault_entry(entry_id)
             if success: flash('Entry deleted.', 'success')
             else: flash('Failed to delete entry.', 'error')
         except Exception as e: flash(f'Error deleting: {e}', 'error')
     else: flash('Cannot delete entry (not found or permission denied).', 'error')
     return redirect(url_for('vault'))

@app.route('/generate_password')
@login_required
def generate_password_api():
    # ... (Generate password API as before) ...
    try: return jsonify({'password': utils.generate_password(16)})
    except Exception as e: print(f"Error generating password: {e}"); return jsonify({'error': 'Failed to generate'}), 500

@app.route('/get_password/<entry_id>')
@login_required
def get_password_api(entry_id):
    # ... (Get/decrypt password API as before) ...
    user_id = session['user_id']; encryption_key = session.get('encryption_key')
    if not encryption_key: return jsonify({'error': 'Encryption key missing'}), 401
    try:
        entry_data = db.find_entry_by_id_and_user(entry_id, user_id)
        if entry_data:
             encrypted_pass = entry_data.get('encrypted_password')
             if encrypted_pass:
                 decrypted_pass = encryption.decrypt_data(encrypted_pass, encryption_key)
                 if decrypted_pass is not None: return jsonify({'password': decrypted_pass})
                 else: return jsonify({'error': 'Decryption failed'}), 500
             else: return jsonify({'password': ''})
        else: return jsonify({'error': 'Entry not found/access denied'}), 404
    except Exception as e: print(f"Error get_password_api: {e}"); return jsonify({'error': 'Internal error'}), 500


# --- Main Execution Block (with corrected DB check) ---
if __name__ == '__main__':
    try:
        print("Attempting initial database connection check...")
        db_conn_check = db.connect_db() # Test connection
        if db_conn_check is not None: # CORRECTED CHECK
            print("Initial connection successful. Checking indexes...")
            db.ensure_indexes()
            db.close_db()
            print("Database connection checked and indexes ensured.")
        else:
             raise ConnectionError("DB check failed (connect_db returned None).")
    except Exception as e:
        print(f"\n{'*'*20}\nCRITICAL: DB setup failed: {e}\n{'*'*20}\n"); import sys; sys.exit(1)

    print("Starting Flask development server (Debug Mode)...")
    app.run(host='0.0.0.0', port=5000, debug=True) # Debug=True for development ONLY
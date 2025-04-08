# web_app.py
import os
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify)
from functools import wraps
import config # Your config file (reads .env)
import db     # Your db interaction file
import encryption # Your encryption file
import utils    # Your utils file (for password generation)
import pyotp # For 2FA

# Initialize Flask App
app = Flask(__name__)
# Load Secret Key from config (which reads from .env)
app.secret_key = config.SECRET_KEY
if not app.secret_key:
     # Ensure the app doesn't run without a secret key
     raise ValueError("FLASK_SECRET_KEY is not set in config or environment variables!")

# Close DB connection when app context tears down
@app.teardown_appcontext
def shutdown_session(exception=None):
    db.close_db()

# --- Decorator for Login Required Routes ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check base login
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        # Check if 2FA verification is pending OR required but not passed
        if session.get('2fa_required') and not session.get('2fa_passed'):
             if request.endpoint != 'login_2fa':
                 flash('Two-factor authentication is required.', 'warning')
                 return redirect(url_for('login_2fa'))
        return f(*args, **kwargs)
    return decorated_function

# --- Standard Routes ---
@app.route('/')
def index():
    """Redirects to vault if logged in, otherwise to login page."""
    if 'user_id' in session:
        return redirect(url_for('vault'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login (Stage 1: Password Check)."""
    if 'user_id' in session and not session.get('2fa_required'):
         return redirect(url_for('vault')) # Already fully logged in

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('login.html')

        user_data = db.find_user(username) # Fetches 2FA fields too

        if user_data and encryption.verify_master_password(user_data['password_hash'], password):
            # Password is Correct! Store temp info and check 2FA status
            session['_2fa_user_id'] = str(user_data['_id'])
            session['_2fa_username'] = user_data['username']
            session['_2fa_salt'] = user_data['salt']

            if user_data.get('is_2fa_enabled'):
                # 2FA enabled -> Go to 2FA step
                session['2fa_required'] = True
                session.pop('_2fa_passed', None)
                return redirect(url_for('login_2fa'))
            else:
                # 2FA not enabled -> Complete login now
                try:
                    key = encryption.derive_key(password, user_data['salt'])
                    # Set final session variables
                    session['user_id'] = session.pop('_2fa_user_id')
                    session['username'] = session.pop('_2fa_username')
                    session['salt'] = session.pop('_2fa_salt')
                    session['encryption_key'] = key
                    session['is_2fa_enabled'] = False
                    session.pop('2fa_required', None)
                    session.pop('_2fa_passed', None)
                    flash('Login successful!', 'success')
                    return redirect(url_for('vault'))
                except Exception as e:
                     print(f"DEBUG: ERROR during key derivation or final session set (no 2FA): {e}")
                     import traceback; traceback.print_exc()
                     flash(f'Failed to process login: {e}', 'error')
                     session.clear()
                     return render_template('login.html')
        else:
            # Invalid username or password
            flash('Invalid username or password.', 'error')
            session.clear()

    # GET request or failed POST
    session.pop('_2fa_user_id', None); session.pop('_2fa_username', None); session.pop('_2fa_salt', None)
    session.pop('2fa_required', None); session.pop('_2fa_passed', None)
    return render_template('login.html')

@app.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    """Handles user login (Stage 2: 2FA Verification)."""
    if '_2fa_user_id' not in session:
        flash('Please enter your username and password first.', 'warning')
        return redirect(url_for('login'))

    user_id = session['_2fa_user_id']

    if request.method == 'POST':
        password = request.form.get('password') # Password submitted AGAIN
        totp_code = request.form.get('totp_code') # TOTP code submitted

        if not password or not totp_code:
             flash('Password and authenticator code are required.', 'error')
             return render_template('login_2fa.html')

        # Fetch full user data again
        user_data = db.find_user(session['_2fa_username'])
        if not user_data or str(user_data['_id']) != user_id:
             flash('User validation error. Please try logging in again.', 'error')
             session.clear(); return redirect(url_for('login'))

        # 1. Verify password AGAIN
        if not encryption.verify_master_password(user_data['password_hash'], password):
             flash('Invalid password provided.', 'error')
             return render_template('login_2fa.html')

        # 2. Verify TOTP code
        totp_secret = user_data.get('totp_secret')
        if not totp_secret:
            flash('2FA secret not found for user. Cannot verify.', 'error')
            session.clear(); return redirect(url_for('login'))

        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(totp_code, valid_window=1):
            flash('Invalid authenticator code.', 'error')
            return render_template('login_2fa.html')

        # --- BOTH Password and TOTP verified ---
        try:
            # Derive encryption key
            key = encryption.derive_key(password, user_data['salt'])

            # Set final session variables, clear temporary ones
            session['user_id'] = session.pop('_2fa_user_id')
            session['username'] = session.pop('_2fa_username')
            session['salt'] = session.pop('_2fa_salt')
            session['encryption_key'] = key
            session['is_2fa_enabled'] = True
            session.pop('2fa_required', None)
            session['2fa_passed'] = True

            flash('Login successful!', 'success')
            return redirect(url_for('vault'))

        except Exception as e:
             print(f"DEBUG: ERROR during key derivation or final session set AFTER 2FA: {e}")
             import traceback; traceback.print_exc()
             flash(f'Failed to process login after 2FA: {e}', 'error')
             session.clear()
             return redirect(url_for('login'))

    # Render the 2FA form for GET request
    return render_template('login_2fa.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handles new user registration."""
    if 'user_id' in session: return redirect(url_for('vault'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        error = None
        if not username or not password or not confirm_password: error = 'All fields required.'
        elif password != confirm_password: error = 'Passwords do not match.'
        elif len(password) < 8: error = 'Password must be at least 8 characters.'
        elif db.find_user(username): error = 'Username already exists.'

        if error:
            flash(error, 'error')
        else:
            # Proceed with creating the user
            try:
                salt = encryption.generate_salt()
                hashed_password = encryption.hash_master_password(password, salt)
                # add_user initializes 2FA fields to None/False
                user_id = db.add_user(username, hashed_password, salt)

                # Check if user was added successfully
                if user_id:
                    flash('Account created! Please log in.', 'success')
                    # Ensure indexes with proper try-except block
                    try:
                        # print("DEBUG: Ensuring indexes after signup...") # Optional
                        db.ensure_indexes()
                    except Exception as idx_e:
                        print(f"Warning: Could not ensure indexes after signup for user {username}: {idx_e}")
                    # Redirect to login after successful signup
                    return redirect(url_for('login'))
                else:
                    # db.add_user returned None (likely DuplicateKey, though checked above)
                    flash('Failed to create account. Please try again.', 'error')
            except Exception as e:
                 # Catch any other unexpected errors during signup
                 print(f"Signup Error: {e}")
                 import traceback; traceback.print_exc()
                 flash(f'An error occurred during signup processing: {e}', 'error')

    # Render signup page template for GET requests or failed POSTs
    return render_template('signup.html')

@app.route('/logout')
def logout():
    """Logs the user out by clearing the session."""
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# --- 2FA Management Routes ---
@app.route('/setup_2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    """Handles setup and verification of 2FA."""
    user_id = session['user_id']
    username = session['username']

    if request.method == 'POST':
        secret_key = request.form.get('secret_key')
        totp_code = request.form.get('totp_code')

        if not secret_key or not totp_code:
             flash('Verification code and secret key required for validation.', 'error')
             return redirect(url_for('setup_2fa'))

        totp = pyotp.TOTP(secret_key)
        if totp.verify(totp_code, valid_window=1):
            # Code valid: Save secret and enable flag
            if db.set_user_2fa_secret(user_id, secret_key) and \
               db.enable_user_2fa(user_id, enable=True):
                flash('Two-factor authentication enabled successfully!', 'success')
                session['is_2fa_enabled'] = True # Update session
                return redirect(url_for('vault'))
            else:
                flash('Failed to save 2FA settings in database.', 'error')
                return redirect(url_for('setup_2fa'))
        else:
            # Invalid code
            flash('Invalid verification code. Please try again.', 'error')
            # Re-render setup page with the SAME secret/QR
            provisioning_uri = pyotp.totp.TOTP(secret_key).provisioning_uri(
                name=username, issuer_name=config.TOTP_ISSUER_NAME
            )
            qr_code_data = utils.generate_qr_code_base64(provisioning_uri)
            if not qr_code_data:
                flash('Error re-generating QR code.', 'error')
                return redirect(url_for('vault'))
            return render_template('setup_2fa.html', secret_key=secret_key, qr_code_data=qr_code_data)

    # --- GET Request Logic ---
    secret_key = pyotp.random_base32()
    provisioning_uri = pyotp.totp.TOTP(secret_key).provisioning_uri(
        name=username, issuer_name=config.TOTP_ISSUER_NAME
    )
    qr_code_data = utils.generate_qr_code_base64(provisioning_uri)
    if not qr_code_data:
        flash('Error generating QR code for 2FA setup.', 'error')
        return redirect(url_for('vault'))
    return render_template('setup_2fa.html', secret_key=secret_key, qr_code_data=qr_code_data)

@app.route('/disable_2fa', methods=['POST'])
@login_required
def disable_2fa():
    """Handles disabling 2FA for the logged-in user."""
    user_id = session['user_id']
    # SECURITY: Add password/TOTP check here in a real application
    if db.disable_user_2fa(user_id): # Clears secret and sets flag to False
        flash('Two-factor authentication disabled.', 'success')
        session['is_2fa_enabled'] = False # Update session
    else:
        flash('Failed to disable 2FA in database.', 'error')
    return redirect(url_for('vault'))

# --- Vault and API Routes ---
@app.route('/vault')
@login_required
def vault():
    """Displays the user's vault entries, handles search."""
    user_id = session['user_id']
    search_term = request.args.get('search_term', '')
    entries = db.get_vault_entries(user_id, search_term=search_term)
    return render_template('vault.html', entries=entries, search_term=search_term, is_2fa_enabled=session.get('is_2fa_enabled'))

@app.route('/add_entry', methods=['POST'])
@login_required
def add_entry():
    """Handles adding a new entry to the vault including brand/label."""
    laptop_server = request.form.get('laptop_server')
    brand_label = request.form.get('brand_label') # Get new field
    entry_username = request.form.get('entry_username')
    password = request.form.get('entry_password')
    user_id = session['user_id']
    encryption_key = session.get('encryption_key')

    if not laptop_server or not entry_username or not password: # brand_label optional
        flash('Laptop/Server ID, Username, and Password are required.', 'error')
    elif not encryption_key:
         flash('Session error: Encryption key missing.', 'error'); session.clear(); return redirect(url_for('login'))
    else:
        try:
            encrypted_password = encryption.encrypt_data(password, encryption_key)
            # Pass brand_label to db function
            entry_id = db.add_vault_entry(user_id, laptop_server, brand_label, entry_username, encrypted_password)
            if entry_id: flash('Entry added successfully!', 'success')
            else: flash('Failed to add entry to database.', 'error')
        except Exception as e:
            flash(f'Error adding entry: {e}', 'error')
    return redirect(url_for('vault'))

@app.route('/delete_entry/<entry_id>', methods=['POST'])
@login_required
def delete_entry(entry_id):
    """Handles deleting a specific vault entry after ownership check."""
    user_id = session['user_id']
    entry_data = db.find_entry_by_id_and_user(entry_id, user_id) # Verify ownership
    if entry_data:
        try:
            success = db.delete_vault_entry(entry_id)
            if success: flash('Entry deleted.', 'success')
            else: flash('Failed to delete.', 'error')
        except Exception as e: flash(f'Error deleting: {e}', 'error')
    else:
         flash('Cannot delete (not found/permission denied).', 'error')
    return redirect(url_for('vault'))

@app.route('/generate_password')
@login_required
def generate_password_api():
    """API endpoint to generate a random password."""
    try:
        password = utils.generate_password(16)
        return jsonify({'password': password})
    except Exception as e:
        print(f"Gen pass error: {e}"); return jsonify({'error': 'Failed'}), 500

@app.route('/get_password/<entry_id>')
@login_required
def get_password_api(entry_id):
    """API endpoint to securely retrieve and decrypt a password."""
    user_id = session['user_id']
    encryption_key = session.get('encryption_key')

    if not encryption_key:
        return jsonify({'error': 'Encryption key missing from session'}), 401

    try:
        # Find the specific entry AND verify ownership
        entry_data = db.find_entry_by_id_and_user(entry_id, user_id)
        if entry_data:
             encrypted_pass = entry_data.get('encrypted_password')
             if encrypted_pass:
                 decrypted_pass = encryption.decrypt_data(encrypted_pass, encryption_key)
                 if decrypted_pass is not None: return jsonify({'password': decrypted_pass})
                 else: return jsonify({'error': 'Decryption failed'}), 500
             else: return jsonify({'password': ''}) # No password stored
        else: return jsonify({'error': 'Entry not found or access denied'}), 404
    except Exception as e:
        print(f"Get pass error for entry '{entry_id}': {e}"); return jsonify({'error': 'Internal error'}), 500

# --- Main Execution Block (with corrected DB check) ---
if __name__ == '__main__':
    try:
        print("Attempting initial database connection check...")
        db_conn_check = db.connect_db() # Test connection
        # CORRECTED CHECK: Explicitly compare with None
        if db_conn_check is not None:
            print("Initial connection successful. Checking indexes...")
            db.ensure_indexes() # Ensure indexes on startup
            db.close_db() # Close initial connection, Flask manages per-request
            print("Database connection checked and indexes ensured.")
        else:
             raise ConnectionError("Failed to get DB connection during startup check (connect_db returned None).")
    except Exception as e:
        print(f"\n{'*'*20}\nCRITICAL: Could not connect/setup database on startup: {e}\n{'*'*20}\n")
        import sys
        sys.exit(1) # Exit if DB connection/setup fails

    print("Starting Flask development server (Debug Mode)...")
    # Use host='0.0.0.0' for network access. debug=True for development ONLY.
    app.run(host='0.0.0.0', port=5000, debug=True)
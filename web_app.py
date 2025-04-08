# web_app.py #collaborative
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
             # Check if we are already going to the 2FA page to avoid redirect loop
             if request.endpoint != 'login_2fa':
                 flash('Two-factor authentication is required.', 'warning')
                 return redirect(url_for('login_2fa'))

        # Check if essential encryption info is present *after* potential 2FA pass
        # (Encryption key is set only after FULL login including 2FA if needed)
        # This check needs refinement - if 2FA passed, key might not be set yet if coming FROM login_2fa
        # Let's rely on vault route to require the key specifically if needed,
        # and other routes might not need it immediately after 2FA pass.
        # Commenting out this specific check for now as it might be too strict right after 2FA pass
        # if not session.get('2fa_required') and ('encryption_key' not in session or 'salt' not in session):
        #      flash('Session error: Encryption info missing. Please log in again.', 'error')
        #      session.clear()
        #      return redirect(url_for('login'))

        # Allow access if basic login is done AND (2FA not required OR 2FA passed)
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
    # If user is already fully logged in (not just passed stage 1), redirect to vault
    if 'user_id' in session and not session.get('2fa_required'):
         return redirect(url_for('vault'))

    # Handle form submission
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password') # Get password submitted here

        # Basic validation
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('login.html')

        # Find user in database (fetches 2FA fields too)
        user_data = db.find_user(username)

        # Verify password and user existence
        if user_data and encryption.verify_master_password(user_data['password_hash'], password):
            # --- DEBUG ---
            print("DEBUG: Password verified successfully!")
            # --- END DEBUG ---

            # Password is Correct! Now check 2FA status
            # Store basic info needed for next step or final login
            session['_2fa_user_id'] = str(user_data['_id']) # Temp store ID for 2FA step
            session['_2fa_username'] = user_data['username'] # Temp store username
            session['_2fa_salt'] = user_data['salt'] # Temp store salt
            # --- DEBUG ---
            print(f"DEBUG: Temp session data set for user: {session['_2fa_username']}")
            # --- END DEBUG ---


            if user_data.get('is_2fa_enabled'):
                # 2FA is enabled, redirect to 2FA verification page
                session['2fa_required'] = True
                session.pop('_2fa_passed', None) # Ensure previous pass state is cleared
                # --- DEBUG ---
                print("DEBUG: 2FA is enabled, redirecting to login_2fa...")
                # --- END DEBUG ---
                return redirect(url_for('login_2fa'))
            else:
                # 2FA is NOT enabled, proceed with full login directly
                # --- DEBUG ---
                print("DEBUG: 2FA not enabled, attempting final login steps...")
                # --- END DEBUG ---
                try:
                    # Derive key using the password submitted in THIS request
                    # --- DEBUG ---
                    print("DEBUG: Deriving encryption key...")
                    # --- END DEBUG ---
                    key = encryption.derive_key(password, user_data['salt'])
                    # --- DEBUG ---
                    print("DEBUG: Key derived successfully.")
                    # --- END DEBUG ---

                    # Set final session variables
                    session['user_id'] = session.pop('_2fa_user_id')
                    session['username'] = session.pop('_2fa_username')
                    session['salt'] = session.pop('_2fa_salt') # Use 'salt' now, not '_2fa_salt'
                    session['encryption_key'] = key
                    session['is_2fa_enabled'] = False # Store status for UI
                    session.pop('2fa_required', None) # Clean up flags
                    session.pop('_2fa_passed', None)
                    # --- DEBUG ---
                    print(f"DEBUG: Final session set: user_id={session.get('user_id')}, key_present={session.get('encryption_key') is not None}, 2fa_enabled={session.get('is_2fa_enabled')}")
                    # --- END DEBUG ---

                    flash('Login successful!', 'success')
                    return redirect(url_for('vault')) # Redirect to the main vault page
                except Exception as e:
                     # --- DEBUG ---
                     # See if an error happens here!
                     print(f"DEBUG: ERROR during key derivation or final session set: {e}")
                     import traceback
                     traceback.print_exc() # Print full traceback
                     # --- END DEBUG ---
                     flash(f'Failed to derive encryption key during login: {e}', 'error')
                     session.clear() # Clear potentially inconsistent session
                     return render_template('login.html')
        else:
            # Invalid username or password
            # --- DEBUG ---
            if user_data:
                 print(f"DEBUG: Password verification failed for user: {username}")
            else:
                 print(f"DEBUG: User not found: {username}")
            # --- END DEBUG ---
            flash('Invalid username or password.', 'error')
            session.clear() # Clear any temporary session data on failure

    # --- GET Request Handling ---
    # Clear temporary 2FA data if just visiting the login page via GET
    # Prevents accessing /login/2fa directly after failed attempts elsewhere
    session.pop('_2fa_user_id', None)
    session.pop('_2fa_username', None)
    session.pop('_2fa_salt', None)
    session.pop('2fa_required', None)
    session.pop('_2fa_passed', None)
    # Render login page template for GET requests or failed POSTs
    return render_template('login.html')

@app.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    """Handles user login (Stage 2: 2FA Verification)."""
    # Ensure user passed password check first by checking temp session var
    if '_2fa_user_id' not in session:
        flash('Please enter your username and password first.', 'warning')
        return redirect(url_for('login'))

    user_id = session['_2fa_user_id'] # Get user ID from temporary session store

    # Handle form submission
    if request.method == 'POST':
        password = request.form.get('password') # Get password AGAIN
        totp_code = request.form.get('totp_code')

        # Basic validation
        if not password or not totp_code:
             flash('Password and authenticator code are required.', 'error')
             return render_template('login_2fa.html')

        # Fetch full user data again using the stored ID/username
        # Need hash, salt, and TOTP secret
        # Use username as it's less likely to change and avoids ObjectId issues if temp ID format was wrong
        user_data = db.find_user(session['_2fa_username'])
        if not user_data or str(user_data['_id']) != user_id:
             # Consistency check
             flash('User validation error. Please try logging in again.', 'error')
             session.clear()
             return redirect(url_for('login'))

        # --- Verification Steps ---
        # 1. Verify password AGAIN (against stored hash)
        if not encryption.verify_master_password(user_data['password_hash'], password):
             flash('Invalid password provided.', 'error')
             # DO NOT clear _2fa_user_id here, let them retry the 2FA page
             return render_template('login_2fa.html')

        # 2. Verify TOTP code (against stored secret)
        totp_secret = user_data.get('totp_secret')
        if not totp_secret:
            flash('2FA secret not found for user. Cannot verify code.', 'error')
            # Maybe redirect to setup? For now, clear session and send to login.
            session.clear()
            return redirect(url_for('login'))

        # Use pyotp to verify
        totp = pyotp.TOTP(totp_secret)
        # Verify the code, allowing for a 1-step window (30-60 seconds) for clock drift
        if not totp.verify(totp_code, valid_window=1):
            flash('Invalid authenticator code.', 'error')
            # DO NOT clear _2fa_user_id here, let them retry the 2FA page
            return render_template('login_2fa.html')

        # --- BOTH Password and TOTP are verified ---
        print(f"DEBUG: User {session['_2fa_username']} passed 2FA.") # Debugging
        try:
            # Derive encryption key using the password submitted in THIS request
            key = encryption.derive_key(password, user_data['salt'])

            # Set final session variables, clearing temporary ones
            session['user_id'] = session.pop('_2fa_user_id')
            session['username'] = session.pop('_2fa_username')
            session['salt'] = session.pop('_2fa_salt') # Use 'salt' now
            session['encryption_key'] = key
            session['is_2fa_enabled'] = True # Store status for UI
            session.pop('2fa_required', None) # Clean up temp flags
            session['2fa_passed'] = True # Mark 2FA as passed for this session

            flash('Login successful!', 'success')
            return redirect(url_for('vault')) # Redirect to vault

        except Exception as e:
             print(f"DEBUG: ERROR during key derivation or final session set AFTER 2FA: {e}") # Debugging
             import traceback
             traceback.print_exc() # Print full traceback
             flash(f'Failed to derive encryption key after 2FA: {e}', 'error')
             session.clear() # Clear session on final step failure
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
        if not username or not password or not confirm_password: error = 'All fields are required.'
        elif password != confirm_password: error = 'Passwords do not match.'
        elif len(password) < 8: error = 'Password must be at least 8 characters.'
        elif db.find_user(username): error = 'Username already exists.'

        if error:
            flash(error, 'error')
        else:
            try:
                salt = encryption.generate_salt()
                hashed_password = encryption.hash_master_password(password, salt)
                # add_user now initializes 2FA fields automatically
                user_id = db.add_user(username, hashed_password, salt)

                if user_id:
                    flash('Account created successfully! Please log in.', 'success')
                    try: db.ensure_indexes()
                    except Exception as idx_e: print(f"Warning: Signup index error: {idx_e}")
                    return redirect(url_for('login'))
                else:
                    flash('Failed to create account. Please try again.', 'error')
            except Exception as e:
                 flash(f'An error occurred during signup: {e}', 'error')

    return render_template('signup.html')

@app.route('/logout')
def logout():
    """Logs the user out by clearing the session."""
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# --- 2FA Management Routes ---

@app.route('/setup_2fa', methods=['GET', 'POST'])
@login_required # User must be logged in
def setup_2fa():
    """Handles setup and verification of 2FA."""
    user_id = session['user_id']
    username = session['username'] # Get username for provisioning URI

    # Handle verification code submission
    if request.method == 'POST':
        secret_key = request.form.get('secret_key') # Get secret from hidden field
        totp_code = request.form.get('totp_code') # Get code user entered

        if not secret_key or not totp_code:
             flash('Verification code and secret key are required for validation.', 'error')
             # Need to regenerate QR if secret is lost, redirect to GET
             return redirect(url_for('setup_2fa'))

        # Verify the submitted code against the secret key generated previously
        totp = pyotp.TOTP(secret_key)
        if totp.verify(totp_code, valid_window=1): # Allow 1 time step tolerance
            # Code is valid! Save secret and enable 2FA in the database.
            if db.set_user_2fa_secret(user_id, secret_key) and \
               db.enable_user_2fa(user_id, enable=True):
                flash('Two-factor authentication enabled successfully!', 'success')
                session['is_2fa_enabled'] = True # Update session state
                return redirect(url_for('vault'))
            else:
                flash('Failed to save 2FA settings in database. Please try again.', 'error')
                # Optionally redirect back to GET to generate new QR/Secret
                return redirect(url_for('setup_2fa'))
        else:
            # Invalid code entered by user
            flash('Invalid verification code. Please check your authenticator app and try again.', 'error')
            # Re-render the setup page WITH THE SAME secret and QR code so they can retry
            # Regenerate QR code data for the template
            provisioning_uri = pyotp.totp.TOTP(secret_key).provisioning_uri(
                name=username, issuer_name=config.TOTP_ISSUER_NAME
            )
            qr_code_data = utils.generate_qr_code_base64(provisioning_uri)
            # Check if QR generation failed
            if not qr_code_data:
                flash('Error generating QR code. Cannot display setup info.', 'error')
                # Maybe redirect to vault or show a generic error page
                return redirect(url_for('vault'))
            # Pass the *same* secret back, along with the regenerated QR
            return render_template('setup_2fa.html', secret_key=secret_key, qr_code_data=qr_code_data)

    # --- GET Request Logic ---
    # Generate a new secret for the user for this setup attempt
    secret_key = pyotp.random_base32()

    # Generate provisioning URI (otpauth:// URI) for the authenticator app
    provisioning_uri = pyotp.totp.TOTP(secret_key).provisioning_uri(
        name=username, issuer_name=config.TOTP_ISSUER_NAME
    )

    # Generate QR code image data (base64 PNG) from the URI
    qr_code_data = utils.generate_qr_code_base64(provisioning_uri)

    # Handle potential QR code generation error
    if not qr_code_data:
        flash('Error generating QR code for 2FA setup.', 'error')
        # Optionally render a simplified template or redirect
        return redirect(url_for('vault')) # Redirect if QR fails

    # Render the setup page template, passing the new secret and QR data
    return render_template('setup_2fa.html', secret_key=secret_key, qr_code_data=qr_code_data)


@app.route('/disable_2fa', methods=['POST'])
@login_required # User must be logged in
def disable_2fa():
    """Handles disabling 2FA for the logged-in user."""
    user_id = session['user_id']

    # SECURITY ENHANCEMENT: Should require current password or TOTP code here
    # password = request.form.get('password')
    # user_data = db.find_user(session['username'])
    # if not encryption.verify_master_password(user_data['password_hash'], password):
    #      flash('Incorrect password. Cannot disable 2FA.', 'error')
    #      return redirect(url_for('vault'))

    # Proceed with disabling (simplified version)
    if db.disable_user_2fa(user_id): # This function clears secret and sets flag to False
        flash('Two-factor authentication disabled.', 'success')
        session['is_2fa_enabled'] = False # Update session status
    else:
        flash('Failed to disable two-factor authentication in the database.', 'error')

    return redirect(url_for('vault'))


# --- Vault and API Routes ---

@app.route('/vault')
@login_required
def vault():
    """Displays the user's vault entries, handles search."""
    user_id = session['user_id']
    search_term = request.args.get('search_term', '')
    entries = db.get_vault_entries(user_id, search_term=search_term)
    # Pass 2FA status from session to template for display
    return render_template('vault.html', entries=entries, search_term=search_term, is_2fa_enabled=session.get('is_2fa_enabled'))


@app.route('/add_entry', methods=['POST'])
@login_required
def add_entry():
    """Handles adding a new entry to the vault."""
    laptop_server = request.form.get('laptop_server')
    entry_username = request.form.get('entry_username')
    password = request.form.get('entry_password')
    user_id = session['user_id']
    encryption_key = session.get('encryption_key')

    if not laptop_server or not entry_username or not password:
        flash('Laptop/Server ID, Username, and Password are required.', 'error')
    elif not encryption_key:
         flash('Session error: Encryption key missing.', 'error'); session.clear(); return redirect(url_for('login'))
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
    """Handles deleting a specific vault entry after ownership check."""
    user_id = session['user_id']
    entry_data = db.find_entry_by_id_and_user(entry_id, user_id) # Verify ownership

    if entry_data:
        try:
            success = db.delete_vault_entry(entry_id)
            if success: flash('Entry deleted.', 'success')
            else: flash('Failed to delete entry.', 'error')
        except Exception as e: flash(f'Error deleting: {e}', 'error')
    else:
         flash('Cannot delete entry (not found or permission denied).', 'error')
    return redirect(url_for('vault'))

@app.route('/generate_password')
@login_required
def generate_password_api():
    """API endpoint to generate a random password."""
    try:
        password = utils.generate_password(16)
        return jsonify({'password': password})
    except Exception as e:
        print(f"Error generating password: {e}")
        return jsonify({'error': 'Failed to generate password'}), 500

@app.route('/get_password/<entry_id>')
@login_required
def get_password_api(entry_id):
    """API endpoint to securely retrieve and decrypt a password."""
    user_id = session['user_id']
    encryption_key = session.get('encryption_key')

    if not encryption_key:
        return jsonify({'error': 'Encryption key missing from session'}), 401 # Unauthorized

    try:
        # Find the specific entry AND verify ownership
        entry_data = db.find_entry_by_id_and_user(entry_id, user_id)

        if entry_data: # Entry found and owned by user
             encrypted_pass = entry_data.get('encrypted_password')
             if encrypted_pass:
                 decrypted_pass = encryption.decrypt_data(encrypted_pass, encryption_key)
                 if decrypted_pass is not None:
                     return jsonify({'password': decrypted_pass}) # Success
                 else:
                     print(f"Decryption failed for entry {entry_id}")
                     return jsonify({'error': 'Decryption failed'}), 500 # Decryption error
             else:
                 return jsonify({'password': ''}) # Entry has no password
        else:
            # Entry not found or doesn't belong to this user
            return jsonify({'error': 'Entry not found or access denied'}), 404 # Not Found/Forbidden

    except Exception as e:
        print(f"Error in get_password_api for entry '{entry_id}': {e}")
        return jsonify({'error': 'An internal server error occurred'}), 500


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
            # This path indicates connect_db returned None without raising an exception
             raise ConnectionError("Failed to get DB connection during startup check (connect_db returned None).")

    except Exception as e:
        # Catch any exception during DB connection or index check
        print(f"\n{'*'*20}\nCRITICAL: Could not connect/setup database on startup: {e}\n{'*'*20}\n")
        import sys
        # Exit if DB connection/setup fails, as the app likely cannot function
        sys.exit(1)

    print("Starting Flask development server...")
    # Use host='0.0.0.0' to make accessible on network.
    # Use debug=True ONLY for development (auto-reload, debugger).
    # For production, use a proper WSGI server (Gunicorn, Waitress) and set debug=False.
    app.run(host='0.0.0.0', port=5000, debug=True)
# web_app.py
import os
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify)
from functools import wraps
import config # Your config file (reads .env)
import db     # Your db interaction file
import encryption # Your encryption file
import utils    # Your utils file (for password generation)

# Initialize Flask App
app = Flask(__name__)
# Load Secret Key from config (which reads from .env)
app.secret_key = config.SECRET_KEY
if not app.secret_key:
     # Ensure the app doesn't run without a secret key
     raise ValueError("FLASK_SECRET_KEY is not set in config or environment variables!")

# --- Database Connection Teardown ---
# Ensure DB connection is closed when the application context ends
@app.teardown_appcontext
def shutdown_session(exception=None):
    db.close_db()

# --- Decorator for Login Required Routes ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user ID is in session (means user is logged in)
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        # Check if essential encryption info is present in session
        if 'encryption_key' not in session or 'user_salt' not in session:
             flash('Session error: Encryption key missing. Please log in again.', 'error')
             session.clear() # Clear potentially corrupt session
             return redirect(url_for('login'))
        # If checks pass, proceed to the original route function
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
    """Handles user login."""
    # If user is already logged in, redirect to vault
    if 'user_id' in session:
        return redirect(url_for('vault'))

    # Handle form submission
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Basic validation
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('login.html')

        # Find user in database
        user_data = db.find_user(username)

        # Verify password and user existence
        if user_data and encryption.verify_master_password(user_data['password_hash'], password):
            # Store essential info in session upon successful login
            session['user_id'] = str(user_data['_id'])
            session['username'] = user_data['username']
            session['user_salt'] = user_data['salt'] # Store salt needed for key derivation

            # CRITICAL: Derive and store encryption key in session
            try:
                key = encryption.derive_key(password, user_data['salt'])
                session['encryption_key'] = key # Store the derived key (bytes)
            except Exception as e:
                 flash(f'Failed to derive encryption key during login: {e}. Cannot proceed.', 'error')
                 session.clear() # Don't leave partial session data
                 return render_template('login.html')

            flash('Login successful!', 'success')
            return redirect(url_for('vault')) # Redirect to the main vault page
        else:
            # Invalid credentials
            flash('Invalid username or password.', 'error')

    # Render login page template for GET requests or failed POSTs
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handles new user registration."""
    # If user is already logged in, redirect to vault
    if 'user_id' in session:
        return redirect(url_for('vault'))

    # Handle form submission
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Input validation checks
        error = None
        if not username or not password or not confirm_password:
            error = 'All fields are required.'
        elif password != confirm_password:
            error = 'Passwords do not match.'
        elif len(password) < 8:
            error = 'Password must be at least 8 characters.'
        elif db.find_user(username): # Check if username already exists
            error = 'Username already exists.'

        # If validation errors, flash message and re-render form
        if error:
            flash(error, 'error')
        else:
            # Proceed with creating the user
            try:
                salt = encryption.generate_salt()
                hashed_password = encryption.hash_master_password(password, salt)
                user_id = db.add_user(username, hashed_password, salt)

                if user_id:
                    flash('Account created successfully! Please log in.', 'success')
                    # Attempt to ensure indexes exist (especially unique username)
                    try: db.ensure_indexes()
                    except Exception as idx_e: print(f"Warning: Could not ensure indexes after signup: {idx_e}")
                    return redirect(url_for('login')) # Redirect to login after successful signup
                else:
                    # This might happen if add_user fails for reasons other than DuplicateKeyError
                    flash('Failed to create account. Please try again.', 'error')
            except Exception as e:
                 # Catch any other unexpected errors during signup process
                 flash(f'An error occurred during signup: {e}', 'error')

    # Render signup page template for GET requests or failed POSTs
    return render_template('signup.html')

@app.route('/logout')
def logout():
    """Logs the user out by clearing the session."""
    session.clear() # Clear all session data
    flash('You have been logged out.', 'success')
    return redirect(url_for('login')) # Redirect to login page

# --- Vault Routes ---

@app.route('/vault')
@login_required # User must be logged in to access the vault
def vault():
    """Displays the user's vault entries, handles search."""
    user_id = session['user_id']
    # Get search term from URL query parameters (?search_term=...)
    search_term = request.args.get('search_term', '') # Default to empty string

    # Fetch entries from DB, passing the search term for filtering
    entries = db.get_vault_entries(user_id, search_term=search_term)

    # Render the vault template, passing the entries and search term
    return render_template('vault.html', entries=entries, search_term=search_term)

@app.route('/add_entry', methods=['POST'])
@login_required # User must be logged in
def add_entry():
    """Handles adding a new entry to the vault via form submission."""
    # Get data from the submitted form
    laptop_server = request.form.get('laptop_server') # Use the renamed field
    entry_username = request.form.get('entry_username')
    password = request.form.get('entry_password') # Plain text password from form
    user_id = session['user_id']
    encryption_key = session.get('encryption_key') # Retrieve key from session

    # Basic validation
    if not laptop_server or not entry_username or not password:
        flash('Laptop/Server ID, Username, and Password are required.', 'error')
    elif not encryption_key:
         # This shouldn't happen if @login_required works, but double-check
         flash('Session error: Encryption key missing. Please log in again.', 'error')
         session.clear()
         return redirect(url_for('login'))
    else:
        # Proceed with adding the entry
        try:
            # Encrypt the password using the key stored in the session
            encrypted_password = encryption.encrypt_data(password, encryption_key)
            # Add entry to the database
            entry_id = db.add_vault_entry(user_id, laptop_server, entry_username, encrypted_password) # Pass renamed field
            if entry_id:
                flash('Entry added successfully!', 'success')
            else:
                flash('Failed to add entry to database.', 'error')
        except Exception as e:
            flash(f'Error adding entry: {e}', 'error')

    # Redirect back to the main vault page after processing
    # Note: Search context is lost on redirect after POST, which is standard behavior.
    return redirect(url_for('vault'))

@app.route('/delete_entry/<entry_id>', methods=['POST'])
@login_required # User must be logged in
def delete_entry(entry_id):
    """Handles deleting a specific vault entry."""
    user_id = session['user_id']
    # IMPORTANT: Verify ownership before deleting
    entry_data = db.find_entry_by_id_and_user(entry_id, user_id)

    if entry_data: # If the entry exists and belongs to the logged-in user
        try:
            success = db.delete_vault_entry(entry_id)
            if success:
                flash('Entry deleted successfully!', 'success')
            else:
                flash('Failed to delete entry from database.', 'error')
        except Exception as e:
             flash(f'Error deleting entry: {e}', 'error')
    else:
         # Entry not found or doesn't belong to user
         flash('You do not have permission to delete this entry or it does not exist.', 'error')

    # Redirect back to the main vault page
    return redirect(url_for('vault'))

# --- API-like endpoints for JavaScript interactions ---

@app.route('/generate_password')
@login_required # Ensures only logged-in users can generate
def generate_password_api():
    """API endpoint to generate a random password."""
    try:
        password = utils.generate_password(16) # Generate a 16-char password
        return jsonify({'password': password}) # Return as JSON
    except Exception as e:
        print(f"Error generating password: {e}") # Log error server-side
        # Return JSON error response with 500 status code
        return jsonify({'error': 'Failed to generate password'}), 500

@app.route('/get_password/<entry_id>')
@login_required # Ensures only logged-in users can request passwords
def get_password_api(entry_id):
    """API endpoint to securely retrieve and decrypt a password for JS."""
    user_id = session['user_id']
    encryption_key = session.get('encryption_key') # Get key from session

    # Check if encryption key exists in session
    if not encryption_key:
        return jsonify({'error': 'Encryption key missing from session'}), 401 # Unauthorized

    try:
        # Find the specific entry AND verify ownership by the current user
        entry_data = db.find_entry_by_id_and_user(entry_id, user_id)

        if entry_data: # If entry found and owned by user
             encrypted_pass = entry_data.get('encrypted_password') # Get encrypted blob
             if encrypted_pass:
                 # Decrypt the password
                 decrypted_pass = encryption.decrypt_data(encrypted_pass, encryption_key)
                 if decrypted_pass is not None:
                     # Success: return decrypted password
                     return jsonify({'password': decrypted_pass})
                 else:
                     # Decryption failed (e.g., key mismatch, data corruption)
                     print(f"Decryption failed for entry {entry_id}") # Log specific error
                     return jsonify({'error': 'Decryption failed'}), 500 # Internal Server Error
             else:
                 # Entry exists but has no password stored
                 return jsonify({'password': ''})
        else:
            # Entry not found or doesn't belong to this user
            return jsonify({'error': 'Entry not found or access denied'}), 404 # Not Found

    except Exception as e:
        # Catch any other unexpected errors
        print(f"Error in get_password_api for entry '{entry_id}': {e}") # Log the error
        return jsonify({'error': 'An internal server error occurred'}), 500 # Internal Server Error


# --- Main Execution Block ---
if __name__ == '__main__':
    # --- Startup Database Connection Check ---
    try:
        print("Attempting initial database connection check...")
        # Try to establish connection and get DB object
        db_conn_check = db.connect_db()

        # Explicitly check if a Database object was returned (not None)
        if db_conn_check is not None:
            print("Initial connection successful. Checking indexes...")
            db.ensure_indexes() # Attempt to create indexes if they don't exist
            db.close_db() # Close this initial connection; Flask manages per-request connections
            print("Database connection checked and indexes ensured.")
        else:
            # This path indicates connect_db returned None without raising an exception, which is unexpected
             raise ConnectionError("Failed to get DB connection during startup check (connect_db returned None).")

    except Exception as e:
        # Catch any exception during connect_db or ensure_indexes
        print(f"\n{'*'*20}\nCRITICAL: Could not connect/setup database on startup: {e}\n{'*'*20}\n")
        import sys
        sys.exit(1) # Exit the application if DB connection fails on startup

    # --- Start Flask Development Server ---
    print("Starting Flask development server...")
    # Use host='0.0.0.0' to make the server accessible on your network IP.
    # Use debug=True ONLY for development (enables auto-reload and debugger).
    # For production, use a proper WSGI server like Gunicorn or Waitress.
    app.run(host='0.0.0.0', port=5000, debug=True)
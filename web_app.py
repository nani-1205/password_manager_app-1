# web_app.py
import os
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify)
from functools import wraps # For login_required decorator
import config # Your config file
import db     # Your db interaction file
import encryption # Your encryption file
import utils    # Your utils file (for password generation)

app = Flask(__name__)
app.secret_key = config.SECRET_KEY # Load secret key for sessions

# --- Database Connection ---
# Optional: Initialize connection pool or ensure connection on first request
# For simplicity, we rely on db.get_db() creating it when needed.
# Consider adding app context handling for DB connection/closing if needed.
@app.teardown_appcontext
def shutdown_session(exception=None):
    db.close_db() # Close DB connection when app context tears down

# --- Decorator for Login Required ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        # --- CRITICAL: Load key and salt from session for use in the request ---
        if 'encryption_key' not in session or 'user_salt' not in session:
             flash('Session error: Encryption key missing. Please log in again.', 'error')
             session.clear() # Clear potentially corrupt session
             return redirect(url_for('login'))
        # You might pass these via g (Flask's request context global)
        # or just access session directly in the routes that need them.
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('vault'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('vault')) # Already logged in

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('login.html')

        user_data = db.find_user(username)

        if user_data and encryption.verify_master_password(user_data['password_hash'], password):
            # --- Store essential info in session ---
            session['user_id'] = str(user_data['_id'])
            session['username'] = user_data['username']
            session['user_salt'] = user_data['salt'] # Store salt

            # --- CRITICAL: Derive and store encryption key in session ---
            try:
                key = encryption.derive_key(password, user_data['salt'])
                session['encryption_key'] = key # Store the derived key
            except Exception as e:
                 flash(f'Failed to derive encryption key: {e}. Cannot proceed.', 'error')
                 session.clear() # Don't leave partial session data
                 return render_template('login.html')

            flash('Login successful!', 'success')
            return redirect(url_for('vault'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user_id' in session:
        return redirect(url_for('vault')) # Already logged in

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not password or not confirm_password:
            flash('All fields are required.', 'error')
        elif password != confirm_password:
            flash('Passwords do not match.', 'error')
        elif len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
        elif db.find_user(username):
            flash('Username already exists.', 'error')
        else:
            # Generate salt and hash password
            try:
                salt = encryption.generate_salt()
                hashed_password = encryption.hash_master_password(password, salt)

                # Add user to DB
                user_id = db.add_user(username, hashed_password, salt)

                if user_id:
                    flash('Account created successfully! Please log in.', 'success')
                    # Ensure indexes exist if this is the first user etc.
                    try:
                        db.ensure_indexes()
                    except Exception as idx_e:
                        print(f"Warning: Could not ensure indexes after signup: {idx_e}") # Log this
                    return redirect(url_for('login'))
                else:
                    flash('Failed to create account. Please try again.', 'error')
            except Exception as e:
                 flash(f'An error occurred during signup: {e}', 'error')

    return render_template('signup.html')

@app.route('/logout')
def logout():
    # --- CRITICAL: Clear all sensitive session data ---
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('user_salt', None)
    session.pop('encryption_key', None)
    # Or just session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/vault')
@login_required
def vault():
    user_id = session['user_id']
    entries = db.get_vault_entries(user_id)
    # We pass the raw entries, decryption happens on demand via API call
    return render_template('vault.html', entries=entries)

@app.route('/add_entry', methods=['POST'])
@login_required
def add_entry():
    website = request.form.get('website')
    entry_username = request.form.get('entry_username')
    password = request.form.get('entry_password') # Plain text from form
    user_id = session['user_id']
    encryption_key = session['encryption_key'] # Get key from session

    if not website or not entry_username or not password:
        flash('Website, Username, and Password are required.', 'error')
    elif not encryption_key:
         flash('Encryption key not found in session. Please log in again.', 'error')
         session.clear()
         return redirect(url_for('login'))
    else:
        try:
            encrypted_password = encryption.encrypt_data(password, encryption_key)
            entry_id = db.add_vault_entry(user_id, website, entry_username, encrypted_password)
            if entry_id:
                flash('Entry added successfully!', 'success')
            else:
                flash('Failed to add entry to database.', 'error')
        except Exception as e:
            flash(f'Error adding entry: {e}', 'error')

    return redirect(url_for('vault'))

@app.route('/delete_entry/<entry_id>', methods=['POST'])
@login_required
def delete_entry(entry_id):
    user_id = session['user_id']
    # Optional: Verify the entry actually belongs to the user before deleting
    entry = db.get_vault_entries(user_id) # Fetch all to check ownership (inefficient but simple)
    is_owner = any(str(e['_id']) == entry_id for e in entry) # Check if ID exists in user's entries

    # A better way: Modify get_vault_entries or add find_entry(entry_id, user_id)
    # entry_data = db.find_one_entry(entry_id)
    # if entry_data and str(entry_data['user_id']) == user_id: is_owner = True

    if is_owner: # Replace with better ownership check if implemented
        try:
            success = db.delete_vault_entry(entry_id)
            if success:
                flash('Entry deleted successfully!', 'success')
            else:
                flash('Failed to delete entry from database.', 'error')
        except Exception as e:
             flash(f'Error deleting entry: {e}', 'error')
    else:
         flash('You do not have permission to delete this entry or it does not exist.', 'error')


    return redirect(url_for('vault'))

# --- API-like endpoints for JavaScript ---

@app.route('/generate_password')
@login_required # User must be logged in to use generator (optional decision)
def generate_password_api():
    try:
        password = utils.generate_password(16) # Or get length from query param: request.args.get('length', 16)
        return jsonify({'password': password})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/get_password/<entry_id>')
@login_required
def get_password_api(entry_id):
    user_id = session['user_id']
    encryption_key = session.get('encryption_key')

    if not encryption_key:
        return jsonify({'error': 'Encryption key missing from session'}), 401 # Unauthorized

    try:
        # SECURITY: Fetch *specifically* this entry and verify ownership!
        # Add a function like db.find_entry_by_id_and_user(entry_id, user_id)
        # For now, using the less efficient method from delete:
        entries = db.get_vault_entries(user_id)
        entry_data = next((e for e in entries if str(e['_id']) == entry_id), None)

        if entry_data:
             encrypted_pass = entry_data.get('encrypted_password')
             if encrypted_pass:
                 decrypted_pass = encryption.decrypt_data(encrypted_pass, encryption_key)
                 if decrypted_pass is not None:
                     return jsonify({'password': decrypted_pass})
                 else:
                     return jsonify({'error': 'Decryption failed'}), 500
             else:
                 return jsonify({'password': ''}) # No password stored
        else:
            return jsonify({'error': 'Entry not found or access denied'}), 404 # Not Found or Forbidden

    except Exception as e:
        print(f"Error in get_password_api: {e}") # Log the error server-side
        return jsonify({'error': 'An internal error occurred'}), 500


# --- Run the App (for development) ---
if __name__ == '__main__':
    # Make sure DB is connectable before starting
    try:
        db.connect_db()
        db.ensure_indexes() # Ensure indexes on startup
        db.close_db() # Close initial connection, will reconnect per request
        print("Database connection checked and indexes ensured.")
    except Exception as e:
        print(f"\n{'*'*20}\nCRITICAL: Could not connect to database on startup: {e}\n{'*'*20}\n")
        # Optionally exit if DB is essential for startup
        # import sys
        # sys.exit(1)

    # Host '0.0.0.0' makes it accessible on your network (use with caution)
    # Debug=True enables auto-reloading and more detailed errors (NEVER use in production)
    app.run(host='0.0.0.0', port=5000, debug=True)
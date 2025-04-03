# web_app.py
import os
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify)
from functools import wraps
import config
import db
import encryption
import utils

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.close_db()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        if 'encryption_key' not in session or 'user_salt' not in session:
             flash('Session error: Encryption key missing. Please log in again.', 'error')
             session.clear()
             return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- index, login, signup, logout remain the same ---
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('vault'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # ... (existing login logic) ...
    if 'user_id' in session:
        return redirect(url_for('vault'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('login.html')

        user_data = db.find_user(username)

        if user_data and encryption.verify_master_password(user_data['password_hash'], password):
            session['user_id'] = str(user_data['_id'])
            session['username'] = user_data['username']
            session['user_salt'] = user_data['salt']
            try:
                key = encryption.derive_key(password, user_data['salt'])
                session['encryption_key'] = key
            except Exception as e:
                 flash(f'Failed to derive encryption key: {e}. Cannot proceed.', 'error')
                 session.clear()
                 return render_template('login.html')
            flash('Login successful!', 'success')
            return redirect(url_for('vault'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # ... (existing signup logic) ...
    if 'user_id' in session:
        return redirect(url_for('vault'))

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
            try:
                salt = encryption.generate_salt()
                hashed_password = encryption.hash_master_password(password, salt)
                user_id = db.add_user(username, hashed_password, salt)

                if user_id:
                    flash('Account created successfully! Please log in.', 'success')
                    try: db.ensure_indexes()
                    except Exception as idx_e: print(f"Warning: Could not ensure indexes after signup: {idx_e}")
                    return redirect(url_for('login'))
                else:
                    flash('Failed to create account. Please try again.', 'error')
            except Exception as e:
                 flash(f'An error occurred during signup: {e}', 'error')

    return render_template('signup.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


# MODIFIED: Handle search term
@app.route('/vault')
@login_required
def vault():
    user_id = session['user_id']
    # Get search term from query parameters (GET request)
    search_term = request.args.get('search_term', '') # Default to empty string if not found

    # Fetch entries, passing the search term to the db function
    entries = db.get_vault_entries(user_id, search_term=search_term)

    # Pass entries and the search term back to the template
    return render_template('vault.html', entries=entries, search_term=search_term)

# MODIFIED: Read 'laptop_server' from form
@app.route('/add_entry', methods=['POST'])
@login_required
def add_entry():
    laptop_server = request.form.get('laptop_server') # CHANGED from 'website'
    entry_username = request.form.get('entry_username')
    password = request.form.get('entry_password')
    user_id = session['user_id']
    encryption_key = session.get('encryption_key') # Use .get for safety

    # VALIDATION: Check if laptop_server exists
    if not laptop_server or not entry_username or not password:
        flash('Laptop/Server, Username, and Password are required.', 'error') # MODIFIED msg
    elif not encryption_key:
         flash('Encryption key not found in session. Please log in again.', 'error')
         session.clear()
         return redirect(url_for('login'))
    else:
        try:
            encrypted_password = encryption.encrypt_data(password, encryption_key)
            # Pass laptop_server to db function
            entry_id = db.add_vault_entry(user_id, laptop_server, entry_username, encrypted_password) # CHANGED
            if entry_id:
                flash('Entry added successfully!', 'success')
            else:
                flash('Failed to add entry to database.', 'error')
        except Exception as e:
            flash(f'Error adding entry: {e}', 'error')

    # Redirect back to vault, preserving search term is complex here,
    # usually search is done via GET, add via POST redirects cleanly.
    return redirect(url_for('vault'))

# --- delete_entry, generate_password_api, get_password_api remain the same ---
# (Assuming get_password_api uses the efficient find_entry_by_id_and_user)
@app.route('/delete_entry/<entry_id>', methods=['POST'])
@login_required
def delete_entry(entry_id):
    user_id = session['user_id']
    # Use the efficient check now if using find_entry_by_id_and_user from db.py
    entry_data = db.find_entry_by_id_and_user(entry_id, user_id)

    if entry_data: # If entry exists and belongs to user
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

    # Redirect back to vault. Again, search term isn't easily preserved after POST->Redirect
    return redirect(url_for('vault'))


@app.route('/generate_password')
@login_required
def generate_password_api():
    try:
        password = utils.generate_password(16)
        return jsonify({'password': password})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/get_password/<entry_id>')
@login_required
def get_password_api(entry_id):
    user_id = session['user_id']
    encryption_key = session.get('encryption_key')

    if not encryption_key:
        return jsonify({'error': 'Encryption key missing from session'}), 401

    try:
        # Use the efficient check
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
                 return jsonify({'password': ''}) # No password stored
        else:
            return jsonify({'error': 'Entry not found or access denied'}), 404

    except Exception as e:
        print(f"Error in get_password_api: {e}")
        return jsonify({'error': 'An internal error occurred'}), 500


# --- Run the App ---
if __name__ == '__main__':
    try:
        db_conn_check = db.connect_db() # Test connection
        if db_conn_check:
            db.ensure_indexes() # Ensure indexes on startup
            db.close_db() # Close initial connection
            print("Database connection checked and indexes ensured.")
        else:
             # Should have been raised by connect_db, but as fallback:
             raise ConnectionError("Failed to get DB connection during startup check.")
    except Exception as e:
        print(f"\n{'*'*20}\nCRITICAL: Could not connect/setup database on startup: {e}\n{'*'*20}\n")
        import sys
        sys.exit(1) # Exit if DB connection fails on startup

    app.run(host='0.0.0.0', port=5000, debug=True) # Use debug=False for production proxy setup
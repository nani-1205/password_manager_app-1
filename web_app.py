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
import traceback # For debugging errors

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
        if 'user_id' not in session: flash('Please log in.', 'warning'); return redirect(url_for('login'))
        if session.get('2fa_required') and not session.get('2fa_passed'):
            if request.endpoint != 'login_2fa': flash('2FA required.', 'warning'); return redirect(url_for('login_2fa'))
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
        if not username or not password: flash('Username and password required.', 'error'); return render_template('quantum_login.html')
        user_data = db.find_user(username)
        if user_data and encryption.verify_master_password(user_data['password_hash'], password):
            session['_2fa_user_id'] = str(user_data['_id']); session['_2fa_username'] = user_data['username']; session['_2fa_salt'] = user_data['salt']
            if user_data.get('is_2fa_enabled'):
                session['2fa_required'] = True; session.pop('_2fa_passed', None); return redirect(url_for('login_2fa'))
            else:
                try:
                    key = encryption.derive_key(password, user_data['salt'])
                    session['user_id'] = session.pop('_2fa_user_id'); session['username'] = session.pop('_2fa_username'); session['salt'] = session.pop('_2fa_salt')
                    session['encryption_key'] = key; session['is_2fa_enabled'] = False; session.pop('2fa_required', None); session.pop('_2fa_passed', None)
                    flash('Login successful!', 'success'); return redirect(url_for('vault'))
                except Exception as e: print(f"DEBUG Login Err (no 2FA): {e}"); traceback.print_exc(); flash(f'Login process error: {e}', 'error'); session.clear(); return render_template('quantum_login.html')
        else: flash('Invalid username or password.', 'error'); session.clear()
    session.pop('_2fa_user_id', None); session.pop('_2fa_username', None); session.pop('_2fa_salt', None); session.pop('2fa_required', None); session.pop('_2fa_passed', None)
    return render_template('quantum_login.html')

@app.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    if '_2fa_user_id' not in session: flash('Please log in first.', 'warning'); return redirect(url_for('login'))
    user_id = session['_2fa_user_id']
    if request.method == 'POST':
        password = request.form.get('password'); totp_code = request.form.get('totp_code')
        if not password or not totp_code: flash('Password and code required.', 'error'); return render_template('quantum_login_2fa.html')
        user_data = db.find_user(session['_2fa_username'])
        if not user_data or str(user_data['_id']) != user_id: flash('User validation error.', 'error'); session.clear(); return redirect(url_for('login'))
        if not encryption.verify_master_password(user_data['password_hash'], password): flash('Invalid password.', 'error'); return render_template('quantum_login_2fa.html')
        totp_secret = user_data.get('totp_secret')
        if not totp_secret: flash('2FA secret not found.', 'error'); session.clear(); return redirect(url_for('login'))
        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(totp_code, valid_window=1): flash('Invalid authenticator code.', 'error'); return render_template('quantum_login_2fa.html')
        try:
            key = encryption.derive_key(password, user_data['salt'])
            session['user_id'] = session.pop('_2fa_user_id'); session['username'] = session.pop('_2fa_username'); session['salt'] = session.pop('_2fa_salt')
            session['encryption_key'] = key; session['is_2fa_enabled'] = True; session.pop('2fa_required', None); session['2fa_passed'] = True
            flash('Login successful!', 'success'); return redirect(url_for('vault'))
        except Exception as e: print(f"DEBUG Login Err (2FA): {e}"); traceback.print_exc(); flash(f'Login process error after 2FA: {e}', 'error'); session.clear(); return redirect(url_for('login'))
    return render_template('quantum_login_2fa.html')

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
                    try:
                        db.ensure_indexes()
                    except Exception as idx_e:
                        print(f"Warning: Could not ensure indexes after signup for user {username}: {idx_e}")
                    return redirect(url_for('login'))
                else: flash('Failed to create account.', 'error')
            except Exception as e: print(f"Signup Error: {e}"); traceback.print_exc(); flash(f'Signup error: {e}', 'error')
    return render_template('quantum_signup.html')

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
            return render_template('quantum_setup_2fa.html', secret_key=secret_key, qr_code_data=qr_code_data)
    secret_key = pyotp.random_base32()
    provisioning_uri = pyotp.totp.TOTP(secret_key).provisioning_uri(name=username, issuer_name=config.TOTP_ISSUER_NAME)
    qr_code_data = utils.generate_qr_code_base64(provisioning_uri)
    if not qr_code_data: flash('Error generating QR code.', 'error'); return redirect(url_for('vault'))
    return render_template('quantum_setup_2fa.html', secret_key=secret_key, qr_code_data=qr_code_data)

@app.route('/disable_2fa', methods=['POST'])
@login_required
def disable_2fa():
    # SECURITY: Add password check here in production
    user_id = session['user_id']
    if db.disable_user_2fa(user_id): flash('2FA disabled.', 'success'); session['is_2fa_enabled'] = False
    else: flash('Failed to disable 2FA.', 'error')
    return redirect(url_for('vault'))

# --- Vault ---
@app.route('/vault')
@login_required
def vault():
    user_id = session['user_id']; search_term = request.args.get('search_term', '')
    entries = db.get_vault_entries(user_id, search_term=search_term)
    return render_template('quantum_vault.html', entries=entries, search_term=search_term, is_2fa_enabled=session.get('is_2fa_enabled'), current_username=session.get('username'))

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

# --- CORRECTED INDENTATION IN THIS FUNCTION ---
@app.route('/delete_entry/<entry_id>', methods=['POST'])
@login_required
def delete_entry(entry_id):
    """Handles deleting a specific vault entry after ownership check."""
    user_id = session['user_id']
    # IMPORTANT: Verify ownership before deleting
    entry_data = db.find_entry_by_id_and_user(entry_id, user_id)

    if entry_data: # If the entry exists and belongs to the logged-in user
        try:
            # This block is indented once relative to 'if entry_data:'
            success = db.delete_vault_entry(entry_id)
            # This 'if/else' block is indented once relative to 'try:'
            if success:
                # This line is indented once relative to 'if success:'
                flash('Entry deleted.', 'success')
            else:
                # This line is indented once relative to 'else:'
                flash('Failed to delete entry from database.', 'error')
        except Exception as e:
            # This block is indented once relative to 'if entry_data:', matching 'try:'
            # This line is indented once relative to 'except:'
            flash(f'Error occurred during deletion: {e}', 'error')
    else:
         # This block is indented once relative to the function definition, matching 'if entry_data:'
         # This line is indented once relative to 'else:'
         flash('Cannot delete entry (not found or permission denied).', 'error')
    # This return is aligned with the initial 'if entry_data:' block
    return redirect(url_for('vault'))
# --- END CORRECTION ---

# --- APIs ---
@app.route('/generate_password')
@login_required
def generate_password_api():
    try: return jsonify({'password': utils.generate_password(16)})
    except Exception as e: print(f"Gen pass error: {e}"); return jsonify({'error': 'Failed'}), 500
@app.route('/get_password/<entry_id>')
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
                 if decrypted_pass is not None: return jsonify({'password': decrypted_pass})
                 else: return jsonify({'error': 'Decryption failed'}), 500
             else: return jsonify({'password': ''})
        else: return jsonify({'error': 'Not found/denied'}), 404
    except Exception as e: print(f"Get pass error for entry '{entry_id}': {e}"); return jsonify({'error': 'Internal error'}), 500

# --- Main Execution ---
if __name__ == '__main__':
    try:
        print("Attempting initial database connection check...")
        db_conn_check = db.connect_db()
        if db_conn_check is not None: # Corrected check
            print("Initial connection successful. Checking indexes...")
            db.ensure_indexes(); db.close_db()
            print("Database connection checked and indexes ensured.")
        else: raise ConnectionError("DB check returned None.")
    except Exception as e: print(f"\nCRITICAL: DB setup failed: {e}\n"); import sys; sys.exit(1)
    print("Starting Flask dev server (Debug Mode)..."); app.run(host='0.0.0.0', port=5000, debug=True)
# Quantum Vault - Secure Web Password Manager

Quantum Vault is a self-hostable, web-based password manager built with Python (Flask) and MongoDB. It provides a secure environment to store and manage sensitive credentials like server/laptop IDs, usernames, and passwords, with features like strong encryption, two-factor authentication, and administrative user management.



## Features

*   **Secure Credential Storage:** Passwords stored in the vault are encrypted using Fernet symmetric encryption.
*   **Master Password Security:** User master passwords are securely hashed using bcrypt with individual salts.
*   **Two-Factor Authentication (2FA):** Supports Time-based One-Time Passwords (TOTP) using standard authenticator apps (Google Authenticator, Authy, etc.) for enhanced login security.
*   **User Management (Admin Panel):** Designated administrators can:
    *   View all registered users.
    *   Enable or disable user accounts.
    *   Change user roles (promote to admin, demote to user).
    *   View vault entry *metadata* (Laptop/Server ID, Brand, Username - **not passwords**) for any user.
    *   Delete users (which also deletes all their associated vault entries).
    *   Delete specific vault entries for any user.
*   **Vault Management:** Regular users can:
    *   Add new entries (Laptop/Server ID, Brand/Label, Username, Password).
    *   View their stored entries.
    *   Edit their own entries (via modal).
    *   Delete their own entries.
    *   Show/Hide stored passwords.
    *   Copy passwords to the clipboard securely.
    *   Generate strong random passwords.
    *   Search vault entries by ID, Brand, or Username.
*   **Web Interface:**
    *   Modern dark theme (V3) for main user interactions (Vault, Login, Signup, 2FA).
    *   Separate modern light theme (V4) for the Admin User Management section.
    *   Built with Flask and utilizes Bootstrap 5 (via CDN) for styling and components.

## Technology Stack

*   **Backend:** Python 3, Flask
*   **Database:** MongoDB
*   **Password Hashing:** bcrypt
*   **Vault Encryption:** Fernet (from `cryptography` library)
*   **2FA:** pyotp
*   **QR Code Generation:** qrcode[pil]
*   **Environment Variables:** python-dotenv
*   **Frontend:** HTML, CSS, JavaScript, Bootstrap 5 (CDN), Bootstrap Icons (CDN)
*   **Process Management (Example):** PM2 (Optional, for running in background)


## Setup and Installation

**Prerequisites:**

*   Python 3.8+
*   Pip (Python package installer)
*   MongoDB instance (local, Docker, or cloud service like MongoDB Atlas)
*   Git (for cloning)
*   (Optional) PM2 or another process manager for running in the background.

**Steps:**

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/nani-1205/password_manager_app-1.git
    cd password_manager_web_-1 # Or your project directory name
    ```

2.  **Create Virtual Environment:**
    ```bash
    python3 -m venv newenv # Or use 'venv'
    source newenv/bin/activate # Linux/macOS
    # .\newenv\Scripts\activate # Windows
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure Environment (`.env`):**
    *   Create a file named `.env` in the project root.
    *   Copy the following content and fill in your details:
        ```dotenv
        # .env file
        MONGO_HOST=YOUR_MONGO_DB_IP_OR_HOSTNAME
        MONGO_PORT=27017
        MONGO_USER=your_mongo_username
        MONGO_PASSWORD=your_mongo_password
        MONGO_AUTH_DB=admin # Or the DB where your user is authenticated
        # Generate a strong random key and paste it here:
        # python -c "import os; print(os.urandom(24).hex())"
        SECRET_KEY=YOUR_UNIQUE_STRONG_FLASK_SECRET_KEY
        TOTP_ISSUER_NAME=QuantumVaultV3 # Or your preferred app name
        ```
    *   **Important:** Make this file secure and add `.env` to your `.gitignore` file.

5.  **Add Logo:**
    *   Place your application logo as `logo.png` inside the `static/images/` directory.

6.  **Run Database Setup (Indexes):**
    *   The application attempts to create necessary MongoDB indexes on startup. Ensure the MongoDB user has permissions to create indexes (like the `dbAdmin` role on the specific database).

## Running the Application

**1. Development Server:**

*   Make sure your virtual environment is activated.
*   Run the Flask development server:
    ```bash
    python web_app.py
    ```
*   Access the application in your browser, typically at `http://127.0.0.1:5000` or `http://<your-server-ip>:5000`.
*   **Note:** The Flask development server is **not suitable for production**.

**2. Production (Using PM2 - Example):**

*   Make sure PM2 is installed (`npm install pm2 -g`).
*   Ensure the `web_app.py` file's `app.run()` call has `debug=False`.
    ```python
    # At the end of web_app.py
    # app.run(host='0.0.0.0', port=5000, debug=True) # DEVELOPMENT
    app.run(host='0.0.0.0', port=5000, debug=False) # PRODUCTION (when using WSGI/PM2)
    ```
    *Alternatively, and better for production, remove `app.run` entirely and use a WSGI server like Gunicorn.*
*   Start the application with PM2:
    ```bash
    # Ensure virtual env is active or provide full path to python interpreter
    pm2 start web_app.py --name quantum-vault --interpreter=newenv/bin/python3
    ```
*   **Recommended:** Use a proper WSGI server like Gunicorn or Waitress behind a reverse proxy like Nginx or Caddy for production deployment, handling HTTPS/SSL termination.
    *   Example with Gunicorn: `pm2 start "gunicorn --bind 0.0.0.0:5000 --workers 2 web_app:app"` (Install Gunicorn: `pip install gunicorn`)

## Usage

1.  **Sign Up:** Create the first user account. This user will automatically become an administrator.
2.  **Login:** Log in using your username and master password. If 2FA is enabled, you will be prompted for your authenticator code.
3.  **Vault Dashboard:** View your stored entries. Use the search bar to filter.
4.  **Add Entry:** Click "+ Add Entry" in the sidebar, fill the form, and save. Use the Generate button (<i class="bi bi-stars"></i>) for strong passwords.
5.  **Show/Copy/Edit/Delete:** Hover over a vault entry card to reveal action buttons. Click the eye icon to show/hide the password, the clipboard icon to copy, the pencil icon to open the edit modal, or the trash icon to delete.
6.  **Enable/Disable 2FA:** Use the links in the sidebar to manage your two-factor authentication settings. Scan the QR code with an authenticator app.
7.  **Admin Panel (Admins Only):** Click "Manage Users" in the sidebar to access the user list, change roles, activate/deactivate users, view their vault metadata, or delete users.

## Security Considerations

*   **HTTPS:** **Crucial** for production. Deploy behind a reverse proxy configured with SSL/TLS certificates (e.g., Let's Encrypt).
*   **Master Password:** The strength of your master password is paramount. Use a strong, unique password.
*   **SECRET_KEY:** Keep the Flask `SECRET_KEY` in your `.env` file secure and do not commit it to version control.
*   **Database Security:** Secure your MongoDB instance with authentication and restrict network access.
*   **CSRF Protection:** For enhanced security, implement CSRF protection using extensions like Flask-WTF.
*   **Rate Limiting:** Protect login endpoints against brute-force attacks.
*   **Regular Updates:** Keep Python, Flask, and all dependencies updated.

## Contributing

*(Add contribution guidelines if applicable - e.g., reporting issues, pull requests)*



## Authors

- [@nani-1205](https://github.com/nani-1205)

- [@dattaprabhakar](https://github.com/dattaprabhakar)


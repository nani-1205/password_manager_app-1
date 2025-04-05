# PASSWORD-VAULT

Project Description:

This project is a self-hostable, web-based Password Manager Vault application built using Python (Flask framework) and MongoDB.

It allows users to securely store and manage sensitive login credentials (usernames, passwords) associated with specific identifiers like Laptop/Server IDs (or website names). Security is prioritized through strong master password hashing (bcrypt), encryption of stored vault passwords (using a key derived from the master password, never stored directly), and robust two-factor authentication (TOTP) support via standard authenticator apps.

Key Features:

Secure user registration and login.

Two-Factor Authentication (TOTP) setup and verification.

Secure storage of credentials (encrypted passwords).

Add, Delete, View, and Copy stored passwords.

Search functionality to filter vault entries by Laptop/Server ID.

Web interface built with Flask and styled with Bootstrap 5.

Who It's For:

Privacy-conscious individuals who prefer to host their own password management solution rather than relying on third-party cloud services.

Developers or tech-savvy users comfortable with deploying and managing a simple web application and MongoDB instance (either locally, on a personal server, or a private cloud instance).

Anyone needing a basic, secure, self-controlled system to manage credentials, particularly for infrastructure access (servers, laptops) but adaptable for websites too.


## Authors

- [@nani-1205](https://github.com/nani-1205)

- [@dattaprabhakar](https://github.com/dattaprabhakar)


# utils.py
import string
import random
# Note: pyperclip is for desktop clipboard, not used in web app

def generate_password(length=16):
    """Generates a random password with letters, digits, and symbols."""
    if length < 8:
        length = 8 # Ensure minimum length
    characters = string.ascii_letters + string.digits + string.punctuation
    # Ensure the generated password doesn't contain characters that might break HTML/JS easily if not handled
    # For simplicity, we allow all punctuation, but be mindful in complex JS/HTML injection scenarios.
    password = ''.join(random.choice(characters) for i in range(length))
    return password

# copy_to_clipboard function is removed/not needed here.
# Clipboard access is handled by JavaScript (navigator.clipboard) in the browser.
# utils.py
import string
import random
import io         # <--- Add
import base64   # <--- Add
import qrcode     # <--- Add
from qrcode.image.pil import PilImage # Use PIL factory for qrcode

def generate_password(length=16):
    """Generates a random password."""
    if length < 8: length = 8
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

# NEW: Function to generate QR code image data
def generate_qr_code_base64(data):
    """Generates a QR code for the given data and returns it as a base64 encoded PNG."""
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)

        img = qr.make_image(image_factory=PilImage, fill_color="black", back_color="white")

        # Save PNG image to a bytes buffer
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)

        # Encode bytes to base64 string for embedding in HTML
        img_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        return f"data:image/png;base64,{img_base64}"

    except Exception as e:
        print(f"Error generating QR code: {e}")
        return None
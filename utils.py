# utils.py
import string; import random; import io; import base64; import qrcode
from qrcode.image.pil import PilImage

def generate_password(length=16):
    if length < 8: length = 8
    characters = string.ascii_letters + string.digits + string.punctuation
    # Avoid characters that might cause issues in simple display contexts if possible
    safe_punctuation = '!@#$%^&*()_-+=[]{};:,.<>/?'
    characters = string.ascii_letters + string.digits + safe_punctuation
    password = ''.join(random.choice(characters) for i in range(length)); return password

def generate_qr_code_base64(data):
    try:
        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
        qr.add_data(data); qr.make(fit=True)
        img = qr.make_image(image_factory=PilImage, fill_color="black", back_color="white")
        buffer = io.BytesIO(); img.save(buffer, format="PNG"); buffer.seek(0)
        img_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        return f"data:image/png;base64,{img_base64}"
    except Exception as e: print(f"QR gen error: {e}"); return None
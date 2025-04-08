# utils.py
import string, random, io, base64, qrcode
from qrcode.image.pil import PilImage

def generate_password(length=16):
    if length < 8: length = 8
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

def generate_qr_code_base64(data):
    try:
        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
        qr.add_data(data); qr.make(fit=True)
        img = qr.make_image(image_factory=PilImage, fill_color="black", back_color="white")
        buffer = io.BytesIO(); img.save(buffer, format="PNG"); buffer.seek(0)
        img_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        return f"data:image/png;base64,{img_base64}"
    except Exception as e: print(f"Error generating QR code: {e}"); return None
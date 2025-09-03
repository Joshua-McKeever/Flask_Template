from io import BytesIO
import qrcode
from base64 import b64encode
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
import os

# Load environment variables from .env file
base_dir = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(base_dir, '.env'))

def get_b64encoded_qr_image(data):
    print(data)
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    buffered = BytesIO()
    img.save(buffered)
    return b64encode(buffered.getvalue()).decode("utf-8")

def send_reset_email(email, token):
    email_from = os.getenv('email_from')
    email_smtp = os.getenv('email_smtp')
    email_subject = os.getenv('email_subject')
    email_reset_link = os.getenv('email_reset_link')
    email_username = os.getenv('email_username')
    email_password = os.getenv('email_password')

    msg = MIMEText(f'Click to reset: {email_reset_link}/reset_password/{token}')
    msg['Subject'] = email_subject
    msg['From'] = email_from
    msg['To'] = email
    with smtplib.SMTP(email_smtp, 587) as server:
        server.starttls()
        server.login(email_username, email_password)
        server.send_message(msg)
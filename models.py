import uuid
import pyotp
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import event

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))  # UUID
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    pw_last_set = db.Column(db.DateTime, nullable=True, default=db.func.now())
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    is_2fa_preferred = db.Column(db.Boolean, nullable=False, default=False)
    is_2fa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    secret_token = db.Column(db.String(32), unique=True, default=pyotp.random_base32())
    pwreset_token = db.Column(db.String(64))
    pwreset_token_set = db.Column(db.DateTime, nullable=True, default=db.func.now())
    created_at = db.Column(db.DateTime, nullable=True, default=db.func.now())
    updated_at = db.Column(db.DateTime, nullable=True, default=db.func.now(), onupdate=db.func.now())

    def get_authentication_setup_uri(self):
        return pyotp.totp.TOTP(self.secret_token).provisioning_uri(
            name=self.email, issuer_name='Falanx')

    def is_otp_valid(self, user_otp):
        totp = pyotp.parse_uri(self.get_authentication_setup_uri())
        return totp.verify(user_otp)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def __repr__(self):
        return f'<User {self.email}>'

@event.listens_for(User.password, 'set', retval=True)
def hash_user_password(target, value, oldvalue, initiator):
    if value != oldvalue:
        return generate_password_hash(value)
    return value
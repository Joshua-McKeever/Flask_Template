from flask import Flask, render_template, url_for, request, redirect, flash, session
from datetime import timedelta, datetime
from models import db, User
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from utils import get_b64encoded_qr_image, send_reset_email
from functools import wraps
from zoneinfo import ZoneInfo
from dotenv import load_dotenv
import os
import secrets

# Load environment variables from .env file if present; fallback to defaults
base_dir = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(base_dir, '.env'))

session_len_min = int(os.getenv('session_len_min', 480))
flask_sec_key = os.getenv('flask_sec_key', "9InU7gT1tf3ue7Ge2M")
db_uri = os.getenv('db_uri')
default_admin_firstname = os.getenv('default_admin_firstname')
default_admin_lastname = os.getenv('default_admin_lastname')
default_admin_email = os.getenv('default_admin_email')
default_admin_password = os.getenv('default_admin_password')

app = Flask(__name__)
app.secret_key = flask_sec_key
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'pool_timeout': 30,
    'pool_recycle': 280,
    'pool_pre_ping': True,
    'max_overflow': 20
}
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=session_len_min)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

db.init_app(app)

with app.app_context():
    db.create_all()
    # Create default admin user if not exists
    firstname = default_admin_firstname
    lastname = default_admin_lastname
    email = default_admin_email
    password = default_admin_password
    if not User.query.filter_by(email=email).first():
        admin = User(email=email, password=password, first_name=firstname, last_name=lastname)
        db.session.add(admin)
        db.session.commit()

# Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

def mfa_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        # If user does not prefer MFA, skip verification
        if not current_user.is_2fa_preferred:
            return f(*args, **kwargs)
        # Redirect to setup if MFA preferred but not enabled
        if not current_user.is_2fa_enabled:
            return redirect(url_for('twofa_setup'))
        # Verify MFA session timestamp (UTC)
        if 'mfa_verified' in session:
            last_mfa = session['mfa_verified']
            if datetime.now(ZoneInfo("UTC")) - last_mfa < timedelta(minutes=60):
                return f(*args, **kwargs)
        flash("Please verify", "danger")
        return redirect(url_for('twofa_verify'))
    return decorated_function

## Internal Web Pages
@app.route("/")
@app.route('/home')
@login_required
@mfa_required
def home():
    title = 'Home'
    return render_template('internal/home.html', title=title)

@app.route('/support')
@login_required
@mfa_required
def support():
    title = 'Support'
    return render_template('internal/support.html', title=title)

@app.route('/profile', methods=["GET", "POST"])
@login_required
@mfa_required
def profile():
    title = 'My Profile'
    # Load current user details
    my_first_name = current_user.first_name
    my_last_name = current_user.last_name
    my_2fa_pref = current_user.is_2fa_preferred
    my_email = current_user.email

    if request.method == "POST":
        # Ignore form user_id for security; use current_user
        user_fname = request.form['my_first_name']
        user_lname = request.form['my_last_name']
        user_2fa_pref = 'my_2fa_pref' in request.form
        # Update user profile
        current_user.first_name = user_fname
        current_user.last_name = user_lname
        current_user.is_2fa_preferred = user_2fa_pref
        db.session.commit()
        flash('Profile updated successfully!')
        return redirect(url_for('profile'))

    return render_template('internal/profile.html', title=title, user_id=current_user.id, my_first_name=my_first_name, my_last_name=my_last_name, my_2fa_pref=my_2fa_pref, my_email=my_email)

@login_required
@app.route('/twofa_setup')
def twofa_setup():
    title = 'Setup Two Factor Auth'
    # Check if MFA already enabled
    if current_user.is_2fa_enabled:
        return redirect(url_for('twofa_verify'))
    # Generate QR for setup
    secret = current_user.secret_token
    uri = current_user.get_authentication_setup_uri()
    base64_qr_image = get_b64encoded_qr_image(uri)
    return render_template('external/2fa_setup.html', title=title, secret=secret, qr_image=base64_qr_image)

@login_required
@app.route('/twofa_verify', methods=['GET', 'POST'])
def twofa_verify():
    title = 'Verify Two Factor Auth'
    if request.method == 'POST':
        enter_otp = request.form['enter_otp']
        if current_user.is_otp_valid(enter_otp):
            flash("2FA verification successful.", "success")
            session['mfa_verified'] = datetime.now(ZoneInfo("UTC"))  # Use UTC
            if not current_user.is_2fa_enabled:
                current_user.is_2fa_enabled = True
                db.session.commit()
            return redirect(url_for('home'))
        else:
            flash("Invalid code, try again.", "danger")
            return redirect(url_for('twofa_verify'))
    return render_template('external/2fa_verify.html', title=title)

## External layout Web Pages

@app.route('/login', methods=['GET', 'POST'])
def login():
    title = 'Login'
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            password = request.form.get('password')
            user = User.query.filter_by(email=email).first()
            if user and user.check_password(password):
                login_user(user)
                session.permanent = True  # Set permanent session here
                if not user.is_2fa_preferred:
                    flash('Sign in successful.', 'success')
                    return redirect(url_for('home'))
                if user.is_2fa_enabled:
                    flash('Sign in successful, please verify.', 'success')
                    return redirect(url_for('twofa_verify'))
                else:
                    flash("Setup 2FA required.", 'info')
                    return redirect(url_for('twofa_setup'))
            else:
                flash('Invalid email or password', 'danger')
        except ValueError as e:  # Narrow to specific errors
            flash('Login error: ' + str(e), 'danger')
    return render_template('external/login.html', title=title)

@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    flash('You have been signed out.', 'success')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    title = 'Register'
    if request.method == "POST":
        reg_email = request.form['email']
        reg_first_name = request.form['first_name']
        reg_last_name = request.form['last_name']
        reg_password = request.form['password']
        reg_password_verify = request.form['verify_password']  # Add verification
        if reg_password != reg_password_verify:
            flash('Passwords do not match.', 'danger')
            return render_template('external/register.html', title=title)
        if not User.query.filter_by(email=reg_email).first():
            new_user = User(first_name=reg_first_name, last_name=reg_last_name, email=reg_email, password=reg_password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            session.permanent = True
            flash(f'Registration Successful. Welcome {reg_first_name}!', 'success')
            return redirect(url_for('twofa_setup'))
        else:
            flash('Email already registered.', 'danger')
    return render_template('external/register.html', title=title)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            # set new password reset token
            pwreset_token = secrets.token_urlsafe(32)
            user.pwreset_token = pwreset_token
            user.pwreset_token_set = db.func.now()
            db.session.commit()

            send_reset_email(email, pwreset_token)
            flash('If this email matches a registered user, a reset link has been sent.')
        else:
            flash('If this email matches a registered user, a reset link has been sent.')
        return redirect(url_for('forgot_password'))
    return render_template('external/forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(pwreset_token=token).first()

    if not user:
        flash('Invalid or expired token.')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        # set new password
        user.password = request.form['password']  # Triggers hash_user_password
        user.pw_last_set = db.func.now()
        # set new password reset token
        user.pwreset_token = secrets.token_urlsafe(32)
        user.pwreset_token_set = db.func.now()
        db.session.commit()

        flash('Password reset successfully.')
        return redirect(url_for('login'))

    return render_template('external/reset_password.html')
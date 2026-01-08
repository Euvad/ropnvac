from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import hmac
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, date
from dotenv import load_dotenv
from pathlib import Path
import calendar as _calendar
from functools import wraps
import os
import re

# Load environment variables from .env file (explicit path next to this file)
env_path = Path(__file__).resolve().parent / '.env'
if env_path.exists():
    load_dotenv(dotenv_path=str(env_path))
else:
    # fallback to default lookup
    load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.environ.get('FLASK_SECRET')
if not app.secret_key:
    raise ValueError("FLASK_SECRET environment variable must be set")

# Log whether admin user is configured (do NOT log the password)
try:
    admin_present = bool(os.environ.get('ADMIN_USER'))
    app.logger.info(f"ADMIN_USER configured: {admin_present}")
except Exception:
    pass

# Session security configuration
# Make the `Secure` flag configurable via ENV so local HTTP development still receives the CSRF cookie.
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'True').lower() in ('1', 'true', 'yes')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# CSRF Protection
csrf = CSRFProtect(app)

db = SQLAlchemy(app)


def validate_password(password):
    """Validate password strength: min 8 chars, at least 1 uppercase, 1 lowercase, 1 digit"""
    if len(password) < 8:
        return False, "Le mot de passe doit contenir au moins 8 caractères"
    if not re.search(r'[A-Z]', password):
        return False, "Le mot de passe doit contenir au moins une lettre majuscule"
    if not re.search(r'[a-z]', password):
        return False, "Le mot de passe doit contenir au moins une lettre minuscule"
    if not re.search(r'[0-9]', password):
        return False, "Le mot de passe doit contenir au moins un chiffre"
    return True, ""


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    surname = db.Column(db.String(120), nullable=False)
    rio = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    rank = db.Column(db.String(10), nullable=False)  # PA or GPX
    date_limit = db.Column(db.Date, nullable=False)


class Availability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)


def init_db():
    db.create_all()


@app.before_request
def ensure_db():
    init_db()


@app.after_request
def set_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    # Set a CSRF token cookie (readable by JS) for double-submit verification
    try:
        token = generate_csrf()
        response.set_cookie('csrf_token', token, secure=app.config.get('SESSION_COOKIE_SECURE', False), httponly=False, samesite=app.config.get('SESSION_COOKIE_SAMESITE', 'Lax'))
    except Exception:
        pass
    return response


def current_user():
    rio = session.get('rio')
    if not rio:
        return None
    return User.query.filter_by(rio=rio).first()


@app.route('/')
def index():
    user = current_user()
    if user:
        return redirect(url_for('calendar'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        surname = request.form.get('surname', '').strip()
        rio = request.form.get('rio', '').strip()
        password = request.form.get('password', '').strip()
        rank = request.form.get('rank', '').strip().upper()
        date_limit_str = request.form.get('date_limit', '').strip()

        if not (name and surname and rio and password and rank and date_limit_str):
            flash('Tous les champs sont obligatoires')
            return render_template('register.html', name=name, surname=surname, rio=rio, rank=rank, date_limit=date_limit_str)

        if rank not in ('PA', 'GPX'):
            flash('Le grade doit être PA ou GPX')
            return render_template('register.html', name=name, surname=surname, rio=rio, rank=rank, date_limit=date_limit_str)

        # Validate password strength
        is_valid, error_msg = validate_password(password)
        if not is_valid:
            flash(error_msg)
            # Do not re-populate password for security reasons
            return render_template('register.html', name=name, surname=surname, rio=rio, rank=rank, date_limit=date_limit_str)

        try:
            date_limit = datetime.strptime(date_limit_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Format de date invalide')
            return render_template('register.html', name=name, surname=surname, rio=rio, rank=rank, date_limit=date_limit_str)

        existing = User.query.filter_by(rio=rio).first()
        if existing:
            flash('RIO déjà enregistré — veuillez vous connecter')
            return redirect(url_for('login'))

        user = User(name=name, surname=surname, rio=rio, password=generate_password_hash(password), rank=rank, date_limit=date_limit)
        db.session.add(user)
        db.session.commit()
        session['rio'] = rio
        flash('Inscription et connexion réussies')
        return redirect(url_for('calendar'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        rio = request.form.get('rio', '').strip()
        password = request.form.get('password', '').strip()
        if not (rio and password):
            flash('Le RIO et le mot de passe sont obligatoires')
            return redirect(url_for('login'))
        user = User.query.filter_by(rio=rio).first()
        if not user or not check_password_hash(user.password, password):
            flash('RIO ou mot de passe incorrect')
            return redirect(url_for('login'))
        session['rio'] = rio
        return redirect(url_for('calendar'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('rio', None)
    return redirect(url_for('login'))


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    user = current_user()
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        surname = request.form.get('surname', '').strip()
        rank = request.form.get('rank', '').strip().upper()
        date_limit_str = request.form.get('date_limit', '').strip()

        if not (surname and rank and date_limit_str):
            flash('All fields are required')
            return redirect(url_for('profile'))

        if rank not in ('PA', 'GPX'):
            flash('Rank must be PA or GPX')
            return redirect(url_for('profile'))

        try:
            date_limit = datetime.strptime(date_limit_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid date format')
            return redirect(url_for('profile'))

        # Update editable fields only
        user.surname = surname
        user.rank = rank
        user.date_limit = date_limit
        db.session.commit()
        flash('Profile updated')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        # Normalize inputs and env values to avoid whitespace issues
        user = request.form.get('user', '')
        pwd = request.form.get('password', '')
        ADMIN_USER_RAW = os.environ.get('ADMIN_USER')
        ADMIN_PASS_RAW = os.environ.get('ADMIN_PASS')

        if not ADMIN_USER_RAW or not ADMIN_PASS_RAW:
            flash('Admin credentials not configured')
            return redirect(url_for('admin_login'))

        ADMIN_USER = ADMIN_USER_RAW.strip()
        ADMIN_PASS = ADMIN_PASS_RAW

        user_in = user.strip()
        pwd_in = pwd

        # Use constant-time comparison for password
        user_match = (user_in == ADMIN_USER)
        pass_match = hmac.compare_digest(pwd_in or '', ADMIN_PASS or '')

        # No verbose diagnostics in production; keep comparisons silent

        if user_match and pass_match:
            session['is_admin'] = True
            session.permanent = True
            return redirect(url_for('admin_index'))

        flash('Identifiants admin incorrects')
        return redirect(url_for('admin_login'))
    return render_template('admin_login.html')


@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    return redirect(url_for('admin_login'))


@app.route('/admin')
@admin_required
def admin_index():
    users = User.query.order_by(User.id).all()
    return render_template('admin_dashboard.html', users=users)


@app.route('/admin/user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        # Admin may edit all fields
        name = request.form.get('name', '').strip()
        surname = request.form.get('surname', '').strip()
        rio = request.form.get('rio', '').strip()
        rank = request.form.get('rank', '').strip().upper()
        date_limit_str = request.form.get('date_limit', '').strip()
        if not (name and surname and rio and rank and date_limit_str):
            flash('Tous les champs sont obligatoires')
            return redirect(url_for('admin_edit_user', user_id=user.id))
        try:
            date_limit = datetime.strptime(date_limit_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Format de date invalide')
            return redirect(url_for('admin_edit_user', user_id=user.id))
        user.name = name
        user.surname = surname
        user.rio = rio
        user.rank = rank
        user.date_limit = date_limit
        db.session.commit()
        flash('Utilisateur mis à jour')
        return redirect(url_for('admin_index'))
    # GET
    avails = Availability.query.filter_by(user_id=user.id).order_by(Availability.date).all()
    return render_template('admin_user.html', user=user, avails=avails)


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    # delete availabilities then user
    Availability.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    flash('Utilisateur supprimé')
    return redirect(url_for('admin_index'))


@app.route('/calendar')
def calendar():
    user = current_user()
    if not user:
        return redirect(url_for('login'))

    # Use today's date as the visible/selectable start (user's contract date is still stored)
    today = datetime.today().date()
    start = today
    # end = last day of the month 3 months after the current month
    m = today.month + 3
    y = today.year + (m - 1) // 12
    m = ((m - 1) % 12) + 1
    end = date(y, m, _calendar.monthrange(y, m)[1])

    # compute contract year window based on user's signed date (date_limit)
    signed = user.date_limit
    def safe_replace_year(d, yr):
        try:
            return d.replace(year=yr)
        except ValueError:
            # handle Feb 29 -> use last day of Feb
            last = _calendar.monthrange(yr, d.month)[1]
            return date(yr, d.month, last)

    # find most recent anniversary <= today
    today = datetime.today().date()
    try_anniv = safe_replace_year(signed, today.year)
    if try_anniv > today:
        contract_start = safe_replace_year(signed, today.year - 1)
    else:
        contract_start = try_anniv
    next_anniv = safe_replace_year(signed, contract_start.year + 1)
    contract_end = next_anniv - timedelta(days=1)

    avails = Availability.query.filter_by(user_id=user.id).all()
    selected = [d.date.isoformat() for d in avails]

    # count how many days already used in this contract year
    used_count = Availability.query.filter(Availability.user_id == user.id, Availability.date >= contract_start, Availability.date <= contract_end).count()
    remaining = max(0, 90 - used_count)

    return render_template('calendar.html', user=user, start=start.isoformat(), end=end.isoformat(), selected=selected, used_count=used_count, remaining=remaining)


@app.route('/save_availabilities', methods=['POST'])
def save_availabilities():
    user = current_user()
    if not user:
        return jsonify({'ok': False, 'message': 'Not authenticated'}), 401

    data = request.get_json() or {}
    dates = data.get('dates', [])
    parsed = []
    try:
        for ds in dates:
            parsed.append(datetime.strptime(ds, '%Y-%m-%d').date())
    except Exception:
        return jsonify({'ok': False, 'message': 'Invalid date format in payload'}), 400

    # Validate against today's date window (today -> today+90)
    today = datetime.today().date()
    start = today
    m = today.month + 3
    y = today.year + (m - 1) // 12
    m = ((m - 1) % 12) + 1
    end = date(y, m, _calendar.monthrange(y, m)[1])
    for d in parsed:
        if not (start <= d <= end):
            return jsonify({'ok': False, 'message': f'Date {d.isoformat()} outside allowed range'}), 400

    # compute contract window
    signed = user.date_limit
    def safe_replace_year(d, yr):
        try:
            return d.replace(year=yr)
        except ValueError:
            last = _calendar.monthrange(yr, d.month)[1]
            return date(yr, d.month, last)

    today = datetime.today().date()
    try_anniv = safe_replace_year(signed, today.year)
    if try_anniv > today:
        contract_start = safe_replace_year(signed, today.year - 1)
    else:
        contract_start = try_anniv
    next_anniv = safe_replace_year(signed, contract_start.year + 1)
    contract_end = next_anniv - timedelta(days=1)

    # existing entries in visible window (we will replace only these)
    existing_visible = Availability.query.filter(Availability.user_id == user.id, Availability.date >= start, Availability.date <= end).all()
    existing_visible_set = set(a.date.isoformat() for a in existing_visible)

    # existing entries in contract window
    existing_contract = Availability.query.filter(Availability.user_id == user.id, Availability.date >= contract_start, Availability.date <= contract_end).all()
    existing_contract_set = set(a.date.isoformat() for a in existing_contract)

    parsed_set = set(d.isoformat() for d in parsed)
    parsed_in_contract = set(ds for ds in parsed_set if contract_start.isoformat() <= ds <= contract_end.isoformat())

    # final contract-year set equals existing_contract minus replaced visible entries, plus parsed_in_contract
    final_contract_set = (existing_contract_set - existing_visible_set) | parsed_in_contract
    if len(final_contract_set) > 90:
        return jsonify({'ok': False, 'message': f'Would exceed 90 work days in contract year (would be {len(final_contract_set)})'}), 400

    # delete only entries in the visible window that are NOT in parsed dates
    dates_to_delete = existing_visible_set - parsed_set
    for ds in dates_to_delete:
        Availability.query.filter(Availability.user_id == user.id, Availability.date == ds).delete(synchronize_session=False)
    
    # add new dates that don't already exist
    dates_to_add = parsed_set - existing_visible_set
    for ds in dates_to_add:
        d = datetime.strptime(ds, '%Y-%m-%d').date()
        a = Availability(user_id=user.id, date=d)
        db.session.add(a)
    db.session.commit()
    return jsonify({'ok': True})


# Note: application entrypoint moved to the end so all routes are registered first.


# Debug endpoints and verbose diagnostics removed for release builds.


if __name__ == '__main__':
    app.run(debug=False)

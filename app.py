import os
import secrets
from decimal import Decimal

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    logout_user, login_required, current_user
)
from flask_wtf.csrf import CSRFProtect
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]

database_url = make_url(os.environ["DATABASE_URL"])
if database_url.drivername in ("postgresql", "postgres"):
    database_url = database_url.set(drivername="postgresql+psycopg")

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
from rate_limit import limiter
limiter.init_app(app)


login_manager = LoginManager(app)
login_manager.login_view = "login"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


    role = db.Column(
        db.String(20),
        nullable=False,
        default="customer"
    )

    pin_hash = db.Column(
        db.String(255),
        nullable=True
    )

    must_change_pin = db.Column(
        db.Boolean,
        nullable=False,
        default=True
    )

    account = db.relationship(
        "Account", backref="owner", uselist=False
    )


class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id"),
        unique=True, nullable=False
    )
    account_number = db.Column(
        db.String(20), unique=True, nullable=False
    )
    balance = db.Column(
        db.Numeric(18, 2),
        default=Decimal("0.00"),
        nullable=False
    )


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (ValueError, TypeError):
        return None


@app.route("/")
def home():
    return redirect(url_for(
        "dashboard" if current_user.is_authenticated else "login"
    ))


@app.route("/register", methods=["GET", "POST"])
def register():
    return redirect(url_for("login"))
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or len(password) < 8:
            flash("Enter a name, email, and password of at least 8 characters.")
            return redirect(url_for("register"))

        if len(name) > 100 or len(email) > 150 or "@" not in email:
            flash("Please enter valid registration details.")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("This email is already registered.")
            return redirect(url_for("register"))

        user = User(
            full_name=name,
            email=email,
            password_hash=generate_password_hash(password)
        )

        try:
            db.session.add(user)
            db.session.flush()

            account = Account(
                user_id=user.id,
                account_number="MB" + secrets.token_hex(8).upper(),
                balance=Decimal("10000.00")
            )
            db.session.add(account)
            db.session.commit()

        except IntegrityError:
            db.session.rollback()
            flash("Registration could not be completed. Try again.")
            return redirect(url_for("register"))

        flash("Account created! You can now sign in.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for("dashboard"))

        flash("Incorrect email or password.")

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role == "admin":
        return redirect(url_for("admin.dashboard"))
    return render_template("dashboard.html", user=current_user)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/health")
def health():
    return {"status": "ok"}


from banking import banking_bp, Transaction
app.register_blueprint(banking_bp)


from admin import admin_bp
app.register_blueprint(admin_bp)


from pin_security import pin_bp
app.register_blueprint(pin_bp)



from flask import request as pin_request
from flask_login import current_user as pin_current_user

@app.before_request
def enforce_initial_pin_change():
    if not pin_current_user.is_authenticated:
        return None

    if getattr(pin_current_user, "role", None) != "customer":
        return None

    if not getattr(pin_current_user, "must_change_pin", False):
        return None

    if pin_request.endpoint in (
        "pin.change_pin",
        "logout",
        "static"
    ):
        return None

    return redirect(url_for("pin.change_pin"))



from security_events import SecurityEvent

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=False)

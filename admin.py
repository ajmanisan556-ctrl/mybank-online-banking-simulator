import secrets
from functools import wraps

from flask import (
    Blueprint, render_template, request,
    redirect, url_for, flash, abort
)
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import IntegrityError

from app import db, User, Account

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def admin_required(func):
    @wraps(func)
    @login_required
    def wrapper(*args, **kwargs):
        if current_user.role != "admin":
            abort(403)
        return func(*args, **kwargs)
    return wrapper


@admin_bp.route("/")
@admin_required
def dashboard():
    customers = (
        User.query
        .filter_by(role="customer")
        .order_by(User.id.desc())
        .all()
    )
    return render_template(
        "admin_dashboard.html",
        customers=customers
    )


@admin_bp.route("/create-customer", methods=["GET", "POST"])
@admin_required
def create_customer():
    if request.method == "POST":
        name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        pin = request.form.get("pin", "")

        if not name or len(name) > 100:
            flash("Enter a valid customer name.")
            return redirect(url_for("admin.create_customer"))

        if not email or "@" not in email or len(email) > 150:
            flash("Enter a valid email address.")
            return redirect(url_for("admin.create_customer"))

        if len(password) < 8:
            flash("Customer password must have at least 8 characters.")
            return redirect(url_for("admin.create_customer"))

        if not (len(pin) == 6 and pin.isascii() and pin.isdigit()):
            flash("Temporary PIN must contain exactly 6 digits.")
            return redirect(url_for("admin.create_customer"))

        if User.query.filter_by(email=email).first():
            flash("Email already registered.")
            return redirect(url_for("admin.create_customer"))

        customer = User(
            full_name=name,
            email=email,
            password_hash=generate_password_hash(password),
            pin_hash=generate_password_hash(pin),
            must_change_pin=True,
            role="customer"
        )

        try:
            db.session.add(customer)
            db.session.flush()

            account = Account(
                user_id=customer.id,
                account_number="MB" + secrets.token_hex(8).upper(),
                balance=10000
            )

            db.session.add(account)
            db.session.commit()

            flash("Customer created successfully.")

        except IntegrityError:
            db.session.rollback()
            flash("Could not create customer.")
            return redirect(url_for("admin.create_customer"))

        return redirect(url_for("admin.dashboard"))

    return render_template("admin_create_customer.html")


@admin_bp.route("/security-events")
@admin_required
def security_events():
    from security_events import SecurityEvent

    events = (
        SecurityEvent.query
        .order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc())
        .limit(100)
        .all()
    )

    return render_template(
        "admin_security_events.html",
        events=events
    )

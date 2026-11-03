from rate_limit import limiter
from flask import (
    Blueprint, render_template, request,
    redirect, url_for, flash
)
from flask_login import login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash

from app import db
from security_events import record_event, save_event

pin_bp = Blueprint("pin", __name__)


@pin_bp.route("/change-pin", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
@login_required
def change_pin():
    if current_user.role != "customer":
        flash("Only customers can change their banking PIN.")
        return redirect(url_for("admin.dashboard"))

    if request.method == "POST":
        current_pin = request.form.get("current_pin", "")
        new_pin = request.form.get("new_pin", "")
        confirm_pin = request.form.get("confirm_pin", "")

        if not (
            len(new_pin) == 6
            and new_pin.isascii()
            and new_pin.isdigit()
        ):
            flash("New PIN must contain exactly 6 digits.")
            return redirect(url_for("pin.change_pin"))

        if new_pin != confirm_pin:
            flash("New PINs do not match.")
            return redirect(url_for("pin.change_pin"))

        if current_user.pin_hash:
            if not check_password_hash(current_user.pin_hash, current_pin):
                save_event(
                    current_user.id,
                    "PIN_CHANGE",
                    "failed",
                    "Incorrect current PIN"
                )
                flash("Current PIN is incorrect.")
                return redirect(url_for("pin.change_pin"))

            if check_password_hash(current_user.pin_hash, new_pin):
                flash("Your new PIN must be different from your old PIN.")
                return redirect(url_for("pin.change_pin"))
        else:
            flash("No PIN is configured. Contact the administrator.")
            return redirect(url_for("pin.change_pin"))

        current_user.pin_hash = generate_password_hash(new_pin)
        current_user.must_change_pin = False

        record_event(
            current_user.id,
            "PIN_CHANGE",
            "success",
            "Customer changed banking PIN"
        )
        db.session.commit()

        flash("Your banking PIN was changed successfully.")
        return redirect(url_for("dashboard"))

    return render_template("change_pin.html")

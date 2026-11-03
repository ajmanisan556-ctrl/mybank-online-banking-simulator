from rate_limit import limiter
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

from flask import abort, Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from sqlalchemy import select
from werkzeug.security import check_password_hash

from app import db, Account
from security_events import record_event, save_event

banking_bp = Blueprint("banking", __name__)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id"),
        nullable=False, index=True
    )
    transaction_type = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Numeric(18, 2), nullable=False)
    counterparty = db.Column(db.String(20), nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

def parse_amount(value):
    try:
        amount = Decimal(value)
    except (InvalidOperation, ValueError, TypeError):
        return None

    if (
        not amount.is_finite()
        or amount <= 0
        or amount > Decimal("1000000000.00")
        or amount.as_tuple().exponent < -2
    ):
        return None

    return amount.quantize(Decimal("0.01"))

@banking_bp.route("/banking", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
@login_required
def banking():
    if current_user.role != "customer":
        abort(403)

    if request.method == "POST":
        transaction_pin = request.form.get("transaction_pin", "")

        if current_user.must_change_pin:
            flash("Change your temporary PIN before making transactions.")
            return redirect(url_for("pin.change_pin"))

        if not current_user.pin_hash:
            flash("No banking PIN configured. Contact your administrator.")
            return redirect(url_for("banking.banking"))

        if not check_password_hash(
            current_user.pin_hash,
            transaction_pin
        ):
            save_event(
                current_user.id,
                "TRANSACTION_PIN_REJECTED",
                "failed",
                "Incorrect transaction PIN"
            )
            flash("Incorrect transaction PIN. Transaction cancelled.")
            return redirect(url_for("banking.banking"))

        action = request.form.get("action", "")
        amount = parse_amount(request.form.get("amount", ""))
        recipient_number = request.form.get(
            "recipient", ""
        ).strip().upper()

        if amount is None:
            flash("Enter a valid positive amount (maximum two decimal places).")
            return redirect(url_for("banking.banking"))

        if action not in ("deposit", "withdraw", "transfer"):
            flash("Invalid transaction type.")
            return redirect(url_for("banking.banking"))

        try:
            sender_id = current_user.account.id

            if action == "transfer":
                recipient = db.session.execute(
                    select(Account).where(
                        Account.account_number == recipient_number
                    )
                ).scalar_one_or_none()

                if recipient is None or recipient.id == sender_id:
                    flash("Invalid recipient account.")
                    return redirect(url_for("banking.banking"))

                locked = {}
                for account_id in sorted([sender_id, recipient.id]):
                    locked[account_id] = db.session.execute(
                        select(Account).where(
                            Account.id == account_id
                        ).with_for_update()
                    ).scalar_one()

                sender = locked[sender_id]
                receiver = locked[recipient.id]

                if sender.balance < amount:
                    db.session.rollback()
                    flash("Insufficient virtual balance.")
                    return redirect(url_for("banking.banking"))

                sender.balance -= amount
                receiver.balance += amount

                db.session.add(Transaction(
                    user_id=current_user.id,
                    transaction_type="transfer_out",
                    amount=amount,
                    counterparty=receiver.account_number
                ))

                db.session.add(Transaction(
                    user_id=receiver.user_id,
                    transaction_type="transfer_in",
                    amount=amount,
                    counterparty=sender.account_number
                ))

            else:
                sender = db.session.execute(
                    select(Account).where(
                        Account.id == sender_id
                    ).with_for_update()
                ).scalar_one()

                if action == "withdraw":
                    if sender.balance < amount:
                        db.session.rollback()
                        flash("Insufficient virtual balance.")
                        return redirect(url_for("banking.banking"))
                    sender.balance -= amount
                else:
                    if sender.balance + amount > Decimal("9999999999999999.99"):
                        db.session.rollback()
                        flash("Account balance limit exceeded.")
                        return redirect(url_for("banking.banking"))
                    sender.balance += amount

                db.session.add(Transaction(
                    user_id=current_user.id,
                    transaction_type=action,
                    amount=amount
                ))

            record_event(
                current_user.id,
                "BANKING_TRANSACTION",
                "success",
                action
            )
            db.session.commit()
            flash("Virtual transaction completed successfully.")

        except Exception:
            db.session.rollback()
            try:
                save_event(
                    current_user.id,
                    "BANKING_TRANSACTION",
                    "failed",
                    "Transaction processing error"
                )
            except Exception:
                pass
            app_message = "Transaction failed. No changes were saved."
            flash(app_message)

        return redirect(url_for("banking.banking"))

    transactions = db.session.execute(
        select(Transaction)
        .where(Transaction.user_id == current_user.id)
        .order_by(Transaction.created_at.desc(), Transaction.id.desc())
        .limit(50)
    ).scalars().all()

    return render_template(
        "banking.html",
        account=current_user.account,
        transactions=transactions
    )

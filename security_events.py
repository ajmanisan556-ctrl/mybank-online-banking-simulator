from datetime import datetime, timezone
from app import db


class SecurityEvent(db.Model):
    __tablename__ = "security_event"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=True,
        index=True
    )
    event_type = db.Column(db.String(60), nullable=False)
    outcome = db.Column(db.String(20), nullable=False)
    details = db.Column(db.String(255), nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )


def record_event(user_id, event_type, outcome, details=None):
    db.session.add(SecurityEvent(
        user_id=user_id,
        event_type=event_type,
        outcome=outcome,
        details=details
    ))


def save_event(user_id, event_type, outcome, details=None):
    try:
        record_event(user_id, event_type, outcome, details)
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise

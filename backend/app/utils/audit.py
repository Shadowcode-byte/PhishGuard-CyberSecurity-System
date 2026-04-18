import json
import uuid
from sqlalchemy.orm import Session
from app.models.models import AuditLog
from typing import Optional
import logging

logger = logging.getLogger(__name__)


def log_action(
    db: Session,
    action: str,
    user_id: Optional[str] = None,
    resource: Optional[str] = None,
    resource_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[dict] = None,
) -> None:
    """Write an audit log entry to the database."""
    try:
        # Convert string user_id to a proper UUID object for SQLAlchemy
        parsed_user_id = None
        if user_id:
            parsed_user_id = uuid.UUID(user_id) if isinstance(user_id, str) else user_id

        # Convert resource_id to UUID as well, just in case that column is also a UUID type
        # Force resource_id to be a string since models.py defines it as String(100)
        parsed_resource_id = str(resource_id) if resource_id else None

        entry = AuditLog(
            user_id=parsed_user_id,
            action=action,
            resource=resource,
            resource_id=parsed_resource_id,
            ip_address=ip_address,
            user_agent=user_agent[:500] if user_agent else None,
            details=json.dumps(details) if details else None,
        )
        db.add(entry)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")
        db.rollback()
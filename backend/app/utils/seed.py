"""
Demo Account Seeder
===================
Creates 3 demo accounts (admin, analyst, user) if they don't already exist.
Called automatically from main.py on startup.

Demo Credentials:
  admin@phishguard.io   / Admin123!   (role: admin)
  analyst@phishguard.io / Analyst1!   (role: analyst)
  user@phishguard.io    / User1234!   (role: user)
"""

import logging
from sqlalchemy.orm import Session
from app.models.models import User, UserRole
from app.security.auth import hash_password

logger = logging.getLogger(__name__)

DEMO_ACCOUNTS = [
    {
        "email": "admin@phishguard.io",
        "username": "admin",
        "password": "Admin123!",
        "role": UserRole.admin,
    },
    {
        "email": "analyst@phishguard.io",
        "username": "analyst",
        "password": "Analyst1!",
        "role": UserRole.analyst,
    },
    {
        "email": "user@phishguard.io",
        "username": "demo_user",
        "password": "User1234!",
        "role": UserRole.user,
    },
]


def seed_demo_accounts(db: Session) -> None:
    """
    Idempotent: only creates accounts that don't already exist.
    Safe to call on every startup.
    """
    created = 0
    for account in DEMO_ACCOUNTS:
        existing = db.query(User).filter(User.email == account["email"]).first()
        if existing:
            continue

        user = User(
            email=account["email"],
            username=account["username"],
            hashed_password=hash_password(account["password"]),
            role=account["role"],
            is_active=True,
            is_verified=True,
        )
        db.add(user)
        created += 1
        logger.info(f"  ✅ Created demo account: {account['email']} ({account['role'].value})")

    if created > 0:
        db.commit()
        logger.info(f"🌱 Seeded {created} demo account(s)")
    else:
        logger.info("🌱 Demo accounts already exist — skipping seed")

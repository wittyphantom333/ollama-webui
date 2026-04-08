"""Database models for Vivus Portal — users, API keys, and usage tracking."""

import secrets
import hashlib
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_active_user = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    api_keys = db.relationship('ApiKey', backref='user', lazy='dynamic',
                                cascade='all, delete-orphan')
    usage_records = db.relationship('UsageRecord', backref='user', lazy='dynamic',
                                    cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_active(self):
        return self.is_active_user


class ApiKey(db.Model):
    __tablename__ = 'api_keys'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    # Store only the hash — the raw key is shown once at creation time.
    key_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    # Store a short prefix for display (e.g. "sk-vivus-a3f8…")
    key_prefix = db.Column(db.String(20), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_used_at = db.Column(db.DateTime, nullable=True)

    @staticmethod
    def generate_key():
        """Return (raw_key, key_hash, key_prefix)."""
        raw = 'sk-vivus-' + secrets.token_hex(24)
        hashed = hashlib.sha256(raw.encode()).hexdigest()
        prefix = raw[:16] + '...'
        return raw, hashed, prefix

    @staticmethod
    def hash_key(raw_key):
        return hashlib.sha256(raw_key.encode()).hexdigest()

    @staticmethod
    def lookup(raw_key):
        """Find an active ApiKey by its raw key string."""
        hashed = ApiKey.hash_key(raw_key)
        return ApiKey.query.filter_by(key_hash=hashed, is_active=True).first()


class UsageRecord(db.Model):
    """One row per API request routed through the proxy."""
    __tablename__ = 'usage_records'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey('api_keys.id'), nullable=True)
    model = db.Column(db.String(120), nullable=False)
    tier = db.Column(db.String(20), nullable=False)  # fast / default / strong
    prompt_tokens = db.Column(db.Integer, default=0)
    completion_tokens = db.Column(db.Integer, default=0)
    total_tokens = db.Column(db.Integer, default=0)
    duration_ms = db.Column(db.Integer, default=0)
    endpoint = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

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


class SiteSettings(db.Model):
    """Site-wide configuration stored as key/value pairs."""
    __tablename__ = 'site_settings'

    key = db.Column(db.String(80), primary_key=True)
    value = db.Column(db.Text, nullable=True)

    @staticmethod
    def get(key, default=None):
        row = SiteSettings.query.get(key)
        return row.value if row else default

    @staticmethod
    def set(key, value):
        row = SiteSettings.query.get(key)
        if row is None:
            row = SiteSettings(key=key)
            db.session.add(row)
        row.value = str(value)
        db.session.commit()


class CloudProvider(db.Model):
    """Cloud LLM provider API keys (OpenAI, Anthropic, Gemini, etc.)."""
    __tablename__ = 'cloud_providers'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    provider = db.Column(db.String(40), nullable=False)  # openai / anthropic / gemini / custom
    api_key = db.Column(db.Text, nullable=False)
    base_url = db.Column(db.String(300), nullable=True)   # optional endpoint override
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    @property
    def masked_key(self):
        """Return a display-safe masked version of the API key."""
        if len(self.api_key) <= 8:
            return '****'
        return self.api_key[:6] + '...' + self.api_key[-4:]


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

    # Extended metrics (added by proxy enrichment)
    stop_reason = db.Column(db.String(30), nullable=True)       # end_turn, tool_use, max_tokens
    tool_names = db.Column(db.String(500), nullable=True)        # comma-separated: Read,Edit
    tools_available = db.Column(db.String(500), nullable=True)   # comma-separated: Bash,Edit,Read
    tool_round = db.Column(db.Integer, default=0)                # conversation depth
    query_summary = db.Column(db.String(500), nullable=True)     # full query or [round N] tool description
    error = db.Column(db.String(200), nullable=True)             # upstream_504, fetch error, etc.
    messages_sent = db.Column(db.Integer, default=0)             # messages sent to Ollama
    prompt_budget_dropped = db.Column(db.Integer, default=0)     # messages dropped by budget trim

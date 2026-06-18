"""Database models for Vivus Portal — users, API keys, and usage tracking."""

import secrets
import hashlib
import base64
import uuid as _uuid
from datetime import datetime, timezone, timedelta
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

    @property
    def account_uuid(self):
        """Stable synthetic account UUID for OAuth identity."""
        return str(_uuid.uuid5(_uuid.NAMESPACE_URL, f'vivus-user-{self.id}'))

    @property
    def org_uuid(self):
        """Stable synthetic organization UUID (single-org deployment)."""
        return str(_uuid.uuid5(_uuid.NAMESPACE_URL, 'vivus-org'))


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

    tool_calls = db.relationship('ToolCall', backref='usage_record', lazy='dynamic',
                                 cascade='all, delete-orphan')


class ToolCall(db.Model):
    """One row per action a model took during a request (Write/Edit/Bash/etc.).

    Populated only when the proxy runs with CAPTURE_TOOL_DETAILS=1. The proxy
    redacts secrets and caps field sizes before sending these, but treat the
    contents as potentially sensitive (source code, shell commands).
    """
    __tablename__ = 'tool_calls'

    id = db.Column(db.Integer, primary_key=True)
    usage_record_id = db.Column(db.Integer, db.ForeignKey('usage_records.id'),
                                nullable=False, index=True)
    seq = db.Column(db.Integer, default=0)              # order within the turn
    name = db.Column(db.String(80), nullable=False)     # tool name as called: Write, Edit, Bash
    action = db.Column(db.String(20), nullable=True)    # write / edit / bash / delete / move
    target = db.Column(db.Text, nullable=True)          # file path, move spec, or bash description
    command = db.Column(db.Text, nullable=True)         # shell command (bash action)
    old_text = db.Column(db.Text, nullable=True)        # edit: prior content
    new_text = db.Column(db.Text, nullable=True)        # edit: new content / notebook source
    content = db.Column(db.Text, nullable=True)         # write: full file content
    bytes = db.Column(db.Integer, default=0)            # size of written content
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# OAuth 2.0 (PKCE) — CLI sign-in
# ---------------------------------------------------------------------------
# Lets `vivus login` authenticate against the portal and provision a per-user
# API key, instead of users pasting a shared key into VIVUS_API_KEY.

# Client IDs hard-coded in the Vivus CLI (ts/src/constants/oauth.ts).
OAUTH_ALLOWED_CLIENT_IDS = {
    '9d1c250a-e61b-44d9-88ed-5944d1962f5e',  # production CLI
    '22422756-60c9-4084-8eb7-27705fd5cf9a',  # staging / local CLI
}

# Scope granted to the CLI. Intentionally EXCLUDES 'user:inference': the CLI
# only mints an API key (which our proxy authenticates via x-api-key) when the
# granted scopes do NOT include user:inference. Granting it would make the CLI
# use the OAuth bearer token directly for inference, which the proxy can't read.
OAUTH_GRANTED_SCOPE = 'org:create_api_key user:profile'

OAUTH_CODE_TTL = timedelta(minutes=10)
OAUTH_ACCESS_TTL = timedelta(days=365)


def _utcnow():
    return datetime.now(timezone.utc)


def _aware(dt):
    """Treat naive datetimes (SQLite round-trips drop tzinfo) as UTC."""
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _b64url_no_pad(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')


class OAuthAuthCode(db.Model):
    """Short-lived, single-use PKCE authorization code."""
    __tablename__ = 'oauth_auth_codes'

    code = db.Column(db.String(64), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    client_id = db.Column(db.String(64), nullable=False)
    redirect_uri = db.Column(db.String(400), nullable=False)
    code_challenge = db.Column(db.String(128), nullable=False)
    scope = db.Column(db.Text, nullable=True)
    state = db.Column(db.String(256), nullable=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow)

    user = db.relationship('User')

    @staticmethod
    def issue(user_id, client_id, redirect_uri, code_challenge, scope, state):
        code = secrets.token_urlsafe(32)
        db.session.add(OAuthAuthCode(
            code=code,
            user_id=user_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            scope=scope,
            state=state,
            expires_at=_utcnow() + OAUTH_CODE_TTL,
        ))
        db.session.commit()
        return code

    @staticmethod
    def consume(code, redirect_uri, code_verifier):
        """Validate, PKCE-check and single-use a code.

        Returns (OAuthAuthCode, None) on success, or (None, error_str).
        """
        if not code:
            return None, 'invalid_request'
        row = OAuthAuthCode.query.get(code)
        if row is None or row.used:
            return None, 'invalid_grant'
        if _aware(row.expires_at) < _utcnow():
            return None, 'invalid_grant'
        if redirect_uri != row.redirect_uri:
            return None, 'invalid_grant'
        expected = _b64url_no_pad(hashlib.sha256((code_verifier or '').encode()).digest())
        if not secrets.compare_digest(expected, row.code_challenge or ''):
            return None, 'invalid_grant'
        row.used = True
        db.session.commit()
        return row, None


class OAuthToken(db.Model):
    """Issued OAuth access / refresh token pair."""
    __tablename__ = 'oauth_tokens'

    id = db.Column(db.Integer, primary_key=True)
    access_token = db.Column(db.String(128), unique=True, nullable=False, index=True)
    refresh_token = db.Column(db.String(128), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    client_id = db.Column(db.String(64), nullable=False)
    scope = db.Column(db.Text, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow)

    user = db.relationship('User')

    @staticmethod
    def issue(user_id, client_id, scope):
        row = OAuthToken(
            access_token='vivus-at-' + secrets.token_urlsafe(32),
            refresh_token='vivus-rt-' + secrets.token_urlsafe(32),
            user_id=user_id,
            client_id=client_id,
            scope=scope,
            expires_at=_utcnow() + OAUTH_ACCESS_TTL,
        )
        db.session.add(row)
        db.session.commit()
        return row

    @staticmethod
    def lookup_access(token):
        if not token:
            return None
        row = OAuthToken.query.filter_by(access_token=token).first()
        if row is None or _aware(row.expires_at) < _utcnow():
            return None
        return row

    @staticmethod
    def lookup_refresh(token):
        if not token:
            return None
        return OAuthToken.query.filter_by(refresh_token=token).first()

    @property
    def expires_in(self):
        return max(0, int((_aware(self.expires_at) - _utcnow()).total_seconds()))


class Feedback(db.Model):
    """User feedback and bug reports submitted via the /feedback slash command."""
    __tablename__ = 'feedback'

    id = db.Column(db.Integer, primary_key=True)
    # Optional: user_id if the API key can be resolved to a user
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    # Feedback category: 'feedback' or 'bug'
    category = db.Column(db.String(20), nullable=True)
    # Free-form comment submitted by the user
    comment = db.Column(db.Text, nullable=True)
    # Structured payload from the CLI (errors, git info, environment, etc.)
    payload = db.Column(db.Text, nullable=True)
    # Source API key prefix for tracing (not the full key)
    key_prefix = db.Column(db.String(20), nullable=True)
    created_at = db.Column(db.DateTime, default=_utcnow, index=True)

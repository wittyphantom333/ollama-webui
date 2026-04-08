"""API blueprint — key management, validation, and metrics ingestion.

Routes used by the Vivus translation proxy:
  POST /api/v1/keys/validate   — check an API key, return user info
  POST /api/v1/metrics         — ingest usage telemetry from the proxy

Routes used by the portal UI:
  GET/POST /keys               — list / create API keys
  POST /keys/<id>/revoke       — revoke a key
"""

from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from models import db, ApiKey, UsageRecord

api_bp = Blueprint('api', __name__, template_folder='templates')


# ---------------------------------------------------------------------------
# Portal UI — API key management
# ---------------------------------------------------------------------------

@api_bp.route('/keys', methods=['GET', 'POST'])
@login_required
def keys():
    if request.method == 'POST':
        name = request.form.get('key_name', '').strip() or 'default'
        raw_key, key_hash, key_prefix = ApiKey.generate_key()
        api_key = ApiKey(
            user_id=current_user.id,
            name=name,
            key_hash=key_hash,
            key_prefix=key_prefix,
        )
        db.session.add(api_key)
        db.session.commit()
        # Show the raw key exactly once
        flash(f'API key created. Copy it now — it will not be shown again: {raw_key}', 'success')
        return redirect(url_for('api.keys'))

    user_keys = current_user.api_keys.order_by(ApiKey.created_at.desc()).all()
    return render_template('keys.html', keys=user_keys)


@api_bp.route('/keys/<int:key_id>/revoke', methods=['POST'])
@login_required
def revoke_key(key_id):
    api_key = ApiKey.query.get_or_404(key_id)
    if api_key.user_id != current_user.id and not current_user.is_admin:
        flash('Not authorized.', 'danger')
        return redirect(url_for('api.keys'))
    api_key.is_active = False
    db.session.commit()
    flash(f'Key "{api_key.name}" revoked.', 'info')
    return redirect(url_for('api.keys'))


# ---------------------------------------------------------------------------
# Proxy-facing API — key validation
# ---------------------------------------------------------------------------

@api_bp.route('/api/v1/keys/validate', methods=['POST'])
def validate_key():
    """Called by server.mjs on every request to authenticate the API key.

    Expects JSON: {"key": "sk-vivus-..."}
    Returns 200 with user info or 401.
    """
    data = request.get_json(silent=True) or {}
    raw_key = data.get('key', '')

    if not raw_key:
        return jsonify({'valid': False, 'error': 'Missing key'}), 401

    api_key = ApiKey.lookup(raw_key)
    if not api_key:
        return jsonify({'valid': False, 'error': 'Invalid or revoked key'}), 401

    user = api_key.user
    if not user.is_active:
        return jsonify({'valid': False, 'error': 'User disabled'}), 401

    # Update last-used timestamp
    api_key.last_used_at = datetime.now(timezone.utc)
    db.session.commit()

    return jsonify({
        'valid': True,
        'user_id': user.id,
        'username': user.username,
        'is_admin': user.is_admin,
        'key_id': api_key.id,
    })


# ---------------------------------------------------------------------------
# Proxy-facing API — metrics / telemetry ingestion
# ---------------------------------------------------------------------------

@api_bp.route('/api/v1/metrics', methods=['POST'])
def ingest_metrics():
    """Called by server.mjs after each completed request to record usage.

    Expects JSON:
    {
      "key": "sk-vivus-...",
      "model": "qwen3.5:35b",
      "tier": "default",
      "prompt_tokens": 1234,
      "completion_tokens": 567,
      "total_tokens": 1801,
      "duration_ms": 4500,
      "endpoint": "/v1/messages"
    }
    """
    data = request.get_json(silent=True) or {}
    raw_key = data.get('key', '')

    api_key = ApiKey.lookup(raw_key) if raw_key else None
    if not api_key:
        # Accept metrics even if key is unknown — don't block on this
        return jsonify({'ok': True, 'warning': 'unknown key'}), 200

    record = UsageRecord(
        user_id=api_key.user_id,
        api_key_id=api_key.id,
        model=data.get('model', 'unknown'),
        tier=data.get('tier', 'default'),
        prompt_tokens=data.get('prompt_tokens', 0),
        completion_tokens=data.get('completion_tokens', 0),
        total_tokens=data.get('total_tokens', 0),
        duration_ms=data.get('duration_ms', 0),
        endpoint=data.get('endpoint', ''),
    )
    db.session.add(record)
    db.session.commit()

    return jsonify({'ok': True}), 200


# ---------------------------------------------------------------------------
# Portal UI — usage dashboard
# ---------------------------------------------------------------------------

@api_bp.route('/usage')
@login_required
def usage():
    """Per-user usage dashboard. Admins see all users."""
    from sqlalchemy import func

    if current_user.is_admin:
        # Totals across all users
        totals = db.session.query(
            func.count(UsageRecord.id).label('requests'),
            func.coalesce(func.sum(UsageRecord.prompt_tokens), 0).label('prompt'),
            func.coalesce(func.sum(UsageRecord.completion_tokens), 0).label('completion'),
            func.coalesce(func.sum(UsageRecord.total_tokens), 0).label('total'),
        ).first()
        # Per-user breakdown
        per_user = db.session.query(
            UsageRecord.user_id,
            func.count(UsageRecord.id).label('requests'),
            func.coalesce(func.sum(UsageRecord.total_tokens), 0).label('total_tokens'),
        ).group_by(UsageRecord.user_id).all()
        # Recent records
        recent = UsageRecord.query.order_by(UsageRecord.created_at.desc()).limit(50).all()
    else:
        totals = db.session.query(
            func.count(UsageRecord.id).label('requests'),
            func.coalesce(func.sum(UsageRecord.prompt_tokens), 0).label('prompt'),
            func.coalesce(func.sum(UsageRecord.completion_tokens), 0).label('completion'),
            func.coalesce(func.sum(UsageRecord.total_tokens), 0).label('total'),
        ).filter(UsageRecord.user_id == current_user.id).first()
        per_user = None
        recent = UsageRecord.query.filter_by(user_id=current_user.id) \
            .order_by(UsageRecord.created_at.desc()).limit(50).all()

    return render_template('usage.html', totals=totals, per_user=per_user, recent=recent)


# ---------------------------------------------------------------------------
# Admin — user management
# ---------------------------------------------------------------------------

@api_bp.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('index'))
    from models import User
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin_users.html', users=users)


@api_bp.route('/admin/users/<int:user_id>/toggle', methods=['POST'])
@login_required
def toggle_user(user_id):
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('index'))
    from models import User
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('Cannot disable yourself.', 'danger')
        return redirect(url_for('api.admin_users'))
    user.is_active_user = not user.is_active_user
    db.session.commit()
    status = 'enabled' if user.is_active_user else 'disabled'
    flash(f'User "{user.username}" {status}.', 'info')
    return redirect(url_for('api.admin_users'))

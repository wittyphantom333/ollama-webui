"""OAuth 2.0 (PKCE) browser surface for Vivus CLI sign-in.

GET/POST /oauth/authorize     — consent screen; issues an authorization code
GET      /oauth/code/callback — manual flow: shows `code#state` to copy
GET      /oauth/code/success  — sign-in complete page
GET      /buy_credits         — bounce target used by the CLI success redirect

Machine-facing endpoints (token exchange, key creation, roles) live on the
CSRF-exempt api blueprint in api_routes.py. These browser routes keep CSRF
protection — the consent form carries a csrf_token.
"""

from urllib.parse import urlparse, urlencode

from flask import Blueprint, request, redirect, render_template_string, url_for
from flask_login import login_required, current_user

from models import OAuthAuthCode, OAUTH_ALLOWED_CLIENT_IDS, OAUTH_GRANTED_SCOPE

oauth_bp = Blueprint('oauth', __name__, template_folder='templates')

MANUAL_CALLBACK_PATH = '/oauth/code/callback'


def _redirect_uri_allowed(uri):
    """Permit only loopback CLI callbacks and this portal's manual callback.

    This is the anti-exfiltration check: an authorization code is only ever
    handed to a localhost listener (the CLI on this machine) or shown on our
    own manual-callback page. It can never be redirected to an arbitrary host.
    """
    try:
        parsed = urlparse(uri)
    except ValueError:
        return False
    if parsed.path == '/callback' and parsed.hostname in ('localhost', '127.0.0.1', '::1'):
        return parsed.scheme in ('http', 'https')
    if parsed.path == MANUAL_CALLBACK_PATH:
        return True
    return False


def _append_query(uri, params):
    sep = '&' if '?' in uri else '?'
    return uri + sep + urlencode(params)


def _page(body, status=200, **ctx):
    html = render_template_string(
        '{% extends "base.html" %}'
        '{% block title %}Sign in \u2014 Vivus{% endblock %}'
        '{% block content %}' + body + '{% endblock %}',
        **ctx,
    )
    return (html, status) if status != 200 else html


_ERROR_BODY = (
    '<div class="row justify-content-center mt-5"><div class="col-md-6">'
    '<div class="card"><div class="card-header text-danger">'
    '<i class="fas fa-triangle-exclamation me-2"></i>{{ title }}</div>'
    '<div class="card-body"><p>{{ message }}</p>'
    '<a class="btn btn-secondary" href="/">Return home</a>'
    '</div></div></div></div>'
)


def _error_page(title, message, status=400):
    return _page(_ERROR_BODY, status=status, title=title, message=message)


_CONSENT_BODY = (
    '<div class="row justify-content-center mt-5"><div class="col-md-6">'
    '<div class="card"><div class="card-header">'
    '<i class="fas fa-terminal me-2"></i>Authorize Vivus CLI</div>'
    '<div class="card-body">'
    '<p>The <strong>Vivus CLI</strong> wants to sign in and create an API key '
    'on your behalf.</p>'
    '<p class="text-muted small">Signed in as <strong>{{ current_user.username }}</strong> '
    '({{ current_user.email }}). <a href="{{ url_for(\'auth.logout\') }}">Not you?</a></p>'
    '<form method="POST" action="{{ url_for(\'oauth.authorize\') }}">'
    '<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">'
    '{% for k, v in fields.items() %}'
    '<input type="hidden" name="{{ k }}" value="{{ v }}">'
    '{% endfor %}'
    '<div class="d-flex gap-2 mt-3">'
    '<button type="submit" name="decision" value="approve" class="btn btn-primary">'
    '<i class="fas fa-check me-1"></i> Authorize</button>'
    '<button type="submit" name="decision" value="deny" class="btn btn-outline-secondary">'
    'Cancel</button>'
    '</div></form>'
    '</div></div></div></div>'
)


@oauth_bp.route('/oauth/authorize', methods=['GET', 'POST'])
@login_required
def authorize():
    p = request.values
    client_id = p.get('client_id', '')
    redirect_uri = p.get('redirect_uri', '')
    response_type = p.get('response_type', 'code')
    code_challenge = p.get('code_challenge', '')
    method = p.get('code_challenge_method', '')
    state = p.get('state', '')

    if response_type != 'code':
        return _error_page('Unsupported request', 'Only the authorization code flow is supported.')
    if client_id not in OAUTH_ALLOWED_CLIENT_IDS:
        return _error_page('Unknown application', 'This client is not authorized to sign in with Vivus.')
    if method != 'S256' or not code_challenge:
        return _error_page('Bad request', 'A PKCE S256 challenge is required.')
    if not _redirect_uri_allowed(redirect_uri):
        return _error_page('Invalid redirect', 'The requested redirect target is not allowed.')

    if request.method == 'POST':
        if p.get('decision') != 'approve':
            return redirect(_append_query(redirect_uri, {'error': 'access_denied', 'state': state}))
        code = OAuthAuthCode.issue(
            user_id=current_user.id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            scope=OAUTH_GRANTED_SCOPE,
            state=state,
        )
        return redirect(_append_query(redirect_uri, {'code': code, 'state': state}))

    # GET → render the consent screen with all params echoed as hidden fields.
    return _page(_CONSENT_BODY, fields={
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': response_type,
        'code_challenge': code_challenge,
        'code_challenge_method': method,
        'state': state,
    })


_MANUAL_BODY = (
    '<div class="row justify-content-center mt-5"><div class="col-md-7">'
    '<div class="card"><div class="card-header">'
    '<i class="fas fa-key me-2"></i>Finish signing in</div>'
    '<div class="card-body">'
    '<p>Copy this code and paste it back into the Vivus CLI:</p>'
    '<div class="input-group mb-2">'
    '<input id="vivus-code" type="text" class="form-control font-monospace" '
    'value="{{ combined }}" readonly onclick="this.select()">'
    '<button class="btn btn-primary" type="button" '
    'onclick="navigator.clipboard.writeText(document.getElementById(\'vivus-code\').value)">'
    '<i class="fas fa-copy me-1"></i> Copy</button>'
    '</div>'
    '<p class="text-muted small mb-0">You can close this tab once the CLI confirms sign-in.</p>'
    '</div></div></div></div>'
)


@oauth_bp.route('/oauth/code/callback')
def manual_callback():
    error = request.args.get('error', '')
    if error:
        return _error_page('Sign-in cancelled', 'The request was not approved (%s).' % error, status=200)
    code = request.args.get('code', '')
    state = request.args.get('state', '')
    return _page(_MANUAL_BODY, combined='%s#%s' % (code, state))


@oauth_bp.route('/oauth/code/success')
def success():
    return _page(
        '<div class="row justify-content-center mt-5"><div class="col-md-6">'
        '<div class="card"><div class="card-header text-success">'
        '<i class="fas fa-circle-check me-2"></i>Signed in</div>'
        '<div class="card-body"><p>You\'re signed in to the Vivus CLI. '
        'You can close this tab and return to your terminal.</p>'
        '</div></div></div></div>'
    )


@oauth_bp.route('/buy_credits')
def buy_credits():
    """The CLI's console success redirect bounces through here; forward to the
    local returnUrl (the success page) and never to an external host."""
    ret = request.args.get('returnUrl', '')
    if ret.startswith('/') and not ret.startswith('//'):
        return redirect(ret)
    return redirect(url_for('oauth.success'))

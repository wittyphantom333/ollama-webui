#!/bin/bash

# Deployment script for Vivus Portal
# Deploys to remote server at 10.5.143.213
#
# Production layout (on remote):
#   /home/witt/vivus/portal/        — app code
#   /home/witt/vivus/portal/venv/   — virtualenv (has flask + gunicorn)
#   ~/.config/systemd/user/vivus-portal.service  — gunicorn unit
#
# The portal is managed by systemd --user (matches the proxy). To change the
# command line (workers, timeout, bind) edit the unit on the host, not this
# script. This script only ships code + restarts the service.

set -e

SSH_TARGET="witt@10.5.143.213"
REMOTE_DIR="/home/witt/vivus/portal"

echo "==> Copying files to ${SSH_TARGET}:${REMOTE_DIR}"
tar -cz \
    --exclude='.git' \
    --exclude='*.pyc' \
    --exclude='__pycache__' \
    --exclude='.venv' \
    --exclude='venv' \
    --exclude='instance' \
    --exclude='*.log' \
    -f - . | ssh "$SSH_TARGET" "cd ${REMOTE_DIR} && tar -xz"

echo "==> Ensuring deps are up to date (venv with gunicorn)"
ssh "$SSH_TARGET" "cd ${REMOTE_DIR} && \
    if [ ! -d venv ]; then python3 -m venv venv; fi && \
    source venv/bin/activate && \
    pip install -q flask flask-login flask-sqlalchemy flask-wtf python-dotenv requests markdown gunicorn"

echo "==> Restarting vivus-portal.service via systemd --user"
ssh "$SSH_TARGET" "systemctl --user restart vivus-portal.service && \
    sleep 2 && \
    systemctl --user is-active vivus-portal.service && \
    curl -s -o /dev/null -w 'internal GET / -> %{http_code} in %{time_total}s\n' http://127.0.0.1:5050/"

echo "==> Deployment complete"
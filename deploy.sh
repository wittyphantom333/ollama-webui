#!/bin/bash

# Deployment script for Vivus Portal
# Deploys to remote server at 10.5.143.213

echo "Starting deployment to remote server..."

# Copy files to remote server
echo "Copying files to remote server..."
tar -cz --exclude='.git' --exclude='*.pyc' --exclude='__pycache__' --exclude='.venv' --exclude='instance' --exclude='*.log' -f - . | ssh witt@10.5.143.213 "cd /home/witt/vivus/portal && tar -xz"

# Restart the application on remote server
echo "Restarting application on remote server..."
ssh 10.5.143.213 '
cd /home/witt/vivus/portal

# Kill existing process if running
PID=$(ps aux | grep "flask run" | grep -v grep | awk "{print \$2}")
if [ ! -z "$PID" ]; then
    echo "Killing existing process $PID"
    kill $PID
    sleep 2
fi

# Install/update dependencies
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install -q flask flask-login flask-sqlalchemy flask-wtf python-dotenv requests markdown gunicorn 2>/dev/null

# Start the application
echo "Starting application..."
nohup python -m flask run --host=0.0.0.0 --port=5050 > /tmp/vivus-portal.log 2>&1 &
echo "Application started with PID $!"
'

echo "Deployment completed!"
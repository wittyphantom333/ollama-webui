# Deployment Process

## Overview
This document describes how to deploy updates to the Vivus Portal application on a remote server.

## Deployment Methods

### Method 1: Automated Deployment Script (Recommended)

For the current deployment at 10.5.143.213, use the provided deployment script:

```bash
./deploy.sh
```

This script will:
1. Copy all updated files to the remote server
2. Kill the existing process
3. Start the application with the new code

### Method 2: Direct Code Deployment (Non-Docker)

1. **Push changes to GitHub:**
   ```bash
   git add .
   git commit -m "Description of changes"
   git push origin main
   ```

2. **On the remote server:**
   ```bash
   # Navigate to the application directory
   cd /home/witt/vivus/portal
   
   # Copy updated files manually or using rsync
   # (This depends on how you transfer files)
   
   # Kill existing process
   PID=$(ps aux | grep "flask run" | grep -v grep | awk "{print \$2}")
   if [ ! -z "$PID" ]; then
       kill $PID
   fi
   
   # Start the application
   source .venv/bin/activate
   nohup python -m flask run --host=0.0.0.0 --port=5050 > /tmp/vivus-portal.log 2>&1 &
   ```

### Method 3: Docker Deployment

1. **Push changes to GitHub:**
   ```bash
   git add .
   git commit -m "Description of changes"
   git push origin main
   ```

2. **Build and push the Docker image (if using GitHub Container Registry):**
   ```bash
   docker build -t ghcr.io/wittyphantom333/ollama-webui:latest .
   docker push ghcr.io/wittyphantom333/ollama-webui:latest
   ```

3. **On the remote server:**
   ```bash
   # Navigate to the application directory
   cd /home/witt/vivus/portal
   
   # Pull the latest docker-compose.yml if it changed
   git pull origin main
   
   # Pull the latest Docker image
   docker-compose pull
   
   # Restart the containers
   docker-compose down
   docker-compose up -d
   ```

## Common Issues and Solutions

### Application Not Starting After Update
- Check if all required environment variables are set
- Verify that the .env file exists and has the correct values
- Ensure all dependencies are installed (pip install -r requirements.txt)

### CSS Changes Not Visible
- Clear browser cache
- Restart the application to ensure static files are reloaded
- Check that the CSS file path is correct in the templates

## Monitoring Deployment
- Check application logs: `tail -f /tmp/vivus-portal.log`
- Verify the application is running: `curl http://localhost:5050`
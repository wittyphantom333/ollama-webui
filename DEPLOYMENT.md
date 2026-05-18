# Deployment Process

## Overview
This document describes how to deploy updates to the Vivus Portal application on a remote server.

## Deployment Methods

### Method 1: Direct Code Deployment (Non-Docker)

1. **Push changes to GitHub:**
   ```bash
   git add .
   git commit -m "Description of changes"
   git push origin main
   ```

2. **On the remote server:**
   ```bash
   # Navigate to the application directory
   cd /path/to/vivus-portal
   
   # Pull the latest changes
   git pull origin main
   
   # If there are new dependencies, update them
   source .venv/bin/activate
   pip install -r requirements.txt
   
   # Restart the application
   # This depends on how the application is running (systemd, screen, etc.)
   ```

### Method 2: Docker Deployment

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
   cd /path/to/vivus-portal
   
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
- Check application logs: `tail -f /var/log/vivus-portal.log` (or wherever logs are stored)
- Verify the application is running: `curl http://localhost:5000`
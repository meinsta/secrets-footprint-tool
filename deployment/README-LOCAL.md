# 🏠 Local Development Deployment Guide

## Quick Local Setup (5 minutes)

This guide helps you deploy the Secrets Assessment Tool locally on your Mac for testing and development.

### Prerequisites
1. **Docker Desktop** - Install from https://docs.docker.com/desktop/install/mac-install/
2. **Git** - Already available on macOS
3. **Terminal access** - You're already here!

### Step 1: Start Docker Desktop
```bash
# Open Docker Desktop application
open -a Docker

# Wait for Docker to start (look for Docker whale icon in menu bar)
# Verify Docker is running:
docker info
```

### Step 2: Deploy Locally
```bash
# Navigate to the project directory (you're already here)
cd /Users/meinaghafouri/secrets-footprint-tool

# Run the local deployment script
./deployment/deploy-local.sh
```

### Step 3: Access Your Local Instance

After deployment completes (3-5 minutes), you'll have:

**🌐 Web Interface:** 
- URL: https://localhost:8443
- Username: admin (created during setup)
- MFA: Will be configured on first login

**🖥️ CLI Access:**
- SSH: `ssh -p 2222 assessment@localhost`  
- Certificate-based access (no passwords)

**📊 Monitoring:**
- Prometheus: http://localhost:9090
- Container logs: `docker logs secrets-assessment-tool`

### Step 4: Run Your First Assessment
1. Open https://localhost:8443 in your browser
2. Accept the self-signed certificate warning
3. Set up your admin account with MFA
4. Click "Start New Assessment"
5. Follow the guided process

### Stopping the Stack
```bash
# Stop all services
cd deployment/docker
docker-compose -f docker-compose.local.yml down

# Remove all data (optional - for complete reset)
docker-compose -f docker-compose.local.yml down -v
```

### Viewing Logs
```bash
# View all service logs
docker-compose -f deployment/docker/docker-compose.local.yml logs -f

# View specific service logs
docker logs teleport-proxy
docker logs secrets-assessment-tool
```

### Troubleshooting
1. **Docker not starting:** Ensure Docker Desktop is running
2. **Port conflicts:** Stop other services using ports 8443, 2222, 9090
3. **Permission errors:** Ensure proper file permissions: `chmod +x deployment/deploy-local.sh`

## Security Notes for Local Deployment
- ✅ Self-signed certificates (browser warnings are normal)
- ✅ MFA still required
- ✅ Session recording enabled
- ✅ All containers run as non-root
- ⚠️ Only use for testing - not production ready

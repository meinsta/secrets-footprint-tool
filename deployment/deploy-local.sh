#!/bin/bash

# Local Development Deployment Script
# Simplified version for local testing on macOS

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

echo "======================================================="
echo "🏠 Local Secrets Assessment Tool Deployment"
echo "======================================================="
echo ""

# Check Docker
log_info "Checking Docker installation..."
if ! command -v docker &> /dev/null; then
    log_error "Docker not found. Please install Docker Desktop first:
    https://docs.docker.com/desktop/install/mac-install/"
fi

if ! docker info &> /dev/null; then
    log_error "Docker is not running. Please start Docker Desktop."
fi

log_success "Docker is ready"

# Create local directories
log_info "Setting up local directories..."
mkdir -p deployment/docker/volumes/{teleport-data,teleport-certs,assessment-data,audit-logs,backups}
mkdir -p deployment/docker/{config,ssl}

# Generate self-signed certificate for local testing
log_info "Generating local SSL certificate..."
if [[ ! -f deployment/docker/ssl/tls.crt ]]; then
    openssl req -x509 -newkey rsa:2048 -keyout deployment/docker/ssl/tls.key \
        -out deployment/docker/ssl/tls.crt -days 365 -nodes \
        -subj "/C=US/ST=CA/L=Local/O=Development/CN=localhost"
    chmod 600 deployment/docker/ssl/tls.key
fi

# Create local docker-compose file
log_info "Creating local configuration..."
cat > deployment/docker/docker-compose.local.yml << 'EOF'
version: '3.8'

networks:
  teleport-net:
    driver: bridge

services:
  # Teleport Auth Server for local development
  teleport-auth:
    image: public.ecr.aws/gravitational/teleport:13
    container_name: teleport-auth
    networks:
      - teleport-net
    volumes:
      - ./volumes/teleport-data:/var/lib/teleport
      - ./config/teleport-local.yaml:/etc/teleport/teleport.yaml:ro
    ports:
      - "3025:3025"
    command: ["teleport", "start", "--config=/etc/teleport/teleport.yaml"]
    environment:
      - TELEPORT_CLUSTER_NAME=local-assessment
    restart: unless-stopped

  # Teleport Proxy for web access
  teleport-proxy:
    image: public.ecr.aws/gravitational/teleport:13
    container_name: teleport-proxy
    networks:
      - teleport-net
    volumes:
      - ./ssl:/etc/ssl/certs:ro
      - ./config/teleport-local.yaml:/etc/teleport/teleport.yaml:ro
    ports:
      - "8443:3080"  # Web UI
      - "2222:3023"  # SSH
    command: ["teleport", "start", "--config=/etc/teleport/teleport.yaml", "--roles=proxy"]
    environment:
      - TELEPORT_AUTH_SERVER=teleport-auth:3025
    depends_on:
      - teleport-auth
    restart: unless-stopped

  # Assessment Tool
  assessment-tool:
    build:
      context: ../../
      dockerfile: deployment/docker/Dockerfile.local
    container_name: secrets-assessment-tool
    networks:
      - teleport-net
    volumes:
      - ./volumes/assessment-data:/app/data
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=development
      - FLASK_DEBUG=false
    restart: unless-stopped

  # Simple monitoring
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    networks:
      - teleport-net
    ports:
      - "9090:9090"
    restart: unless-stopped
EOF

# Create simplified Teleport config for local use
cat > deployment/docker/config/teleport-local.yaml << 'EOF'
version: v3
teleport:
  cluster_name: "local-assessment"
  data_dir: /var/lib/teleport
  log:
    output: stderr
    severity: INFO

auth_service:
  enabled: true
  cluster_name: "local-assessment"
  authentication:
    type: local
    second_factor: off  # Disabled for local development
  session_recording: node-sync

proxy_service:
  enabled: true
  web_listen_addr: "0.0.0.0:3080"
  tunnel_listen_addr: "0.0.0.0:3024"
  public_addr: "localhost:8443"
  https_keypairs:
  - key_file: /etc/ssl/certs/tls.key
    cert_file: /etc/ssl/certs/tls.crt

ssh_service:
  enabled: true
  listen_addr: "0.0.0.0:3023"
  labels:
    service: "local-assessment"
    environment: "development"

app_service:
  enabled: true
  apps:
  - name: "secrets-footprint"
    uri: "http://assessment-tool:5000"
    public_addr: "localhost:8443"
    labels:
      app: "secrets-footprint"
EOF

# Create simplified Dockerfile for local development
cat > deployment/docker/Dockerfile.local << 'EOF'
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    openssh-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -u 1001 assessment
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY --chown=assessment:assessment . .
USER assessment

# Add health endpoint for local testing
RUN echo 'from flask import Flask, jsonify
app = Flask(__name__)
@app.route("/health")
def health():
    return jsonify({"status": "healthy"})
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)' > health_server.py

EXPOSE 5000
CMD ["python3", "run_webapp.py"]
EOF

# Deploy locally
log_info "Building and starting services..."
cd deployment/docker

# Build the assessment tool
docker-compose -f docker-compose.local.yml build assessment-tool

# Start services
docker-compose -f docker-compose.local.yml up -d

# Wait for services to start
log_info "Waiting for services to start..."
sleep 15

# Check if services are running
if docker-compose -f docker-compose.local.yml ps | grep -q "Up"; then
    log_success "Services are starting up!"
else
    log_error "Some services failed to start. Check logs with: docker-compose -f deployment/docker/docker-compose.local.yml logs"
fi

cd ../..

# Create initial admin user
log_info "Creating admin user..."
sleep 5  # Wait for Teleport to initialize

# Simple user creation for local development
docker exec -it teleport-auth tctl users add admin --roles=editor,access --logins=root,assessment > admin-invite.txt 2>&1 || true

echo ""
log_success "Local deployment completed!"
echo ""
echo "🌐 ACCESS YOUR LOCAL INSTANCE:"
echo "================================"
echo "Web Interface: https://localhost:8443"
echo "  (Accept the certificate warning - it's self-signed)"
echo ""
echo "SSH Access: ssh -p 2222 assessment@localhost"
echo "Monitoring: http://localhost:9090"
echo ""
echo "📋 NEXT STEPS:"
echo "1. Open https://localhost:8443 in your browser"
echo "2. Set up your admin account (check admin-invite.txt for invite link)"
echo "3. Start a new assessment!"
echo ""
echo "🔧 MANAGEMENT COMMANDS:"
echo "Stop:     cd deployment/docker && docker-compose -f docker-compose.local.yml down"
echo "Logs:     docker-compose -f deployment/docker/docker-compose.local.yml logs -f"
echo "Restart:  docker-compose -f deployment/docker/docker-compose.local.yml restart"
echo ""
log_warning "This is a LOCAL DEVELOPMENT setup only - not for production use!"

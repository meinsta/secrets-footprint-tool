#!/bin/bash

# Keyless Deployment Script for Secrets Assessment Tool
# Uses Teleport certificates instead of SSH keys for maximum security

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

# Configuration
DOMAIN="${DOMAIN:-assessment.company.com}"
CERT_EMAIL="${CERT_EMAIL:-security@company.com}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@company.com}"
CLOUD_PROVIDER="${CLOUD_PROVIDER:-digitalocean}"

print_header() {
    echo ""
    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}======================================${NC}"
    echo ""
}

# Generate cloud-init script for keyless deployment
generate_cloud_init() {
    print_header "Generating Cloud-Init Script"
    
    cat > deployment/cloud-init.yml << 'EOF'
#cloud-config

# Keyless Secrets Assessment Tool Deployment
# This script automatically deploys the tool without requiring SSH keys

users:
  - name: assessment
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true  # No password login
    ssh_authorized_keys: []  # No SSH keys

package_update: true
package_upgrade: true

packages:
  - docker.io
  - docker-compose
  - curl
  - jq
  - git
  - unzip
  - certbot
  - ufw

write_files:
  # Teleport configuration
  - path: /opt/teleport/teleport.yaml
    permissions: '0600'
    owner: assessment:assessment
    content: |
      version: v3
      teleport:
        cluster_name: secrets-assessment
        data_dir: /var/lib/teleport
        log:
          output: stderr
          severity: INFO
      
      auth_service:
        enabled: true
        cluster_name: secrets-assessment
        listen_addr: 0.0.0.0:3025
        
        # Certificate-based authentication only
        authentication:
          type: local
          second_factor: webauthn  # Hardware keys preferred
          webauthn:
            rp_id: DOMAIN_PLACEHOLDER
            attestation_allowed_cas: []
            attestation_denied_cas: []
          connector_name: ""
          require_session_mfa: true
          
        # Session settings
        session_recording: node-sync
        session_control_timeout: 30s
        client_idle_timeout: 2h
        disconnect_expired_cert: true
        
        # Certificate settings
        ca_key_params:
          pkcs11:
            module_path: ""
            slot_number: 0
            pin: ""
        
        # Cluster networking
        cluster_networking_config:
          client_idle_timeout: 1h
          session_control_timeout: 2h
          
      proxy_service:
        enabled: true
        web_listen_addr: 0.0.0.0:3080
        tunnel_listen_addr: 0.0.0.0:3024
        public_addr: DOMAIN_PLACEHOLDER:443
        
        # ACME for automatic certificates
        acme:
          enabled: true
          email: CERT_EMAIL_PLACEHOLDER
          
      ssh_service:
        enabled: true
        listen_addr: 0.0.0.0:3022
        labels:
          service: secrets-assessment
          environment: production
          auth_method: certificate-only
        
        # Enhanced session recording
        enhanced_recording:
          enabled: true
          command_buffer_size: 8192
          disk_buffer_size: 128000000
          network_buffer_size: 65536
        
        # Disable password authentication completely
        permit_user_env: false
        pam:
          enabled: false

  # Firewall configuration
  - path: /opt/setup/configure-firewall.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      # Configure secure firewall
      ufw --force reset
      ufw default deny incoming
      ufw default allow outgoing
      
      # Allow only Teleport ports
      ufw allow 443/tcp    # HTTPS/Teleport Web
      ufw allow 3023/tcp   # Teleport SSH Proxy
      ufw allow 3024/tcp   # Teleport Tunnel
      
      # Optional: Restrict to specific IPs
      # ufw allow from YOUR_OFFICE_IP to any port 443
      
      ufw --force enable
      log_info "Firewall configured - only Teleport ports open"

  # Main deployment script
  - path: /opt/setup/deploy-assessment.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      set -euo pipefail
      
      log_info() { echo "[$(date)] INFO: $1"; }
      log_error() { echo "[$(date)] ERROR: $1"; exit 1; }
      
      log_info "Starting keyless deployment..."
      
      # Create application user
      useradd -r -s /bin/false -m -d /opt/assessment assessment || true
      
      # Clone repository
      cd /opt/assessment
      git clone https://github.com/meinsta/secrets-footprint-tool.git . || true
      chown -R assessment:assessment /opt/assessment
      
      # Install Teleport
      cd /tmp
      curl -O https://cdn.teleport.dev/teleport_14.0.0_amd64.deb
      dpkg -i teleport_14.0.0_amd64.deb
      
      # Replace placeholders in Teleport config
      sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN/g" /opt/teleport/teleport.yaml
      sed -i "s/CERT_EMAIL_PLACEHOLDER/$CERT_EMAIL/g" /opt/teleport/teleport.yaml
      
      # Create systemd service for Teleport
      cat > /etc/systemd/system/teleport.service << 'TELEPORT_EOF'
      [Unit]
      Description=Teleport SSH Server
      After=network.target
      
      [Service]
      Type=simple
      User=assessment
      Group=assessment
      ExecStart=/usr/local/bin/teleport start --config=/opt/teleport/teleport.yaml
      ExecReload=/bin/kill -HUP $MAINPID
      PIDFile=/var/lib/teleport/teleport.pid
      LimitNOFILE=65536
      
      [Install]
      WantedBy=multi-user.target
      TELEPORT_EOF
      
      # Set up directories
      mkdir -p /var/lib/teleport /var/log/teleport
      chown -R assessment:assessment /var/lib/teleport /var/log/teleport /opt/teleport
      
      # Start Teleport
      systemctl daemon-reload
      systemctl enable teleport
      systemctl start teleport
      
      # Wait for Teleport to initialize
      sleep 30
      
      # Deploy assessment tool containers
      cd /opt/assessment/deployment/docker
      
      # Build and start assessment tool
      docker-compose -f docker-compose.keyless.yml build
      docker-compose -f docker-compose.keyless.yml up -d
      
      log_info "Deployment completed successfully!"
      
      # Create initial admin user
      sleep 10
      INVITE_LINK=$(tctl users add admin security-admin --logins=assessment --ttl=24h)
      
      echo "======================================"
      echo "DEPLOYMENT COMPLETED!"
      echo "======================================"
      echo ""
      echo "Access your secure assessment tool:"
      echo "Web Interface: https://$DOMAIN"
      echo ""
      echo "Admin Setup Link (expires in 24h):"
      echo "$INVITE_LINK"
      echo ""
      echo "Save this link securely!"
      echo "======================================"

runcmd:
  # Update hostname
  - hostnamectl set-hostname secrets-assessment-prod
  
  # Add assessment user to docker group
  - usermod -aG docker assessment
  
  # Run setup scripts
  - /opt/setup/configure-firewall.sh
  - /opt/setup/deploy-assessment.sh > /var/log/deployment.log 2>&1

final_message: |
  Keyless Secrets Assessment Tool deployment completed!
  Check /var/log/deployment.log for details.
  Access via: https://DOMAIN_PLACEHOLDER
EOF

    # Replace placeholders
    sed -i.bak "s/DOMAIN_PLACEHOLDER/$DOMAIN/g" deployment/cloud-init.yml
    sed -i.bak "s/CERT_EMAIL_PLACEHOLDER/$CERT_EMAIL/g" deployment/cloud-init.yml
    rm deployment/cloud-init.yml.bak
    
    log_success "Cloud-init script generated"
}

# Generate keyless Docker Compose
generate_keyless_compose() {
    print_header "Generating Keyless Docker Compose"
    
    mkdir -p deployment/docker
    cat > deployment/docker/docker-compose.keyless.yml << 'EOF'
version: '3.8'

services:
  # Assessment Tool - Certificate access only
  assessment-tool:
    build:
      context: ../../
      dockerfile: deployment/docker/Dockerfile.keyless
    hostname: assessment-tool
    container_name: assessment-tool
    restart: unless-stopped
    environment:
      - AUTH_MODE=certificate-only
      - TELEPORT_PROXY=localhost:3023
      - DOMAIN=${DOMAIN}
    volumes:
      - assessment_data:/app/data
      - assessment_logs:/app/logs
      - /var/lib/teleport:/var/lib/teleport:ro  # Access to certificates
    networks:
      - assessment_network
    depends_on:
      - teleport-proxy
    security_opt:
      - no-new-privileges:true
    user: "1000:1000"
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=100m

  # Web-based access portal
  web-portal:
    build:
      context: ../../
      dockerfile: deployment/docker/Dockerfile.portal
    hostname: web-portal
    container_name: web-portal
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - TELEPORT_ADDR=localhost:3023
      - DOMAIN=${DOMAIN}
    volumes:
      - portal_data:/app/data:ro
    networks:
      - assessment_network
    security_opt:
      - no-new-privileges:true
    user: "1000:1000"

  # Certificate manager
  cert-manager:
    image: certbot/certbot:latest
    hostname: cert-manager
    container_name: cert-manager
    volumes:
      - letsencrypt_certs:/etc/letsencrypt
      - letsencrypt_lib:/var/lib/letsencrypt
    networks:
      - assessment_network
    command: >
      sh -c "while :; do
        certbot renew --quiet --no-self-upgrade --post-hook 'killall -USR1 teleport || true'
        sleep 86400
      done"

  # Monitoring without SSH access
  monitoring:
    image: prom/prometheus:v2.48.0
    hostname: monitoring
    container_name: monitoring
    restart: unless-stopped
    ports:
      - "127.0.0.1:9090:9090"  # Only localhost access
    volumes:
      - prometheus_data:/prometheus
      - ./config/prometheus-keyless.yml:/etc/prometheus/prometheus.yml:ro
    networks:
      - assessment_network
    security_opt:
      - no-new-privileges:true
    user: "65534:65534"

volumes:
  assessment_data:
  assessment_logs:
  portal_data:
  letsencrypt_certs:
  letsencrypt_lib:
  prometheus_data:

networks:
  assessment_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.22.0.0/16
EOF

    log_success "Keyless Docker Compose generated"
}

# Generate keyless Dockerfile
generate_keyless_dockerfile() {
    print_header "Generating Keyless Application Dockerfile"
    
    cat > deployment/docker/Dockerfile.keyless << 'EOF'
# Keyless Application Container
FROM python:3.11-slim-bullseye as builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage - certificate authentication only
FROM python:3.11-slim-bullseye

# Install Teleport client for certificate-based access
RUN curl -O https://cdn.teleport.dev/teleport_14.0.0_amd64.deb \
    && dpkg -i teleport_14.0.0_amd64.deb \
    && rm teleport_14.0.0_amd64.deb

# Create non-root user
RUN groupadd -r assessment && useradd -r -g assessment -u 1000 assessment

WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /root/.local /home/assessment/.local

# Copy application code
COPY --chown=assessment:assessment . .

# Remove any SSH-related files
RUN find /app -name "*.key" -type f -delete \
    && find /app -name "*.pem" -type f -delete \
    && find /app -name "*ssh*" -type f -delete \
    && rm -rf /app/.ssh /home/assessment/.ssh

# Create secure directories
RUN mkdir -p /app/{data,logs,config,certs} \
    && chown -R assessment:assessment /app \
    && chmod 700 /app/certs

# Switch to non-root user
USER assessment

# Set environment for certificate-only access
ENV PATH="/home/assessment/.local/bin:$PATH"
ENV PYTHONPATH="/app"
ENV TELEPORT_AUTH_TYPE="certificate"
ENV SSH_AUTH_SOCK=""

# Health check without SSH
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import assessment_tool; print('OK')" || exit 1

# Entry point for certificate-based access
CMD ["python", "/app/assessment_tool.py", "--auth-mode=certificate"]
EOF

    log_success "Keyless Dockerfile generated"
}

# Generate web portal for certificate access
generate_web_portal() {
    print_header "Generating Web Access Portal"
    
    cat > deployment/docker/Dockerfile.portal << 'EOF'
# Web Portal for Certificate-Based Access
FROM python:3.11-slim-bullseye

RUN pip install flask teleport-lib qrcode[pil] pyotp

WORKDIR /app

COPY deployment/portal/ .

USER 1000:1000

EXPOSE 8080

CMD ["python", "portal.py"]
EOF

    mkdir -p deployment/portal
    cat > deployment/portal/portal.py << 'EOF'
#!/usr/bin/env python3
"""
Web Portal for Certificate-Based Access
Provides secure web interface for getting short-lived certificates
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for
import subprocess
import json
import qrcode
import io
import base64
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    """Handle MFA login and certificate generation"""
    username = request.form.get('username')
    mfa_code = request.form.get('mfa_code')
    
    try:
        # Validate MFA and get certificate
        result = subprocess.run([
            'tctl', 'auth', 'login',
            '--user', username,
            '--otp', mfa_code,
            '--format', 'json'
        ], capture_output=True, text=True, check=True)
        
        cert_info = json.loads(result.stdout)
        
        return jsonify({
            'success': True,
            'certificate': cert_info,
            'expires': cert_info.get('expires', 'Unknown'),
            'access_url': f"https://{os.environ.get('DOMAIN')}"
        })
        
    except subprocess.CalledProcessError as e:
        return jsonify({
            'success': False,
            'error': 'Invalid credentials or MFA code'
        }), 401

@app.route('/setup-mfa')
def setup_mfa():
    """Generate QR code for MFA setup"""
    # Generate TOTP secret and QR code
    # This would integrate with Teleport's MFA setup
    return render_template('mfa_setup.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
EOF

    mkdir -p deployment/portal/templates
    cat > deployment/portal/templates/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Secure Assessment Access</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto; }
        .container { max-width: 400px; margin: 50px auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"] { 
            width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; 
        }
        button { 
            width: 100%; padding: 12px; background: #007bff; color: white; 
            border: none; border-radius: 4px; cursor: pointer; font-size: 16px; 
        }
        button:hover { background: #0056b3; }
        .security-notice { 
            background: #f8f9fa; border: 1px solid #dee2e6; 
            border-radius: 4px; padding: 15px; margin-bottom: 20px; 
        }
        .success { color: green; }
        .error { color: red; }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔒 Secure Assessment Access</h2>
        
        <div class="security-notice">
            <strong>Certificate-Based Authentication</strong><br>
            ✅ No SSH keys required<br>
            ✅ Short-lived certificates (2 hours)<br>
            ✅ Multi-factor authentication<br>
            ✅ Complete audit trail
        </div>
        
        <form id="loginForm">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="mfa_code">MFA Code (from app):</label>
                <input type="text" id="mfa_code" name="mfa_code" required placeholder="123456">
            </div>
            
            <button type="submit">Get Access Certificate</button>
        </form>
        
        <div id="result"></div>
        
        <p><a href="/setup-mfa">Set up MFA device</a></p>
    </div>

    <script>
        document.getElementById('loginForm').onsubmit = async function(e) {
            e.preventDefault();
            const formData = new FormData(e.target);
            
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                const resultDiv = document.getElementById('result');
                
                if (result.success) {
                    resultDiv.innerHTML = `
                        <div class="success">
                            <h3>✅ Access Granted!</h3>
                            <p>Certificate expires: ${result.expires}</p>
                            <a href="${result.access_url}" target="_blank">Open Assessment Tool</a>
                        </div>
                    `;
                } else {
                    resultDiv.innerHTML = `<div class="error">❌ ${result.error}</div>`;
                }
            } catch (error) {
                document.getElementById('result').innerHTML = 
                    `<div class="error">❌ Connection error</div>`;
            }
        };
    </script>
</body>
</html>
EOF

    log_success "Web access portal generated"
}

# Generate DigitalOcean deployment instructions
generate_digitalocean_instructions() {
    print_header "Generating DigitalOcean Keyless Instructions"
    
    cat > deployment/DIGITALOCEAN-KEYLESS.md << 'EOF'
# DigitalOcean Keyless Deployment Guide

## 🚀 Deploy Without SSH Keys

This guide shows how to deploy the Secrets Assessment Tool using **certificate-based authentication only** - no SSH keys required!

### Step 1: Create DigitalOcean Droplet

1. **Go to:** https://digitalocean.com → Create → Droplets
2. **Image:** Ubuntu 22.04 (LTS) x64
3. **Plan:** Basic - $48/month (2 vCPU, 4GB RAM, 80GB SSD)
4. **Authentication:** ❌ **Skip SSH Keys completely**
5. **Advanced Options → User Data:** Paste the contents of `deployment/cloud-init.yml`
6. **Hostname:** `secrets-assessment-keyless`
7. **Create Droplet**

### Step 2: Wait for Automatic Deployment

- ⏱️ **Wait 5-10 minutes** for automatic deployment
- 📋 **Check logs:** DigitalOcean Console → Access → Launch Console → `tail -f /var/log/deployment.log`

### Step 3: Access Your Secure Tool

1. **Domain Setup:** Point your domain to the droplet IP
2. **Access:** `https://yourdomain.com`
3. **First Login:** Use the admin invite link from deployment logs
4. **Set up MFA:** Scan QR code with authenticator app

### Step 4: Create Team Members

```bash
# Get temporary access to create users (via browser console)
tctl users add john.doe security-assessor --logins=assessment --ttl=8h
```

## 🔒 Security Benefits

✅ **No SSH Keys:** Zero long-lived credentials
✅ **Short Certificates:** 2-8 hour expiry maximum  
✅ **MFA Required:** Hardware keys or TOTP
✅ **Complete Audit:** Every action logged
✅ **Zero Trust:** Certificate validation on every connection

## 🆘 Recovery Access

If you lose access:
1. **DigitalOcean Console:** Access → Launch Console (browser-based)
2. **Reset Admin:** `sudo tctl users reset admin`
3. **Create New User:** `sudo tctl users add recovery-admin security-admin`

**No SSH keys to lose or compromise!** 🎉
EOF

    log_success "DigitalOcean keyless instructions generated"
}

# Main function
main() {
    print_header "🔑 KEYLESS DEPLOYMENT GENERATOR"
    
    log_info "Generating keyless deployment configuration..."
    log_info "Domain: $DOMAIN"
    log_info "Cloud Provider: $CLOUD_PROVIDER"
    
    # Generate all keyless components
    generate_cloud_init
    generate_keyless_compose
    generate_keyless_dockerfile
    generate_web_portal
    generate_digitalocean_instructions
    
    print_header "✅ KEYLESS DEPLOYMENT READY"
    
    echo -e "${GREEN}Generated Files:${NC}"
    echo "📄 deployment/cloud-init.yml - Automatic server setup"
    echo "🐳 deployment/docker/docker-compose.keyless.yml - Keyless containers"
    echo "🏗️  deployment/docker/Dockerfile.keyless - Certificate-only app"
    echo "🌐 deployment/portal/ - Web access portal"
    echo "📋 deployment/DIGITALOCEAN-KEYLESS.md - Step-by-step guide"
    
    echo ""
    log_info "Next Steps:"
    echo "1. Set your domain: export DOMAIN='assessment.yourcompany.com'"
    echo "2. Follow the guide: deployment/DIGITALOCEAN-KEYLESS.md"
    echo "3. Create droplet with cloud-init.yml as user data"
    echo "4. Access via web browser - no SSH needed!"
    
    echo ""
    log_success "🚀 Ready for keyless deployment!"
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

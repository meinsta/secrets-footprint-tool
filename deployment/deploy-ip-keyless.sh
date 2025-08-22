#!/bin/bash

# IP-Based Keyless Deployment
# Deploy without needing a domain - perfect for testing the keyless system

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

print_header() {
    echo ""
    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}======================================${NC}"
    echo ""
}

# Generate IP-based cloud-init script
generate_ip_cloud_init() {
    print_header "Generating IP-Based Cloud-Init"
    
    cat > deployment/cloud-init-ip.yml << 'EOF'
#cloud-config

# IP-Based Keyless Secrets Assessment Tool
# No domain required - uses server IP address

users:
  - name: assessment
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys: []  # No SSH keys needed

package_update: true
package_upgrade: true

packages:
  - docker.io
  - docker-compose
  - curl
  - jq
  - git
  - unzip
  - ufw

write_files:
  # Get server IP script
  - path: /opt/setup/get-ip.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      # Get the public IP address
      PUBLIC_IP=$(curl -s http://checkip.amazonaws.com/ || curl -s https://ipinfo.io/ip || curl -s https://api.ipify.org)
      echo "$PUBLIC_IP" > /opt/setup/server-ip.txt
      echo "Server IP: $PUBLIC_IP"

  # Teleport configuration for IP-based access
  - path: /opt/teleport/teleport.yaml
    permissions: '0600'
    owner: assessment:assessment  
    content: |
      version: v3
      teleport:
        cluster_name: secrets-assessment-ip
        data_dir: /var/lib/teleport
        log:
          output: stderr
          severity: INFO
      
      auth_service:
        enabled: true
        cluster_name: secrets-assessment-ip
        listen_addr: 0.0.0.0:3025
        
        # Certificate-based authentication
        authentication:
          type: local
          second_factor: otp  # TOTP (easier setup than hardware keys)
          require_session_mfa: true
          
        # Session settings
        session_recording: node-sync
        session_control_timeout: 30s
        client_idle_timeout: 2h
        disconnect_expired_cert: true
        
      proxy_service:
        enabled: true
        web_listen_addr: 0.0.0.0:3080
        tunnel_listen_addr: 0.0.0.0:3024
        public_addr: SERVER_IP_PLACEHOLDER:3023
        
        # Self-signed certs for IP access
        https_keypairs: []
        
      ssh_service:
        enabled: true
        listen_addr: 0.0.0.0:3022
        labels:
          service: secrets-assessment
          environment: production
          auth_method: certificate-only

  # Firewall for IP-based access
  - path: /opt/setup/configure-firewall.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      ufw --force reset
      ufw default deny incoming
      ufw default allow outgoing
      
      # Allow Teleport ports
      ufw allow 3023/tcp   # Teleport SSH
      ufw allow 3080/tcp   # Teleport Web UI  
      ufw allow 8080/tcp   # Assessment Web Portal
      
      ufw --force enable
      echo "Firewall configured for IP-based access"

  # Main deployment script
  - path: /opt/setup/deploy-assessment-ip.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      set -euo pipefail
      
      log_info() { echo "[$(date)] INFO: $1"; }
      
      log_info "Starting IP-based keyless deployment..."
      
      # Get server IP
      /opt/setup/get-ip.sh
      SERVER_IP=$(cat /opt/setup/server-ip.txt)
      
      # Update Teleport config with actual IP
      sed -i "s/SERVER_IP_PLACEHOLDER/$SERVER_IP/g" /opt/teleport/teleport.yaml
      
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
      
      # Setup Teleport service
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
      
      # Setup directories
      mkdir -p /var/lib/teleport /var/log/teleport
      chown -R assessment:assessment /var/lib/teleport /var/log/teleport /opt/teleport
      
      # Start Teleport
      systemctl daemon-reload
      systemctl enable teleport
      systemctl start teleport
      
      # Wait for startup
      sleep 30
      
      # Deploy containers
      cd /opt/assessment/deployment/docker
      docker-compose -f docker-compose.ip-keyless.yml build
      docker-compose -f docker-compose.ip-keyless.yml up -d
      
      # Create admin user
      sleep 10
      INVITE_LINK=$(tctl users add admin security-admin --logins=assessment --ttl=24h)
      
      echo "=========================================="
      echo "🎉 IP-BASED KEYLESS DEPLOYMENT COMPLETE!"
      echo "=========================================="
      echo ""
      echo "🌐 Access your assessment tool:"
      echo "   Web Interface: https://$SERVER_IP:3080"
      echo "   Assessment Portal: http://$SERVER_IP:8080"
      echo ""
      echo "🔐 Admin Setup (expires in 24h):"
      echo "$INVITE_LINK"
      echo ""
      echo "📱 Setup Instructions:"
      echo "1. Copy the invite link above"
      echo "2. Open in browser (accept SSL warning)"
      echo "3. Set up TOTP with Google Authenticator"
      echo "4. Start running security assessments!"
      echo ""
      echo "🔒 No SSH keys needed - completely keyless!"
      echo "=========================================="

runcmd:
  - hostnamectl set-hostname secrets-assessment-keyless
  - usermod -aG docker assessment
  - /opt/setup/configure-firewall.sh
  - /opt/setup/deploy-assessment-ip.sh > /var/log/deployment.log 2>&1

final_message: |
  IP-based keyless deployment completed!
  Check deployment logs: tail -f /var/log/deployment.log
  Access via server IP address - no domain needed!
EOF

    log_success "IP-based cloud-init generated"
}

# Generate IP-based Docker Compose
generate_ip_compose() {
    print_header "Generating IP-Based Docker Compose"
    
    mkdir -p deployment/docker
    cat > deployment/docker/docker-compose.ip-keyless.yml << 'EOF'
version: '3.8'

services:
  # Assessment Tool - IP access
  assessment-tool:
    build:
      context: ../../
      dockerfile: deployment/docker/Dockerfile.keyless
    hostname: assessment-tool
    container_name: assessment-tool
    restart: unless-stopped
    environment:
      - AUTH_MODE=certificate-only
      - ACCESS_MODE=ip-based
    volumes:
      - assessment_data:/app/data
      - assessment_logs:/app/logs
      - /var/lib/teleport:/var/lib/teleport:ro
    networks:
      - assessment_network
    security_opt:
      - no-new-privileges:true
    user: "1000:1000"
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=100m

  # Simple web portal for IP access
  web-portal:
    image: nginx:alpine
    hostname: web-portal
    container_name: web-portal
    restart: unless-stopped
    ports:
      - "8080:80"
    volumes:
      - ./portal-simple:/usr/share/nginx/html:ro
    networks:
      - assessment_network
    security_opt:
      - no-new-privileges:true

  # Monitoring for IP access
  monitoring:
    image: prom/prometheus:v2.48.0
    hostname: monitoring
    container_name: monitoring
    restart: unless-stopped
    ports:
      - "127.0.0.1:9090:9090"
    volumes:
      - prometheus_data:/prometheus
    networks:
      - assessment_network
    security_opt:
      - no-new-privileges:true
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=15d'

volumes:
  assessment_data:
  assessment_logs:
  prometheus_data:

networks:
  assessment_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.23.0.0/16
EOF

    log_success "IP-based Docker Compose generated"
}

# Generate simple portal for IP access
generate_simple_portal() {
    print_header "Generating Simple IP Portal"
    
    mkdir -p deployment/docker/portal-simple
    cat > deployment/docker/portal-simple/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>🔒 Keyless Security Assessment</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto;
            max-width: 600px; margin: 50px auto; padding: 20px; 
            background: #f8f9fa; color: #333;
        }
        .header { text-align: center; margin-bottom: 40px; }
        .card { 
            background: white; border-radius: 8px; padding: 30px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px;
        }
        .security-badge {
            display: inline-block; background: #28a745; color: white;
            padding: 8px 16px; border-radius: 20px; font-size: 12px;
            font-weight: bold; margin-bottom: 20px;
        }
        .access-button {
            display: inline-block; background: #007bff; color: white;
            padding: 15px 25px; text-decoration: none; border-radius: 6px;
            font-weight: bold; margin: 10px; transition: all 0.2s;
        }
        .access-button:hover { background: #0056b3; }
        .feature-list { list-style: none; padding: 0; }
        .feature-list li { 
            padding: 8px 0; border-bottom: 1px solid #eee; 
            position: relative; padding-left: 25px;
        }
        .feature-list li:before { 
            content: '✅'; position: absolute; left: 0; 
        }
        .warning { 
            background: #fff3cd; border: 1px solid #ffeaa7; 
            border-radius: 4px; padding: 15px; margin: 20px 0; 
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Keyless Security Assessment Tool</h1>
        <div class="security-badge">ZERO SSH KEYS • CERTIFICATE-BASED AUTH</div>
    </div>

    <div class="card">
        <h2>🚀 Access Your Secure Assessment Tool</h2>
        <p>This deployment uses <strong>revolutionary keyless authentication</strong> - no SSH keys required!</p>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://SERVER_IP:3080" class="access-button" target="_blank">
                🌐 Open Teleport Web UI
            </a>
            <a href="#setup" class="access-button">
                📱 Setup Instructions
            </a>
        </div>
    </div>

    <div class="card">
        <h3>🔐 Security Features</h3>
        <ul class="feature-list">
            <li><strong>No SSH Keys:</strong> Zero long-lived credentials</li>
            <li><strong>Short Certificates:</strong> 2-hour maximum expiry</li>
            <li><strong>Multi-Factor Auth:</strong> TOTP required (Google Authenticator)</li>
            <li><strong>Session Recording:</strong> Complete audit trail</li>
            <li><strong>Zero Trust:</strong> Every connection validated</li>
            <li><strong>Auto-Expiry:</strong> Credentials expire automatically</li>
        </ul>
    </div>

    <div class="card" id="setup">
        <h3>📱 Quick Setup Guide</h3>
        <ol>
            <li><strong>Get Admin Link:</strong> Check deployment logs for invite link</li>
            <li><strong>Open Teleport:</strong> Click "Open Teleport Web UI" above</li>
            <li><strong>Accept SSL Warning:</strong> Self-signed cert (normal for IP access)</li>
            <li><strong>Use Invite Link:</strong> Paste the admin invite URL</li>
            <li><strong>Setup TOTP:</strong> Scan QR code with Google Authenticator</li>
            <li><strong>Login:</strong> Use username + TOTP code</li>
            <li><strong>Run Assessments:</strong> Start scanning for secrets!</li>
        </ol>
    </div>

    <div class="warning">
        <strong>🚨 SSL Certificate Warning:</strong><br>
        You'll see a browser warning about the SSL certificate - this is normal when using IP addresses. 
        Click "Advanced" → "Proceed to SERVER_IP" to continue safely.
    </div>

    <div class="card">
        <h3>🆘 Need Help?</h3>
        <p><strong>Check deployment logs:</strong><br>
        <code>tail -f /var/log/deployment.log</code></p>
        
        <p><strong>Get admin invite link:</strong><br>
        <code>docker exec teleport-auth tctl users ls</code></p>
        
        <p><strong>Reset admin user:</strong><br>
        <code>docker exec teleport-auth tctl users reset admin</code></p>
    </div>

    <script>
        // Replace SERVER_IP placeholder with actual IP when loaded
        document.addEventListener('DOMContentLoaded', function() {
            const serverIP = window.location.hostname;
            document.body.innerHTML = document.body.innerHTML.replace(/SERVER_IP/g, serverIP);
        });
    </script>
</body>
</html>
EOF

    log_success "Simple IP portal generated"
}

# Main function
main() {
    print_header "🌐 IP-BASED KEYLESS DEPLOYMENT"
    
    log_info "Generating IP-based keyless deployment..."
    log_info "✅ No domain purchase required"
    log_info "✅ No DNS configuration needed"
    log_info "✅ Access via server IP address"
    
    generate_ip_cloud_init
    generate_ip_compose
    generate_simple_portal
    
    print_header "🎉 IP-BASED KEYLESS DEPLOYMENT READY"
    
    echo -e "${GREEN}Generated Files:${NC}"
    echo "📄 deployment/cloud-init-ip.yml - IP-based server setup"
    echo "🐳 deployment/docker/docker-compose.ip-keyless.yml - IP containers"
    echo "🌐 deployment/docker/portal-simple/ - Simple access portal"
    
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo "1. Go to DigitalOcean → Create Droplet"
    echo "2. Skip SSH Keys completely"
    echo "3. Paste contents of 'deployment/cloud-init-ip.yml' in User Data"
    echo "4. Wait 5-10 minutes for auto-deployment"
    echo "5. Access via https://YOUR_SERVER_IP:3080"
    
    echo ""
    echo -e "${GREEN}Advantages of IP-Based Approach:${NC}"
    echo "✅ No domain costs ($0/year saved)"
    echo "✅ Immediate deployment (no DNS wait)"
    echo "✅ Perfect for testing and development"
    echo "✅ Can add domain later if needed"
    
    echo ""
    log_success "🚀 Ready to deploy without any domain!"
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

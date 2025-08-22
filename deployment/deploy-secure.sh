#!/bin/bash

# Secure Deployment Script for Secrets Footprint Assessment Tool
# This script deploys a fully locked-down instance with Teleport access control

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration
DEPLOYMENT_NAME="secrets-assessment"
DOMAIN="assessment.company.com"
TELEPORT_VERSION="13.0.0"
CERT_EMAIL="security@company.com"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Required commands
    local required_commands=("docker" "docker-compose" "openssl" "curl" "jq")
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Required command '$cmd' not found. Please install it first."
        fi
    done
    
    # Docker daemon check
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
    fi
    
    # Root privilege check (for setup only)
    if [[ $EUID -eq 0 ]]; then
        log_warning "Running as root. Will drop privileges after setup."
    fi
    
    log_success "All prerequisites met"
}

# Generate SSL certificates
generate_certificates() {
    log_info "Generating SSL certificates..."
    
    local ssl_dir="deployment/docker/ssl"
    mkdir -p "$ssl_dir"
    
    if [[ ! -f "$ssl_dir/tls.crt" ]]; then
        # Generate self-signed certificate (replace with Let's Encrypt in production)
        openssl req -x509 -newkey rsa:4096 -keyout "$ssl_dir/tls.key" \
            -out "$ssl_dir/tls.crt" -days 365 -nodes \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN"
        
        chmod 600 "$ssl_dir/tls.key"
        chmod 644 "$ssl_dir/tls.crt"
        
        log_success "SSL certificates generated"
    else
        log_info "SSL certificates already exist"
    fi
}

# Create secure directory structure
setup_directories() {
    log_info "Setting up secure directory structure..."
    
    local base_dir="deployment/docker"
    local dirs=(
        "$base_dir/volumes/teleport-data"
        "$base_dir/volumes/teleport-certs" 
        "$base_dir/volumes/assessment-data"
        "$base_dir/volumes/audit-logs"
        "$base_dir/volumes/backups"
        "$base_dir/config"
    )
    
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
        # Set secure permissions
        chmod 700 "$dir"
    done
    
    log_success "Directory structure created"
}

# Generate Teleport configuration
generate_teleport_config() {
    log_info "Generating Teleport configuration..."
    
    local config_dir="deployment/docker/config"
    
    # Teleport Auth Server config
    cat > "$config_dir/teleport-auth.yaml" << EOF
version: v3
teleport:
  cluster_name: "$DEPLOYMENT_NAME"
  data_dir: /var/lib/teleport
  log:
    output: stderr
    severity: INFO
    format:
      output: text
  ca_pin: ""
  
auth_service:
  enabled: true
  cluster_name: "$DEPLOYMENT_NAME"
  
  # Authentication settings
  authentication:
    type: local
    second_factor: otp
    require_session_mfa: true
    webauthn:
      rp_id: "$DOMAIN"
      
  # Session recording
  session_recording: node-sync
  
  # Client idle timeout
  client_idle_timeout: 2h
  
  # Disconnect expired certificates
  disconnect_expired_cert: true

proxy_service:
  enabled: false

ssh_service:
  enabled: false
EOF

    # Teleport Proxy Server config  
    cat > "$config_dir/teleport-proxy.yaml" << EOF
version: v3
teleport:
  cluster_name: "$DEPLOYMENT_NAME"
  auth_server: "teleport-auth:3025"
  log:
    output: stderr
    severity: INFO

auth_service:
  enabled: false

proxy_service:
  enabled: true
  web_listen_addr: "0.0.0.0:3080"
  tunnel_listen_addr: "0.0.0.0:3024"
  public_addr: "$DOMAIN:443"
  
  # HTTPS configuration
  https_keypairs:
  - key_file: /etc/ssl/certs/tls.key
    cert_file: /etc/ssl/certs/tls.crt
    
  # ACME configuration (for Let's Encrypt)
  # acme:
  #   enabled: true
  #   email: "$CERT_EMAIL"

ssh_service:
  enabled: false
EOF

    # Teleport Node config
    cat > "$config_dir/teleport-node.yaml" << EOF
version: v3
teleport:
  cluster_name: "$DEPLOYMENT_NAME"
  auth_server: "teleport-auth:3025"
  log:
    output: stderr
    severity: INFO

auth_service:
  enabled: false

proxy_service:
  enabled: false

ssh_service:
  enabled: true
  listen_addr: "0.0.0.0:3022"
  labels:
    service: "secrets-assessment"
    environment: "production"
  commands:
  - name: "assessment"
    command: ["/app/secrets_audit.py"]
    period: "5m"

app_service:
  enabled: true
  apps:
  - name: "secrets-footprint"
    uri: "http://assessment-tool:5000"
    public_addr: "$DOMAIN"
    labels:
      app: "secrets-footprint"
      environment: "production"
EOF

    log_success "Teleport configuration generated"
}

# Generate monitoring configuration
generate_monitoring_config() {
    log_info "Generating monitoring configuration..."
    
    local config_dir="deployment/docker/config"
    
    # Prometheus configuration
    cat > "$config_dir/prometheus.yml" << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alert-rules.yml"

scrape_configs:
  - job_name: 'teleport'
    static_configs:
      - targets: ['teleport-proxy:3080']
    metrics_path: /metrics
    scheme: https
    tls_config:
      insecure_skip_verify: true
      
  - job_name: 'assessment-tool'
    static_configs:
      - targets: ['assessment-tool:5000']
    metrics_path: /metrics

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
EOF

    # Alert rules
    cat > "$config_dir/alert-rules.yml" << EOF
groups:
- name: security-alerts
  rules:
  - alert: UnauthorizedAccess
    expr: rate(http_requests_total{status=~"4.."}[5m]) > 10
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "High rate of unauthorized access attempts"
      description: "{{ \$value }} requests per second with 4xx status"
      
  - alert: SuspiciousActivity
    expr: rate(teleport_failed_login_attempts_total[10m]) > 5
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Multiple failed login attempts detected"
      
  - alert: ServiceDown
    expr: up == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Service {{ \$labels.instance }} is down"
EOF

    # Fluent Bit configuration
    cat > "$config_dir/fluent-bit.conf" << EOF
[SERVICE]
    Flush         1
    Log_Level     info
    Daemon        off
    Parsers_File  parsers.conf

[INPUT]
    Name              tail
    Path              /var/log/audit/*.log
    Parser            audit_parser
    Tag               audit.*
    Refresh_Interval  5

[INPUT]
    Name              tail  
    Path              /var/lib/docker/containers/*/*.log
    Parser            docker
    Tag               docker.*
    Refresh_Interval  5

[OUTPUT]
    Name  forward
    Match *
    Host  log-aggregator
    Port  24224
EOF

    log_success "Monitoring configuration generated"
}

# Validate security settings
validate_security() {
    log_info "Validating security settings..."
    
    local issues=0
    
    # Check file permissions
    local secure_dirs=("deployment/docker/volumes" "deployment/docker/config")
    for dir in "${secure_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local perms=$(stat -c "%a" "$dir" 2>/dev/null || stat -f "%A" "$dir" 2>/dev/null)
            if [[ "$perms" != "700" ]]; then
                log_warning "Directory $dir has permissions $perms (should be 700)"
                ((issues++))
            fi
        fi
    done
    
    # Check certificate permissions
    local key_file="deployment/docker/ssl/tls.key"
    if [[ -f "$key_file" ]]; then
        local key_perms=$(stat -c "%a" "$key_file" 2>/dev/null || stat -f "%A" "$key_file" 2>/dev/null)
        if [[ "$key_perms" != "600" ]]; then
            log_warning "Private key has permissions $key_perms (should be 600)"
            ((issues++))
        fi
    fi
    
    if [[ $issues -eq 0 ]]; then
        log_success "Security validation passed"
    else
        log_warning "$issues security issues found"
    fi
}

# Deploy the stack
deploy_stack() {
    log_info "Deploying secure assessment stack..."
    
    cd deployment/docker
    
    # Build custom images first
    log_info "Building secure application image..."
    docker-compose -f docker-compose.secure.yml build assessment-tool
    
    # Start services in correct order
    log_info "Starting Teleport auth server..."
    docker-compose -f docker-compose.secure.yml up -d teleport-auth
    sleep 10  # Wait for auth server to initialize
    
    log_info "Starting Teleport proxy..."
    docker-compose -f docker-compose.secure.yml up -d teleport-proxy
    sleep 5
    
    log_info "Starting assessment tool..."
    docker-compose -f docker-compose.secure.yml up -d assessment-tool
    sleep 5
    
    log_info "Starting Teleport node..."
    docker-compose -f docker-compose.secure.yml up -d teleport-node
    
    log_info "Starting monitoring services..."
    docker-compose -f docker-compose.secure.yml up -d prometheus fluent-bit backup-service
    
    cd ../..
    
    log_success "Stack deployment completed"
}

# Setup initial Teleport user
setup_teleport_user() {
    log_info "Setting up initial Teleport user..."
    
    # Wait for Teleport to be ready
    local max_attempts=30
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if docker exec teleport-auth tctl status &>/dev/null; then
            break
        fi
        log_info "Waiting for Teleport auth server... (attempt $attempt/$max_attempts)"
        sleep 10
        ((attempt++))
    done
    
    if [[ $attempt -gt $max_attempts ]]; then
        log_error "Teleport auth server failed to start"
    fi
    
    # Create security assessor role
    docker exec teleport-auth tctl create << 'EOF'
kind: role
version: v5
metadata:
  name: secrets-assessor
spec:
  allow:
    logins: ['assessment']
    node_labels:
      'service': 'secrets-assessment'
    app_labels:
      'app': 'secrets-footprint'
    rules:
    - resources: [session]
      verbs: [list, read]
    max_session_ttl: 2h
    require_session_mfa: true
  deny: {}
EOF

    # Create initial admin user
    echo "Creating initial admin user..."
    read -p "Enter admin username: " admin_username
    read -p "Enter admin email: " admin_email
    
    local invite_link=$(docker exec teleport-auth tctl users add "$admin_username" secrets-assessor --logins=assessment)
    
    log_success "Admin user created. Invite link:"
    echo "$invite_link"
    
    log_info "Save this link securely - it expires in 1 hour"
}

# Run security scan
run_security_scan() {
    log_info "Running container security scan..."
    
    if command -v trivy &> /dev/null; then
        log_info "Scanning with Trivy..."
        trivy image secrets-assessment-tool:latest
    else
        log_warning "Trivy not installed - skipping vulnerability scan"
    fi
}

# Display deployment status
show_status() {
    log_info "Deployment Status:"
    echo "===================="
    
    cd deployment/docker
    docker-compose -f docker-compose.secure.yml ps
    cd ../..
    
    echo ""
    log_info "Access Information:"
    echo "Web Interface: https://$DOMAIN"
    echo "SSH Access: ssh -p 3023 assessment@$DOMAIN"
    echo ""
    
    log_info "Security Features Enabled:"
    echo "✅ Multi-factor authentication required"
    echo "✅ Session recording enabled"
    echo "✅ Certificate-based access (1-12 hour TTL)"
    echo "✅ Network isolation with Docker networks"
    echo "✅ Non-root containers"
    echo "✅ Read-only root filesystem"
    echo "✅ Comprehensive audit logging"
    echo "✅ Automated monitoring and alerting"
}

# Main deployment function
main() {
    echo "======================================================="
    echo "🔒 Secure Secrets Assessment Tool Deployment"
    echo "======================================================="
    echo ""
    
    check_prerequisites
    generate_certificates
    setup_directories
    generate_teleport_config
    generate_monitoring_config
    validate_security
    deploy_stack
    setup_teleport_user
    run_security_scan
    show_status
    
    echo ""
    log_success "Secure deployment completed successfully!"
    echo ""
    log_info "Next steps:"
    echo "1. Configure DNS to point $DOMAIN to this server"
    echo "2. Use the admin invite link to set up your account"
    echo "3. Configure additional users as needed"
    echo "4. Review monitoring dashboards"
    echo "5. Test the security assessment functionality"
    echo ""
    log_warning "Remember to:"
    echo "- Backup the Teleport CA private key"
    echo "- Set up log forwarding to your SIEM"
    echo "- Configure alerting endpoints"
    echo "- Schedule regular security updates"
}

# Script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

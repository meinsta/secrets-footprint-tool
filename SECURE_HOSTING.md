# 🔒 Secure Hosting Architecture for Secrets Footprint Assessment Tool

## 🎯 Overview

This document provides a comprehensive secure hosting architecture using **Teleport** and other enterprise security tools to ensure the Secrets Footprint Assessment Tool is completely locked down while remaining accessible to authorized users.

## 🏗️ Architecture Components

### **1. Teleport-Based Secure Access**
```
┌─────────────────────────────────────────────────────────────┐
│                    TELEPORT CLUSTER                         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐    ┌─────────────────┐                │
│  │   Teleport      │    │   Teleport      │                │
│  │   Auth Server   │────│   Proxy Server  │                │
│  │                 │    │                 │                │
│  └─────────────────┘    └─────────────────┘                │
│           │                       │                        │
│           │              ┌─────────────────┐               │
│           └──────────────│   Teleport      │               │
│                          │   Node Agent    │               │
│                          │                 │               │
│                          └─────────────────┘               │
└─────────────────────────────────────────────────────────────┘
                                   │
                          ┌─────────────────┐
                          │  Hardened VM    │
                          │  ┌───────────┐  │
                          │  │ Assessment│  │
                          │  │    Tool   │  │
                          │  └───────────┘  │
                          └─────────────────┘
```

## 🛡️ Security Layers

### **Layer 1: Teleport Access Control**

#### **Authentication & Authorization**
```yaml
# teleport.yaml - Auth Server Config
teleport:
  auth_service:
    enabled: true
    cluster_name: "secrets-assessment"
    
    # Multi-factor authentication required
    authentication:
      type: local
      second_factor: otp  # or webauthn
      require_session_mfa: true
      
    # Session recording
    session_recording: node-sync
    
  proxy_service:
    enabled: true
    web_listen_addr: "0.0.0.0:3080"
    tunnel_listen_addr: "0.0.0.0:3024"
    
    # HTTPS only with valid certs
    https_keypairs:
    - key_file: /etc/teleport/tls.key
      cert_file: /etc/teleport/tls.crt

# RBAC Policies
kind: role
version: v3
metadata:
  name: secrets-assessor
spec:
  allow:
    # Restricted access to assessment tool only
    logins: ['assessment']
    node_labels:
      'service': 'secrets-assessment'
    
    # Limited session time
    max_session_ttl: 2h
    
    # Specific commands only
    rules:
    - resources: ['session']
      verbs: ['list', 'read']
    - resources: ['node']
      verbs: ['list', 'read']
      
    # Application access (web interface)
    app_labels:
      'app': 'secrets-footprint'
```

#### **Session Security**
- ✅ **Full session recording** - All actions logged and auditable
- ✅ **Time-limited sessions** - 2-hour maximum session duration
- ✅ **MFA required** - Multi-factor authentication for all access
- ✅ **Certificate-based access** - Short-lived certificates (1-12 hours)
- ✅ **IP restrictions** - Access limited to specific source IPs/networks

### **Layer 2: Hardened Operating System**

#### **Container/VM Configuration**
```dockerfile
# Dockerfile for secure hosting
FROM ubuntu:22.04-minimal

# Security hardening
RUN apt-get update && apt-get install -y \
    # Minimal packages only
    python3 \
    python3-pip \
    openssh-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1001 -s /bin/bash assessment

# Install tool with minimal permissions
COPY --chown=assessment:assessment . /app/
WORKDIR /app

# Install dependencies as non-root
USER assessment
RUN pip3 install --user -r requirements.txt

# Security: Remove build tools and unnecessary binaries
USER root
RUN apt-get remove -y curl && \
    apt-get autoremove -y && \
    rm -rf /var/cache/apt/* /tmp/*

# Set secure permissions
RUN chmod 755 /app && \
    chmod -R o-rwx /app && \
    chmod +x /app/secrets_audit.py

# Final security lockdown
USER assessment
EXPOSE 5000
CMD ["python3", "secrets_audit.py"]
```

#### **System Hardening**
```bash
#!/bin/bash
# security-hardening.sh

# Disable unnecessary services
systemctl disable --now cups bluetooth

# Set strict file permissions
chmod 700 /home/assessment
chmod 755 /app
chmod -R o-rwx /app

# Configure secure SSH (for Teleport node)
cat >> /etc/ssh/sshd_config << EOF
# Teleport-specific hardening
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
MaxSessions 3
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

# Install and configure fail2ban
apt-get install -y fail2ban
systemctl enable fail2ban

# Set up filesystem monitoring
apt-get install -y auditd
systemctl enable auditd

# Configure firewall
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow from 10.0.0.0/8 to any port 22  # Teleport access only
ufw allow from 10.0.0.0/8 to any port 5000  # Web interface
```

### **Layer 3: Network Security**

#### **Network Isolation**
```yaml
# docker-compose.yml with network isolation
version: '3.8'

networks:
  teleport-net:
    driver: bridge
    ipam:
      config:
      - subnet: 172.20.0.0/24
  
  assessment-net:
    driver: bridge
    internal: true  # No external access
    ipam:
      config:
      - subnet: 172.21.0.0/24

services:
  teleport-proxy:
    image: gravitational/teleport:13
    networks:
      - teleport-net
    ports:
      - "443:3080"  # HTTPS only
    volumes:
      - ./teleport.yaml:/etc/teleport/teleport.yaml:ro
      - teleport-certs:/etc/teleport/certs:ro
    
  assessment-tool:
    build: .
    networks:
      - assessment-net
      - teleport-net
    ports:
      - "127.0.0.1:5000:5000"  # Localhost only
    volumes:
      - assessment-data:/app/data:rw
    user: "1001:1001"  # Non-root
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=100M
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - DAC_OVERRIDE  # Minimal required capabilities

volumes:
  teleport-certs:
    external: true
  assessment-data:
    driver: local
```

### **Layer 4: Application Security**

#### **Web Application Hardening**
```python
# secure_webapp.py - Enhanced security configuration
from flask import Flask, request, session
from flask_talisman import Talisman
import secrets
import os

app = Flask(__name__)

# Security headers and CSP
Talisman(app, 
    force_https=True,
    strict_transport_security=True,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline'",  # Minimal inline JS
        'style-src': "'self' 'unsafe-inline'",
        'img-src': "'self' data:",
        'connect-src': "'self'",
        'frame-ancestors': "'none'",
    },
    referrer_policy='strict-origin-when-cross-origin'
)

# Secure session configuration
app.config.update(
    SECRET_KEY=secrets.token_urlsafe(32),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=7200,  # 2 hours max
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_TIME_LIMIT=3600,
)

# Rate limiting per user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per hour", "20 per minute"]
)

# Audit logging
import logging
import json
from datetime import datetime

audit_logger = logging.getLogger('audit')
handler = logging.FileHandler('/app/logs/audit.log')
handler.setFormatter(logging.Formatter('%(message)s'))
audit_logger.addHandler(handler)
audit_logger.setLevel(logging.INFO)

@app.before_request
def log_request():
    """Log all requests for security auditing."""
    audit_data = {
        'timestamp': datetime.utcnow().isoformat(),
        'remote_addr': request.remote_addr,
        'method': request.method,
        'url': request.url,
        'user_agent': str(request.user_agent),
        'headers': dict(request.headers)
    }
    audit_logger.info(json.dumps(audit_data))

# Input validation middleware
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
```

## 🚀 Deployment Guide

### **Step 1: Infrastructure Setup**

#### **AWS/GCP/Azure Setup**
```bash
#!/bin/bash
# infrastructure-setup.sh

# Create isolated VPC
aws ec2 create-vpc --cidr-block 10.0.0.0/16 --tag-specifications \
  'ResourceType=vpc,Tags=[{Key=Name,Value=secrets-assessment-vpc}]'

# Create private subnet
aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.1.0/24 \
  --availability-zone us-east-1a \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=secrets-assessment-private}]'

# Create security group with minimal access
aws ec2 create-security-group --group-name secrets-assessment-sg \
  --description "Security group for secrets assessment tool" \
  --vpc-id $VPC_ID

# Allow only Teleport proxy access
aws ec2 authorize-security-group-ingress --group-id $SG_ID \
  --protocol tcp --port 3022 --source-group $TELEPORT_SG_ID

# Launch hardened instance
aws ec2 run-instances --image-id ami-0abcdef1234567890 \
  --count 1 --instance-type t3.small \
  --key-name teleport-access \
  --security-group-ids $SG_ID \
  --subnet-id $SUBNET_ID \
  --user-data file://user-data.sh \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=secrets-assessment},{Key=service,Value=secrets-assessment}]'
```

### **Step 2: Teleport Configuration**

#### **Deploy Teleport Cluster**
```bash
# Install Teleport
curl -O https://cdn.teleport.dev/teleport-v13.0.0-linux-amd64-bin.tar.gz
tar -xzf teleport-v13.0.0-linux-amd64-bin.tar.gz
sudo ./teleport/install

# Configure auth server
sudo tctl create << EOF
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

# Create user with restricted access
sudo tctl users add security-auditor secrets-assessor
```

#### **Application Access Setup**
```yaml
# teleport-app.yaml
kind: app
version: v3
metadata:
  name: secrets-footprint
spec:
  uri: "http://localhost:5000"
  public_addr: "assessment.company.com"
  labels:
    app: secrets-footprint
    environment: production
  description: "Secrets Footprint Assessment Tool"
```

### **Step 3: Monitoring & Alerting**

#### **Security Monitoring**
```yaml
# monitoring-setup.yml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "127.0.0.1:9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
    
  grafana:
    image: grafana/grafana:latest
    ports:
      - "127.0.0.1:3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=secure_password
    volumes:
      - grafana-storage:/var/lib/grafana
    
  filebeat:
    image: elastic/filebeat:8.5.0
    volumes:
      - ./filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - /var/log:/var/log:ro
      - /app/logs:/app/logs:ro
```

#### **Alert Rules**
```yaml
# alerts.yml
groups:
- name: security-alerts
  rules:
  - alert: UnauthorizedAccessAttempt
    expr: rate(http_requests_total{status=~"4.."}[5m]) > 5
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High rate of 4xx errors detected"
      
  - alert: SuspiciousActivity  
    expr: rate(audit_log_entries[10m]) > 50
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "Unusual activity patterns detected"

  - alert: SessionTimeoutViolation
    expr: active_session_duration > 7200  # 2 hours
    for: 1m
    labels:
      severity: warning
    annotations:
      summary: "Session exceeding maximum allowed time"
```

## 🔧 Operational Security

### **Access Procedures**

#### **User Onboarding**
```bash
# secure-onboarding.sh
#!/bin/bash

USERNAME=$1
EMAIL=$2

# Create Teleport user with time-limited access
sudo tctl users add $USERNAME secrets-assessor \
  --ttl=8760h \  # 1 year max
  --logins=assessment

# Generate secure invite
INVITE_URL=$(sudo tctl users ls | grep $USERNAME | awk '{print $3}')

# Send secure invite (encrypted email)
echo "Secure access link for Secrets Assessment Tool: $INVITE_URL" | \
  gpg --encrypt --armor -r $EMAIL | \
  sendmail $EMAIL
```

#### **Session Management**
```bash
# session-management.sh

# List active sessions
sudo tctl get sessions

# Terminate suspicious session
sudo tctl rm session/<session-id>

# Audit session recordings
sudo tctl get session_recording/<session-id>

# Generate access report
sudo tctl get events --type=session.start,session.end \
  --from="2024-01-01" --to="2024-12-31" \
  --format=json > access-audit.json
```

### **Backup & Recovery**

#### **Secure Backup Strategy**
```bash
# secure-backup.sh
#!/bin/bash

# Encrypted backup of assessment data
tar -czf - /app/config /app/reports | \
  gpg --symmetric --cipher-algo AES256 \
  > "backup-$(date +%Y%m%d).tar.gz.gpg"

# Upload to secure storage
aws s3 cp backup-*.tar.gz.gpg s3://secure-backups/ \
  --server-side-encryption AES256 \
  --storage-class GLACIER
```

## 📊 Security Metrics & KPIs

### **Monitoring Dashboard**
```sql
-- Security metrics queries
SELECT 
    DATE(timestamp) as date,
    COUNT(*) as total_sessions,
    COUNT(DISTINCT user_id) as unique_users,
    AVG(session_duration) as avg_duration
FROM audit_logs 
WHERE event_type = 'session.start'
GROUP BY DATE(timestamp);

-- Failed access attempts
SELECT 
    remote_addr,
    COUNT(*) as failed_attempts,
    MAX(timestamp) as last_attempt
FROM audit_logs 
WHERE status_code >= 400
GROUP BY remote_addr
HAVING COUNT(*) > 10;
```

## 🚨 Incident Response

### **Security Incident Playbook**
```yaml
# incident-response.yml
name: "Security Incident Response"
triggers:
  - unauthorized_access
  - suspicious_activity
  - data_breach_attempt

immediate_actions:
  1. isolate_affected_systems
  2. preserve_evidence
  3. notify_security_team
  4. activate_incident_commander

investigation_steps:
  1. analyze_logs
  2. review_session_recordings  
  3. check_system_integrity
  4. identify_impact_scope

recovery_actions:
  1. patch_vulnerabilities
  2. rotate_certificates
  3. update_access_controls
  4. restore_from_backup

post_incident:
  1. document_lessons_learned
  2. update_security_procedures
  3. conduct_training
  4. improve_monitoring
```

## ✅ Security Validation Checklist

### **Pre-Deployment Security Review**
- [ ] **Multi-factor authentication** configured and tested
- [ ] **Network segmentation** properly implemented  
- [ ] **Session recording** enabled and verified
- [ ] **Access controls** tested with least privilege
- [ ] **Certificate rotation** automated
- [ ] **Monitoring and alerting** configured
- [ ] **Backup and recovery** tested
- [ ] **Incident response** procedures documented
- [ ] **Compliance requirements** validated
- [ ] **Penetration testing** completed

### **Ongoing Security Maintenance**
- [ ] **Weekly access reviews** - Remove unused accounts
- [ ] **Monthly certificate rotation** - Automated renewal
- [ ] **Quarterly security audits** - Review logs and access
- [ ] **Annual penetration testing** - Third-party security assessment
- [ ] **Continuous monitoring** - Real-time threat detection
- [ ] **Security training** - Keep team updated on threats

## 🎯 Benefits of This Architecture

### **Security Benefits**
- ✅ **Zero-trust access** - Every connection authenticated and authorized
- ✅ **Complete audit trail** - All actions recorded and searchable
- ✅ **Time-limited access** - Sessions automatically expire
- ✅ **MFA enforcement** - Multi-factor authentication required
- ✅ **Network isolation** - Assessment tool in secure network
- ✅ **Principle of least privilege** - Minimal permissions granted

### **Operational Benefits**
- ✅ **Centralized access management** - Single point of control
- ✅ **Automated certificate management** - No manual key distribution
- ✅ **Session sharing** - Team collaboration with full audit
- ✅ **Compliance reporting** - Built-in audit logs and reports
- ✅ **High availability** - Redundant infrastructure components

### **Cost Benefits**
- ✅ **Reduced infrastructure** - No VPN or bastion hosts needed
- ✅ **Simplified management** - Single access solution
- ✅ **Compliance automation** - Reduces manual audit effort
- ✅ **Incident reduction** - Better security reduces breach costs

## 📞 Contact & Support

For questions about secure deployment:
- **Security Team**: security@company.com
- **DevOps Team**: devops@company.com
- **Emergency**: Follow incident response procedures

---

**Last Updated**: 2025-01-22  
**Version**: 1.0  
**Classification**: Internal Use Only

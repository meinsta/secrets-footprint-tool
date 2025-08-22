# 🏢 Production Cloud Deployment Guide

## Enterprise-Grade Secure Deployment

This guide walks you through deploying the Secrets Assessment Tool as a production-ready service with enterprise security features.

## 📋 Prerequisites

### What You'll Need:
1. **Cloud Provider Account** (AWS, GCP, Azure, or DigitalOcean)
2. **Domain Name** (e.g., `assessment.yourcompany.com`)
3. **SSH Key Pair** (for server access)
4. **Email Address** (for SSL certificates)
5. **30 minutes** of your time

### Estimated Monthly Cost:
- **Small deployment:** $50-80/month (2 vCPU, 4GB RAM, 50GB storage)
- **Medium deployment:** $100-150/month (4 vCPU, 8GB RAM, 100GB storage) 
- **Large deployment:** $200-300/month (8 vCPU, 16GB RAM, 200GB storage)

## 🚀 Step 1: Choose Your Cloud Provider

### Option A: AWS (Recommended)
**Pros:** Most enterprise features, excellent security, global presence
**Cons:** Complex pricing, steeper learning curve

### Option B: Google Cloud Platform  
**Pros:** Simple pricing, excellent performance, integrated security
**Cons:** Smaller ecosystem than AWS

### Option C: Microsoft Azure
**Pros:** Great for Microsoft shops, hybrid cloud capabilities
**Cons:** Can be complex to navigate

### Option D: DigitalOcean (Easiest)
**Pros:** Simple, predictable pricing, great for startups
**Cons:** Fewer enterprise features

**🎯 Recommendation:** Start with DigitalOcean for simplicity, or AWS for maximum enterprise features.

## 🏗️ Step 2: Launch Your Cloud Server

### DigitalOcean Instructions (Recommended for beginners):

1. **Create DigitalOcean Account:**
   - Go to https://digitalocean.com
   - Sign up with your business email
   - Add payment method

2. **Create a Droplet:**
   - Click "Create" → "Droplets"
   - **Image:** Ubuntu 22.04 (LTS) x64
   - **Plan:** Basic ($48/month - 2 vCPU, 4GB RAM, 80GB SSD)
   - **Region:** Choose closest to your users
   - **Authentication:** SSH Key (upload your public key)
   - **Hostname:** `secrets-assessment-prod`
   - **Tags:** `production`, `security-tools`

3. **Configure Firewall:**
   - Go to Networking → Firewalls → Create Firewall
   - **Name:** `secrets-assessment-firewall`
   - **Inbound Rules:**
     ```
     SSH     | 22    | All IPv4, All IPv6
     HTTPS   | 443   | All IPv4, All IPv6  
     Custom  | 3023  | All IPv4, All IPv6 (Teleport SSH)
     ```
   - **Outbound Rules:** All traffic allowed
   - **Droplets:** Assign to your droplet

### AWS Instructions (Enterprise):

1. **Launch EC2 Instance:**
   ```bash
   # Using AWS CLI (or use AWS Console)
   aws ec2 run-instances \
     --image-id ami-0c02fb55956c7d316 \
     --instance-type t3.medium \
     --key-name your-key-pair \
     --security-group-ids sg-xxxxxx \
     --subnet-id subnet-xxxxxx \
     --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=secrets-assessment-prod}]'
   ```

2. **Security Group Rules:**
   ```bash
   # Allow SSH, HTTPS, and Teleport SSH
   aws ec2 authorize-security-group-ingress \
     --group-id sg-xxxxxx \
     --protocol tcp \
     --port 22 \
     --cidr 0.0.0.0/0
   
   aws ec2 authorize-security-group-ingress \
     --group-id sg-xxxxxx \
     --protocol tcp \
     --port 443 \
     --cidr 0.0.0.0/0
     
   aws ec2 authorize-security-group-ingress \
     --group-id sg-xxxxxx \
     --protocol tcp \
     --port 3023 \
     --cidr 0.0.0.0/0
   ```

## 🌐 Step 3: Configure Your Domain

### DNS Setup:
1. **Create A Record:**
   - **Name:** `assessment` (or whatever subdomain you want)
   - **Value:** Your server's IP address
   - **TTL:** 300 seconds

2. **Verify DNS Propagation:**
   ```bash
   # Test from your local machine
   nslookup assessment.yourcompany.com
   dig assessment.yourcompany.com
   ```

## 🔧 Step 4: Server Setup

### Connect to Your Server:
```bash
# Replace with your server's IP and key
ssh -i ~/.ssh/your-private-key ubuntu@your-server-ip
```

### Install Prerequisites:
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
sudo usermod -aG docker ubuntu

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Install additional tools
sudo apt install -y git curl jq htop

# Verify installations
docker --version
docker-compose --version
```

### Clone the Repository:
```bash
# Clone the secure assessment tool
git clone https://github.com/meinsta/secrets-footprint-tool.git
cd secrets-footprint-tool
```

## 🚀 Step 5: Deploy with Enterprise Security

### Configure Environment:
```bash
# Set your domain name
export DOMAIN="assessment.yourcompany.com"
export CERT_EMAIL="security@yourcompany.com"

# Optional: Set admin email for initial user
export ADMIN_EMAIL="admin@yourcompany.com"
```

### Run the Secure Deployment:
```bash
# This will take 5-10 minutes
./deployment/deploy-secure.sh
```

### What This Script Does:
1. ✅ **Generates SSL certificates** (self-signed initially, upgradeable to Let's Encrypt)
2. ✅ **Creates secure directory structure** with proper permissions
3. ✅ **Configures Teleport cluster** with enterprise security settings
4. ✅ **Deploys hardened containers** (non-root, read-only filesystems)
5. ✅ **Sets up monitoring** (Prometheus, log aggregation)
6. ✅ **Creates admin user** with MFA setup
7. ✅ **Runs security validation** checks

## 🔐 Step 6: Initial Security Setup

### Access the Admin Interface:
1. **Open your browser:** `https://assessment.yourcompany.com`
2. **Accept certificate warning** (temporary - we'll fix this next)
3. **Set up admin account** using the invite link from deployment
4. **Configure MFA** (Google Authenticator, Authy, or hardware key)

### Configure Let's Encrypt SSL (Recommended):
```bash
# Install Certbot
sudo apt install -y certbot

# Get real SSL certificate
sudo certbot certonly --standalone -d assessment.yourcompany.com --email security@yourcompany.com

# Update certificate in deployment
sudo cp /etc/letsencrypt/live/assessment.yourcompany.com/fullchain.pem deployment/docker/ssl/tls.crt
sudo cp /etc/letsencrypt/live/assessment.yourcompany.com/privkey.pem deployment/docker/ssl/tls.key

# Restart services with new certificate
cd deployment/docker
docker-compose -f docker-compose.secure.yml restart teleport-proxy
```

### Set Up Certificate Auto-Renewal:
```bash
# Add to crontab for automatic renewal
sudo crontab -e

# Add this line:
0 2 * * * certbot renew --deploy-hook "cd /home/ubuntu/secrets-footprint-tool/deployment/docker && docker-compose -f docker-compose.secure.yml restart teleport-proxy"
```

## 👥 Step 7: User Management

### Create Additional Users:
```bash
# SSH to your server
ssh -i ~/.ssh/your-key ubuntu@your-server-ip

# Create security team members
cd secrets-footprint-tool
docker exec teleport-auth tctl users add john.doe secrets-assessor --logins=assessment --ttl=8760h
docker exec teleport-auth tctl users add jane.smith secrets-assessor --logins=assessment --ttl=8760h

# The command will output secure invite links - send these to users
```

### User Roles Available:
- **`secrets-assessor`**: Can run assessments, limited session time (2 hours)
- **`security-admin`**: Can run assessments + manage users
- **`auditor`**: Read-only access to session recordings and reports

## 📊 Step 8: Monitoring & Maintenance

### Access Monitoring:
- **Prometheus Metrics:** `https://assessment.yourcompany.com:9090`
- **Container Logs:** `docker-compose -f deployment/docker/docker-compose.secure.yml logs -f`
- **System Metrics:** `htop` on the server

### Set Up Log Forwarding (Optional):
```bash
# Configure log forwarding to your SIEM
# Edit the Fluent Bit configuration:
sudo nano deployment/docker/config/fluent-bit.conf

# Add your log destination (Splunk, ELK, etc.)
[OUTPUT]
    Name  forward
    Match *
    Host  your-siem-server.com
    Port  514
```

### Backup Configuration:
```bash
# Create automated backups
cd secrets-footprint-tool
./deployment/backup-config.sh

# Set up daily backups (add to crontab)
crontab -e
# Add: 0 1 * * * /home/ubuntu/secrets-footprint-tool/deployment/backup-config.sh
```

## 🚨 Step 9: Security Validation

### Run Security Checks:
```bash
# Verify all security features are working
./deployment/validate-security.sh

# Check container security
docker exec secrets-assessment-tool whoami  # Should return 'assessment', not 'root'
docker exec teleport-auth tctl status       # Should show cluster is healthy
```

### Test Access Controls:
1. **MFA Test:** Try logging in - should require 2FA
2. **Session Recording:** Verify sessions are being recorded
3. **Time Limits:** Verify sessions expire after 2 hours
4. **Certificate Expiry:** Check certificate rotation is working

## ✅ Step 10: Go Live!

### Final Checklist:
- [ ] Domain DNS is propagated
- [ ] SSL certificate is valid (green lock in browser)
- [ ] Admin user can log in with MFA
- [ ] Test assessment completes successfully
- [ ] Monitoring dashboards are accessible
- [ ] Backup scripts are configured
- [ ] Additional users have been created
- [ ] Security team has been trained

### Announce to Your Team:
```
🎉 Our new Secrets Assessment Tool is live!

🔗 Access: https://assessment.yourcompany.com
🔐 Login: Use your secure invite link + MFA
📋 Documentation: Internal wiki link
👨‍💼 Support: security-team@yourcompany.com

Security Features:
✅ Multi-factor authentication required
✅ Complete session recording
✅ Certificate-based access (no passwords)
✅ 2-hour session limits
✅ Full audit trails
```

## 🔧 Ongoing Maintenance

### Weekly Tasks:
- [ ] Review access logs for suspicious activity
- [ ] Check system resource usage
- [ ] Verify backup integrity
- [ ] Update user access as needed

### Monthly Tasks:
- [ ] Update system packages: `sudo apt update && sudo apt upgrade`
- [ ] Review and rotate admin certificates
- [ ] Analyze usage patterns and optimize resources
- [ ] Security assessment of the tool itself

### Quarterly Tasks:
- [ ] Full security audit and penetration testing
- [ ] Review and update access policies
- [ ] Disaster recovery testing
- [ ] Performance optimization

## 🆘 Troubleshooting

### Common Issues:

**1. Certificate Errors:**
```bash
# Regenerate certificates
sudo certbot delete --cert-name assessment.yourcompany.com
sudo certbot certonly --standalone -d assessment.yourcompany.com
```

**2. Service Won't Start:**
```bash
# Check logs
docker-compose -f deployment/docker/docker-compose.secure.yml logs teleport-auth
```

**3. Can't Access Web Interface:**
```bash
# Check firewall
sudo ufw status
# Verify ports are open
sudo netstat -tlnp | grep -E ':(443|3023|3080)'
```

**4. MFA Issues:**
```bash
# Reset user MFA
docker exec teleport-auth tctl users reset john.doe
```

## 📞 Support

For deployment support:
- **Internal:** security-team@yourcompany.com  
- **Technical Issues:** Check logs first, then escalate
- **Security Incidents:** Follow your incident response plan

---

## 🎯 Summary

You now have a **production-ready, enterprise-grade** secrets assessment tool with:

✅ **Zero-trust access control**  
✅ **Multi-factor authentication**  
✅ **Complete audit trails**  
✅ **Enterprise security monitoring**  
✅ **Automated certificate management**  
✅ **Scalable cloud infrastructure**  

**Total deployment time:** 30 minutes  
**Monthly cost:** $50-200 depending on usage  
**Security level:** Enterprise-grade  

🎉 **Congratulations! Your secure assessment tool is now live and ready for enterprise use!**

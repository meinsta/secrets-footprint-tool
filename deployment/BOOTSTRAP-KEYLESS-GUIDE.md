# 🚀 Bootstrap-to-Keyless Deployment Guide

## Teleport's Recommended Security Pattern

This deployment follows **Teleport's recommended approach**:
1. **Temporary SSH** for initial bootstrap only
2. **Automatic SSH elimination** after Teleport is running  
3. **Certificate-based access** for all future connections
4. **Zero long-lived credentials**

## 🎯 Why This Approach?

**Problem:** Cloud providers require authentication for server creation
**Solution:** Use temporary SSH that self-destructs after Teleport setup

### Security Benefits:
- ✅ SSH exists for <5 minutes during bootstrap only
- ✅ SSH is automatically disabled by the system itself
- ✅ Firewall blocks SSH permanently after setup
- ✅ No SSH keys remain on the system
- ✅ All access requires MFA + short-lived certificates

## 📋 Deployment Steps

### Step 1: Prepare SSH Key (Temporary)
```bash
# Generate temporary bootstrap key (will be deleted)
ssh-keygen -t ed25519 -f ~/.ssh/bootstrap_temp -C "bootstrap-temp"

# Get the public key
cat ~/.ssh/bootstrap_temp.pub
```

### Step 2: Update Cloud-Init Script
```bash
# Replace the SSH key placeholder
sed -i 's/BOOTSTRAP_SSH_KEY_PLACEHOLDER/YOUR_PUBLIC_KEY_HERE/g' deployment/cloud-init-bootstrap.yml
```

### Step 3: Create DigitalOcean Droplet
1. **Go to:** DigitalOcean → Create Droplets
2. **Image:** Ubuntu 22.04 (LTS) x64
3. **Plan:** Basic - $48/month (2 vCPU, 4GB RAM, 80GB SSD)
4. **Authentication:** SSH Key (upload your temporary bootstrap key)
5. **User Data:** Paste contents of `deployment/cloud-init-bootstrap.yml`
6. **Hostname:** `secrets-assessment-bootstrap`
7. **Create Droplet**

### Step 4: Monitor Bootstrap Process
1. **Status Portal:** `http://YOUR_SERVER_IP:8080`
2. **SSH Monitor:** `ssh -i ~/.ssh/bootstrap_temp bootstrap@YOUR_SERVER_IP`
3. **Watch Logs:** `tail -f /var/log/bootstrap.log`

### Step 5: SSH Self-Destructs
After ~5 minutes:
- ✅ Teleport starts and generates certificates
- ✅ Admin user invite link is created
- ✅ SSH daemon is stopped and disabled
- ✅ SSH keys are deleted from server
- ✅ Firewall blocks port 22
- ❌ SSH access no longer works

### Step 6: Access Via Certificates
1. **Save admin invite link** from bootstrap logs
2. **Access Teleport:** `https://YOUR_SERVER_IP:3080`
3. **Complete MFA setup** with authenticator app
4. **Delete local SSH key:** `rm ~/.ssh/bootstrap_temp*`

## 🔒 Security Validation

After deployment, verify keyless security:

```bash
# These should all fail (proving SSH is disabled):
ssh root@YOUR_SERVER_IP          # Connection refused
ssh ubuntu@YOUR_SERVER_IP        # Connection refused  
ssh bootstrap@YOUR_SERVER_IP     # Connection refused

# This should work (proving Teleport works):
curl -k https://YOUR_SERVER_IP:3080  # Teleport login page
```

## 🆘 Recovery Options

If something goes wrong:
1. **DigitalOcean Console:** Browser-based access available
2. **Rebuild:** Destroy and recreate droplet with same process
3. **No SSH Recovery:** This is intentional - certificate access only

## 📊 Timeline

| Time | Event | SSH Status | Access Method |
|------|-------|------------|---------------|
| 0-2 min | Server boots, installs packages | SSH Active | Temporary SSH |
| 2-4 min | Teleport installing and starting | SSH Active | Temporary SSH |
| 4-6 min | Teleport ready, admin user created | SSH Active | SSH or Teleport |
| 6+ min | SSH disabled permanently | SSH DISABLED | Teleport only |

## 🎉 Final State

After bootstrap completion:
- ❌ **SSH:** Permanently disabled, daemon stopped
- ❌ **SSH Keys:** Deleted from server and firewall-blocked
- ✅ **Teleport:** Certificate-based access with MFA
- ✅ **Security:** Zero long-lived credentials
- ✅ **Audit:** Complete session recording

**This achieves the ultimate goal: A completely keyless system with enterprise security!**

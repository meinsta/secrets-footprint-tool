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

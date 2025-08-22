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

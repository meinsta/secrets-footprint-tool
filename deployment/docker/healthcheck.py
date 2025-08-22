#!/usr/bin/env python3
"""
Health Check Script for Secrets Assessment Tool Container
Verifies container health and security status
"""

import sys
import os
import subprocess
import json
from datetime import datetime

def check_application_health():
    """Check if the application is responding."""
    try:
        import requests
        response = requests.get('http://localhost:5000/health', timeout=5)
        return response.status_code == 200
    except:
        # Fallback to basic process check
        try:
            subprocess.run(['pgrep', '-f', 'python'], check=True, capture_output=True)
            return True
        except:
            return False

def check_security_status():
    """Verify security configurations."""
    checks = {
        'non_root_user': os.getuid() != 0,
        'secure_permissions': os.stat('/app').st_mode & 0o077 == 0,
        'ssh_tools_available': subprocess.run(['which', 'ssh-keygen'], 
                                            capture_output=True).returncode == 0
    }
    return all(checks.values())

def check_file_system():
    """Check critical directories and files."""
    required_paths = [
        '/app/src/secure_ssh_scanner.py',
        '/app/src/models.py',
        '/app/secrets_audit.py'
    ]
    
    return all(os.path.exists(path) for path in required_paths)

def main():
    """Main health check function."""
    health_status = {
        'timestamp': datetime.utcnow().isoformat(),
        'status': 'healthy',
        'checks': {}
    }
    
    # Run health checks
    checks = {
        'application': check_application_health(),
        'security': check_security_status(),
        'filesystem': check_file_system()
    }
    
    health_status['checks'] = checks
    
    # Determine overall health
    if all(checks.values()):
        health_status['status'] = 'healthy'
        print(json.dumps(health_status, indent=2))
        sys.exit(0)
    else:
        health_status['status'] = 'unhealthy'
        print(json.dumps(health_status, indent=2))
        sys.exit(1)

if __name__ == '__main__':
    main()

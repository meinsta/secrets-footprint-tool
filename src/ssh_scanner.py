"""
SSH Key Scanner and Analyzer
Detects SSH keys in common locations and analyzes their security properties.
"""

import os
import glob
import re
import stat
import subprocess
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519

from models import SSHKeyInfo, Secret, SecretType, StorageLocation, RotationFrequency


class SSHKeyScanner:
    """Scans for and analyzes SSH keys in the local environment."""
    
    def __init__(self):
        self.common_ssh_locations = [
            "~/.ssh/",
            "~/.ssh/id_*",
            "~/.ssh/*_rsa",
            "~/.ssh/*_ed25519",
            "~/.ssh/*_ecdsa",
            "~/.ssh/*_dsa",
        ]
        
        self.ssh_config_files = [
            "~/.ssh/config",
            "~/.ssh/authorized_keys",
            "~/.ssh/known_hosts"
        ]
    
    def scan_ssh_keys(self) -> List[SSHKeyInfo]:
        """
        Scan for SSH keys in common locations and analyze them.
        Returns a list of SSHKeyInfo objects.
        """
        ssh_keys = []
        
        # Expand user path
        ssh_dir = os.path.expanduser("~/.ssh")
        
        if not os.path.exists(ssh_dir):
            print("⚠️  No ~/.ssh directory found")
            return ssh_keys
        
        # Find potential SSH key files
        key_files = self._find_ssh_key_files(ssh_dir)
        
        print(f"📋 Found {len(key_files)} potential SSH key files")
        
        for key_file in key_files:
            try:
                key_info = self._analyze_ssh_key(key_file)
                if key_info:
                    ssh_keys.append(key_info)
                    print(f"✅ Analyzed: {os.path.basename(key_file)}")
            except Exception as e:
                print(f"❌ Error analyzing {key_file}: {str(e)}")
        
        # Check SSH agent
        agent_keys = self._get_ssh_agent_keys()
        for agent_key in agent_keys:
            # Mark keys that are loaded in agent
            for key in ssh_keys:
                if agent_key.get('fingerprint') == key.fingerprint:
                    key.is_agent_key = True
        
        return ssh_keys
    
    def _find_ssh_key_files(self, ssh_dir: str) -> List[str]:
        """Find SSH key files in the SSH directory."""
        key_files = []
        
        # Common SSH key file patterns
        patterns = [
            "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
            "*_rsa", "*_dsa", "*_ecdsa", "*_ed25519"
        ]
        
        for pattern in patterns:
            matches = glob.glob(os.path.join(ssh_dir, pattern))
            for match in matches:
                # Skip .pub files (we'll handle them separately)
                if not match.endswith('.pub') and os.path.isfile(match):
                    key_files.append(match)
        
        # Also look for any file that might be a private key
        for file in os.listdir(ssh_dir):
            file_path = os.path.join(ssh_dir, file)
            if (os.path.isfile(file_path) and 
                not file.endswith('.pub') and 
                not file in ['config', 'authorized_keys', 'known_hosts'] and
                self._is_likely_private_key(file_path)):
                if file_path not in key_files:
                    key_files.append(file_path)
        
        return key_files
    
    def _is_likely_private_key(self, file_path: str) -> bool:
        """Check if a file is likely a private SSH key."""
        try:
            with open(file_path, 'r') as f:
                first_line = f.readline().strip()
                return (first_line.startswith('-----BEGIN') and 
                       ('PRIVATE KEY' in first_line or 'RSA PRIVATE KEY' in first_line or
                        'DSA PRIVATE KEY' in first_line or 'EC PRIVATE KEY' in first_line or
                        'OPENSSH PRIVATE KEY' in first_line))
        except:
            return False
    
    def _analyze_ssh_key(self, key_path: str) -> Optional[SSHKeyInfo]:
        """Analyze a single SSH key file."""
        try:
            # Get file stats
            file_stats = os.stat(key_path)
            permissions = oct(file_stats.st_mode)[-3:]
            
            # Try to read the key
            with open(key_path, 'rb') as f:
                key_data = f.read()
            
            # Determine key type and get fingerprint
            key_type, key_size, fingerprint, comment = self._get_key_info(key_path)
            
            # Check if key has passphrase
            has_passphrase = self._check_passphrase(key_data)
            
            # Get associated hosts from SSH config
            associated_hosts = self._get_associated_hosts(key_path)
            
            # Check last modification time as proxy for creation
            last_modified = datetime.fromtimestamp(file_stats.st_mtime)
            
            return SSHKeyInfo(
                file_path=key_path,
                key_type=key_type,
                key_size=key_size,
                fingerprint=fingerprint,
                comment=comment,
                has_passphrase=has_passphrase,
                permissions=permissions,
                last_used=last_modified,  # Approximation
                associated_hosts=associated_hosts,
                is_agent_key=False  # Will be set later if found in agent
            )
            
        except Exception as e:
            print(f"Error analyzing SSH key {key_path}: {e}")
            return None
    
    def _get_key_info(self, key_path: str) -> Tuple[str, Optional[int], str, str]:
        """Get key type, size, fingerprint, and comment."""
        try:
            # Try using ssh-keygen to get key information
            result = subprocess.run([
                'ssh-keygen', '-l', '-f', key_path
            ], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # Parse ssh-keygen output: "2048 SHA256:fingerprint comment (RSA)"
                parts = result.stdout.strip().split()
                if len(parts) >= 2:
                    key_size = int(parts[0]) if parts[0].isdigit() else None
                    fingerprint = parts[1]
                    
                    # Extract key type from parentheses
                    key_type = "unknown"
                    if '(' in result.stdout and ')' in result.stdout:
                        key_type = result.stdout.split('(')[-1].split(')')[0].lower()
                    
                    # Extract comment (everything after fingerprint)
                    comment_parts = parts[2:] if len(parts) > 2 else []
                    # Remove the key type in parentheses
                    comment = ' '.join(comment_parts)
                    if '(' in comment:
                        comment = comment.split('(')[0].strip()
                    
                    return key_type, key_size, fingerprint, comment
            
            # Fallback: try to determine key type from file content
            with open(key_path, 'r') as f:
                first_line = f.readline()
                if 'RSA' in first_line:
                    return 'rsa', None, '', ''
                elif 'DSA' in first_line:
                    return 'dsa', None, '', ''
                elif 'EC' in first_line:
                    return 'ecdsa', None, '', ''
                elif 'OPENSSH' in first_line:
                    return 'ed25519', None, '', ''
                    
        except Exception as e:
            print(f"Error getting key info for {key_path}: {e}")
        
        return 'unknown', None, '', ''
    
    def _check_passphrase(self, key_data: bytes) -> bool:
        """Check if SSH key is protected with a passphrase."""
        try:
            # Try to load the key without a passphrase
            serialization.load_pem_private_key(key_data, password=None)
            return False  # No passphrase needed
        except TypeError:
            # This usually means a passphrase is required
            return True
        except Exception:
            # Could be OpenSSH format, check for encryption indicators
            key_text = key_data.decode('utf-8', errors='ignore')
            return 'Proc-Type: 4,ENCRYPTED' in key_text or 'aes' in key_text.lower()
    
    def _get_associated_hosts(self, key_path: str) -> List[str]:
        """Find hosts associated with this SSH key from SSH config."""
        hosts = []
        ssh_config_path = os.path.expanduser("~/.ssh/config")
        
        if not os.path.exists(ssh_config_path):
            return hosts
        
        try:
            with open(ssh_config_path, 'r') as f:
                config_content = f.read()
            
            # Look for references to this key file
            key_filename = os.path.basename(key_path)
            
            # Parse SSH config for hosts using this key
            current_host = None
            for line in config_content.split('\n'):
                line = line.strip()
                if line.startswith('Host '):
                    current_host = line.split()[1] if len(line.split()) > 1 else None
                elif line.startswith('IdentityFile') and current_host:
                    identity_file = line.split()[1] if len(line.split()) > 1 else ''
                    if key_filename in identity_file or key_path in identity_file:
                        hosts.append(current_host)
                        
        except Exception as e:
            print(f"Error reading SSH config: {e}")
        
        return hosts
    
    def _get_ssh_agent_keys(self) -> List[Dict]:
        """Get keys currently loaded in SSH agent."""
        agent_keys = []
        
        try:
            result = subprocess.run(['ssh-add', '-l'], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and not line.startswith('The agent has no identities'):
                        parts = line.split()
                        if len(parts) >= 2:
                            agent_keys.append({
                                'size': parts[0],
                                'fingerprint': parts[1],
                                'comment': ' '.join(parts[2:]) if len(parts) > 2 else ''
                            })
        except Exception as e:
            print(f"Error checking SSH agent: {e}")
        
        return agent_keys
    
    def convert_to_secrets(self, ssh_keys: List[SSHKeyInfo]) -> List[Secret]:
        """Convert SSH key info to Secret objects for risk assessment."""
        secrets = []
        
        for ssh_key in ssh_keys:
            # Estimate creation date from file modification time
            created_date = ssh_key.last_used
            
            # Determine rotation frequency based on key age and type
            rotation_freq = RotationFrequency.NEVER  # Most SSH keys are never rotated
            
            # Create risk factors based on key analysis
            risk_factors = []
            
            if not ssh_key.has_passphrase:
                risk_factors.append("No passphrase protection")
            
            if ssh_key.permissions and ssh_key.permissions != '600':
                risk_factors.append(f"Incorrect permissions: {ssh_key.permissions}")
            
            if ssh_key.key_type == 'rsa' and ssh_key.key_size and ssh_key.key_size < 2048:
                risk_factors.append(f"Weak RSA key size: {ssh_key.key_size}")
            
            if ssh_key.key_type in ['dsa']:
                risk_factors.append("Using deprecated DSA algorithm")
            
            if not ssh_key.associated_hosts:
                risk_factors.append("No associated hosts found")
            
            # Determine access level based on risk factors
            access_level = "restricted"
            if len(risk_factors) > 2:
                access_level = "high_risk"
            elif ssh_key.has_passphrase and ssh_key.permissions == '600':
                access_level = "confidential"
            
            secret = Secret(
                id=f"ssh_key_{os.path.basename(ssh_key.file_path)}",
                secret_type=SecretType.SSH_KEY,
                name=f"SSH Key: {os.path.basename(ssh_key.file_path)}",
                location=StorageLocation.LOCAL_FILESYSTEM,
                file_path=ssh_key.file_path,
                created_date=created_date,
                last_rotated=created_date,  # SSH keys typically aren't rotated
                rotation_frequency=rotation_freq,
                access_level=access_level,
                encryption_status=ssh_key.has_passphrase,
                shared_with=[],
                risk_factors=risk_factors
            )
            
            secrets.append(secret)
        
        return secrets
    
    def get_ssh_key_recommendations(self, ssh_keys: List[SSHKeyInfo]) -> List[str]:
        """Generate security recommendations based on SSH key analysis."""
        recommendations = []
        
        if not ssh_keys:
            recommendations.append("No SSH keys found. Consider setting up SSH keys for secure authentication.")
            return recommendations
        
        # Check for keys without passphrases
        unprotected_keys = [k for k in ssh_keys if not k.has_passphrase]
        if unprotected_keys:
            recommendations.append(
                f"🔒 Add passphrases to {len(unprotected_keys)} unprotected SSH keys "
                f"for additional security."
            )
        
        # Check for weak key types or sizes
        weak_keys = []
        for key in ssh_keys:
            if key.key_type == 'dsa':
                weak_keys.append(key)
            elif key.key_type == 'rsa' and key.key_size and key.key_size < 2048:
                weak_keys.append(key)
        
        if weak_keys:
            recommendations.append(
                f"🔄 Replace {len(weak_keys)} weak SSH keys with stronger algorithms "
                f"(Ed25519 or RSA 4096-bit)."
            )
        
        # Check permissions
        bad_permissions = [k for k in ssh_keys if k.permissions != '600']
        if bad_permissions:
            recommendations.append(
                f"🛡️ Fix file permissions for {len(bad_permissions)} SSH keys "
                f"(should be 600: readable/writable by owner only)."
            )
        
        # Check for keys not in SSH agent
        agent_keys = [k for k in ssh_keys if k.is_agent_key]
        if len(agent_keys) < len(ssh_keys):
            recommendations.append(
                f"🔑 Consider adding SSH keys to ssh-agent for better key management "
                f"({len(ssh_keys) - len(agent_keys)} keys not in agent)."
            )
        
        # General recommendations
        if len(ssh_keys) > 5:
            recommendations.append(
                f"🧹 Review and clean up SSH keys - found {len(ssh_keys)} keys. "
                f"Remove unused keys to reduce attack surface."
            )
        
        recommendations.append(
            "📋 Consider implementing SSH key rotation policy and certificate-based authentication."
        )
        
        return recommendations

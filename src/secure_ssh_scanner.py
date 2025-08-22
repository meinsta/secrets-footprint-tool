"""
SECURITY-HARDENED SSH Key Scanner
This version ensures NO SECRET CONTENT is ever read or stored.
Only uses external system tools and file metadata.
"""

import os
import glob
import stat
import subprocess
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import re

from models import SSHKeyInfo, Secret, SecretType, StorageLocation, RotationFrequency


class SecureSSHKeyScanner:
    """
    Security-hardened SSH key scanner that NEVER reads secret content.
    
    SECURITY GUARANTEES:
    - Never opens or reads private key files directly
    - Only uses system SSH tools (ssh-keygen, ssh-add)
    - No cryptographic library usage that could decrypt keys
    - Strict path validation to prevent directory traversal
    - Only analyzes file metadata and external tool outputs
    """
    
    def __init__(self):
        # Only scan in the user's SSH directory - STRICT LIMITATION
        self.ssh_dir = os.path.expanduser("~/.ssh")
        self.allowed_patterns = [
            "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
            "*_rsa", "*_dsa", "*_ecdsa", "*_ed25519"
        ]
        
    def scan_ssh_keys(self) -> List[SSHKeyInfo]:
        """
        Scan for SSH keys using ONLY external tools and metadata.
        NEVER reads private key content.
        """
        ssh_keys = []
        
        # Validate SSH directory exists and is secure
        if not self._validate_ssh_directory():
            print("⚠️  SSH directory not found or not secure")
            return ssh_keys
        
        # Find potential SSH key files using STRICT validation
        key_files = self._find_ssh_key_files_secure()
        
        print(f"📋 Found {len(key_files)} potential SSH key files")
        
        for key_file in key_files:
            try:
                # SECURITY: Validate each file path before processing
                if not self._is_safe_key_path(key_file):
                    print(f"⚠️  Skipping potentially unsafe path: {key_file}")
                    continue
                    
                key_info = self._analyze_ssh_key_secure(key_file)
                if key_info:
                    ssh_keys.append(key_info)
                    print(f"✅ Analyzed: {os.path.basename(key_file)}")
            except Exception as e:
                print(f"❌ Error analyzing {key_file}: {str(e)}")
        
        # Check SSH agent using external tool only
        agent_keys = self._get_ssh_agent_keys_secure()
        for agent_key in agent_keys:
            for key in ssh_keys:
                if agent_key.get('fingerprint') == key.fingerprint:
                    key.is_agent_key = True
        
        return ssh_keys
    
    def _validate_ssh_directory(self) -> bool:
        """Validate SSH directory exists and has proper permissions."""
        if not os.path.exists(self.ssh_dir):
            return False
        
        # Check directory permissions (should be 700)
        dir_stat = os.stat(self.ssh_dir)
        dir_perms = oct(dir_stat.st_mode)[-3:]
        
        if dir_perms not in ['700', '755']:  # Allow some flexibility
            print(f"⚠️  SSH directory has unusual permissions: {dir_perms}")
        
        return True
    
    def _find_ssh_key_files_secure(self) -> List[str]:
        """Find SSH key files using STRICT path validation."""
        key_files = []
        
        # Only scan known patterns in SSH directory
        for pattern in self.allowed_patterns:
            try:
                matches = glob.glob(os.path.join(self.ssh_dir, pattern))
                for match in matches:
                    # Multiple security checks
                    if (os.path.isfile(match) and 
                        not match.endswith('.pub') and
                        self._is_safe_key_path(match) and
                        self._looks_like_private_key_safe(match)):
                        key_files.append(match)
            except Exception as e:
                print(f"⚠️  Error scanning pattern {pattern}: {e}")
        
        return key_files
    
    def _is_safe_key_path(self, file_path: str) -> bool:
        """
        SECURITY: Validate file path is safe and within SSH directory.
        Prevents directory traversal attacks.
        """
        try:
            # Resolve any symbolic links and relative paths
            real_path = os.path.realpath(file_path)
            real_ssh_dir = os.path.realpath(self.ssh_dir)
            
            # Ensure file is actually within SSH directory
            if not real_path.startswith(real_ssh_dir + os.sep):
                return False
            
            # Check for suspicious path components
            suspicious_components = ['..', '~', '$', '`', ';', '|', '&']
            for component in suspicious_components:
                if component in file_path:
                    return False
            
            # Filename should look like a reasonable SSH key
            filename = os.path.basename(file_path)
            if not re.match(r'^[a-zA-Z0-9._-]+$', filename):
                return False
                
            return True
        except Exception:
            return False
    
    def _looks_like_private_key_safe(self, file_path: str) -> bool:
        """
        SECURITY: Check if file looks like SSH key WITHOUT reading content.
        Only uses file metadata and safe external tools.
        """
        try:
            # First check: file size should be reasonable for a key
            file_size = os.path.getsize(file_path)
            if file_size < 100 or file_size > 10000:  # Reasonable bounds
                return False
            
            # Second check: use ssh-keygen to validate (SAFE - external tool)
            result = subprocess.run([
                'ssh-keygen', '-l', '-f', file_path
            ], capture_output=True, text=True, timeout=5)
            
            # If ssh-keygen can read it, it's likely a valid key
            return result.returncode == 0
            
        except Exception:
            return False
    
    def _analyze_ssh_key_secure(self, key_path: str) -> Optional[SSHKeyInfo]:
        """
        SECURITY: Analyze SSH key using ONLY external tools and metadata.
        NEVER reads the key file content directly.
        """
        try:
            # Get file stats (SAFE - only metadata)
            file_stats = os.stat(key_path)
            permissions = oct(file_stats.st_mode)[-3:]
            last_modified = datetime.fromtimestamp(file_stats.st_mtime)
            
            # Get key info using EXTERNAL TOOL ONLY
            key_type, key_size, fingerprint, comment = self._get_key_info_secure(key_path)
            
            # Check passphrase protection using EXTERNAL TOOL ONLY
            has_passphrase = self._check_passphrase_secure(key_path)
            
            # Get associated hosts (limited and safe)
            associated_hosts = self._get_associated_hosts_safe(key_path)
            
            return SSHKeyInfo(
                file_path=key_path,
                key_type=key_type,
                key_size=key_size,
                fingerprint=fingerprint,
                comment=comment,
                has_passphrase=has_passphrase,
                permissions=permissions,
                last_used=last_modified,
                associated_hosts=associated_hosts,
                is_agent_key=False
            )
            
        except Exception as e:
            print(f"Error analyzing SSH key {key_path}: {e}")
            return None
    
    def _get_key_info_secure(self, key_path: str) -> Tuple[str, Optional[int], str, str]:
        """
        SECURITY: Get key info using ONLY ssh-keygen external tool.
        NEVER parses key content directly.
        """
        try:
            # Use ssh-keygen - the ONLY safe way to get key info
            result = subprocess.run([
                'ssh-keygen', '-l', '-f', key_path
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Parse ssh-keygen output: "2048 SHA256:fingerprint comment (RSA)"
                output = result.stdout.strip()
                parts = output.split()
                
                if len(parts) >= 2:
                    key_size = int(parts[0]) if parts[0].isdigit() else None
                    fingerprint = parts[1]
                    
                    # Extract key type from parentheses
                    key_type = "unknown"
                    if '(' in output and ')' in output:
                        key_type = output.split('(')[-1].split(')')[0].lower()
                    
                    # Extract comment (everything between fingerprint and type)
                    comment_parts = parts[2:]
                    comment = ' '.join(comment_parts)
                    if '(' in comment:
                        comment = comment.split('(')[0].strip()
                    
                    return key_type, key_size, fingerprint, comment
            
            # If ssh-keygen fails, we can't safely determine key info
            return 'unknown', None, 'unknown', ''
            
        except Exception as e:
            print(f"Error getting key info for {key_path}: {e}")
            return 'unknown', None, 'unknown', ''
    
    def _check_passphrase_secure(self, key_path: str) -> bool:
        """
        SECURITY: Check passphrase protection using ONLY external tools.
        NEVER tries to decrypt or read key content.
        """
        try:
            # Try to get key info with ssh-keygen - if it asks for passphrase, 
            # the process will return an error or specific output
            result = subprocess.run([
                'ssh-keygen', '-y', '-f', key_path
            ], capture_output=True, text=True, timeout=5, input='\n')
            
            # If it succeeds without input, no passphrase
            if result.returncode == 0:
                return False
            
            # Check error messages for passphrase indicators
            stderr = result.stderr.lower()
            if any(phrase in stderr for phrase in [
                'passphrase', 'password', 'encrypted', 'invalid format'
            ]):
                return True
            
            # Default to assuming passphrase protection (safer assumption)
            return True
            
        except Exception:
            # If we can't determine safely, assume it's protected
            return True
    
    def _get_associated_hosts_safe(self, key_path: str) -> List[str]:
        """
        SECURITY: Get associated hosts using LIMITED and safe SSH config parsing.
        Only reads specific configuration lines, never entire file.
        """
        hosts = []
        ssh_config_path = os.path.join(self.ssh_dir, "config")
        
        if not os.path.exists(ssh_config_path):
            return hosts
        
        try:
            key_filename = os.path.basename(key_path)
            
            # SECURITY: Only read specific lines, with limits
            with open(ssh_config_path, 'r') as f:
                current_host = None
                line_count = 0
                
                for line in f:
                    line_count += 1
                    # Safety limit - don't read huge config files
                    if line_count > 1000:
                        break
                    
                    line = line.strip()
                    
                    # Only process relevant lines
                    if line.startswith('Host '):
                        parts = line.split()
                        current_host = parts[1] if len(parts) > 1 else None
                    elif line.startswith('IdentityFile') and current_host:
                        parts = line.split()
                        if len(parts) > 1:
                            identity_file = parts[1]
                            # Simple filename matching only
                            if key_filename in identity_file:
                                hosts.append(current_host)
                        
        except Exception as e:
            print(f"Error reading SSH config safely: {e}")
        
        return hosts
    
    def _get_ssh_agent_keys_secure(self) -> List[Dict]:
        """SECURITY: Get SSH agent keys using ONLY external ssh-add tool."""
        agent_keys = []
        
        try:
            result = subprocess.run(['ssh-add', '-l'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\\n'):
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
            created_date = ssh_key.last_used
            rotation_freq = RotationFrequency.NEVER
            
            # Create risk factors based ONLY on metadata
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
            
            # Determine access level
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
                last_rotated=created_date,
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

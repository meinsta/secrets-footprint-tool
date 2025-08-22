"""
Web Application for Secrets Footprint Assessment Tool
A Flask-based web interface for the secrets security assessment tool.
"""

import sys
import os
import json
import uuid
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response, flash, send_file
import tempfile

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from models import AuditSession, Secret, System, SecretType, StorageLocation, RotationFrequency
from secure_ssh_scanner import SecureSSHKeyScanner
from systems import SystemsManager, SystemCategory
from risk_engine import RiskScoringEngine
from visualizer import SecretsFootprintVisualizer

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize core components
systems_manager = SystemsManager()
risk_engine = RiskScoringEngine()
visualizer = SecretsFootprintVisualizer()

# Example environments for demo purposes
EXAMPLE_ENVIRONMENTS = {
    "startup": {
        "name": "Tech Startup",
        "description": "Small development team using modern cloud services",
        "systems": [
            {"name": "GitHub Actions", "secrets_count": 8, "responses": {"repo_secrets": "8", "org_secrets": "n", "environment_secrets": "y", "secret_rotation": "never"}},
            {"name": "AWS", "secrets_count": 12, "responses": {"iam_users": "3", "secrets_manager": "n", "parameter_store": "y", "rotation_enabled": "n"}},
            {"name": "Docker", "secrets_count": 5, "responses": {"secrets_in_env": "y", "secrets_in_files": "n", "base_images": "n"}},
        ],
        "ssh_keys": [
            {"type": "rsa", "size": 2048, "passphrase": False, "permissions": "600", "age_days": 180},
            {"type": "ed25519", "size": None, "passphrase": True, "permissions": "600", "age_days": 30},
        ]
    },
    "enterprise": {
        "name": "Enterprise Corporation",
        "description": "Large organization with mature security practices",
        "systems": [
            {"name": "Jenkins", "secrets_count": 45, "responses": {"credential_store": "vault", "credentials_count": "45", "access_control": "y"}},
            {"name": "HashiCorp Vault", "secrets_count": 200, "responses": {"secret_engines": "kv,database,aws", "auth_methods": "ldap,kubernetes", "policies_count": "25", "dynamic_secrets": "y"}},
            {"name": "AWS", "secrets_count": 30, "responses": {"iam_users": "8", "secrets_manager": "y", "parameter_store": "y", "rotation_enabled": "y"}},
            {"name": "Kubernetes", "secrets_count": 65, "responses": {"secrets_count": "65", "etcd_encryption": "y", "external_secrets": "y", "rbac": "y"}},
        ],
        "ssh_keys": [
            {"type": "ed25519", "size": None, "passphrase": True, "permissions": "600", "age_days": 45},
            {"type": "rsa", "size": 4096, "passphrase": True, "permissions": "600", "age_days": 90},
            {"type": "ed25519", "size": None, "passphrase": True, "permissions": "600", "age_days": 15},
        ]
    },
    "mixed": {
        "name": "Mixed Environment",
        "description": "Organization in transition with legacy and modern systems",
        "systems": [
            {"name": "GitHub Actions", "secrets_count": 15, "responses": {"repo_secrets": "10", "org_secrets": "y", "environment_secrets": "y", "secret_rotation": "quarterly"}},
            {"name": "Jenkins", "secrets_count": 35, "responses": {"credential_store": "built-in", "credentials_count": "35", "access_control": "n"}},
            {"name": "1Password", "secrets_count": 80, "responses": {"vaults_count": "5", "shared_secrets": "25", "integrations": "y"}},
            {"name": "Git Repository", "secrets_count": 3, "responses": {"secrets_in_code": "y", "secrets_scanning": "n", "git_history": "n", "gitignore": "y"}},
            {"name": "MySQL", "secrets_count": 8, "responses": {"root_password": "stored in config", "ssl_enabled": "n", "password_policy": "n"}},
        ],
        "ssh_keys": [
            {"type": "rsa", "size": 1024, "passphrase": False, "permissions": "644", "age_days": 800},
            {"type": "rsa", "size": 2048, "passphrase": False, "permissions": "600", "age_days": 400},
            {"type": "ed25519", "size": None, "passphrase": True, "permissions": "600", "age_days": 60},
        ]
    }
}


@app.route('/')
def index():
    """Main landing page."""
    return render_template('index.html')


@app.route('/start')
def start_assessment():
    """Start a new assessment."""
    return render_template('start.html', example_environments=EXAMPLE_ENVIRONMENTS)


@app.route('/assessment/new', methods=['POST'])
def create_assessment():
    """Create a new assessment session."""
    session_id = str(uuid.uuid4())[:8]
    
    # Check if using an example environment
    example_env = request.form.get('example_environment')
    
    if example_env and example_env in EXAMPLE_ENVIRONMENTS:
        # Load example environment - but follow normal flow
        session['using_example'] = True
        session['example_name'] = EXAMPLE_ENVIRONMENTS[example_env]['name']
        session['session_id'] = session_id
        session['example_type'] = example_env
        
        # Pre-populate example data but still show the steps
        env_data = EXAMPLE_ENVIRONMENTS[example_env]
        audit_session = AuditSession(
            session_id=session_id,
            timestamp=datetime.now(),
            discovered_secrets=[],
            ssh_keys=[],
            selected_systems=[],
            user_responses={}
        )
        
        # Load example environment data
        audit_session = load_example_environment(audit_session, env_data)
        
        # Save full data to cache to avoid session size limits
        audit_data = {
            'session_id': session_id,
            'timestamp': datetime.now().isoformat(),
            'discovered_secrets': [_secret_to_dict(s) for s in audit_session.discovered_secrets],
            'ssh_keys': [_ssh_key_to_dict(k) for k in audit_session.ssh_keys],
            'selected_systems': [_system_to_dict(s) for s in audit_session.selected_systems],
            'user_responses': audit_session.user_responses
        }
        _save_audit_data(audit_data)
        
        # Store minimal data in session
        session['audit_session'] = {
            'session_id': session_id,
            'timestamp': datetime.now().isoformat(),
            'discovered_secrets': [],  # Empty - load from cache
            'ssh_keys': [],  # Empty - load from cache  
            'selected_systems': [],  # Empty - load from cache
            'user_responses': {}
        }
    else:
        session['using_example'] = False
        session['session_id'] = session_id
        # Initialize empty audit session
        session['audit_session'] = {
            'session_id': session_id,
            'timestamp': datetime.now().isoformat(),
            'discovered_secrets': [],
            'ssh_keys': [],
            'selected_systems': [],
            'user_responses': {}
        }
    
    # Always start with SSH analysis step
    return redirect(url_for('ssh_analysis'))


@app.route('/ssh-analysis')
def ssh_analysis():
    """SSH key analysis step."""
    if not session.get('session_id') or 'audit_session' not in session:
        return redirect(url_for('start_assessment'))
    
    # If using example, show simulated SSH keys from cache
    if session.get('using_example', False):
        audit_data = _load_audit_data()
        if audit_data:
            ssh_keys = audit_data.get('ssh_keys', [])
        else:
            ssh_keys = []
        
        return render_template('ssh_analysis.html', 
                             ssh_keys=ssh_keys,
                             using_example=True,
                             example_name=session.get('example_name', ''))
    
    return render_template('ssh_analysis.html', using_example=False)


@app.route('/api/scan-ssh', methods=['POST'])
def scan_ssh_keys():
    """API endpoint to scan SSH keys."""
    if 'audit_session' not in session:
        return jsonify({'error': 'No active session'}), 400
    
    try:
        scanner = SecureSSHKeyScanner()
        ssh_keys = scanner.scan_ssh_keys()
        
        # Convert SSH keys to secrets
        ssh_secrets = scanner.convert_to_secrets(ssh_keys)
        
        # Update session
        audit_data = session['audit_session']
        audit_data['ssh_keys'] = [key.__dict__ if hasattr(key, '__dict__') else key for key in ssh_keys]
        audit_data['discovered_secrets'].extend([secret.to_dict() if hasattr(secret, 'to_dict') else secret.__dict__ for secret in ssh_secrets])
        session['audit_session'] = audit_data
        
        return jsonify({
            'success': True,
            'ssh_keys_count': len(ssh_keys),
            'ssh_keys': [_ssh_key_to_dict(key) for key in ssh_keys],
            'security_issues': sum(1 for key in ssh_keys if not key.has_passphrase or key.permissions != '600')
        })
        
    except Exception as e:
        return jsonify({'error': f'SSH scan failed: {str(e)}'}), 500


@app.route('/systems')
def systems_selection():
    """System selection step."""
    if 'audit_session' not in session:
        return redirect(url_for('start_assessment'))
    
    categories = systems_manager.get_systems_by_category()
    
    # Organize systems for display
    organized_systems = {}
    for category, system_names in categories.items():
        category_name = category.value.replace('_', ' ').title()
        organized_systems[category_name] = []
        
        for system_name in system_names:
            template = systems_manager.get_system_template(system_name)
            if template:
                organized_systems[category_name].append({
                    'name': template.name,
                    'description': template.description,
                    'common_secrets': template.common_secret_types,
                    'questions': template.questions
                })
    
    # Get selected systems - either from cache (examples) or session (regular)
    selected_systems = []
    if session.get('using_example', False):
        # Load from cache for example environments
        audit_data = _load_audit_data()
        if audit_data:
            selected_systems = audit_data.get('selected_systems', [])
    else:
        # Load from session for regular flow
        selected_systems = session['audit_session'].get('selected_systems', [])
    
    return render_template('systems.html', 
                         systems=organized_systems,
                         using_example=session.get('using_example', False),
                         example_name=session.get('example_name', ''),
                         selected_systems=selected_systems)


@app.route('/api/configure-system', methods=['POST'])
def configure_system():
    """API endpoint to configure a system."""
    if 'audit_session' not in session:
        return jsonify({'error': 'No active session'}), 400
    
    data = request.get_json()
    system_name = data.get('system_name')
    responses = data.get('responses', {})
    
    try:
        # Create system from template and responses
        system = systems_manager.create_system_from_template(system_name, responses)
        
        # Update session
        audit_data = session['audit_session']
        if 'selected_systems' not in audit_data:
            audit_data['selected_systems'] = []
        
        # Convert system to dict for JSON serialization
        system_dict = {
            'name': system.name,
            'type': system.type,
            'is_used': system.is_used,
            'secrets_count': system.secrets_count,
            'encryption_enabled': system.encryption_enabled,
            'audit_logging': system.audit_logging,
            'auto_rotation': system.auto_rotation,
            'access_controls': system.access_controls,
            'risk_score': system.risk_score
        }
        
        audit_data['selected_systems'].append(system_dict)
        audit_data['user_responses'][system_name] = responses
        session['audit_session'] = audit_data
        
        return jsonify({
            'success': True,
            'system': system_dict
        })
        
    except Exception as e:
        return jsonify({'error': f'System configuration failed: {str(e)}'}), 500


@app.route('/assessment')
def show_assessment():
    """Show the risk assessment results."""
    if not session.get('session_id'):
        return redirect(url_for('start_assessment'))
    
    # Handle example environments
    if session.get('using_example', False):
        example_type = session.get('example_type')
        if example_type and example_type in EXAMPLE_ENVIRONMENTS:
            # Generate example data on-demand
            env_data = EXAMPLE_ENVIRONMENTS[example_type]
            
            # Create audit session with example data
            audit_session = AuditSession(
                session_id=session['session_id'],
                timestamp=datetime.now(),
                discovered_secrets=[],
                ssh_keys=[],
                selected_systems=[],
                user_responses={}
            )
            
            # Load example environment
            audit_session = load_example_environment(audit_session, env_data)
            
            # Generate risk assessment from example data
            assessment = risk_engine.generate_risk_assessment(
                audit_session.discovered_secrets,
                audit_session.ssh_keys,
                audit_session.selected_systems
            )
        else:
            return redirect(url_for('start_assessment'))
    else:
        # Handle regular (non-example) sessions
        if 'audit_session' not in session:
            return redirect(url_for('start_assessment'))
        
        audit_data = session['audit_session']
        
        # Recreate objects from session data
        secrets = [_dict_to_secret(s) for s in audit_data.get('discovered_secrets', [])]
        systems = [_dict_to_system(s) for s in audit_data.get('selected_systems', [])]
        ssh_keys = [_dict_to_ssh_key(k) for k in audit_data.get('ssh_keys', [])]
        
        # Generate risk assessment
        assessment = risk_engine.generate_risk_assessment(secrets, ssh_keys, systems)
    
    # Get summary stats
    stats = risk_engine.get_risk_summary_stats(assessment)
    
    # Convert assessment to dict for JSON serialization in template
    assessment_dict = _assessment_to_dict(assessment)
    
    return render_template('assessment.html',
                         assessment=assessment,
                         assessment_dict=assessment_dict,
                         stats=stats,
                         using_example=session.get('using_example', False),
                         example_name=session.get('example_name', ''))


@app.route('/api/generate-report/<report_type>')
def generate_report(report_type):
    """Generate and download reports."""
    if 'audit_session' not in session:
        return jsonify({'error': 'No active session'}), 400
    
    audit_data = session['audit_session']
    
    # Recreate objects from session data
    secrets = [_dict_to_secret(s) for s in audit_data.get('discovered_secrets', [])]
    systems = [_dict_to_system(s) for s in audit_data.get('selected_systems', [])]
    ssh_keys = [_dict_to_ssh_key(k) for k in audit_data.get('ssh_keys', [])]
    
    # Generate risk assessment
    assessment = risk_engine.generate_risk_assessment(secrets, ssh_keys, systems)
    
    try:
        if report_type == 'html':
            # Generate HTML report
            html_content = visualizer.create_html_report(assessment, ssh_keys)
            
            # Create temporary file
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False)
            temp_file.write(html_content)
            temp_file.close()
            
            return send_file(temp_file.name, 
                           as_attachment=True,
                           download_name=f"secrets_assessment_{session['session_id']}.html",
                           mimetype='text/html')
        
        elif report_type == 'json':
            # Generate JSON report
            report_data = {
                'session_id': session['session_id'],
                'timestamp': datetime.now().isoformat(),
                'assessment': _assessment_to_dict(assessment),
                'secrets': [_secret_to_dict(s) for s in secrets],
                'systems': [_system_to_dict(s) for s in systems],
                'ssh_keys': [_ssh_key_to_dict(k) for k in ssh_keys]
            }
            
            # Create temporary file
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
            json.dump(report_data, temp_file, indent=2, default=str)
            temp_file.close()
            
            return send_file(temp_file.name,
                           as_attachment=True, 
                           download_name=f"secrets_data_{session['session_id']}.json",
                           mimetype='application/json')
        
        elif report_type == 'executive':
            # Generate executive summary
            summary = visualizer.generate_executive_summary(assessment)
            
            # Create temporary file
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
            temp_file.write(summary)
            temp_file.close()
            
            return send_file(temp_file.name,
                           as_attachment=True,
                           download_name=f"executive_summary_{session['session_id']}.txt",
                           mimetype='text/plain')
        
        else:
            return jsonify({'error': 'Invalid report type'}), 400
    
    except Exception as e:
        return jsonify({'error': f'Report generation failed: {str(e)}'}), 500


@app.route('/start_smart_assessment', methods=['POST'])
def start_smart_assessment():
    """Start a smart assessment with auto-scanning."""
    try:
        # Create new session
        session_id = str(uuid.uuid4())[:8]
        session['session_id'] = session_id
        session['using_example'] = False
        session['smart_assessment'] = True
        
        # Initialize audit session
        audit_session = {
            'session_id': session_id,
            'timestamp': datetime.now().isoformat(),
            'discovered_secrets': [],
            'ssh_keys': [],
            'selected_systems': [],
            'user_responses': {},
            'auto_scan_complete': False
        }
        session['audit_session'] = audit_session
        
        return jsonify({
            'success': True,
            'redirect_url': url_for('smart_configure')
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/smart-configure')
def smart_configure():
    """Smart assessment configuration page with auto-scan and minimal input."""
    if not session.get('session_id') or not session.get('smart_assessment'):
        return redirect(url_for('start_assessment'))
    
    return render_template('smart_configure.html')


@app.route('/api/auto-scan', methods=['POST'])
def auto_scan():
    """Perform automated scanning and environment detection."""
    if 'audit_session' not in session or not session.get('smart_assessment'):
        return jsonify({'error': 'No active smart assessment session'}), 400
    
    try:
        scan_results = {
            'ssh_keys': [],
            'detected_systems': [],
            'environment_type': 'development',
            'estimated_secrets': 0
        }
        
        # 1. Scan SSH keys
        try:
            scanner = SecureSSHKeyScanner()
            ssh_keys = scanner.scan_ssh_keys()
            ssh_secrets = scanner.convert_to_secrets(ssh_keys)
            
            scan_results['ssh_keys'] = [_ssh_key_to_dict(key) for key in ssh_keys]
            scan_results['estimated_secrets'] += len(ssh_secrets)
            
            # Update session
            audit_data = session['audit_session']
            audit_data['ssh_keys'] = [_ssh_key_to_dict(key) for key in ssh_keys]
            audit_data['discovered_secrets'] = [_secret_to_dict(secret) for secret in ssh_secrets]
            session['audit_session'] = audit_data
            
        except Exception as e:
            # If SSH scanning fails, continue with empty results
            pass
        
        # 2. Detect installed systems/tools
        detected_systems = _auto_detect_systems()
        scan_results['detected_systems'] = detected_systems
        scan_results['estimated_secrets'] += sum(sys.get('estimated_secrets', 0) for sys in detected_systems)
        
        # 3. Estimate environment type based on findings
        if len(detected_systems) > 5:
            scan_results['environment_type'] = 'enterprise'
        elif any('kubernetes' in sys['name'].lower() or 'vault' in sys['name'].lower() for sys in detected_systems):
            scan_results['environment_type'] = 'enterprise'
        elif len(detected_systems) > 2:
            scan_results['environment_type'] = 'startup'
        else:
            scan_results['environment_type'] = 'development'
        
        return jsonify({
            'success': True,
            'scan_results': scan_results
        })
        
    except Exception as e:
        return jsonify({'error': f'Auto-scan failed: {str(e)}'}), 500


@app.route('/api/finalize-smart-assessment', methods=['POST'])
def finalize_smart_assessment():
    """Finalize smart assessment with minimal user input."""
    if 'audit_session' not in session or not session.get('smart_assessment'):
        return jsonify({'error': 'No active smart assessment session'}), 400
    
    try:
        data = request.get_json()
        selected_systems = data.get('selected_systems', [])
        environment_size = data.get('environment_size', 'small')
        security_priority = data.get('security_priority', 'medium')
        
        # Auto-configure selected systems with smart defaults
        audit_data = session['audit_session']
        configured_systems = []
        
        for system_name in selected_systems:
            system = _auto_configure_system(system_name, environment_size, security_priority)
            if system:
                configured_systems.append(_system_to_dict(system))
                
                # Generate realistic secrets for this system
                system_secrets = _generate_smart_secrets(system, environment_size)
                audit_data['discovered_secrets'].extend([_secret_to_dict(s) for s in system_secrets])
        
        audit_data['selected_systems'] = configured_systems
        audit_data['auto_scan_complete'] = True
        session['audit_session'] = audit_data
        
        return jsonify({
            'success': True,
            'redirect_url': url_for('show_assessment')
        })
        
    except Exception as e:
        return jsonify({'error': f'Assessment finalization failed: {str(e)}'}), 500


@app.route('/examples')
def show_examples():
    """Show example environments."""
    return render_template('examples.html', examples=EXAMPLE_ENVIRONMENTS)


def load_example_environment(audit_session: AuditSession, env_data: Dict) -> AuditSession:
    """Load an example environment into the audit session."""
    # Create systems from example data
    for system_data in env_data['systems']:
        system = System(
            name=system_data['name'],
            type=systems_manager.get_system_template(system_data['name']).category.value,
            is_used=True,
            secrets_count=system_data['secrets_count'],
            encryption_enabled=True,  # Default for examples
            audit_logging=True,  # Default for examples
            risk_score=2  # Will be recalculated
        )
        
        # Process responses to calculate proper risk score
        if 'responses' in system_data:
            template = systems_manager.get_system_template(system_data['name'])
            if template:
                systems_manager._process_user_responses(system, template, system_data['responses'])
        
        audit_session.selected_systems.append(system)
        audit_session.user_responses[system_data['name']] = system_data.get('responses', {})
    
    # Create SSH keys from example data
    from models import SSHKeyInfo
    for i, key_data in enumerate(env_data['ssh_keys']):
        ssh_key = SSHKeyInfo(
            file_path=f"~/.ssh/example_key_{i+1}",
            key_type=key_data['type'],
            key_size=key_data.get('size'),
            fingerprint=f"SHA256:example_fingerprint_{i+1}",
            comment=f"example_key_{i+1}@example.com",
            has_passphrase=key_data['passphrase'],
            permissions=key_data['permissions'],
            last_used=datetime.now(),
            associated_hosts=['example.com'],
            is_agent_key=True
        )
        audit_session.ssh_keys.append(ssh_key)
    
    # Convert SSH keys to secrets
    scanner = SecureSSHKeyScanner()
    ssh_secrets = scanner.convert_to_secrets(audit_session.ssh_keys)
    audit_session.discovered_secrets.extend(ssh_secrets)
    
    # Generate example secrets based on the systems configured
    _generate_example_secrets(audit_session, env_data)
    
    return audit_session


def _generate_example_secrets(audit_session: AuditSession, env_data: Dict):
    """Generate realistic example secrets based on configured systems."""
    import uuid
    from datetime import timedelta
    
    secret_id = 1
    
    for system_data in env_data['systems']:
        system_name = system_data['name']
        secrets_count = system_data.get('secrets_count', 0)
        responses = system_data.get('responses', {})
        
        # Generate secrets based on system type and responses
        if system_name == 'GitHub Actions':
            secrets = _create_github_secrets(secret_id, secrets_count, responses)
        elif system_name == 'AWS':
            secrets = _create_aws_secrets(secret_id, secrets_count, responses)
        elif system_name == 'Docker':
            secrets = _create_docker_secrets(secret_id, secrets_count, responses)
        elif system_name == 'Jenkins':
            secrets = _create_jenkins_secrets(secret_id, secrets_count, responses)
        elif system_name == 'HashiCorp Vault':
            secrets = _create_vault_secrets(secret_id, secrets_count, responses)
        elif system_name == 'Kubernetes':
            secrets = _create_k8s_secrets(secret_id, secrets_count, responses)
        elif system_name == '1Password':
            secrets = _create_1password_secrets(secret_id, secrets_count, responses)
        elif system_name == 'Git Repository':
            secrets = _create_git_secrets(secret_id, secrets_count, responses)
        elif system_name == 'MySQL':
            secrets = _create_mysql_secrets(secret_id, secrets_count, responses)
        else:
            secrets = _create_generic_secrets(secret_id, secrets_count, system_name)
        
        audit_session.discovered_secrets.extend(secrets)
        secret_id += len(secrets)


def _create_github_secrets(start_id: int, count: int, responses: Dict) -> List[Secret]:
    """Create GitHub Actions example secrets."""
    secrets = []
    base_date = datetime.now() - timedelta(days=90)
    
    secret_types = [
        (SecretType.API_KEY, "GitHub API Token", StorageLocation.CI_CD_VARIABLES),
        (SecretType.WEBHOOK_SECRET, "Webhook Secret", StorageLocation.CI_CD_VARIABLES),
        (SecretType.CLOUD_ACCESS_KEY, "AWS Access Key", StorageLocation.CI_CD_VARIABLES),
        (SecretType.DATABASE_PASSWORD, "DB Password", StorageLocation.CI_CD_VARIABLES),
    ]
    
    for i in range(min(count, len(secret_types) * 2)):
        secret_type, name, location = secret_types[i % len(secret_types)]
        
        # Higher risk if secrets are in repo vs environment
        if responses.get('repo_secrets', '0') != '0' and i < int(responses.get('repo_secrets', '0')):
            location = StorageLocation.GIT_REPOSITORY
            access_level = "public"
            encryption_status = False
        else:
            access_level = "internal"
            encryption_status = True
        
        secrets.append(Secret(
            id=f"github_secret_{start_id + i}",
            secret_type=secret_type,
            name=f"{name} #{i+1}",
            location=location,
            created_date=base_date + timedelta(days=i*10),
            last_rotated=base_date + timedelta(days=i*10) if responses.get('secret_rotation') == 'quarterly' else None,
            rotation_frequency=RotationFrequency.QUARTERLY if responses.get('secret_rotation') == 'quarterly' else RotationFrequency.NEVER,
            access_level=access_level,
            encryption_status=encryption_status,
            shared_with=[],
            risk_factors=['Stored in repository'] if location == StorageLocation.GIT_REPOSITORY else []
        ))
    
    return secrets


def _create_aws_secrets(start_id: int, count: int, responses: Dict) -> List[Secret]:
    """Create AWS example secrets."""
    secrets = []
    base_date = datetime.now() - timedelta(days=180)
    
    # Create IAM user access keys
    iam_users = int(responses.get('iam_users', '3'))
    for i in range(min(iam_users * 2, count)):
        secrets.append(Secret(
            id=f"aws_secret_{start_id + i}",
            secret_type=SecretType.CLOUD_ACCESS_KEY,
            name=f"AWS Access Key {i//2 + 1}",
            location=StorageLocation.CLOUD_SECRET_MANAGER if responses.get('secrets_manager') == 'y' else StorageLocation.ENVIRONMENT_VARIABLES,
            created_date=base_date + timedelta(days=i*20),
            last_rotated=base_date + timedelta(days=i*20) if responses.get('rotation_enabled') == 'y' else base_date,
            rotation_frequency=RotationFrequency.QUARTERLY if responses.get('rotation_enabled') == 'y' else RotationFrequency.NEVER,
            access_level="restricted",
            encryption_status=responses.get('secrets_manager') == 'y',
            shared_with=[],
            risk_factors=[] if responses.get('rotation_enabled') == 'y' else ['Never rotated']
        ))
    
    return secrets[:count]


def _create_docker_secrets(start_id: int, count: int, responses: Dict) -> List[Secret]:
    """Create Docker example secrets."""
    secrets = []
    base_date = datetime.now() - timedelta(days=60)
    
    for i in range(count):
        # Determine location and risk based on responses
        if responses.get('secrets_in_env') == 'y':
            location = StorageLocation.ENVIRONMENT_VARIABLES
            risk_factors = ['Passed via environment variables']
            access_level = "internal"
        elif responses.get('base_images') == 'y':
            location = StorageLocation.CONTAINER_IMAGE
            risk_factors = ['Embedded in base image']
            access_level = "public"
        else:
            location = StorageLocation.LOCAL_FILESYSTEM
            risk_factors = []
            access_level = "restricted"
        
        secrets.append(Secret(
            id=f"docker_secret_{start_id + i}",
            secret_type=SecretType.DATABASE_PASSWORD if i % 2 == 0 else SecretType.API_KEY,
            name=f"Docker Secret {i+1}",
            location=location,
            created_date=base_date + timedelta(days=i*5),
            last_rotated=base_date,
            rotation_frequency=RotationFrequency.NEVER,
            access_level=access_level,
            encryption_status=location != StorageLocation.CONTAINER_IMAGE,
            shared_with=[],
            risk_factors=risk_factors
        ))
    
    return secrets


def _create_jenkins_secrets(start_id: int, count: int, responses: Dict) -> List[Secret]:
    """Create Jenkins example secrets."""
    secrets = []
    base_date = datetime.now() - timedelta(days=365)
    
    for i in range(count):
        secrets.append(Secret(
            id=f"jenkins_secret_{start_id + i}",
            secret_type=SecretType.DATABASE_PASSWORD if i % 3 == 0 else SecretType.API_KEY if i % 3 == 1 else SecretType.SSH_KEY,
            name=f"Jenkins Credential {i+1}",
            location=StorageLocation.CI_CD_VARIABLES,
            created_date=base_date + timedelta(days=i*3),
            last_rotated=base_date,
            rotation_frequency=RotationFrequency.NEVER,
            access_level="restricted" if responses.get('access_control') == 'y' else "internal",
            encryption_status=responses.get('credential_store') == 'vault',
            shared_with=['jenkins-admins'] if responses.get('access_control') != 'y' else [],
            risk_factors=['Old credential', 'Never rotated']
        ))
    
    return secrets


def _create_vault_secrets(start_id: int, count: int, responses: Dict) -> List[Secret]:
    """Create HashiCorp Vault example secrets."""
    secrets = []
    base_date = datetime.now() - timedelta(days=30)
    
    for i in range(count):
        is_dynamic = responses.get('dynamic_secrets') == 'y' and i % 3 == 0
        
        secrets.append(Secret(
            id=f"vault_secret_{start_id + i}",
            secret_type=SecretType.DATABASE_PASSWORD if i % 3 == 0 else SecretType.CLOUD_ACCESS_KEY if i % 3 == 1 else SecretType.ENCRYPTION_KEY,
            name=f"Vault Secret {i+1}",
            location=StorageLocation.CLOUD_SECRET_MANAGER,
            created_date=base_date + timedelta(hours=i*2) if is_dynamic else base_date,
            last_rotated=base_date + timedelta(hours=i*2) if is_dynamic else base_date,
            rotation_frequency=RotationFrequency.AUTOMATED if is_dynamic else RotationFrequency.MONTHLY,
            access_level="confidential",
            encryption_status=True,
            shared_with=[],
            risk_factors=[] if is_dynamic else []
        ))
    
    return secrets


def _create_k8s_secrets(start_id: int, count: int, responses: Dict) -> List[Secret]:
    """Create Kubernetes example secrets."""
    secrets = []
    base_date = datetime.now() - timedelta(days=120)
    
    for i in range(count):
        secrets.append(Secret(
            id=f"k8s_secret_{start_id + i}",
            secret_type=SecretType.TLS_CERTIFICATE if i % 4 == 0 else SecretType.DATABASE_PASSWORD if i % 4 == 1 else SecretType.API_KEY,
            name=f"K8s Secret {i+1}",
            location=StorageLocation.CLOUD_SECRET_MANAGER if responses.get('external_secrets') == 'y' else StorageLocation.ENVIRONMENT_VARIABLES,
            created_date=base_date + timedelta(days=i*2),
            last_rotated=base_date,
            rotation_frequency=RotationFrequency.QUARTERLY if responses.get('external_secrets') == 'y' else RotationFrequency.NEVER,
            access_level="restricted",
            encryption_status=responses.get('etcd_encryption') == 'y',
            shared_with=[],
            risk_factors=[] if responses.get('etcd_encryption') == 'y' else ['Unencrypted etcd storage']
        ))
    
    return secrets


def _create_1password_secrets(start_id: int, count: int, responses: Dict) -> List[Secret]:
    """Create 1Password example secrets."""
    secrets = []
    base_date = datetime.now() - timedelta(days=200)
    
    shared_count = int(responses.get('shared_secrets', '0'))
    
    for i in range(count):
        is_shared = i < shared_count
        
        secrets.append(Secret(
            id=f"1password_secret_{start_id + i}",
            secret_type=SecretType.DATABASE_PASSWORD if i % 3 == 0 else SecretType.API_KEY,
            name=f"1Password Item {i+1}",
            location=StorageLocation.CLOUD_SECRET_MANAGER,
            created_date=base_date + timedelta(days=i*5),
            last_rotated=base_date,
            rotation_frequency=RotationFrequency.NEVER,
            access_level="confidential",
            encryption_status=True,
            shared_with=['team-members'] if is_shared else [],
            risk_factors=['Shared with team'] if is_shared else []
        ))
    
    return secrets


def _create_git_secrets(start_id: int, count: int, responses: Dict) -> List[Secret]:
    """Create Git Repository example secrets."""
    secrets = []
    base_date = datetime.now() - timedelta(days=400)
    
    for i in range(count):
        secrets.append(Secret(
            id=f"git_secret_{start_id + i}",
            secret_type=SecretType.API_KEY if i % 2 == 0 else SecretType.DATABASE_PASSWORD,
            name=f"Hardcoded Secret {i+1}",
            location=StorageLocation.GIT_REPOSITORY,
            created_date=base_date + timedelta(days=i*30),
            last_rotated=None,
            rotation_frequency=RotationFrequency.NEVER,
            access_level="public",
            encryption_status=False,
            shared_with=['entire-team'],
            risk_factors=['Committed to git', 'Public repository', 'Never rotated', 'Unencrypted']
        ))
    
    return secrets


def _create_mysql_secrets(start_id: int, count: int, responses: Dict) -> List[Secret]:
    """Create MySQL example secrets."""
    secrets = []
    base_date = datetime.now() - timedelta(days=500)
    
    for i in range(count):
        location = StorageLocation.CONFIGURATION_FILE if 'config' in responses.get('root_password', '') else StorageLocation.DATABASE
        
        secrets.append(Secret(
            id=f"mysql_secret_{start_id + i}",
            secret_type=SecretType.DATABASE_PASSWORD,
            name=f"MySQL Password {i+1}",
            location=location,
            created_date=base_date + timedelta(days=i*20),
            last_rotated=base_date,
            rotation_frequency=RotationFrequency.NEVER,
            access_level="internal",
            encryption_status=responses.get('ssl_enabled') == 'y',
            shared_with=[],
            risk_factors=['Stored in config file'] if location == StorageLocation.CONFIGURATION_FILE else []
        ))
    
    return secrets


def _create_generic_secrets(start_id: int, count: int, system_name: str) -> List[Secret]:
    """Create generic example secrets."""
    secrets = []
    base_date = datetime.now() - timedelta(days=100)
    
    for i in range(count):
        secrets.append(Secret(
            id=f"generic_secret_{start_id + i}",
            secret_type=SecretType.API_KEY,
            name=f"{system_name} Secret {i+1}",
            location=StorageLocation.ENVIRONMENT_VARIABLES,
            created_date=base_date + timedelta(days=i*10),
            last_rotated=base_date,
            rotation_frequency=RotationFrequency.NEVER,
            access_level="internal",
            encryption_status=True,
            shared_with=[],
            risk_factors=[]
        ))
    
    return secrets


# Helper functions for caching and data conversion
def _load_audit_data() -> Dict:
    """Load audit data from cache."""
    if 'session_id' not in session:
        return None
    
    cache_file = f"/tmp/audit_session_{session['session_id']}.json"
    try:
        with open(cache_file, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _save_audit_data(audit_data: Dict):
    """Save audit data to cache."""
    if 'session_id' not in session:
        return
    
    cache_file = f"/tmp/audit_session_{session['session_id']}.json"
    with open(cache_file, 'w') as f:
        json.dump(audit_data, f, default=str)


# Helper functions for data conversion
def _dict_to_secret(data: Dict) -> Secret:
    """Convert dictionary to Secret object."""
    return Secret(
        id=data['id'],
        secret_type=SecretType(data['secret_type']),
        name=data['name'],
        location=StorageLocation(data['location']),
        file_path=data.get('file_path'),
        created_date=datetime.fromisoformat(data['created_date']) if data.get('created_date') else None,
        last_rotated=datetime.fromisoformat(data['last_rotated']) if data.get('last_rotated') else None,
        rotation_frequency=RotationFrequency(data['rotation_frequency']),
        access_level=data['access_level'],
        encryption_status=data['encryption_status'],
        shared_with=data['shared_with'],
        risk_factors=data['risk_factors']
    )


def _dict_to_system(data: Dict) -> System:
    """Convert dictionary to System object."""
    return System(
        name=data['name'],
        type=data['type'],
        is_used=data['is_used'],
        secrets_count=data['secrets_count'],
        encryption_enabled=data['encryption_enabled'],
        access_controls=data['access_controls'],
        audit_logging=data['audit_logging'],
        auto_rotation=data['auto_rotation'],
        risk_score=data['risk_score']
    )


def _dict_to_ssh_key(data: Dict):
    """Convert dictionary to SSHKeyInfo object."""
    from models import SSHKeyInfo
    return SSHKeyInfo(
        file_path=data['file_path'],
        key_type=data['key_type'],
        key_size=data.get('key_size'),
        fingerprint=data['fingerprint'],
        comment=data['comment'],
        has_passphrase=data['has_passphrase'],
        permissions=data['permissions'],
        last_used=datetime.fromisoformat(data['last_used']) if data.get('last_used') else None,
        associated_hosts=data['associated_hosts'],
        is_agent_key=data['is_agent_key']
    )


def _ssh_key_to_dict(ssh_key) -> Dict:
    """Convert SSH key to dictionary."""
    return {
        'file_path': ssh_key.file_path,
        'key_type': ssh_key.key_type,
        'key_size': ssh_key.key_size,
        'fingerprint': ssh_key.fingerprint,
        'comment': ssh_key.comment,
        'has_passphrase': ssh_key.has_passphrase,
        'permissions': ssh_key.permissions,
        'last_used': ssh_key.last_used.isoformat() if ssh_key.last_used else None,
        'associated_hosts': ssh_key.associated_hosts,
        'is_agent_key': ssh_key.is_agent_key
    }


def _secret_to_dict(secret) -> Dict:
    """Convert Secret to dictionary."""
    return {
        'id': secret.id,
        'secret_type': secret.secret_type.value,
        'name': secret.name,
        'location': secret.location.value,
        'file_path': secret.file_path,
        'created_date': secret.created_date.isoformat() if secret.created_date else None,
        'last_rotated': secret.last_rotated.isoformat() if secret.last_rotated else None,
        'rotation_frequency': secret.rotation_frequency.value,
        'access_level': secret.access_level,
        'encryption_status': secret.encryption_status,
        'shared_with': secret.shared_with,
        'risk_factors': secret.risk_factors
    }


def _system_to_dict(system) -> Dict:
    """Convert System to dictionary."""
    return {
        'name': system.name,
        'type': system.type,
        'is_used': system.is_used,
        'secrets_count': system.secrets_count,
        'encryption_enabled': system.encryption_enabled,
        'access_controls': system.access_controls,
        'audit_logging': system.audit_logging,
        'auto_rotation': system.auto_rotation,
        'risk_score': system.risk_score
    }


def _assessment_to_dict(assessment) -> Dict:
    """Convert RiskAssessment to dictionary."""
    return {
        'total_secrets': assessment.total_secrets,
        'overall_risk_score': assessment.overall_risk_score,
        'secrets_by_type': {k.value: v for k, v in assessment.secrets_by_type.items()},
        'secrets_by_location': {k.value: v for k, v in assessment.secrets_by_location.items()},
        'risk_distribution': {k.value: v for k, v in assessment.risk_distribution.items()},
        'critical_findings': assessment.critical_findings,
        'recommendations': assessment.recommendations
    }


def _auto_detect_systems() -> List[Dict]:
    """Auto-detect installed systems and tools."""
    detected_systems = []
    
    # Check for common development tools and systems
    checks = {
        'docker': (['docker', '--version'], 'Docker'),
        'kubectl': (['kubectl', 'version', '--client'], 'Kubernetes'),
        'git': (['git', '--version'], 'Git Repository'),
        'aws': (['aws', '--version'], 'AWS'),
        'gh': (['gh', '--version'], 'GitHub Actions'),
        'jenkins': (['which', 'jenkins'], 'Jenkins'),
        'vault': (['vault', 'version'], 'HashiCorp Vault'),
        'mysql': (['mysql', '--version'], 'MySQL'),
        'psql': (['psql', '--version'], 'PostgreSQL'),
        'redis-cli': (['redis-cli', '--version'], 'Redis'),
    }
    
    for cmd, (check_cmd, system_name) in checks.items():
        try:
            import subprocess
            result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                # Estimate secrets count based on system type
                if system_name == 'AWS':
                    estimated_secrets = 15
                elif system_name == 'Kubernetes':
                    estimated_secrets = 25
                elif system_name in ['Jenkins', 'HashiCorp Vault']:
                    estimated_secrets = 30
                elif system_name == 'Docker':
                    estimated_secrets = 8
                elif system_name == 'GitHub Actions':
                    estimated_secrets = 12
                else:
                    estimated_secrets = 5
                
                detected_systems.append({
                    'name': system_name,
                    'detected_via': cmd,
                    'estimated_secrets': estimated_secrets,
                    'confidence': 'high'
                })
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            continue
    
    # Check for common configuration files that indicate system usage
    config_checks = {
        '.aws/credentials': 'AWS',
        '.kube/config': 'Kubernetes',
        'docker-compose.yml': 'Docker',
        '.github/workflows': 'GitHub Actions',
        'Jenkinsfile': 'Jenkins',
    }
    
    for config_path, system_name in config_checks.items():
        try:
            full_path = os.path.expanduser(f'~/{config_path}')
            if os.path.exists(full_path):
                # Only add if not already detected
                if not any(sys['name'] == system_name for sys in detected_systems):
                    estimated_secrets = 10 if system_name in ['AWS', 'Kubernetes'] else 5
                    detected_systems.append({
                        'name': system_name,
                        'detected_via': f'config file: {config_path}',
                        'estimated_secrets': estimated_secrets,
                        'confidence': 'medium'
                    })
        except Exception:
            continue
    
    return detected_systems


def _auto_configure_system(system_name: str, environment_size: str, security_priority: str) -> System:
    """Auto-configure a system with smart defaults based on environment context."""
    template = systems_manager.get_system_template(system_name)
    if not template:
        return None
    
    # Get base secrets count from template risk level (higher risk = more typical secrets)
    base_secrets_count = template.typical_risk_level * 3  # Convert 1-5 scale to 3-15 secrets
    
    # Smart defaults based on environment size and security priority
    if environment_size == 'large':
        secrets_count = base_secrets_count * 2
        encryption_enabled = True
        audit_logging = True
        access_controls = True
        auto_rotation = security_priority == 'high'
    elif environment_size == 'medium':
        secrets_count = base_secrets_count
        encryption_enabled = security_priority in ['high', 'medium']
        audit_logging = security_priority == 'high'
        access_controls = security_priority == 'high'
        auto_rotation = security_priority == 'high'
    else:  # small
        secrets_count = max(3, base_secrets_count // 2)
        encryption_enabled = security_priority == 'high'
        audit_logging = False
        access_controls = False
        auto_rotation = False
    
    # Override with template capabilities
    encryption_enabled = encryption_enabled and template.supports_encryption
    audit_logging = audit_logging and template.supports_audit_logging
    access_controls = access_controls and template.supports_access_controls
    auto_rotation = auto_rotation and template.supports_rotation
    
    # Calculate risk score based on configuration
    risk_score = template.typical_risk_level  # Start with template base risk
    if not encryption_enabled and template.supports_encryption:
        risk_score += 1
    if not audit_logging and template.supports_audit_logging:
        risk_score += 1
    if not access_controls and template.supports_access_controls:
        risk_score += 1
    if not auto_rotation and template.supports_rotation:
        risk_score += 1
    
    risk_score = min(5, risk_score)  # Cap at 5
    
    return System(
        name=system_name,
        type=template.category.value,
        is_used=True,
        secrets_count=secrets_count,
        encryption_enabled=encryption_enabled,
        access_controls=access_controls,
        audit_logging=audit_logging,
        auto_rotation=auto_rotation,
        risk_score=risk_score
    )


def _generate_smart_secrets(system: System, environment_size: str) -> List[Secret]:
    """Generate realistic secrets for a system based on smart configuration."""
    secrets = []
    base_date = datetime.now() - timedelta(days=90)
    
    # Common secret types based on system type
    if system.name == 'AWS':
        secret_types = [SecretType.CLOUD_ACCESS_KEY, SecretType.DATABASE_PASSWORD]
        location = StorageLocation.CLOUD_SECRET_MANAGER if system.encryption_enabled else StorageLocation.ENVIRONMENT_VARIABLES
    elif system.name == 'GitHub Actions':
        secret_types = [SecretType.API_KEY, SecretType.WEBHOOK_SECRET]
        location = StorageLocation.CI_CD_VARIABLES
    elif system.name == 'Docker':
        secret_types = [SecretType.DATABASE_PASSWORD, SecretType.API_KEY]
        location = StorageLocation.ENVIRONMENT_VARIABLES
    elif system.name == 'Kubernetes':
        secret_types = [SecretType.TLS_CERTIFICATE, SecretType.DATABASE_PASSWORD, SecretType.API_KEY]
        location = StorageLocation.CLOUD_SECRET_MANAGER if system.encryption_enabled else StorageLocation.ENVIRONMENT_VARIABLES
    elif 'Database' in system.name or 'MySQL' in system.name or 'PostgreSQL' in system.name:
        secret_types = [SecretType.DATABASE_PASSWORD]
        location = StorageLocation.DATABASE
    else:
        secret_types = [SecretType.API_KEY, SecretType.DATABASE_PASSWORD]
        location = StorageLocation.ENVIRONMENT_VARIABLES
    
    # Generate secrets
    for i in range(system.secrets_count):
        secret_type = secret_types[i % len(secret_types)]
        
        # Determine risk factors based on system configuration
        risk_factors = []
        if not system.encryption_enabled:
            risk_factors.append('Unencrypted storage')
        if not system.auto_rotation:
            risk_factors.append('Never rotated')
        if not system.access_controls:
            risk_factors.append('No access controls')
        
        # Determine access level based on security configuration
        if system.access_controls:
            access_level = 'restricted'
        elif system.encryption_enabled:
            access_level = 'internal'
        else:
            access_level = 'public'
        
        secrets.append(Secret(
            id=f"{system.name.lower()}_smart_secret_{i+1}",
            secret_type=secret_type,
            name=f"{system.name} {secret_type.value.replace('_', ' ').title()} {i+1}",
            location=location,
            created_date=base_date + timedelta(days=i*5),
            last_rotated=base_date + timedelta(days=i*5) if system.auto_rotation else base_date,
            rotation_frequency=RotationFrequency.QUARTERLY if system.auto_rotation else RotationFrequency.NEVER,
            access_level=access_level,
            encryption_status=system.encryption_enabled,
            shared_with=[],
            risk_factors=risk_factors
        ))
    
    return secrets


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

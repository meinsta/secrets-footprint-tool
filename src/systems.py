"""
Systems and Tools Selection Module
Manages information about various systems that can store secrets and their configurations.
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from models import System, StorageLocation, RotationFrequency


class SystemCategory(Enum):
    CI_CD = "ci_cd"
    CLOUD_PROVIDER = "cloud_provider"
    SECRET_MANAGER = "secret_manager"
    CONTAINER_PLATFORM = "container_platform"
    SOURCE_CONTROL = "source_control"
    DATABASE = "database"
    WEB_SERVER = "web_server"
    MONITORING = "monitoring"
    OTHER = "other"


@dataclass
class SystemTemplate:
    """Template for a system with default security characteristics."""
    name: str
    category: SystemCategory
    description: str
    common_secret_types: List[str] = field(default_factory=list)
    typical_risk_level: int = 3  # 1-5 scale
    supports_encryption: bool = True
    supports_rotation: bool = False
    supports_audit_logging: bool = False
    supports_access_controls: bool = True
    questions: List[Dict[str, str]] = field(default_factory=list)


class SystemsManager:
    """Manages system templates and user selections."""
    
    def __init__(self):
        self.system_templates = self._initialize_system_templates()
        self.selected_systems: List[System] = []
    
    def _initialize_system_templates(self) -> Dict[str, SystemTemplate]:
        """Initialize the catalog of known systems and their characteristics."""
        templates = {}
        
        # CI/CD Systems
        ci_cd_systems = [
            SystemTemplate(
                name="GitHub Actions",
                category=SystemCategory.CI_CD,
                description="GitHub's integrated CI/CD platform",
                common_secret_types=["API keys", "Deploy keys", "OAuth tokens"],
                typical_risk_level=2,
                supports_encryption=True,
                supports_rotation=False,
                supports_audit_logging=True,
                supports_access_controls=True,
                questions=[
                    {"key": "repo_secrets", "text": "How many repository secrets do you have configured?"},
                    {"key": "org_secrets", "text": "Do you use organization-level secrets? (y/n)"},
                    {"key": "environment_secrets", "text": "Do you use environment-specific secrets? (y/n)"},
                    {"key": "secret_rotation", "text": "How often do you rotate secrets? (never/yearly/quarterly/monthly)"}
                ]
            ),
            SystemTemplate(
                name="Jenkins",
                category=SystemCategory.CI_CD,
                description="Open source CI/CD server",
                common_secret_types=["Credentials", "SSH keys", "API tokens"],
                typical_risk_level=3,
                supports_encryption=True,
                supports_rotation=False,
                supports_audit_logging=True,
                supports_access_controls=True,
                questions=[
                    {"key": "credential_store", "text": "Which credential store do you use? (built-in/vault/other)"},
                    {"key": "credentials_count", "text": "Approximately how many credentials are stored?"},
                    {"key": "access_control", "text": "Do you restrict credential access by job/user? (y/n)"}
                ]
            ),
            SystemTemplate(
                name="GitLab CI",
                category=SystemCategory.CI_CD,
                description="GitLab's integrated CI/CD",
                common_secret_types=["Variables", "Files", "Deploy tokens"],
                typical_risk_level=2,
                supports_encryption=True,
                supports_rotation=False,
                supports_audit_logging=True,
                supports_access_controls=True,
                questions=[
                    {"key": "variable_scope", "text": "What variable scopes do you use? (project/group/instance)"},
                    {"key": "protected_vars", "text": "Do you use protected variables? (y/n)"},
                    {"key": "file_variables", "text": "Do you store secrets as file variables? (y/n)"}
                ]
            ),
            SystemTemplate(
                name="Azure DevOps",
                category=SystemCategory.CI_CD,
                description="Microsoft's DevOps platform",
                common_secret_types=["Variables", "Secure files", "Service connections"],
                typical_risk_level=2,
                supports_encryption=True,
                supports_rotation=False,
                supports_audit_logging=True,
                supports_access_controls=True,
                questions=[
                    {"key": "variable_groups", "text": "Do you use variable groups? (y/n)"},
                    {"key": "key_vault_integration", "text": "Do you integrate with Azure Key Vault? (y/n)"},
                    {"key": "secure_files", "text": "How many secure files do you have?"}
                ]
            )
        ]
        
        # Cloud Providers
        cloud_providers = [
            SystemTemplate(
                name="AWS",
                category=SystemCategory.CLOUD_PROVIDER,
                description="Amazon Web Services",
                common_secret_types=["Access keys", "IAM roles", "RDS passwords"],
                typical_risk_level=3,
                supports_encryption=True,
                supports_rotation=True,
                supports_audit_logging=True,
                supports_access_controls=True,
                questions=[
                    {"key": "iam_users", "text": "How many IAM users with programmatic access do you have?"},
                    {"key": "secrets_manager", "text": "Do you use AWS Secrets Manager? (y/n)"},
                    {"key": "parameter_store", "text": "Do you use Systems Manager Parameter Store? (y/n)"},
                    {"key": "rotation_enabled", "text": "Do you have automatic rotation enabled? (y/n)"}
                ]
            ),
            SystemTemplate(
                name="Google Cloud Platform",
                category=SystemCategory.CLOUD_PROVIDER,
                description="Google Cloud Platform",
                common_secret_types=["Service account keys", "API keys", "OAuth credentials"],
                typical_risk_level=3,
                supports_encryption=True,
                supports_rotation=True,
                supports_audit_logging=True,
                supports_access_controls=True,
                questions=[
                    {"key": "service_accounts", "text": "How many service accounts do you have?"},
                    {"key": "secret_manager", "text": "Do you use Google Secret Manager? (y/n)"},
                    {"key": "key_rotation", "text": "Do you rotate service account keys? (y/n)"}
                ]
            ),
            SystemTemplate(
                name="Microsoft Azure",
                category=SystemCategory.CLOUD_PROVIDER,
                description="Microsoft Azure Cloud",
                common_secret_types=["Service principals", "Managed identities", "Storage keys"],
                typical_risk_level=3,
                supports_encryption=True,
                supports_rotation=True,
                supports_audit_logging=True,
                supports_access_controls=True,
                questions=[
                    {"key": "service_principals", "text": "How many service principals do you have?"},
                    {"key": "key_vault", "text": "Do you use Azure Key Vault? (y/n)"},
                    {"key": "managed_identity", "text": "Do you use managed identities? (y/n)"}
                ]
            )
        ]
        
        # Secret Managers
        secret_managers = [
            SystemTemplate(
                name="HashiCorp Vault",
                category=SystemCategory.SECRET_MANAGER,
                description="Enterprise secret management",
                common_secret_types=["Dynamic secrets", "Static secrets", "Encryption keys"],
                typical_risk_level=1,
                supports_encryption=True,
                supports_rotation=True,
                supports_audit_logging=True,
                supports_access_controls=True,
                questions=[
                    {"key": "secret_engines", "text": "Which secret engines do you use? (kv/database/pki/aws/other)"},
                    {"key": "auth_methods", "text": "What authentication methods are configured?"},
                    {"key": "policies_count", "text": "Approximately how many policies do you have?"},
                    {"key": "dynamic_secrets", "text": "Do you use dynamic secrets? (y/n)"}
                ]
            ),
            SystemTemplate(
                name="1Password",
                category=SystemCategory.SECRET_MANAGER,
                description="Password manager with team features",
                common_secret_types=["Passwords", "SSH keys", "API keys", "Certificates"],
                typical_risk_level=2,
                supports_encryption=True,
                supports_rotation=False,
                supports_audit_logging=True,
                supports_access_controls=True,
                questions=[
                    {"key": "vaults_count", "text": "How many vaults do you have?"},
                    {"key": "shared_secrets", "text": "How many shared secrets/items?"},
                    {"key": "integrations", "text": "Do you use CLI/API integrations? (y/n)"}
                ]
            ),
            SystemTemplate(
                name="Bitwarden",
                category=SystemCategory.SECRET_MANAGER,
                description="Open source password manager",
                common_secret_types=["Passwords", "Secure notes", "SSH keys"],
                typical_risk_level=2,
                supports_encryption=True,
                supports_rotation=False,
                supports_audit_logging=True,
                supports_access_controls=True,
                questions=[
                    {"key": "org_vault", "text": "Do you use organization vault? (y/n)"},
                    {"key": "shared_items", "text": "How many shared items do you have?"},
                    {"key": "cli_usage", "text": "Do you use Bitwarden CLI? (y/n)"}
                ]
            )
        ]
        
        # Container Platforms
        container_platforms = [
            SystemTemplate(
                name="Docker",
                category=SystemCategory.CONTAINER_PLATFORM,
                description="Container runtime platform",
                common_secret_types=["Registry credentials", "Environment variables"],
                typical_risk_level=4,
                supports_encryption=False,
                supports_rotation=False,
                supports_audit_logging=False,
                supports_access_controls=False,
                questions=[
                    {"key": "secrets_in_env", "text": "Do you pass secrets via environment variables? (y/n)"},
                    {"key": "secrets_in_files", "text": "Do you mount secrets as files? (y/n)"},
                    {"key": "base_images", "text": "Do you embed secrets in base images? (y/n)"}
                ]
            ),
            SystemTemplate(
                name="Kubernetes",
                category=SystemCategory.CONTAINER_PLATFORM,
                description="Container orchestration platform",
                common_secret_types=["Secrets", "ConfigMaps", "Service account tokens"],
                typical_risk_level=2,
                supports_encryption=True,
                supports_rotation=False,
                supports_audit_logging=True,
                supports_access_controls=True,
                questions=[
                    {"key": "secrets_count", "text": "How many Kubernetes secrets do you have?"},
                    {"key": "etcd_encryption", "text": "Is etcd encryption enabled? (y/n)"},
                    {"key": "external_secrets", "text": "Do you use external secret operators? (y/n)"},
                    {"key": "rbac", "text": "Do you use RBAC for secret access? (y/n)"}
                ]
            )
        ]
        
        # Source Control
        source_control = [
            SystemTemplate(
                name="Git Repository",
                category=SystemCategory.SOURCE_CONTROL,
                description="Git-based source control",
                common_secret_types=["API keys", "Passwords", "Certificates", "Private keys"],
                typical_risk_level=5,
                supports_encryption=False,
                supports_rotation=False,
                supports_audit_logging=True,
                supports_access_controls=False,
                questions=[
                    {"key": "secrets_in_code", "text": "Have you found secrets in your code? (y/n)"},
                    {"key": "secrets_scanning", "text": "Do you use secret scanning tools? (y/n)"},
                    {"key": "git_history", "text": "Have you checked git history for secrets? (y/n)"},
                    {"key": "gitignore", "text": "Do you have proper .gitignore files? (y/n)"}
                ]
            )
        ]
        
        # Databases
        databases = [
            SystemTemplate(
                name="PostgreSQL",
                category=SystemCategory.DATABASE,
                description="PostgreSQL database server",
                common_secret_types=["Connection strings", "User passwords", "SSL certificates"],
                typical_risk_level=3,
                supports_encryption=True,
                supports_rotation=False,
                supports_audit_logging=True,
                supports_access_controls=True,
                questions=[
                    {"key": "connection_strings", "text": "Where do you store database connection strings?"},
                    {"key": "ssl_enabled", "text": "Is SSL/TLS encryption enabled? (y/n)"},
                    {"key": "user_accounts", "text": "How many database user accounts do you have?"}
                ]
            ),
            SystemTemplate(
                name="MySQL",
                category=SystemCategory.DATABASE,
                description="MySQL database server",
                common_secret_types=["Root passwords", "User passwords", "Connection strings"],
                typical_risk_level=3,
                supports_encryption=True,
                supports_rotation=False,
                supports_audit_logging=True,
                supports_access_controls=True,
                questions=[
                    {"key": "root_password", "text": "How is the root password managed?"},
                    {"key": "ssl_enabled", "text": "Is SSL encryption enabled? (y/n)"},
                    {"key": "password_policy", "text": "Do you have a password policy? (y/n)"}
                ]
            )
        ]
        
        # Combine all templates
        all_templates = (ci_cd_systems + cloud_providers + secret_managers + 
                        container_platforms + source_control + databases)
        
        for template in all_templates:
            templates[template.name] = template
        
        return templates
    
    def get_systems_by_category(self) -> Dict[SystemCategory, List[str]]:
        """Get systems organized by category."""
        categories = {}
        for name, template in self.system_templates.items():
            if template.category not in categories:
                categories[template.category] = []
            categories[template.category].append(name)
        return categories
    
    def get_system_template(self, name: str) -> Optional[SystemTemplate]:
        """Get a system template by name."""
        return self.system_templates.get(name)
    
    def create_system_from_template(self, template_name: str, user_responses: Dict[str, str]) -> System:
        """Create a System object from a template and user responses."""
        template = self.system_templates.get(template_name)
        if not template:
            raise ValueError(f"Unknown system template: {template_name}")
        
        # Create base system
        system = System(
            name=template.name,
            type=template.category.value,
            is_used=True,
            encryption_enabled=template.supports_encryption,
            audit_logging=template.supports_audit_logging,
            auto_rotation=template.supports_rotation
        )
        
        # Process user responses to calculate risk and populate details
        self._process_user_responses(system, template, user_responses)
        
        return system
    
    def _process_user_responses(self, system: System, template: SystemTemplate, responses: Dict[str, str]):
        """Process user responses and update system configuration."""
        risk_score = template.typical_risk_level
        secrets_count = 0
        access_controls = []
        
        # Process responses based on system type
        if template.category == SystemCategory.CI_CD:
            secrets_count = self._extract_number(responses.get('repo_secrets', '0'))
            if responses.get('org_secrets', '').lower() == 'y':
                secrets_count += self._extract_number(responses.get('org_secrets_count', '5'))
            if responses.get('environment_secrets', '').lower() == 'y':
                secrets_count += self._extract_number(responses.get('env_secrets_count', '3'))
            
            rotation = responses.get('secret_rotation', 'never').lower()
            if rotation in ['monthly', 'quarterly']:
                risk_score -= 1
            elif rotation == 'never':
                risk_score += 1
                
        elif template.category == SystemCategory.CLOUD_PROVIDER:
            if 'iam_users' in responses:
                secrets_count = self._extract_number(responses['iam_users'])
                if secrets_count > 10:
                    risk_score += 1
            
            if responses.get('secrets_manager', '').lower() == 'y':
                risk_score -= 1
                access_controls.append("Managed secret service")
            
            if responses.get('rotation_enabled', '').lower() == 'y':
                risk_score -= 1
                system.auto_rotation = True
                
        elif template.category == SystemCategory.SECRET_MANAGER:
            if 'dynamic_secrets' in responses and responses['dynamic_secrets'].lower() == 'y':
                risk_score -= 2
                system.auto_rotation = True
            
            secrets_count = self._extract_number(responses.get('shared_secrets', '0'))
            
        elif template.category == SystemCategory.SOURCE_CONTROL:
            if responses.get('secrets_in_code', '').lower() == 'y':
                risk_score += 2
            if responses.get('secrets_scanning', '').lower() == 'y':
                risk_score -= 1
                access_controls.append("Secret scanning")
            if responses.get('git_history', '').lower() == 'n':
                risk_score += 1
                
        elif template.category == SystemCategory.CONTAINER_PLATFORM:
            if responses.get('secrets_in_env', '').lower() == 'y':
                risk_score += 1
            if responses.get('secrets_in_files', '').lower() == 'y':
                risk_score -= 1
            if responses.get('base_images', '').lower() == 'y':
                risk_score += 2
            
            if system.name == "Kubernetes":
                if responses.get('etcd_encryption', '').lower() == 'y':
                    risk_score -= 1
                    system.encryption_enabled = True
                if responses.get('rbac', '').lower() == 'y':
                    access_controls.append("RBAC")
        
        # Apply the calculated values
        system.secrets_count = secrets_count
        system.risk_score = max(1, min(5, risk_score))  # Clamp between 1-5
        system.access_controls = access_controls
    
    def _extract_number(self, text: str) -> int:
        """Extract a number from text, return 0 if not found."""
        try:
            # Extract first number from the string
            import re
            numbers = re.findall(r'\d+', str(text))
            return int(numbers[0]) if numbers else 0
        except:
            return 0
    
    def get_system_questions(self, system_name: str) -> List[Dict[str, str]]:
        """Get the questions to ask for a specific system."""
        template = self.system_templates.get(system_name)
        return template.questions if template else []
    
    def add_selected_system(self, system: System):
        """Add a system to the selected systems list."""
        self.selected_systems.append(system)
    
    def get_selected_systems(self) -> List[System]:
        """Get all selected systems."""
        return self.selected_systems
    
    def get_risk_summary(self) -> Dict[str, any]:
        """Get a risk summary of all selected systems."""
        if not self.selected_systems:
            return {}
        
        total_systems = len(self.selected_systems)
        total_secrets = sum(s.secrets_count for s in self.selected_systems)
        avg_risk = sum(s.risk_score for s in self.selected_systems) / total_systems
        
        high_risk_systems = [s for s in self.selected_systems if s.risk_score >= 4]
        systems_with_rotation = [s for s in self.selected_systems if s.auto_rotation]
        systems_with_encryption = [s for s in self.selected_systems if s.encryption_enabled]
        
        return {
            'total_systems': total_systems,
            'total_secrets': total_secrets,
            'average_risk_score': round(avg_risk, 2),
            'high_risk_systems': len(high_risk_systems),
            'systems_with_rotation': len(systems_with_rotation),
            'systems_with_encryption': len(systems_with_encryption),
            'systems_by_category': self._group_systems_by_category()
        }
    
    def _group_systems_by_category(self) -> Dict[str, int]:
        """Group selected systems by category."""
        categories = {}
        for system in self.selected_systems:
            if system.type not in categories:
                categories[system.type] = 0
            categories[system.type] += 1
        return categories
    
    def get_system_recommendations(self) -> List[str]:
        """Generate recommendations based on selected systems."""
        recommendations = []
        
        if not self.selected_systems:
            recommendations.append("🚨 No systems selected. Consider auditing your secret management practices.")
            return recommendations
        
        # Analyze systems for recommendations
        high_risk_systems = [s for s in self.selected_systems if s.risk_score >= 4]
        no_rotation_systems = [s for s in self.selected_systems if not s.auto_rotation]
        no_encryption_systems = [s for s in self.selected_systems if not s.encryption_enabled]
        no_audit_systems = [s for s in self.selected_systems if not s.audit_logging]
        
        if high_risk_systems:
            recommendations.append(
                f"⚠️ {len(high_risk_systems)} high-risk systems detected: "
                f"{', '.join(s.name for s in high_risk_systems[:3])}{'...' if len(high_risk_systems) > 3 else ''}. "
                f"Review and improve security configurations."
            )
        
        if len(no_rotation_systems) > len(self.selected_systems) / 2:
            recommendations.append(
                f"🔄 {len(no_rotation_systems)} systems lack automatic secret rotation. "
                f"Implement rotation policies to reduce risk of compromised credentials."
            )
        
        if len(no_encryption_systems) > 0:
            recommendations.append(
                f"🔐 {len(no_encryption_systems)} systems don't have encryption enabled. "
                f"Enable encryption at rest for: {', '.join(s.name for s in no_encryption_systems[:3])}."
            )
        
        if len(no_audit_systems) > len(self.selected_systems) / 2:
            recommendations.append(
                f"📋 {len(no_audit_systems)} systems lack audit logging. "
                f"Enable logging to track secret access and modifications."
            )
        
        # Check for source control risks
        source_control_systems = [s for s in self.selected_systems if s.type == "source_control"]
        if source_control_systems and any(s.risk_score >= 4 for s in source_control_systems):
            recommendations.append(
                "📝 High risk detected in source control. Implement secret scanning and "
                "remove any committed secrets from git history."
            )
        
        # Check for container platform risks
        container_systems = [s for s in self.selected_systems if s.type == "container_platform"]
        if container_systems and any(s.risk_score >= 4 for s in container_systems):
            recommendations.append(
                "🐳 Container platform risks detected. Avoid environment variables for secrets "
                "and consider using dedicated secret management solutions."
            )
        
        # General recommendations
        total_secrets = sum(s.secrets_count for s in self.selected_systems)
        if total_secrets > 100:
            recommendations.append(
                f"🔍 Large secret footprint detected ({total_secrets} secrets across systems). "
                f"Consider centralizing secret management and implementing governance policies."
            )
        
        return recommendations

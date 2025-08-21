"""
Data models for the secrets footprint assessment tool.
Defines structures for tracking secrets, storage locations, and risk assessment.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Set
from datetime import datetime
import json


class SecretType(Enum):
    SSH_KEY = "ssh_key"
    API_KEY = "api_key"
    DATABASE_PASSWORD = "database_password"
    TLS_CERTIFICATE = "tls_certificate"
    OAUTH_TOKEN = "oauth_token"
    CLOUD_ACCESS_KEY = "cloud_access_key"
    WEBHOOK_SECRET = "webhook_secret"
    ENCRYPTION_KEY = "encryption_key"


class StorageLocation(Enum):
    LOCAL_FILESYSTEM = "local_filesystem"
    GIT_REPOSITORY = "git_repository"
    CI_CD_VARIABLES = "ci_cd_variables"
    CLOUD_SECRET_MANAGER = "cloud_secret_manager"
    CONFIGURATION_FILE = "configuration_file"
    ENVIRONMENT_VARIABLES = "environment_variables"
    CONTAINER_IMAGE = "container_image"
    DATABASE = "database"


class RiskLevel(Enum):
    VERY_LOW = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class RotationFrequency(Enum):
    NEVER = "never"
    YEARLY = "yearly"
    QUARTERLY = "quarterly"
    MONTHLY = "monthly"
    WEEKLY = "weekly"
    DAILY = "daily"
    AUTOMATED = "automated"


@dataclass
class Secret:
    """Represents a single secret/credential in the system."""
    id: str
    secret_type: SecretType
    name: str
    location: StorageLocation
    file_path: Optional[str] = None
    created_date: Optional[datetime] = None
    last_rotated: Optional[datetime] = None
    rotation_frequency: RotationFrequency = RotationFrequency.NEVER
    access_level: str = "unknown"  # public, internal, restricted, confidential
    encryption_status: bool = False
    shared_with: List[str] = field(default_factory=list)
    risk_factors: List[str] = field(default_factory=list)
    
    def calculate_age_risk(self) -> int:
        """Calculate risk based on secret age and rotation frequency."""
        if not self.last_rotated or not self.created_date:
            return 4  # High risk for unknown dates
        
        age_days = (datetime.now() - self.last_rotated).days
        
        # Risk scoring based on age and rotation frequency
        if self.rotation_frequency == RotationFrequency.AUTOMATED:
            return 1
        elif self.rotation_frequency == RotationFrequency.DAILY and age_days > 7:
            return 3
        elif self.rotation_frequency == RotationFrequency.WEEKLY and age_days > 14:
            return 3
        elif self.rotation_frequency == RotationFrequency.MONTHLY and age_days > 60:
            return 4
        elif self.rotation_frequency == RotationFrequency.QUARTERLY and age_days > 120:
            return 4
        elif self.rotation_frequency == RotationFrequency.YEARLY and age_days > 400:
            return 5
        elif self.rotation_frequency == RotationFrequency.NEVER and age_days > 365:
            return 5
        
        return 2


@dataclass
class System:
    """Represents a system or tool that manages secrets."""
    name: str
    type: str  # ci_cd, cloud_provider, secret_manager, etc.
    is_used: bool = False
    secrets_count: int = 0
    encryption_enabled: bool = False
    access_controls: List[str] = field(default_factory=list)
    audit_logging: bool = False
    auto_rotation: bool = False
    risk_score: int = 0


@dataclass
class SSHKeyInfo:
    """Detailed information about SSH keys."""
    file_path: str
    key_type: str  # rsa, ed25519, ecdsa, dsa
    key_size: Optional[int] = None
    fingerprint: str = ""
    comment: str = ""
    has_passphrase: bool = False
    permissions: str = ""
    last_used: Optional[datetime] = None
    associated_hosts: List[str] = field(default_factory=list)
    is_agent_key: bool = False


@dataclass
class RiskAssessment:
    """Overall risk assessment results."""
    total_secrets: int
    secrets_by_type: Dict[SecretType, int] = field(default_factory=dict)
    secrets_by_location: Dict[StorageLocation, int] = field(default_factory=dict)
    overall_risk_score: float = 0.0
    risk_distribution: Dict[RiskLevel, int] = field(default_factory=dict)
    critical_findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    assessed_systems: List[System] = field(default_factory=list)
    
    def calculate_overall_risk(self, secrets: List[Secret]) -> float:
        """Calculate the overall risk score based on all secrets."""
        if not secrets:
            return 0.0
        
        total_risk = 0
        for secret in secrets:
            # Base risk from location
            location_risk = {
                StorageLocation.LOCAL_FILESYSTEM: 3,
                StorageLocation.GIT_REPOSITORY: 4,
                StorageLocation.CI_CD_VARIABLES: 2,
                StorageLocation.CLOUD_SECRET_MANAGER: 1,
                StorageLocation.CONFIGURATION_FILE: 4,
                StorageLocation.ENVIRONMENT_VARIABLES: 3,
                StorageLocation.CONTAINER_IMAGE: 4,
                StorageLocation.DATABASE: 2
            }.get(secret.location, 3)
            
            # Age-based risk
            age_risk = secret.calculate_age_risk()
            
            # Encryption bonus/penalty
            encryption_modifier = -1 if secret.encryption_status else 1
            
            # Calculate weighted risk
            secret_risk = (location_risk + age_risk + encryption_modifier) / 3
            total_risk += max(1, min(5, secret_risk))  # Clamp between 1-5
        
        self.overall_risk_score = round(total_risk / len(secrets), 2)
        return self.overall_risk_score


@dataclass
class AuditSession:
    """Represents a complete audit session."""
    session_id: str
    timestamp: datetime
    user_responses: Dict[str, any] = field(default_factory=dict)
    discovered_secrets: List[Secret] = field(default_factory=list)
    ssh_keys: List[SSHKeyInfo] = field(default_factory=list)
    selected_systems: List[System] = field(default_factory=list)
    risk_assessment: Optional[RiskAssessment] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'session_id': self.session_id,
            'timestamp': self.timestamp.isoformat(),
            'user_responses': self.user_responses,
            'discovered_secrets': [self._secret_to_dict(s) for s in self.discovered_secrets],
            'ssh_keys': [self._ssh_key_to_dict(k) for k in self.ssh_keys],
            'selected_systems': [self._system_to_dict(s) for s in self.selected_systems],
            'risk_assessment': self._risk_assessment_to_dict(self.risk_assessment) if self.risk_assessment else None
        }
    
    def _secret_to_dict(self, secret: Secret) -> Dict:
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
    
    def _ssh_key_to_dict(self, ssh_key: SSHKeyInfo) -> Dict:
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
    
    def _system_to_dict(self, system: System) -> Dict:
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
    
    def _risk_assessment_to_dict(self, assessment: RiskAssessment) -> Dict:
        return {
            'total_secrets': assessment.total_secrets,
            'secrets_by_type': {k.value: v for k, v in assessment.secrets_by_type.items()},
            'secrets_by_location': {k.value: v for k, v in assessment.secrets_by_location.items()},
            'overall_risk_score': assessment.overall_risk_score,
            'risk_distribution': {k.value: v for k, v in assessment.risk_distribution.items()},
            'critical_findings': assessment.critical_findings,
            'recommendations': assessment.recommendations,
            'assessed_systems': [self._system_to_dict(s) for s in assessment.assessed_systems]
        }

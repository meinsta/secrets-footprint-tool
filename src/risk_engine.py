"""
Risk Scoring Engine
Calculates comprehensive risk scores for secrets and systems based on multiple factors.
"""

from typing import List, Dict, Tuple, Optional
from datetime import datetime, timedelta
from collections import Counter
import math

from models import (
    Secret, System, SSHKeyInfo, RiskAssessment, RiskLevel, 
    SecretType, StorageLocation, RotationFrequency
)


class RiskScoringEngine:
    """Comprehensive risk scoring system for secrets and infrastructure."""
    
    def __init__(self):
        # Risk weight factors for different aspects
        self.location_weights = {
            StorageLocation.CLOUD_SECRET_MANAGER: 0.2,
            StorageLocation.CI_CD_VARIABLES: 0.4,
            StorageLocation.DATABASE: 0.5,
            StorageLocation.ENVIRONMENT_VARIABLES: 0.7,
            StorageLocation.LOCAL_FILESYSTEM: 0.8,
            StorageLocation.CONFIGURATION_FILE: 0.9,
            StorageLocation.CONTAINER_IMAGE: 0.9,
            StorageLocation.GIT_REPOSITORY: 1.0,
        }
        
        self.secret_type_weights = {
            SecretType.SSH_KEY: 0.8,
            SecretType.TLS_CERTIFICATE: 0.6,
            SecretType.API_KEY: 0.7,
            SecretType.CLOUD_ACCESS_KEY: 0.9,
            SecretType.DATABASE_PASSWORD: 0.8,
            SecretType.OAUTH_TOKEN: 0.7,
            SecretType.WEBHOOK_SECRET: 0.6,
            SecretType.ENCRYPTION_KEY: 1.0,
        }
        
        self.rotation_multipliers = {
            RotationFrequency.AUTOMATED: 0.3,
            RotationFrequency.DAILY: 0.4,
            RotationFrequency.WEEKLY: 0.5,
            RotationFrequency.MONTHLY: 0.7,
            RotationFrequency.QUARTERLY: 0.9,
            RotationFrequency.YEARLY: 1.1,
            RotationFrequency.NEVER: 1.3,
        }
    
    def calculate_secret_risk_score(self, secret: Secret) -> float:
        """Calculate a comprehensive risk score for a single secret (0-10 scale)."""
        base_score = 5.0  # Start with medium risk
        
        # Factor 1: Storage location risk
        location_weight = self.location_weights.get(secret.location, 0.8)
        base_score *= location_weight * 2
        
        # Factor 2: Secret type criticality
        type_weight = self.secret_type_weights.get(secret.secret_type, 0.7)
        base_score *= (1 + type_weight)
        
        # Factor 3: Age and rotation frequency
        age_multiplier = self._calculate_age_multiplier(secret)
        rotation_multiplier = self.rotation_multipliers.get(secret.rotation_frequency, 1.0)
        base_score *= age_multiplier * rotation_multiplier
        
        # Factor 4: Encryption status
        if not secret.encryption_status:
            base_score *= 1.4  # Significant penalty for unencrypted secrets
        else:
            base_score *= 0.8  # Bonus for encrypted secrets
        
        # Factor 5: Access level and sharing
        access_multiplier = self._calculate_access_multiplier(secret)
        base_score *= access_multiplier
        
        # Factor 6: Risk factors from analysis
        risk_factor_penalty = len(secret.risk_factors) * 0.3
        base_score += risk_factor_penalty
        
        # Factor 7: Sharing penalty
        if secret.shared_with:
            sharing_penalty = min(len(secret.shared_with) * 0.2, 1.0)
            base_score += sharing_penalty
        
        # Normalize to 0-10 scale
        return min(10.0, max(0.0, base_score))
    
    def _calculate_age_multiplier(self, secret: Secret) -> float:
        """Calculate risk multiplier based on secret age."""
        if not secret.last_rotated:
            return 1.5  # High penalty for unknown rotation date
        
        age_days = (datetime.now() - secret.last_rotated).days
        
        # Age-based risk curve (exponential growth)
        if age_days <= 30:
            return 0.8  # Recent secrets are lower risk
        elif age_days <= 90:
            return 1.0  # Baseline risk
        elif age_days <= 180:
            return 1.2
        elif age_days <= 365:
            return 1.4
        elif age_days <= 730:
            return 1.7
        else:
            return 2.0  # Very old secrets are high risk
    
    def _calculate_access_multiplier(self, secret: Secret) -> float:
        """Calculate risk multiplier based on access level."""
        access_multipliers = {
            'public': 2.0,
            'internal': 1.2,
            'restricted': 1.0,
            'confidential': 0.8,
            'unknown': 1.3,
            'high_risk': 1.8
        }
        return access_multipliers.get(secret.access_level, 1.0)
    
    def calculate_system_risk_score(self, system: System, associated_secrets: List[Secret]) -> float:
        """Calculate risk score for a system based on its configuration and secrets."""
        base_score = float(system.risk_score)  # Start with system's inherent risk
        
        # Factor 1: Number of secrets (more secrets = higher risk)
        if system.secrets_count > 0:
            secret_count_multiplier = 1 + (system.secrets_count / 50)  # Scale factor
            base_score *= min(secret_count_multiplier, 2.0)  # Cap the multiplier
        
        # Factor 2: Security features
        security_bonus = 0
        if system.encryption_enabled:
            security_bonus += 0.5
        if system.audit_logging:
            security_bonus += 0.3
        if system.auto_rotation:
            security_bonus += 0.7
        if system.access_controls:
            security_bonus += 0.2 * len(system.access_controls)
        
        base_score -= security_bonus
        
        # Factor 3: Average risk of associated secrets
        if associated_secrets:
            avg_secret_risk = sum(self.calculate_secret_risk_score(s) for s in associated_secrets) / len(associated_secrets)
            base_score = (base_score + avg_secret_risk) / 2  # Blend system and secret risks
        
        return min(10.0, max(0.0, base_score))
    
    def generate_risk_assessment(
        self, 
        secrets: List[Secret], 
        ssh_keys: List[SSHKeyInfo], 
        systems: List[System]
    ) -> RiskAssessment:
        """Generate a comprehensive risk assessment."""
        
        # Calculate individual secret risks
        secret_risks = {}
        for secret in secrets:
            secret_risks[secret.id] = self.calculate_secret_risk_score(secret)
        
        # Calculate system risks
        system_risks = {}
        for system in systems:
            associated_secrets = [s for s in secrets if self._is_secret_associated_with_system(s, system)]
            system_risks[system.name] = self.calculate_system_risk_score(system, associated_secrets)
            system.risk_score = int(system_risks[system.name])  # Update system risk score
        
        # Create risk assessment
        assessment = RiskAssessment(total_secrets=len(secrets))
        
        # Calculate overall risk score
        if secrets:
            assessment.overall_risk_score = sum(secret_risks.values()) / len(secrets)
        
        # Group secrets by type and location
        assessment.secrets_by_type = Counter(s.secret_type for s in secrets)
        assessment.secrets_by_location = Counter(s.location for s in secrets)
        
        # Calculate risk distribution
        risk_levels = []
        for risk_score in secret_risks.values():
            if risk_score <= 2.0:
                risk_levels.append(RiskLevel.VERY_LOW)
            elif risk_score <= 4.0:
                risk_levels.append(RiskLevel.LOW)
            elif risk_score <= 6.0:
                risk_levels.append(RiskLevel.MEDIUM)
            elif risk_score <= 8.0:
                risk_levels.append(RiskLevel.HIGH)
            else:
                risk_levels.append(RiskLevel.CRITICAL)
        
        assessment.risk_distribution = Counter(risk_levels)
        assessment.assessed_systems = systems
        
        # Generate critical findings
        assessment.critical_findings = self._generate_critical_findings(secrets, ssh_keys, systems, secret_risks, system_risks)
        
        # Generate recommendations
        assessment.recommendations = self._generate_recommendations(secrets, ssh_keys, systems, secret_risks, system_risks)
        
        return assessment
    
    def _is_secret_associated_with_system(self, secret: Secret, system: System) -> bool:
        """Determine if a secret is associated with a system."""
        # Simple heuristic based on system type and secret location
        system_location_mapping = {
            'ci_cd': [StorageLocation.CI_CD_VARIABLES, StorageLocation.ENVIRONMENT_VARIABLES],
            'cloud_provider': [StorageLocation.CLOUD_SECRET_MANAGER, StorageLocation.ENVIRONMENT_VARIABLES],
            'secret_manager': [StorageLocation.CLOUD_SECRET_MANAGER],
            'container_platform': [StorageLocation.CONTAINER_IMAGE, StorageLocation.ENVIRONMENT_VARIABLES],
            'source_control': [StorageLocation.GIT_REPOSITORY],
            'database': [StorageLocation.DATABASE, StorageLocation.CONFIGURATION_FILE],
        }
        
        expected_locations = system_location_mapping.get(system.type, [])
        return secret.location in expected_locations
    
    def _generate_critical_findings(
        self, 
        secrets: List[Secret], 
        ssh_keys: List[SSHKeyInfo],
        systems: List[System],
        secret_risks: Dict[str, float],
        system_risks: Dict[str, float]
    ) -> List[str]:
        """Generate critical security findings."""
        findings = []
        
        # High-risk secrets
        high_risk_secrets = [s for s in secrets if secret_risks.get(s.id, 0) >= 8.0]
        if high_risk_secrets:
            findings.append(
                f"🚨 {len(high_risk_secrets)} secrets have CRITICAL risk scores (≥8.0). "
                f"Immediate attention required for: {', '.join(s.name[:30] + '...' if len(s.name) > 30 else s.name for s in high_risk_secrets[:3])}"
            )
        
        # Secrets in git repositories
        git_secrets = [s for s in secrets if s.location == StorageLocation.GIT_REPOSITORY]
        if git_secrets:
            findings.append(
                f"⚠️ {len(git_secrets)} secrets found in git repositories. "
                f"This poses a severe security risk and requires immediate remediation."
            )
        
        # Unencrypted sensitive secrets
        unencrypted_sensitive = [
            s for s in secrets 
            if not s.encryption_status and s.secret_type in [
                SecretType.ENCRYPTION_KEY, SecretType.CLOUD_ACCESS_KEY, SecretType.DATABASE_PASSWORD
            ]
        ]
        if unencrypted_sensitive:
            findings.append(
                f"🔓 {len(unencrypted_sensitive)} highly sensitive secrets are stored without encryption. "
                f"Enable encryption immediately."
            )
        
        # Never-rotated old secrets
        old_never_rotated = [
            s for s in secrets 
            if (s.rotation_frequency == RotationFrequency.NEVER and 
                s.last_rotated and 
                (datetime.now() - s.last_rotated).days > 365)
        ]
        if old_never_rotated:
            findings.append(
                f"⏰ {len(old_never_rotated)} secrets are over 1 year old and never rotated. "
                f"Implement rotation policies immediately."
            )
        
        # SSH key specific findings
        if ssh_keys:
            weak_ssh_keys = [
                k for k in ssh_keys 
                if (k.key_type in ['dsa'] or 
                    (k.key_type == 'rsa' and k.key_size and k.key_size < 2048) or
                    not k.has_passphrase)
            ]
            if weak_ssh_keys:
                findings.append(
                    f"🔑 {len(weak_ssh_keys)} SSH keys have security weaknesses "
                    f"(weak algorithms, small key sizes, or no passphrase protection)."
                )
        
        # High-risk systems
        high_risk_systems = [s for s in systems if system_risks.get(s.name, 0) >= 7.0]
        if high_risk_systems:
            findings.append(
                f"🏢 {len(high_risk_systems)} systems have high risk scores: "
                f"{', '.join(s.name for s in high_risk_systems[:3])}. Review configurations."
            )
        
        # Large secret footprint
        if len(secrets) > 50:
            findings.append(
                f"📊 Large secret footprint detected ({len(secrets)} secrets total). "
                f"Consider secret consolidation and governance policies."
            )
        
        return findings
    
    def _generate_recommendations(
        self,
        secrets: List[Secret],
        ssh_keys: List[SSHKeyInfo],
        systems: List[System],
        secret_risks: Dict[str, float],
        system_risks: Dict[str, float]
    ) -> List[str]:
        """Generate actionable security recommendations."""
        recommendations = []
        
        # Immediate actions
        critical_secrets = [s for s in secrets if secret_risks.get(s.id, 0) >= 8.0]
        if critical_secrets:
            recommendations.append(
                f"🚨 IMMEDIATE: Review and remediate {len(critical_secrets)} critical-risk secrets"
            )
        
        # Secret management improvements
        if any(s.location in [StorageLocation.GIT_REPOSITORY, StorageLocation.CONFIGURATION_FILE] for s in secrets):
            recommendations.append(
                "📝 Move secrets from git repositories and config files to dedicated secret management systems"
            )
        
        # Encryption recommendations
        unencrypted_count = sum(1 for s in secrets if not s.encryption_status)
        if unencrypted_count > 0:
            recommendations.append(
                f"🔐 Enable encryption for {unencrypted_count} unencrypted secrets"
            )
        
        # Rotation recommendations  
        no_rotation_count = sum(1 for s in secrets if s.rotation_frequency == RotationFrequency.NEVER)
        if no_rotation_count > len(secrets) * 0.5:
            recommendations.append(
                f"🔄 Implement rotation policies for {no_rotation_count} secrets that are never rotated"
            )
        
        # Access control recommendations
        shared_secrets = [s for s in secrets if s.shared_with]
        if shared_secrets:
            recommendations.append(
                f"👥 Review access controls for {len(shared_secrets)} shared secrets to implement least privilege"
            )
        
        # System-specific recommendations
        systems_without_encryption = [s for s in systems if not s.encryption_enabled]
        if systems_without_encryption:
            recommendations.append(
                f"🔒 Enable encryption at rest for systems: {', '.join(s.name for s in systems_without_encryption[:3])}"
            )
        
        systems_without_audit = [s for s in systems if not s.audit_logging]
        if len(systems_without_audit) > len(systems) * 0.3:
            recommendations.append(
                f"📋 Enable audit logging for {len(systems_without_audit)} systems to improve visibility"
            )
        
        # SSH key recommendations
        if ssh_keys:
            ssh_recommendations = self._get_ssh_specific_recommendations(ssh_keys)
            recommendations.extend(ssh_recommendations)
        
        # Strategic recommendations
        if len(systems) > 5:
            recommendations.append(
                "🏗️ Consider implementing centralized secret management to reduce complexity"
            )
        
        if len(secrets) > 20:
            recommendations.append(
                "📊 Implement secret governance policies including regular audits and lifecycle management"
            )
        
        # Monitoring recommendations
        recommendations.append(
            "📡 Implement continuous monitoring for secret exposure in code repositories"
        )
        
        recommendations.append(
            "🎯 Establish a secret rotation schedule based on sensitivity and usage patterns"
        )
        
        return recommendations[:10]  # Limit to top 10 recommendations
    
    def _get_ssh_specific_recommendations(self, ssh_keys: List[SSHKeyInfo]) -> List[str]:
        """Generate SSH key specific recommendations."""
        recommendations = []
        
        weak_keys = [k for k in ssh_keys if k.key_type in ['dsa'] or (k.key_type == 'rsa' and k.key_size and k.key_size < 2048)]
        if weak_keys:
            recommendations.append(f"🔑 Replace {len(weak_keys)} weak SSH keys with Ed25519 or RSA 4096-bit keys")
        
        unprotected_keys = [k for k in ssh_keys if not k.has_passphrase]
        if unprotected_keys:
            recommendations.append(f"🛡️ Add passphrase protection to {len(unprotected_keys)} SSH keys")
        
        bad_permissions = [k for k in ssh_keys if k.permissions != '600']
        if bad_permissions:
            recommendations.append(f"📁 Fix file permissions for {len(bad_permissions)} SSH keys (should be 600)")
        
        return recommendations
    
    def get_risk_summary_stats(self, assessment: RiskAssessment) -> Dict[str, any]:
        """Get summary statistics for the risk assessment."""
        total_secrets = assessment.total_secrets
        if total_secrets == 0:
            return {}
        
        risk_counts = assessment.risk_distribution
        critical_count = risk_counts.get(RiskLevel.CRITICAL, 0)
        high_count = risk_counts.get(RiskLevel.HIGH, 0)
        medium_count = risk_counts.get(RiskLevel.MEDIUM, 0)
        low_count = risk_counts.get(RiskLevel.LOW, 0)
        very_low_count = risk_counts.get(RiskLevel.VERY_LOW, 0)
        
        return {
            'total_secrets': total_secrets,
            'overall_risk_score': round(assessment.overall_risk_score, 2),
            'risk_percentages': {
                'critical': round((critical_count / total_secrets) * 100, 1),
                'high': round((high_count / total_secrets) * 100, 1),
                'medium': round((medium_count / total_secrets) * 100, 1),
                'low': round((low_count / total_secrets) * 100, 1),
                'very_low': round((very_low_count / total_secrets) * 100, 1)
            },
            'risk_counts': {
                'critical': critical_count,
                'high': high_count,
                'medium': medium_count,
                'low': low_count,
                'very_low': very_low_count
            },
            'critical_findings_count': len(assessment.critical_findings),
            'recommendations_count': len(assessment.recommendations),
            'systems_assessed': len(assessment.assessed_systems)
        }

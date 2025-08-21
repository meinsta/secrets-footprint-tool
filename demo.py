#!/usr/bin/env python3
"""
Demo script for the Secrets Footprint Assessment Tool
Shows key features without requiring user interaction.
"""

import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from models import *
from ssh_scanner import SSHKeyScanner
from systems import SystemsManager
from risk_engine import RiskScoringEngine
from visualizer import SecretsFootprintVisualizer
from datetime import datetime


def demo_ssh_analysis():
    """Demonstrate SSH key analysis."""
    print("🔍 SSH KEY ANALYSIS DEMO")
    print("=" * 50)
    
    scanner = SSHKeyScanner()
    try:
        ssh_keys = scanner.scan_ssh_keys()
        
        if ssh_keys:
            print(f"✅ Found {len(ssh_keys)} SSH keys")
            
            visualizer = SecretsFootprintVisualizer()
            report = visualizer.create_detailed_ssh_report(ssh_keys)
            print(report)
        else:
            print("ℹ️  No SSH keys found - creating simulated data for demo")
            demo_ssh_key()
            
    except Exception as e:
        print(f"Demo with simulated data (SSH scan failed: {e})")
        demo_ssh_key()


def demo_ssh_key():
    """Create a demo SSH key for demonstration."""
    # Create sample SSH key info
    demo_key = SSHKeyInfo(
        file_path="~/.ssh/id_rsa",
        key_type="rsa",
        key_size=2048,
        fingerprint="SHA256:demo_fingerprint_here",
        comment="user@example.com",
        has_passphrase=False,
        permissions="644",
        last_used=datetime(2023, 1, 1),
        associated_hosts=["github.com", "server.example.com"],
        is_agent_key=True
    )
    
    visualizer = SecretsFootprintVisualizer()
    report = visualizer.create_detailed_ssh_report([demo_key])
    print(report)


def demo_systems_overview():
    """Demonstrate system management capabilities."""
    print("\n🏢 SYSTEM TEMPLATES DEMO")
    print("=" * 50)
    
    systems_manager = SystemsManager()
    categories = systems_manager.get_systems_by_category()
    
    print("Available system categories and templates:")
    for category, systems in categories.items():
        category_name = category.value.replace('_', ' ').title()
        print(f"\n📁 {category_name}:")
        for system_name in systems[:3]:  # Show first 3
            template = systems_manager.get_system_template(system_name)
            print(f"   • {template.name} - {template.description}")
        if len(systems) > 3:
            print(f"   ... and {len(systems) - 3} more")


def demo_risk_assessment():
    """Demonstrate risk assessment with sample data."""
    print("\n⚡ RISK ASSESSMENT DEMO")
    print("=" * 50)
    
    # Create sample secrets with different risk profiles
    secrets = [
        Secret(
            id="git_api_key",
            secret_type=SecretType.API_KEY,
            name="GitHub API Key",
            location=StorageLocation.GIT_REPOSITORY,
            created_date=datetime(2023, 1, 1),
            last_rotated=datetime(2023, 1, 1),
            rotation_frequency=RotationFrequency.NEVER,
            encryption_status=False,
            risk_factors=["Found in git history", "Never rotated", "No encryption"]
        ),
        Secret(
            id="vault_secret",
            secret_type=SecretType.DATABASE_PASSWORD,
            name="Production DB Password",
            location=StorageLocation.CLOUD_SECRET_MANAGER,
            created_date=datetime(2024, 6, 1),
            last_rotated=datetime(2024, 8, 1),
            rotation_frequency=RotationFrequency.QUARTERLY,
            encryption_status=True,
            access_level="confidential"
        ),
        Secret(
            id="ssh_key_demo",
            secret_type=SecretType.SSH_KEY,
            name="Server SSH Key",
            location=StorageLocation.LOCAL_FILESYSTEM,
            created_date=datetime(2022, 3, 1),
            last_rotated=datetime(2022, 3, 1),
            rotation_frequency=RotationFrequency.NEVER,
            encryption_status=False,
            risk_factors=["Old key", "No passphrase", "Wide permissions"]
        )
    ]
    
    # Create sample systems
    systems = [
        System(
            name="GitHub Actions",
            type="ci_cd",
            is_used=True,
            secrets_count=5,
            encryption_enabled=True,
            audit_logging=True,
            risk_score=2
        ),
        System(
            name="HashiCorp Vault",
            type="secret_manager",
            is_used=True,
            secrets_count=25,
            encryption_enabled=True,
            audit_logging=True,
            auto_rotation=True,
            access_controls=["RBAC", "Policies"],
            risk_score=1
        )
    ]
    
    # Generate risk assessment
    risk_engine = RiskScoringEngine()
    assessment = risk_engine.generate_risk_assessment(secrets, [], systems)
    
    # Display results
    visualizer = SecretsFootprintVisualizer()
    visualizer.print_assessment_summary(assessment)
    
    # Show executive summary
    print("\n📋 EXECUTIVE SUMMARY")
    print("=" * 50)
    executive_summary = visualizer.generate_executive_summary(assessment)
    print(executive_summary)


def main():
    """Run the demo."""
    print("🔍 SECRETS FOOTPRINT ASSESSMENT TOOL - DEMO")
    print("=" * 60)
    print("This demo showcases the key features of the tool.")
    print("For the full interactive experience, run: python secrets_audit.py")
    print()
    
    # Demo SSH analysis
    demo_ssh_analysis()
    
    # Demo systems overview
    demo_systems_overview()
    
    # Demo risk assessment
    demo_risk_assessment()
    
    print("\n✅ Demo completed!")
    print("To run a full assessment: python secrets_audit.py")


if __name__ == "__main__":
    main()

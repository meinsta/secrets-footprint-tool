"""
Interactive CLI Interface
Provides a user-friendly command-line interface for secrets footprint assessment.
"""

import os
import sys
import json
import uuid
from typing import List, Dict, Optional
from datetime import datetime
from pathlib import Path

from models import AuditSession, Secret, System
from secure_ssh_scanner import SecureSSHKeyScanner
from systems import SystemsManager, SystemCategory
from risk_engine import RiskScoringEngine
from visualizer import SecretsFootprintVisualizer


class SecretsFootprintCLI:
    """Interactive CLI for secrets footprint assessment."""
    
    def __init__(self):
        self.ssh_scanner = SecureSSHKeyScanner()
        self.systems_manager = SystemsManager()
        self.risk_engine = RiskScoringEngine()
        self.visualizer = SecretsFootprintVisualizer()
        self.current_session: Optional[AuditSession] = None
        
    def run(self):
        """Main CLI loop."""
        self.print_welcome()
        
        while True:
            try:
                choice = self.show_main_menu()
                
                if choice == '1':
                    self.start_new_assessment()
                elif choice == '2':
                    self.view_previous_assessments()
                elif choice == '3':
                    self.show_help()
                elif choice == '4':
                    print("👋 Thank you for using the Secrets Footprint Assessment Tool!")
                    break
                else:
                    print("❌ Invalid choice. Please try again.")
                    
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"\n❌ An error occurred: {e}")
                print("Please try again or contact support if the issue persists.")
    
    def print_welcome(self):
        """Print welcome message and tool overview."""
        print("\n" + "="*80)
        print("🔍 SECRETS FOOTPRINT ASSESSMENT TOOL")
        print("="*80)
        print("Welcome! This tool helps you assess and improve your secrets security posture.")
        print("It will:")
        print("  • 🔑 Scan for SSH keys and analyze their security")
        print("  • 🏢 Audit systems where you store secrets")
        print("  • ⚡ Calculate risk scores and provide recommendations")
        print("  • 📊 Generate detailed security reports")
        print("="*80)
    
    def show_main_menu(self) -> str:
        """Show main menu and get user choice."""
        print("\n📋 MAIN MENU")
        print("-" * 30)
        print("1. 🚀 Start New Assessment")
        print("2. 📂 View Previous Assessments") 
        print("3. ❓ Help & Information")
        print("4. 🚪 Exit")
        
        return input("\nSelect an option (1-4): ").strip()
    
    def start_new_assessment(self):
        """Start a new secrets footprint assessment."""
        print("\n" + "="*60)
        print("🚀 STARTING NEW SECRETS FOOTPRINT ASSESSMENT")
        print("="*60)
        
        # Create new session
        session_id = str(uuid.uuid4())[:8]
        self.current_session = AuditSession(
            session_id=session_id,
            timestamp=datetime.now()
        )
        
        print(f"Session ID: {session_id}")
        print("This assessment will take about 5-10 minutes to complete.\n")
        
        # Step 1: SSH Key Analysis
        if self.confirm_action("🔑 Scan for SSH keys on this system?"):
            self.scan_ssh_keys()
        
        # Step 2: System Selection
        if self.confirm_action("🏢 Configure systems and tools you use?"):
            self.select_systems()
        
        # Step 3: Risk Assessment
        print("\n⚡ Calculating risk assessment...")
        self.calculate_risk_assessment()
        
        # Step 4: Show Results
        self.show_assessment_results()
        
        # Step 5: Save Results
        if self.confirm_action("💾 Save this assessment for future reference?"):
            self.save_assessment()
        
        print(f"\n✅ Assessment {session_id} completed!")
    
    def scan_ssh_keys(self):
        """Scan and analyze SSH keys."""
        print("\n🔍 Scanning for SSH keys...")
        print("This will look for SSH keys in ~/.ssh/ and analyze their security.")
        
        try:
            ssh_keys = self.ssh_scanner.scan_ssh_keys()
            self.current_session.ssh_keys = ssh_keys
            
            if ssh_keys:
                print(f"\n✅ Found {len(ssh_keys)} SSH keys")
                
                # Show summary
                key_types = {}
                security_issues = 0
                
                for key in ssh_keys:
                    key_types[key.key_type] = key_types.get(key.key_type, 0) + 1
                    if not key.has_passphrase or key.permissions != '600':
                        security_issues += 1
                
                print(f"   Key types: {', '.join(f'{k}:{v}' for k, v in key_types.items())}")
                if security_issues > 0:
                    print(f"   ⚠️  {security_issues} keys have potential security issues")
                
                # Convert to secrets for risk analysis
                ssh_secrets = self.ssh_scanner.convert_to_secrets(ssh_keys)
                self.current_session.discovered_secrets.extend(ssh_secrets)
                
                # Show detailed analysis option
                if self.confirm_action("View detailed SSH key analysis?"):
                    report = self.visualizer.create_detailed_ssh_report(ssh_keys)
                    print(f"\n{report}")
                    
            else:
                print("ℹ️  No SSH keys found in ~/.ssh/")
                
        except Exception as e:
            print(f"❌ Error during SSH key scan: {e}")
    
    def select_systems(self):
        """Interactive system selection process."""
        print("\n🏢 SYSTEM & TOOL CONFIGURATION")
        print("Let's identify where you store secrets and credentials.")
        print("This helps assess your overall security posture.\n")
        
        categories = self.systems_manager.get_systems_by_category()
        
        for category, system_names in categories.items():
            if not system_names:
                continue
                
            category_name = category.value.replace('_', ' ').title()
            print(f"\n📁 {category_name}")
            print("-" * 40)
            
            for system_name in system_names:
                template = self.systems_manager.get_system_template(system_name)
                if not template:
                    continue
                
                print(f"\n{template.name}")
                print(f"   {template.description}")
                print(f"   Common secrets: {', '.join(template.common_secret_types)}")
                
                if self.confirm_action(f"Do you use {template.name}?"):
                    self.configure_system(system_name)
    
    def configure_system(self, system_name: str):
        """Configure a specific system with user responses."""
        template = self.systems_manager.get_system_template(system_name)
        if not template:
            return
        
        print(f"\n🔧 Configuring {system_name}")
        responses = {}
        
        for question in template.questions:
            print(f"\n❓ {question['text']}")
            answer = input("   Answer: ").strip()
            responses[question['key']] = answer
        
        # Create system from template and responses
        system = self.systems_manager.create_system_from_template(system_name, responses)
        self.current_session.selected_systems.append(system)
        self.current_session.user_responses[system_name] = responses
        
        print(f"✅ {system_name} configured (Risk Score: {system.risk_score}/5)")
    
    def calculate_risk_assessment(self):
        """Calculate comprehensive risk assessment."""
        if not self.current_session:
            return
        
        # Generate risk assessment
        assessment = self.risk_engine.generate_risk_assessment(
            secrets=self.current_session.discovered_secrets,
            ssh_keys=self.current_session.ssh_keys,
            systems=self.current_session.selected_systems
        )
        
        self.current_session.risk_assessment = assessment
        print("✅ Risk assessment calculated")
    
    def show_assessment_results(self):
        """Display the assessment results."""
        if not self.current_session or not self.current_session.risk_assessment:
            print("❌ No assessment results available")
            return
        
        assessment = self.current_session.risk_assessment
        
        # Show summary
        self.visualizer.print_assessment_summary(assessment)
        
        # Additional options
        while True:
            print("\n📊 REPORT OPTIONS")
            print("1. 📋 Executive Summary")
            print("2. 🔑 Detailed SSH Analysis")  
            print("3. 💾 Export HTML Report")
            print("4. 📄 Export JSON Data")
            print("5. ↩️  Return to Main Menu")
            
            choice = input("\nSelect option (1-5): ").strip()
            
            if choice == '1':
                summary = self.visualizer.generate_executive_summary(assessment)
                print(f"\n{summary}")
                
            elif choice == '2' and self.current_session.ssh_keys:
                report = self.visualizer.create_detailed_ssh_report(self.current_session.ssh_keys)
                print(f"\n{report}")
                
            elif choice == '3':
                self.export_html_report()
                
            elif choice == '4':
                self.export_json_data()
                
            elif choice == '5':
                break
                
            else:
                print("❌ Invalid choice")
    
    def export_html_report(self):
        """Export HTML report to file."""
        if not self.current_session or not self.current_session.risk_assessment:
            return
        
        try:
            # Create reports directory
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)
            
            # Generate HTML report
            html_content = self.visualizer.create_html_report(
                self.current_session.risk_assessment,
                self.current_session.ssh_keys
            )
            
            # Save to file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"secrets_assessment_{self.current_session.session_id}_{timestamp}.html"
            filepath = reports_dir / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"✅ HTML report saved to: {filepath}")
            print(f"   Open in browser: file://{filepath.absolute()}")
            
        except Exception as e:
            print(f"❌ Error exporting HTML report: {e}")
    
    def export_json_data(self):
        """Export assessment data as JSON."""
        if not self.current_session:
            return
        
        try:
            # Create reports directory
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)
            
            # Export session data
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"secrets_data_{self.current_session.session_id}_{timestamp}.json"
            filepath = reports_dir / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.current_session.to_dict(), f, indent=2, default=str)
            
            print(f"✅ JSON data saved to: {filepath}")
            
        except Exception as e:
            print(f"❌ Error exporting JSON data: {e}")
    
    def save_assessment(self):
        """Save assessment to persistent storage."""
        if not self.current_session:
            return
        
        try:
            # Create config directory
            config_dir = Path("config")
            config_dir.mkdir(exist_ok=True)
            
            # Save session
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"assessment_{self.current_session.session_id}_{timestamp}.json"
            filepath = config_dir / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.current_session.to_dict(), f, indent=2, default=str)
            
            print(f"✅ Assessment saved to: {filepath}")
            
        except Exception as e:
            print(f"❌ Error saving assessment: {e}")
    
    def view_previous_assessments(self):
        """View and manage previous assessments."""
        config_dir = Path("config")
        
        if not config_dir.exists():
            print("\n📂 No previous assessments found.")
            return
        
        # Find assessment files
        assessment_files = list(config_dir.glob("assessment_*.json"))
        
        if not assessment_files:
            print("\n📂 No previous assessments found.")
            return
        
        print(f"\n📂 PREVIOUS ASSESSMENTS ({len(assessment_files)} found)")
        print("-" * 50)
        
        # Sort by modification time (newest first)
        assessment_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
        
        for i, filepath in enumerate(assessment_files, 1):
            try:
                # Load and show summary
                with open(filepath, 'r') as f:
                    data = json.load(f)
                
                timestamp = datetime.fromisoformat(data['timestamp']).strftime('%Y-%m-%d %H:%M')
                session_id = data['session_id']
                total_secrets = len(data.get('discovered_secrets', []))
                total_systems = len(data.get('selected_systems', []))
                
                risk_score = 0.0
                if data.get('risk_assessment'):
                    risk_score = data['risk_assessment'].get('overall_risk_score', 0.0)
                
                print(f"{i:2d}. Session {session_id} - {timestamp}")
                print(f"    Secrets: {total_secrets}, Systems: {total_systems}, Risk: {risk_score:.1f}/10.0")
                
            except Exception as e:
                print(f"{i:2d}. {filepath.name} - Error loading: {e}")
        
        # Allow user to select an assessment
        print("\nOptions:")
        print("1. 👁️  View detailed results for an assessment")
        print("2. 🗑️  Delete an assessment")
        print("3. ↩️  Return to main menu")
        
        choice = input("\nSelect option (1-3): ").strip()
        
        if choice == '1':
            self.view_assessment_details(assessment_files)
        elif choice == '2':
            self.delete_assessment(assessment_files)
    
    def view_assessment_details(self, assessment_files: List[Path]):
        """View details of a selected assessment."""
        try:
            selection = int(input(f"\nEnter assessment number (1-{len(assessment_files)}): ")) - 1
            
            if 0 <= selection < len(assessment_files):
                filepath = assessment_files[selection]
                
                with open(filepath, 'r') as f:
                    data = json.load(f)
                
                # Load the assessment data back into objects (simplified)
                print(f"\n📊 Assessment Details: {data['session_id']}")
                print("-" * 50)
                print(f"Date: {data['timestamp']}")
                print(f"Secrets Found: {len(data.get('discovered_secrets', []))}")
                print(f"SSH Keys: {len(data.get('ssh_keys', []))}")
                print(f"Systems: {len(data.get('selected_systems', []))}")
                
                if data.get('risk_assessment'):
                    risk_data = data['risk_assessment']
                    print(f"Overall Risk Score: {risk_data.get('overall_risk_score', 0.0):.1f}/10.0")
                    print(f"Critical Findings: {len(risk_data.get('critical_findings', []))}")
                    print(f"Recommendations: {len(risk_data.get('recommendations', []))}")
                
            else:
                print("❌ Invalid selection")
                
        except (ValueError, IndexError):
            print("❌ Invalid input")
        except Exception as e:
            print(f"❌ Error viewing assessment: {e}")
    
    def delete_assessment(self, assessment_files: List[Path]):
        """Delete a selected assessment."""
        try:
            selection = int(input(f"\nEnter assessment number to delete (1-{len(assessment_files)}): ")) - 1
            
            if 0 <= selection < len(assessment_files):
                filepath = assessment_files[selection]
                
                if self.confirm_action(f"Delete assessment {filepath.name}? This cannot be undone."):
                    filepath.unlink()
                    print("✅ Assessment deleted")
                else:
                    print("❌ Deletion cancelled")
            else:
                print("❌ Invalid selection")
                
        except (ValueError, IndexError):
            print("❌ Invalid input")
        except Exception as e:
            print(f"❌ Error deleting assessment: {e}")
    
    def show_help(self):
        """Show help information."""
        print("\n" + "="*60)
        print("❓ HELP & INFORMATION")
        print("="*60)
        
        print("\n🎯 PURPOSE")
        print("This tool helps organizations assess their 'secrets footprint' - the")
        print("security posture of sensitive credentials and keys across their infrastructure.")
        
        print("\n🔍 WHAT IT DOES")
        print("• Scans for SSH keys and analyzes their security properties")
        print("• Inventories systems where you store secrets (CI/CD, cloud, etc.)")
        print("• Calculates risk scores based on storage methods and practices")
        print("• Provides actionable security recommendations")
        print("• Generates reports for security teams and management")
        
        print("\n🔑 SSH KEY ANALYSIS")
        print("• Finds SSH keys in ~/.ssh/")
        print("• Checks key types, sizes, and encryption")
        print("• Identifies security issues (weak algorithms, missing passphrases)")
        print("• Analyzes file permissions and usage patterns")
        
        print("\n🏢 SYSTEM ASSESSMENT")
        print("• Covers CI/CD platforms (GitHub Actions, Jenkins, GitLab)")
        print("• Cloud providers (AWS, GCP, Azure)")
        print("• Secret managers (Vault, 1Password, Bitwarden)")
        print("• Container platforms (Docker, Kubernetes)")
        print("• Source control and database systems")
        
        print("\n⚡ RISK SCORING")
        print("• Calculates risk based on multiple factors:")
        print("  - Storage location (git repos = highest risk)")
        print("  - Secret type and sensitivity")
        print("  - Age and rotation frequency")
        print("  - Encryption and access controls")
        print("  - Sharing and exposure patterns")
        
        print("\n📊 REPORTING")
        print("• Terminal summary with visual risk distribution")
        print("• Executive summary for management")
        print("• Detailed technical reports")
        print("• HTML reports for sharing")
        print("• JSON data export for integration")
        
        print("\n🔒 PRIVACY & SECURITY")
        print("• Tool runs locally - no data sent to external servers")
        print("• Only analyzes metadata, not secret values")
        print("• SSH keys are analyzed by properties, content not stored")
        print("• All data saved locally in config/ and reports/ directories")
        
        print("\n💡 BEST PRACTICES")
        print("• Run assessments regularly (quarterly recommended)")
        print("• Share executive summaries with security leadership") 
        print("• Use technical reports for remediation planning")
        print("• Track improvements over time with repeated assessments")
        
        print("\n🛠️ FILES CREATED")
        print("• config/assessment_*.json - Saved assessments")
        print("• reports/secrets_assessment_*.html - HTML reports")
        print("• reports/secrets_data_*.json - Raw data exports")
        
        input("\nPress Enter to continue...")
    
    def confirm_action(self, message: str) -> bool:
        """Ask user for confirmation."""
        while True:
            response = input(f"{message} (y/n): ").strip().lower()
            if response in ['y', 'yes']:
                return True
            elif response in ['n', 'no']:
                return False
            else:
                print("Please enter 'y' or 'n'")


def main():
    """Main entry point."""
    try:
        cli = SecretsFootprintCLI()
        cli.run()
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

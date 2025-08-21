"""
Visualization and Reporting Module
Creates visual representations and reports for secrets footprint assessment.
"""

import json
from typing import List, Dict, Optional
from datetime import datetime
from pathlib import Path

from models import RiskAssessment, Secret, System, SSHKeyInfo, RiskLevel, SecretType, StorageLocation


class SecretsFootprintVisualizer:
    """Creates visualizations and reports for secrets assessment."""
    
    def __init__(self):
        self.colors = {
            'critical': '🟥',
            'high': '🟧', 
            'medium': '🟨',
            'low': '🟩',
            'very_low': '🟢'
        }
        
        self.risk_level_names = {
            RiskLevel.CRITICAL: 'Critical',
            RiskLevel.HIGH: 'High', 
            RiskLevel.MEDIUM: 'Medium',
            RiskLevel.LOW: 'Low',
            RiskLevel.VERY_LOW: 'Very Low'
        }
    
    def print_assessment_summary(self, assessment: RiskAssessment) -> None:
        """Print a comprehensive summary of the risk assessment."""
        print("\n" + "="*80)
        print("🔍 SECRETS FOOTPRINT ASSESSMENT SUMMARY")
        print("="*80)
        
        # Overall statistics
        self._print_overall_stats(assessment)
        
        # Risk distribution
        self._print_risk_distribution(assessment)
        
        # Secrets by type and location
        self._print_secrets_breakdown(assessment)
        
        # Systems overview
        self._print_systems_overview(assessment)
        
        # Critical findings
        if assessment.critical_findings:
            self._print_critical_findings(assessment.critical_findings)
        
        # Recommendations
        if assessment.recommendations:
            self._print_recommendations(assessment.recommendations)
        
        print("="*80)
    
    def _print_overall_stats(self, assessment: RiskAssessment) -> None:
        """Print overall statistics."""
        print(f"\n📊 OVERALL STATISTICS")
        print("-" * 40)
        print(f"Total Secrets Found:     {assessment.total_secrets}")
        print(f"Overall Risk Score:      {assessment.overall_risk_score:.1f}/10.0")
        print(f"Systems Assessed:        {len(assessment.assessed_systems)}")
        
        # Risk level indicator
        if assessment.overall_risk_score >= 8.0:
            risk_indicator = "🚨 CRITICAL"
        elif assessment.overall_risk_score >= 6.0:
            risk_indicator = "⚠️ HIGH"
        elif assessment.overall_risk_score >= 4.0:
            risk_indicator = "🟡 MEDIUM"
        else:
            risk_indicator = "✅ LOW"
        
        print(f"Risk Level:              {risk_indicator}")
    
    def _print_risk_distribution(self, assessment: RiskAssessment) -> None:
        """Print risk distribution with visual bars."""
        if not assessment.total_secrets:
            return
            
        print(f"\n📈 RISK DISTRIBUTION")
        print("-" * 40)
        
        for risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.VERY_LOW]:
            count = assessment.risk_distribution.get(risk_level, 0)
            percentage = (count / assessment.total_secrets) * 100 if assessment.total_secrets > 0 else 0
            
            # Create visual bar
            bar_length = 20
            filled_length = int((count / max(assessment.total_secrets, 1)) * bar_length)
            bar = "█" * filled_length + "░" * (bar_length - filled_length)
            
            # Color coding
            color = self.colors.get(risk_level.name.lower(), '⚪')
            level_name = self.risk_level_names.get(risk_level, risk_level.name)
            
            print(f"{color} {level_name:<10} │{bar}│ {count:3d} ({percentage:4.1f}%)")
    
    def _print_secrets_breakdown(self, assessment: RiskAssessment) -> None:
        """Print breakdown of secrets by type and location."""
        print(f"\n🗂️  SECRETS BY TYPE")
        print("-" * 40)
        
        if assessment.secrets_by_type:
            for secret_type, count in assessment.secrets_by_type.most_common():
                type_name = secret_type.value.replace('_', ' ').title()
                print(f"  {type_name:<25} {count:3d}")
        else:
            print("  No secrets categorized by type")
        
        print(f"\n🏪 SECRETS BY LOCATION")
        print("-" * 40)
        
        if assessment.secrets_by_location:
            for location, count in assessment.secrets_by_location.most_common():
                location_name = location.value.replace('_', ' ').title()
                
                # Add risk indicator for locations
                risk_indicators = {
                    'Git Repository': '🚨',
                    'Configuration File': '⚠️',
                    'Container Image': '⚠️',
                    'Local Filesystem': '🟡',
                    'Environment Variables': '🟡',
                    'Database': '🟠',
                    'Ci Cd Variables': '🟢',
                    'Cloud Secret Manager': '✅'
                }
                
                indicator = risk_indicators.get(location_name, '⚪')
                print(f"  {indicator} {location_name:<25} {count:3d}")
        else:
            print("  No secrets categorized by location")
    
    def _print_systems_overview(self, assessment: RiskAssessment) -> None:
        """Print overview of assessed systems."""
        if not assessment.assessed_systems:
            return
            
        print(f"\n🏢 SYSTEMS OVERVIEW")
        print("-" * 40)
        
        # Sort by risk score descending
        sorted_systems = sorted(assessment.assessed_systems, key=lambda s: s.risk_score, reverse=True)
        
        for system in sorted_systems:
            risk_color = self._get_risk_color_for_score(system.risk_score)
            
            # Security features indicators
            features = []
            if system.encryption_enabled:
                features.append("🔐")
            if system.audit_logging:
                features.append("📋")
            if system.auto_rotation:
                features.append("🔄")
            if system.access_controls:
                features.append("🛡️")
            
            features_str = "".join(features) if features else "⚪"
            
            print(f"  {risk_color} {system.name:<25} Risk: {system.risk_score}/5 │ Secrets: {system.secrets_count:3d} │ {features_str}")
    
    def _get_risk_color_for_score(self, score: int) -> str:
        """Get color emoji for risk score."""
        if score >= 4:
            return "🚨"
        elif score >= 3:
            return "⚠️"
        elif score >= 2:
            return "🟡"
        else:
            return "✅"
    
    def _print_critical_findings(self, findings: List[str]) -> None:
        """Print critical findings."""
        print(f"\n🚨 CRITICAL FINDINGS ({len(findings)})")
        print("-" * 40)
        
        for i, finding in enumerate(findings, 1):
            print(f"{i:2d}. {finding}")
    
    def _print_recommendations(self, recommendations: List[str]) -> None:
        """Print recommendations."""
        print(f"\n💡 RECOMMENDATIONS ({len(recommendations)})")
        print("-" * 40)
        
        for i, rec in enumerate(recommendations, 1):
            print(f"{i:2d}. {rec}")
    
    def create_detailed_ssh_report(self, ssh_keys: List[SSHKeyInfo]) -> str:
        """Create a detailed SSH key security report."""
        if not ssh_keys:
            return "No SSH keys found for analysis.\n"
        
        report = []
        report.append("🔑 SSH KEY SECURITY ANALYSIS")
        report.append("=" * 50)
        report.append(f"Total SSH Keys: {len(ssh_keys)}\n")
        
        # Key types summary
        key_types = {}
        for key in ssh_keys:
            key_types[key.key_type] = key_types.get(key.key_type, 0) + 1
        
        report.append("KEY TYPES:")
        for key_type, count in sorted(key_types.items()):
            security_rating = self._get_key_type_security_rating(key_type)
            report.append(f"  {key_type.upper():<10} {count:3d} keys  {security_rating}")
        
        report.append("")
        
        # Security issues
        issues = self._analyze_ssh_security_issues(ssh_keys)
        if issues:
            report.append("SECURITY ISSUES:")
            for issue in issues:
                report.append(f"  ⚠️  {issue}")
            report.append("")
        
        # Detailed key information
        report.append("DETAILED KEY ANALYSIS:")
        report.append("-" * 30)
        
        for i, key in enumerate(ssh_keys, 1):
            report.append(f"{i:2d}. {key.file_path}")
            report.append(f"    Type: {key.key_type.upper()}")
            if key.key_size:
                report.append(f"    Size: {key.key_size} bits")
            report.append(f"    Passphrase: {'✓' if key.has_passphrase else '✗'}")
            report.append(f"    Permissions: {key.permissions}")
            report.append(f"    SSH Agent: {'✓' if key.is_agent_key else '✗'}")
            if key.associated_hosts:
                report.append(f"    Hosts: {', '.join(key.associated_hosts)}")
            if key.comment:
                report.append(f"    Comment: {key.comment}")
            
            # Security assessment
            security_score = self._calculate_ssh_key_security_score(key)
            security_level = self._get_security_level_description(security_score)
            report.append(f"    Security: {security_level}")
            report.append("")
        
        return "\n".join(report)
    
    def _get_key_type_security_rating(self, key_type: str) -> str:
        """Get security rating for SSH key type."""
        ratings = {
            'ed25519': '✅ Excellent',
            'rsa': '🟡 Good (if ≥2048 bits)',
            'ecdsa': '🟡 Acceptable',
            'dsa': '🚨 Deprecated',
            'unknown': '⚪ Unknown'
        }
        return ratings.get(key_type.lower(), '⚪ Unknown')
    
    def _analyze_ssh_security_issues(self, ssh_keys: List[SSHKeyInfo]) -> List[str]:
        """Analyze SSH keys for security issues."""
        issues = []
        
        # Check for deprecated algorithms
        deprecated_keys = [k for k in ssh_keys if k.key_type in ['dsa']]
        if deprecated_keys:
            issues.append(f"{len(deprecated_keys)} keys use deprecated DSA algorithm")
        
        # Check for weak RSA keys
        weak_rsa = [k for k in ssh_keys if k.key_type == 'rsa' and k.key_size and k.key_size < 2048]
        if weak_rsa:
            issues.append(f"{len(weak_rsa)} RSA keys are smaller than 2048 bits")
        
        # Check for unprotected keys
        unprotected = [k for k in ssh_keys if not k.has_passphrase]
        if unprotected:
            issues.append(f"{len(unprotected)} keys lack passphrase protection")
        
        # Check for bad permissions
        bad_perms = [k for k in ssh_keys if k.permissions and k.permissions != '600']
        if bad_perms:
            issues.append(f"{len(bad_perms)} keys have incorrect file permissions")
        
        # Check for unused keys (not in SSH agent and no associated hosts)
        unused = [k for k in ssh_keys if not k.is_agent_key and not k.associated_hosts]
        if unused:
            issues.append(f"{len(unused)} keys appear unused (not in agent, no configured hosts)")
        
        return issues
    
    def _calculate_ssh_key_security_score(self, key: SSHKeyInfo) -> int:
        """Calculate security score for SSH key (1-5 scale)."""
        score = 3  # Start with baseline
        
        # Algorithm bonus/penalty
        if key.key_type == 'ed25519':
            score += 2
        elif key.key_type == 'rsa' and key.key_size and key.key_size >= 4096:
            score += 1
        elif key.key_type == 'rsa' and key.key_size and key.key_size >= 2048:
            pass  # baseline
        elif key.key_type == 'rsa' and key.key_size and key.key_size < 2048:
            score -= 2
        elif key.key_type == 'dsa':
            score -= 3
        
        # Passphrase bonus
        if key.has_passphrase:
            score += 1
        else:
            score -= 1
        
        # Permissions check
        if key.permissions == '600':
            pass  # baseline
        else:
            score -= 1
        
        # Usage indicators
        if key.is_agent_key or key.associated_hosts:
            pass  # baseline - key is in use
        else:
            score -= 1  # unused key
        
        return max(1, min(5, score))
    
    def _get_security_level_description(self, score: int) -> str:
        """Get description for security score."""
        descriptions = {
            1: '🚨 Poor',
            2: '⚠️ Weak',
            3: '🟡 Fair',
            4: '🟢 Good',
            5: '✅ Excellent'
        }
        return descriptions.get(score, '⚪ Unknown')
    
    def generate_executive_summary(self, assessment: RiskAssessment) -> str:
        """Generate an executive summary suitable for management."""
        summary = []
        summary.append("SECRETS SECURITY EXECUTIVE SUMMARY")
        summary.append("=" * 50)
        summary.append(f"Assessment Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        summary.append("")
        
        # Key metrics
        summary.append("KEY METRICS:")
        summary.append(f"• Total secrets discovered: {assessment.total_secrets}")
        summary.append(f"• Overall risk score: {assessment.overall_risk_score:.1f}/10.0")
        summary.append(f"• Systems assessed: {len(assessment.assessed_systems)}")
        summary.append("")
        
        # Risk summary
        if assessment.total_secrets > 0:
            critical_pct = (assessment.risk_distribution.get(RiskLevel.CRITICAL, 0) / assessment.total_secrets) * 100
            high_pct = (assessment.risk_distribution.get(RiskLevel.HIGH, 0) / assessment.total_secrets) * 100
            
            summary.append("RISK BREAKDOWN:")
            summary.append(f"• Critical risk secrets: {critical_pct:.1f}%")
            summary.append(f"• High risk secrets: {high_pct:.1f}%")
            summary.append("")
        
        # Top concerns
        if assessment.critical_findings:
            summary.append("TOP SECURITY CONCERNS:")
            for i, finding in enumerate(assessment.critical_findings[:3], 1):
                # Clean up emoji and formatting for executive summary
                clean_finding = finding.replace('🚨', '').replace('⚠️', '').replace('🔓', '').strip()
                summary.append(f"{i}. {clean_finding}")
            summary.append("")
        
        # Priority actions
        if assessment.recommendations:
            summary.append("PRIORITY ACTIONS:")
            for i, rec in enumerate(assessment.recommendations[:5], 1):
                # Clean up emoji and formatting
                clean_rec = rec.replace('🚨', '').replace('📝', '').replace('🔐', '').replace('🔄', '').strip()
                if clean_rec.startswith('IMMEDIATE:'):
                    clean_rec = clean_rec.replace('IMMEDIATE:', 'IMMEDIATE ACTION REQUIRED:')
                summary.append(f"{i}. {clean_rec}")
            summary.append("")
        
        # Business impact
        summary.append("BUSINESS IMPACT ASSESSMENT:")
        if assessment.overall_risk_score >= 8.0:
            impact = "CRITICAL - Immediate action required to prevent potential security incidents"
        elif assessment.overall_risk_score >= 6.0:
            impact = "HIGH - Significant security improvements needed within 30 days"
        elif assessment.overall_risk_score >= 4.0:
            impact = "MEDIUM - Moderate security risks requiring attention within 90 days"
        else:
            impact = "LOW - Continue with current security practices and regular monitoring"
        
        summary.append(f"• {impact}")
        summary.append("")
        
        # Next steps
        summary.append("RECOMMENDED NEXT STEPS:")
        summary.append("1. Review and approve remediation plan for critical findings")
        summary.append("2. Implement centralized secret management solution")
        summary.append("3. Establish regular secret rotation policies")
        summary.append("4. Schedule follow-up assessment in 3-6 months")
        
        return "\n".join(summary)
    
    def create_html_report(self, assessment: RiskAssessment, ssh_keys: List[SSHKeyInfo] = None) -> str:
        """Create an HTML report for web viewing."""
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Secrets Footprint Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
                .risk-critical {{ background-color: #ffebee; border-left: 4px solid #f44336; }}
                .risk-high {{ background-color: #fff3e0; border-left: 4px solid #ff9800; }}
                .risk-medium {{ background-color: #fffde7; border-left: 4px solid #ffeb3b; }}
                .risk-low {{ background-color: #e8f5e8; border-left: 4px solid #4caf50; }}
                .metric-box {{ display: inline-block; background: #f8f9fa; padding: 15px; margin: 10px; border-radius: 4px; text-align: center; min-width: 150px; }}
                .metric-value {{ font-size: 2em; font-weight: bold; color: #333; }}
                .metric-label {{ font-size: 0.9em; color: #666; }}
                .chart-container {{ margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 4px; }}
                .finding {{ margin: 10px 0; padding: 10px; border-radius: 4px; }}
                .recommendation {{ margin: 10px 0; padding: 10px; background: #e3f2fd; border-radius: 4px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; font-weight: bold; }}
                .progress-bar {{ width: 100%; height: 20px; background-color: #e0e0e0; border-radius: 10px; overflow: hidden; }}
                .progress-fill {{ height: 100%; transition: width 0.3s ease; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 Secrets Footprint Assessment Report</h1>
                    <p>Generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}</p>
                </div>
                
                {self._generate_html_overview(assessment)}
                {self._generate_html_risk_distribution(assessment)}
                {self._generate_html_findings(assessment)}
                {self._generate_html_recommendations(assessment)}
                {self._generate_html_systems_table(assessment)}
                {self._generate_html_ssh_section(ssh_keys) if ssh_keys else ""}
            </div>
        </body>
        </html>
        """
        return html
    
    def _generate_html_overview(self, assessment: RiskAssessment) -> str:
        """Generate HTML overview section."""
        risk_level = "critical" if assessment.overall_risk_score >= 8.0 else "high" if assessment.overall_risk_score >= 6.0 else "medium" if assessment.overall_risk_score >= 4.0 else "low"
        
        return f"""
        <div class="chart-container">
            <h2>📊 Assessment Overview</h2>
            <div class="metric-box">
                <div class="metric-value">{assessment.total_secrets}</div>
                <div class="metric-label">Total Secrets</div>
            </div>
            <div class="metric-box">
                <div class="metric-value">{assessment.overall_risk_score:.1f}</div>
                <div class="metric-label">Risk Score (0-10)</div>
            </div>
            <div class="metric-box">
                <div class="metric-value">{len(assessment.assessed_systems)}</div>
                <div class="metric-label">Systems Assessed</div>
            </div>
            <div class="metric-box">
                <div class="metric-value">{len(assessment.critical_findings)}</div>
                <div class="metric-label">Critical Findings</div>
            </div>
        </div>
        """
    
    def _generate_html_risk_distribution(self, assessment: RiskAssessment) -> str:
        """Generate HTML risk distribution section."""
        if not assessment.total_secrets:
            return ""
        
        html = ['<div class="chart-container"><h2>📈 Risk Distribution</h2>']
        
        for risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.VERY_LOW]:
            count = assessment.risk_distribution.get(risk_level, 0)
            percentage = (count / assessment.total_secrets) * 100 if assessment.total_secrets > 0 else 0
            
            color_map = {
                RiskLevel.CRITICAL: '#f44336',
                RiskLevel.HIGH: '#ff9800', 
                RiskLevel.MEDIUM: '#ffeb3b',
                RiskLevel.LOW: '#4caf50',
                RiskLevel.VERY_LOW: '#2e7d32'
            }
            
            color = color_map.get(risk_level, '#666')
            level_name = self.risk_level_names.get(risk_level, risk_level.name)
            
            html.append(f"""
            <div style="margin: 10px 0;">
                <div style="display: flex; align-items: center; margin-bottom: 5px;">
                    <span style="width: 100px; font-weight: bold;">{level_name}</span>
                    <span style="width: 60px;">{count} ({percentage:.1f}%)</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {percentage}%; background-color: {color};"></div>
                </div>
            </div>
            """)
        
        html.append('</div>')
        return ''.join(html)
    
    def _generate_html_findings(self, assessment: RiskAssessment) -> str:
        """Generate HTML critical findings section."""
        if not assessment.critical_findings:
            return ""
        
        html = ['<div class="chart-container"><h2>🚨 Critical Findings</h2>']
        
        for i, finding in enumerate(assessment.critical_findings, 1):
            # Determine severity class based on emoji
            severity_class = "risk-critical"
            if "⚠️" in finding:
                severity_class = "risk-high"
            elif "🟡" in finding:
                severity_class = "risk-medium"
            
            html.append(f'<div class="finding {severity_class}"><strong>{i}.</strong> {finding}</div>')
        
        html.append('</div>')
        return ''.join(html)
    
    def _generate_html_recommendations(self, assessment: RiskAssessment) -> str:
        """Generate HTML recommendations section."""
        if not assessment.recommendations:
            return ""
        
        html = ['<div class="chart-container"><h2>💡 Recommendations</h2>']
        
        for i, rec in enumerate(assessment.recommendations, 1):
            html.append(f'<div class="recommendation"><strong>{i}.</strong> {rec}</div>')
        
        html.append('</div>')
        return ''.join(html)
    
    def _generate_html_systems_table(self, assessment: RiskAssessment) -> str:
        """Generate HTML systems table."""
        if not assessment.assessed_systems:
            return ""
        
        html = ['<div class="chart-container"><h2>🏢 Systems Overview</h2><table>']
        html.append('<tr><th>System</th><th>Type</th><th>Risk Score</th><th>Secrets</th><th>Encryption</th><th>Audit Logging</th><th>Auto Rotation</th></tr>')
        
        sorted_systems = sorted(assessment.assessed_systems, key=lambda s: s.risk_score, reverse=True)
        
        for system in sorted_systems:
            risk_class = "risk-critical" if system.risk_score >= 4 else "risk-high" if system.risk_score >= 3 else "risk-medium" if system.risk_score >= 2 else "risk-low"
            
            html.append(f"""
            <tr class="{risk_class}">
                <td>{system.name}</td>
                <td>{system.type.replace('_', ' ').title()}</td>
                <td>{system.risk_score}/5</td>
                <td>{system.secrets_count}</td>
                <td>{'✅' if system.encryption_enabled else '❌'}</td>
                <td>{'✅' if system.audit_logging else '❌'}</td>
                <td>{'✅' if system.auto_rotation else '❌'}</td>
            </tr>
            """)
        
        html.append('</table></div>')
        return ''.join(html)
    
    def _generate_html_ssh_section(self, ssh_keys: List[SSHKeyInfo]) -> str:
        """Generate HTML SSH keys section."""
        if not ssh_keys:
            return ""
        
        html = ['<div class="chart-container"><h2>🔑 SSH Keys Analysis</h2>']
        html.append(f'<p>Found {len(ssh_keys)} SSH keys</p>')
        
        # Create table
        html.append('<table>')
        html.append('<tr><th>File</th><th>Type</th><th>Size</th><th>Passphrase</th><th>Permissions</th><th>Security Score</th></tr>')
        
        for key in ssh_keys:
            security_score = self._calculate_ssh_key_security_score(key)
            security_class = "risk-low" if security_score >= 4 else "risk-medium" if security_score >= 3 else "risk-high" if security_score >= 2 else "risk-critical"
            
            html.append(f"""
            <tr class="{security_class}">
                <td>{Path(key.file_path).name}</td>
                <td>{key.key_type.upper()}</td>
                <td>{key.key_size if key.key_size else 'Unknown'}</td>
                <td>{'✅' if key.has_passphrase else '❌'}</td>
                <td>{key.permissions}</td>
                <td>{self._get_security_level_description(security_score)}</td>
            </tr>
            """)
        
        html.append('</table></div>')
        return ''.join(html)

# 🔍 Secrets Footprint Assessment Tool

An interactive tool that helps organizations assess their "secrets footprint" - the security posture of sensitive credentials and keys across their infrastructure. The tool provides comprehensive analysis, risk scoring, and actionable security recommendations.

## ✨ Features

### 🔑 SSH Key Analysis
- Automatically scans for SSH keys in `~/.ssh/`
- Analyzes key types, sizes, and encryption strength
- Checks file permissions and passphrase protection
- Identifies security issues (weak algorithms, deprecated keys)
- Provides detailed security recommendations

### 🏢 System & Tool Inventory
- **CI/CD Platforms**: GitHub Actions, Jenkins, GitLab CI, Azure DevOps
- **Cloud Providers**: AWS, Google Cloud Platform, Microsoft Azure
- **Secret Managers**: HashiCorp Vault, 1Password, Bitwarden
- **Container Platforms**: Docker, Kubernetes
- **Source Control**: Git repositories (with risk analysis)
- **Databases**: PostgreSQL, MySQL

### ⚡ Risk Assessment Engine
- Calculates comprehensive risk scores (0-10 scale)
- Considers multiple factors:
  - Storage location (git repos = highest risk)
  - Secret type and sensitivity
  - Age and rotation frequency
  - Encryption and access controls
  - Sharing patterns and exposure

### 📊 Reporting & Visualization
- Interactive terminal interface with visual charts
- Executive summaries for management
- Detailed technical reports for security teams
- HTML reports for sharing
- JSON data export for integration

### 🌐 Web Application
- **Complete 4-step workflow**: Start → SSH Analysis → Systems Selection → Assessment Results
- **Interactive risk visualization**: Chart.js powered charts showing risk distribution and secrets analysis
- **Three example environments**: Tech Startup, Enterprise Corporation, and Mixed Environment demos
- **Comprehensive reporting**: HTML, JSON, and Executive summary exports
- **Real-time analysis**: Live SSH key scanning and system configuration
- **Optimized performance**: Cache-based session management for large datasets

**Example Environments:**
1. **🚀 Tech Startup** - Modern cloud-first environment (3 systems, 21 secrets)
2. **🏢 Enterprise Corporation** - Mature security practices (4 systems, 329 secrets)
3. **🔄 Mixed Environment** - Legacy + modern integration (5 systems, 137 secrets)

## 🚀 Quick Start

### Prerequisites
- Python 3.7 or higher
- macOS, Linux, or Windows

### Installation

1. **Clone or download the tool:**
   ```bash
   # If using git
   git clone <repository-url>
   cd secrets-footprint-tool
   
   # Or extract from zip file
   unzip secrets-footprint-tool.zip
   cd secrets-footprint-tool
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the tool:**
   
   **CLI Version (Terminal):**
   ```bash
   python secrets_audit.py
   ```
   
   **Web Version (Browser):**
   ```bash
   python run_webapp.py
   ```
   Then open http://localhost:5000 in your browser

### First Assessment

1. **Start the tool** - Run `python secrets_audit.py`
2. **Select "Start New Assessment"** from the main menu
3. **SSH Key Scan** - Choose to scan your SSH keys (analyzes ~/.ssh/)
4. **System Configuration** - Select systems/tools you use for storing secrets
5. **Review Results** - View comprehensive security assessment
6. **Export Reports** - Generate HTML reports or executive summaries

## 📋 Detailed Usage

### Assessment Process

The tool guides you through a 5-10 minute assessment process:

#### 1. SSH Key Analysis
- Scans `~/.ssh/` directory for private keys
- Analyzes key algorithms (RSA, Ed25519, ECDSA, DSA)
- Checks key sizes and strength
- Verifies file permissions (should be 600)
- Tests for passphrase protection
- Identifies keys loaded in SSH agent

#### 2. System Selection
You'll be asked about systems you use, organized by category:

**CI/CD Systems:**
- Questions about repository secrets, environment variables
- Rotation policies and access controls

**Cloud Providers:**
- Number of IAM users, service accounts
- Use of managed secret services
- Automatic rotation capabilities

**Secret Managers:**
- Vault configuration, policies, dynamic secrets
- Password manager usage and sharing

**Container Platforms:**
- Secret storage methods (environment variables vs. mounted files)
- Encryption and access control settings

#### 3. Risk Calculation
The tool calculates risk scores based on:
- **Location Risk**: Git repos (10/10) > Config files (9/10) > Environment vars (7/10) > Secret managers (2/10)
- **Secret Type Risk**: Encryption keys > Cloud access keys > Database passwords > API keys
- **Age Risk**: Exponential increase for older, never-rotated secrets
- **Security Controls**: Encryption, rotation, access controls provide risk reduction

### Report Types

#### Terminal Summary
- Visual risk distribution with progress bars
- Secrets breakdown by type and location
- Systems overview with security features
- Critical findings and recommendations

#### Executive Summary
- Clean, management-friendly format
- Key metrics and business impact assessment
- Priority actions and next steps
- No technical jargon or emojis

#### HTML Report
- Professional web-based report
- Interactive charts and tables
- Color-coded risk levels
- Shareable via email or web

#### JSON Export
- Raw data for integration with other tools
- Complete assessment results
- Suitable for automation and analysis

## 🔒 Privacy & Security

### 🛡️ Security-Hardened Design
- **ZERO SECRET ACCESS** - Tool is hardened to prevent reading any secret values
- **External tools only** - Uses only system `ssh-keygen` and `ssh-add` commands
- **Path validation** - Comprehensive protection against directory traversal attacks
- **Resource limits** - Bounded file sizes and processing limits prevent abuse

### Local Operation
- **No external network calls** - All analysis happens locally
- **No data transmission** - Nothing sent to external servers
- **Metadata only** - Secret values are never read or stored
- **Offline analysis** - Works completely without internet connection

### SSH Key Analysis (Security-Hardened)
- **Never reads private key content** - Uses only external `ssh-keygen` tool
- **Strict path validation** - Prevents directory traversal and symlink attacks
- **File size limits** - Rejects suspicious files outside normal SSH key bounds
- **No cryptographic libraries** - Cannot accidentally decrypt or expose keys
- **Timeout protection** - All operations have strict time limits

### Attack Prevention
- ✅ **Directory traversal attacks** - Blocked by path validation
- ✅ **Symlink attacks** - Real path resolution prevents link following
- ✅ **Command injection** - Input sanitization blocks malicious filenames
- ✅ **Memory exhaustion** - File size and line count limits
- ✅ **Race conditions** - Single-pass atomic operations only

### Data Storage
All data is stored locally with appropriate permissions:
- `config/assessment_*.json` - Saved assessments
- `reports/secrets_assessment_*.html` - HTML reports
- `reports/secrets_data_*.json` - Raw data exports

## 🎯 Use Cases

### Security Teams
- **Quarterly assessments** to track security improvements
- **Incident response** to quickly assess secret exposure
- **Compliance audits** with detailed documentation
- **Remediation planning** with prioritized recommendations

### DevOps Teams
- **SSH key hygiene** across development environments
- **CI/CD security** assessment and improvement
- **Secret management** strategy evaluation
- **Migration planning** to better secret storage solutions

### Management
- **Risk visibility** with executive summaries
- **Security metrics** for board reporting
- **Budget justification** for security tools
- **Compliance reporting** with detailed assessments

## 📊 Sample Output

```
🔍 SECRETS FOOTPRINT ASSESSMENT SUMMARY
================================================================================

📊 OVERALL STATISTICS
----------------------------------------
Total Secrets Found:     12
Overall Risk Score:      4.3/10.0
Systems Assessed:        5
Risk Level:              🟡 MEDIUM

📈 RISK DISTRIBUTION
----------------------------------------
🚨 Critical    │████░░░░░░░░░░░░░░░░│   2 ( 16.7%)
⚠️  High       │██████░░░░░░░░░░░░░░│   3 ( 25.0%)
🟡 Medium      │████████░░░░░░░░░░░░│   4 ( 33.3%)
🟢 Low         │██████░░░░░░░░░░░░░░│   3 ( 25.0%)

🏢 SYSTEMS OVERVIEW
----------------------------------------
  🚨 Git Repository         Risk: 5/5 │ Secrets:   2 │ ⚪
  ⚠️  Jenkins              Risk: 3/5 │ Secrets:   8 │ 🔐📋
  ✅ HashiCorp Vault       Risk: 1/5 │ Secrets:  15 │ 🔐📋🔄🛡️

🚨 CRITICAL FINDINGS (3)
----------------------------------------
 1. 🚨 2 secrets found in git repositories. This poses a severe security risk...
 2. ⏰ 4 secrets are over 1 year old and never rotated...
 3. 🔓 3 highly sensitive secrets are stored without encryption...

💡 RECOMMENDATIONS (8)
----------------------------------------
 1. 🚨 IMMEDIATE: Review and remediate 2 critical-risk secrets
 2. 📝 Move secrets from git repositories to dedicated secret management systems
 3. 🔐 Enable encryption for 5 unencrypted secrets
 4. 🔄 Implement rotation policies for 7 secrets that are never rotated
```

## ⚠️ Limitations

### SSH Key Analysis
- Only analyzes keys in `~/.ssh/` directory
- Requires `ssh-keygen` command available
- Cannot detect keys embedded in applications

### System Assessment
- Based on user-provided information
- Cannot directly audit remote systems
- Relies on honest self-assessment

### Risk Scoring
- Uses heuristic-based algorithms
- May not reflect all organizational contexts
- Should be combined with professional security assessment

## 🛠️ Development

### Architecture
```
secrets-footprint-tool/
├── src/
│   ├── models.py          # Data models and structures
│   ├── ssh_scanner.py     # SSH key detection and analysis
│   ├── systems.py         # System templates and management
│   ├── risk_engine.py     # Risk scoring algorithms
│   ├── visualizer.py      # Reports and visualization
│   └── cli.py             # Interactive CLI interface
├── config/                # Saved assessments
├── reports/               # Generated reports
├── secrets_audit.py       # Main entry point
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

### Contributing
1. Follow PEP 8 style guidelines
2. Add type hints for new functions
3. Include docstrings for public methods
4. Test on multiple platforms

## 📜 License

MIT License - See LICENSE file for details.

## 🤝 Support

For issues, questions, or contributions:
1. Check existing documentation
2. Review the help system (`python secrets_audit.py` → Help & Information)
3. File issues with detailed information about your environment

## 🏆 Acknowledgments

- Built with security best practices in mind
- Inspired by real-world security assessment needs
- Thanks to the open-source security community

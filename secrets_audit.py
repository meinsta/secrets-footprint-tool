#!/usr/bin/env python3
"""
Secrets Footprint Assessment Tool
A comprehensive tool for analyzing and assessing the security posture of secrets and credentials.

Usage:
    python secrets_audit.py
    
The tool provides an interactive CLI interface that guides users through:
- SSH key security analysis
- System and tool inventory
- Risk assessment and scoring
- Security recommendations
- Report generation

Author: Security Assessment Tool
License: MIT
"""

import sys
import os
from pathlib import Path

# Add src directory to path so we can import modules
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

try:
    from cli import main
    
    if __name__ == "__main__":
        print("🔍 Secrets Footprint Assessment Tool")
        print("=====================================")
        
        # Check Python version
        if sys.version_info < (3, 7):
            print("❌ Python 3.7 or higher is required")
            print(f"   Current version: {sys.version}")
            sys.exit(1)
        
        # Check if we're in the right directory
        if not (Path(__file__).parent / "src").exists():
            print("❌ Please run this script from the secrets-footprint-tool directory")
            sys.exit(1)
        
        # Run the main CLI
        main()

except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Please ensure all required dependencies are installed:")
    print("   pip install -r requirements.txt")
    sys.exit(1)
except Exception as e:
    print(f"❌ Unexpected error: {e}")
    sys.exit(1)

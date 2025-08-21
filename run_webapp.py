#!/usr/bin/env python3
"""
Startup script for the Secrets Footprint Assessment Web Application.

Usage:
    python run_webapp.py
    
This starts the Flask web application on http://localhost:5000
"""

import sys
import os
from pathlib import Path

# Add webapp directory to path
webapp_path = Path(__file__).parent / "webapp"
sys.path.insert(0, str(webapp_path))

try:
    from app import app
    
    if __name__ == "__main__":
        print("🌐 Starting Secrets Footprint Assessment Web Application")
        print("=" * 60)
        print("Access the application at: http://localhost:5000")
        print("Press Ctrl+C to stop the server")
        print("=" * 60)
        
        # Check if we have the required dependencies
        try:
            import flask
        except ImportError:
            print("❌ Flask not found. Please install dependencies:")
            print("   pip install -r requirements.txt")
            sys.exit(1)
        
        # Run the Flask app
        app.run(
            debug=True,
            host='0.0.0.0', 
            port=5000,
            use_reloader=True
        )

except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Please ensure all required dependencies are installed:")
    print("   pip install -r requirements.txt")
    sys.exit(1)
except Exception as e:
    print(f"❌ Startup error: {e}")
    sys.exit(1)

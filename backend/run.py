#!/usr/bin/env python3
"""
EnCodeLab Crypto Backend Runner
Run this script to start the Flask development server
"""

import os
from app import app
from config import config

def main():
    """Main function to run the Flask app"""
    # Get configuration from environment or default to development
    config_name = os.environ.get('FLASK_ENV', 'development')
    app_config = config.get(config_name, config['default'])
    
    # Apply configuration
    app.config.from_object(app_config)
    
    # Run the application
    print(f"🚀 Starting EnCodeLab Crypto Backend in {config_name} mode...")
    print(f"📡 Server will be available at: http://localhost:5000")
    print(f"🔐 Supported modes: CBC, CFB, OFB, CTR, GCM, ECB")
    print(f"📝 Supported encodings: HEX, Base64, UTF-8")
    print(f"🔑 Key sizes: 16, 24, or 32 bytes (AES-128, AES-192, AES-256)")
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=app_config.DEBUG
    )

if __name__ == '__main__':
    main() 
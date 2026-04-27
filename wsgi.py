# wsgi.py - Production entry point
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from app import create_app
from __init__ import socketio

# Create application
app = create_app(os.environ.get('FLASK_CONFIG', 'production'))

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8000)
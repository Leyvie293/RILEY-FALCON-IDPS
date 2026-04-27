# app.py - Production entry point for Render ONLY
# This file is specifically for Gunicorn on Render
# Your local development still uses run.py

from __init__ import create_app, socketio

# Create the application with production config
# This matches what you have in run.py but for production
app = create_app()

# For Gunicorn with SocketIO support
# The 'app' variable is what Gunicorn looks for

# Note: We don't call socketio.run() here because Gunicorn handles that
# SocketIO is initialized in __init__.py and will work with eventlet worker
# app.py - Production entry point for Gunicorn on Render
from __init__ import create_app

# Create the Flask application instance
# This MUST be named 'app' for Gunicorn to find it by default
app = create_app()

# For Gunicorn - the variable name 'app' is what Gunicorn looks for
# No socketio.run() here - Gunicorn handles the server
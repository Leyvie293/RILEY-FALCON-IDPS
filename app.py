# app.py - Entry point for Gunicorn on Render
from __init__ import create_app, socketio

# Create the application instance
app = create_app()

# For Gunicorn to work with SocketIO
# This makes the app compatible with SocketIO running under Gunicorn
if __name__ != '__main__':
    # When running under Gunicorn, we need to ensure socketio is initialized
    socketio.init_app(app)

# The 'app' variable is what Gunicorn looks for
# SocketIO will be handled by the eventlet worker
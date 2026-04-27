# __init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO
from config import Config
import os

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
socketio = SocketIO()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(Config)
    
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(app)
    
    login_manager.login_view = 'login'
    login_manager.login_message_category = 'info'
    
    from routes import init_routes
    from utils.ai_engine import AIEngine
    from utils.alert_manager import AlertManager
    
    # Initialize AI Engine
    app.ai_engine = AIEngine()
    
    # Initialize Alert Manager
    app.alert_manager = AlertManager()
    
    # Register routes
    init_routes(app)
    
    with app.app_context():
        db.create_all()
    
    return app
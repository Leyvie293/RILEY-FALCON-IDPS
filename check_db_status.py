import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import using the correct structure
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_socketio import SocketIO
from flask_bcrypt import Bcrypt
from flask_mail import Mail

# Create app context
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///riley_falcon.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Import models after db is created
from models import NetworkTraffic, Alert, HostActivity, User

with app.app_context():
    print("=" * 60)
    print("DATABASE STATUS REPORT")
    print("=" * 60)
    
    network_count = NetworkTraffic.query.count()
    alert_count = Alert.query.count()
    host_count = HostActivity.query.count()
    user_count = User.query.count()
    
    print(f"\n📊 Network Traffic Records: {network_count}")
    print(f"⚠️ Alert Records: {alert_count}")
    print(f"🖥️ Host Activity Records: {host_count}")
    print(f"👤 User Records: {user_count}")
    
    if network_count == 0 and alert_count == 0 and host_count == 0:
        print("\n⚠️ No data found in database!")
        print("   You need to:")
        print("   1. Start network capture in the web interface")
        print("   2. Or generate test data")

# models.py - PRODUCTION READY
from __init__ import db, login_manager
from flask_login import UserMixin
from datetime import datetime, timedelta
import pytz
import json
import secrets
from werkzeug.security import generate_password_hash, check_password_hash

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    role = db.Column(db.String(20), default='staff', index=True)
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    verified_at = db.Column(db.DateTime)
    last_login = db.Column(db.DateTime)
    last_login_ip = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    phone_number = db.Column(db.String(15))
    department = db.Column(db.String(50))
    
    # Security fields
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    password_history = db.Column(db.Text)  # JSON array of previous password hashes
    
    # MFA fields
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret = db.Column(db.String(32))
    mfa_backup_codes = db.Column(db.Text)  # JSON array of backup codes
    
    # API access
    api_key = db.Column(db.String(64), unique=True)
    api_key_created = db.Column(db.DateTime)
    api_key_last_used = db.Column(db.DateTime)
    api_rate_limit = db.Column(db.Integer, default=100)  # requests per hour
    
    # Security questions
    security_question_1 = db.Column(db.String(50))
    security_answer_hash_1 = db.Column(db.String(128))
    security_question_2 = db.Column(db.String(50))
    security_answer_hash_2 = db.Column(db.String(128))
    
    # Relationships
    alerts = db.relationship('Alert', backref='user', lazy='dynamic')
    actions = db.relationship('UserAction', backref='user', lazy='dynamic')
    reset_tokens = db.relationship('PasswordResetToken', backref='user', lazy='dynamic')
    reports = db.relationship('Report', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        """Set password with history tracking"""
        # Check if password was used before
        if self.password_history:
            old_hashes = json.loads(self.password_history)
            for old_hash in old_hashes[-5:]:  # Check last 5 passwords
                if check_password_hash(old_hash, password):
                    raise ValueError("Password has been used recently. Please choose a different password.")
        
        # Hash new password
        new_hash = generate_password_hash(password)
        
        # Update password history
        history = json.loads(self.password_history) if self.password_history else []
        if self.password_hash:
            history.append(self.password_hash)
        self.password_history = json.dumps(history[-10:])  # Keep last 10 passwords
        
        self.password_hash = new_hash
        self.password_changed_at = datetime.utcnow()
    
    def check_password(self, password):
        """Verify password"""
        return check_password_hash(self.password_hash, password)
    
    def is_locked(self):
        """Check if account is locked"""
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False
    
    def record_failed_login(self):
        """Record failed login attempt"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.locked_until = datetime.utcnow() + timedelta(minutes=15)
        db.session.commit()
    
    def record_successful_login(self, ip_address):
        """Record successful login"""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login = datetime.utcnow()
        self.last_login_ip = ip_address
        db.session.commit()
    
    def generate_api_key(self):
        """Generate new API key"""
        self.api_key = secrets.token_urlsafe(32)
        self.api_key_created = datetime.utcnow()
        db.session.commit()
        return self.api_key
    
    def get_eat_time(self):
        """Get current time in East Africa Time"""
        utc_time = datetime.utcnow()
        eat_tz = pytz.timezone('Africa/Nairobi')
        return utc_time.replace(tzinfo=pytz.UTC).astimezone(eat_tz)
    
    def is_admin(self):
        """Check if user is admin"""
        return self.role == 'admin'
    
    def has_permission(self, permission):
        """Check user permissions"""
        permissions = {
            'admin': ['read', 'write', 'delete', 'admin'],
            'security': ['read', 'write', 'resolve_alerts'],
            'analyst': ['read', 'write'],
            'staff': ['read']
        }
        return permission in permissions.get(self.role, [])
    
    def __repr__(self):
        return f'<User {self.username}>'

class NetworkTraffic(db.Model):
    __tablename__ = 'network_traffic'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(45), index=True)
    destination_ip = db.Column(db.String(45), index=True)
    protocol = db.Column(db.String(10), index=True)
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer, index=True)
    packet_size = db.Column(db.Integer)
    flags = db.Column(db.String(50))
    info = db.Column(db.Text)
    is_suspicious = db.Column(db.Boolean, default=False, index=True)
    anomaly_score = db.Column(db.Float, default=0.0)
    
    # Additional metadata
    interface = db.Column(db.String(50))
    wifi_ssid = db.Column(db.String(100))
    direction = db.Column(db.String(10))  # ingress/egress
    
    # Threat intelligence
    threat_type = db.Column(db.String(50))
    threat_signature_id = db.Column(db.Integer, db.ForeignKey('signatures.id'))
    
    def __repr__(self):
        return f'<NetworkTraffic {self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port}>'

class HostActivity(db.Model):
    __tablename__ = 'host_activity'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    hostname = db.Column(db.String(100), index=True)
    process_name = db.Column(db.String(200), index=True)
    process_id = db.Column(db.Integer)
    cpu_usage = db.Column(db.Float)
    memory_usage = db.Column(db.Float)
    network_connections = db.Column(db.Integer)
    open_files = db.Column(db.Integer)
    user = db.Column(db.String(50), index=True)
    is_suspicious = db.Column(db.Boolean, default=False, index=True)
    
    # Additional process details
    process_path = db.Column(db.String(500))
    command_line = db.Column(db.Text)
    parent_process_id = db.Column(db.Integer)
    parent_process_name = db.Column(db.String(200))
    
    def __repr__(self):
        return f'<HostActivity {self.process_name} (PID: {self.process_id})>'

class Alert(db.Model):
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    alert_type = db.Column(db.String(50), index=True)
    severity = db.Column(db.String(20), index=True)
    source = db.Column(db.String(50), index=True)
    description = db.Column(db.Text)
    details = db.Column(db.Text)
    is_resolved = db.Column(db.Boolean, default=False, index=True)
    resolved_at = db.Column(db.DateTime)
    resolved_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Additional fields
    mitre_tactic = db.Column(db.String(100))
    mitre_technique = db.Column(db.String(100))
    cvss_score = db.Column(db.Float)
    notification_sent = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<Alert {self.severity}: {self.description[:50]}>'

class Signature(db.Model):
    __tablename__ = 'signatures'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    pattern = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), index=True)
    severity = db.Column(db.String(20), index=True)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True, index=True)
    
    # MITRE ATT&CK mapping
    mitre_id = db.Column(db.String(20))
    mitre_tactic = db.Column(db.String(100))
    mitre_technique = db.Column(db.String(100))
    
    def __repr__(self):
        return f'<Signature {self.name}>'

class UserAction(db.Model):
    __tablename__ = 'user_actions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    action = db.Column(db.String(100), index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    details = db.Column(db.Text)
    
    # Audit fields
    category = db.Column(db.String(50), index=True)
    severity = db.Column(db.String(20), default='info')
    resource_type = db.Column(db.String(50))
    resource_id = db.Column(db.Integer)
    
    def __repr__(self):
        return f'<UserAction {self.user_id}: {self.action}>'

class Report(db.Model):
    __tablename__ = 'reports'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    type = db.Column(db.String(50), index=True)
    format = db.Column(db.String(10))
    generated_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    generated_by = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    file_path = db.Column(db.String(500))
    file_size = db.Column(db.Integer)  # Size in bytes
    date_range_start = db.Column(db.DateTime)
    date_range_end = db.Column(db.DateTime)
    
    # Additional fields
    parameters = db.Column(db.Text)  # JSON of report parameters
    download_count = db.Column(db.Integer, default=0)
    last_downloaded = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<Report {self.name}>'

class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    token = db.Column(db.String(200), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False, index=True)
    
    @property
    def is_expired(self):
        return datetime.utcnow() > self.expires_at
    
    def __repr__(self):
        return f'<PasswordResetToken user={self.user_id}>'

class LoginAttempt(db.Model):
    __tablename__ = 'login_attempts'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), index=True)
    ip_address = db.Column(db.String(45), index=True)
    user_agent = db.Column(db.String(500))
    success = db.Column(db.Boolean, default=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f'<LoginAttempt {self.email} success={self.success}>'

class SystemConfig(db.Model):
    __tablename__ = 'system_config'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False, index=True)
    value = db.Column(db.Text)
    description = db.Column(db.String(500))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    def __repr__(self):
        return f'<SystemConfig {self.key}>'

class DataRetentionPolicy(db.Model):
    __tablename__ = 'data_retention_policies'
    
    id = db.Column(db.Integer, primary_key=True)
    table_name = db.Column(db.String(100), unique=True, nullable=False, index=True)
    retention_days = db.Column(db.Integer, nullable=False, default=30)
    last_cleanup = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<DataRetentionPolicy {self.table_name}: {self.retention_days} days>'

class APIToken(db.Model):
    __tablename__ = 'api_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    permissions = db.Column(db.String(20), default='read')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    last_used = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    @property
    def is_expired(self):
        if self.expires_at:
            return datetime.utcnow() > self.expires_at
        return False
    
    def __repr__(self):
        return f'<APIToken {self.name} for user {self.user_id}>'
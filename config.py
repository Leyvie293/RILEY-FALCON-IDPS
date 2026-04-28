# config.py - FIXED VERSION
import os
from datetime import timedelta
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent

class Config:
    """Base configuration"""
    
    # ==========================================================================
    # SECURITY - CRITICAL
    # ==========================================================================
    
    # Secret key
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'riley-falcon-security-secret-key-2024'
    
    # Security headers
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_SECURE = os.environ.get('REMEMBER_COOKIE_SECURE', 'False').lower() == 'true'
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_DURATION = timedelta(days=int(os.environ.get('REMEMBER_COOKIE_DAYS', 14)))
    PERMANENT_SESSION_LIFETIME = timedelta(hours=int(os.environ.get('SESSION_LIFETIME_HOURS', 2)))
    
    # CSRF Protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    
    # Password security
    BCRYPT_LOG_ROUNDS = int(os.environ.get('BCRYPT_ROUNDS', 13))
    
    # Account lockout
    MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', 5))
    LOCKOUT_DURATION = timedelta(minutes=int(os.environ.get('LOCKOUT_MINUTES', 15)))
    
    # ==========================================================================
    # DATABASE - FIXED: No property decorator
    # ==========================================================================
    
    # Get database URL from environment or use SQLite default
    _DATABASE_URL = os.environ.get('DATABASE_URL')
    
    if _DATABASE_URL:
        # Handle Heroku-style postgres URLs
        if _DATABASE_URL.startswith('postgres://'):
            _DATABASE_URL = _DATABASE_URL.replace('postgres://', 'postgresql://', 1)
        SQLALCHEMY_DATABASE_URI = _DATABASE_URL
    else:
        # Default to SQLite for development
        db_path = BASE_DIR / 'database.db'
        SQLALCHEMY_DATABASE_URI = f'sqlite:///{db_path}'
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Connection pooling (only for PostgreSQL)
    if 'postgresql' in SQLALCHEMY_DATABASE_URI:
        SQLALCHEMY_ENGINE_OPTIONS = {
            'pool_size': int(os.environ.get('DB_POOL_SIZE', 10)),
            'pool_recycle': int(os.environ.get('DB_POOL_RECYCLE', 3600)),
            'pool_pre_ping': True,
            'max_overflow': int(os.environ.get('DB_MAX_OVERFLOW', 20))
        }
    else:
        SQLALCHEMY_ENGINE_OPTIONS = {}
    
    # ==========================================================================
    # REDIS & CACHING (Optional)
    # ==========================================================================
    
    REDIS_URL = os.environ.get('REDIS_URL')
    CACHE_TYPE = 'redis' if REDIS_URL else 'simple'
    CACHE_REDIS_URL = REDIS_URL
    CACHE_DEFAULT_TIMEOUT = int(os.environ.get('CACHE_TIMEOUT', 300))
    
    # Rate Limiting (will use memory if Redis not available)
    RATELIMIT_STORAGE_URL = REDIS_URL or 'memory://'
    RATELIMIT_DEFAULT = os.environ.get('RATELIMIT_DEFAULT', '200 per hour')
    RATELIMIT_STRATEGY = 'fixed-window'
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_ENABLED = os.environ.get('RATELIMIT_ENABLED', 'False').lower() == 'true'
    
    # ==========================================================================
    # EMAIL CONFIGURATION
    # ==========================================================================
    
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'False').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or 'security@rileyfalcon.com'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'your-app-password'
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', ('Riley Falcon IDPS', 'security@rileyfalcon.com'))
    MAIL_MAX_EMAILS = int(os.environ.get('MAIL_MAX_EMAILS', 50))
    
    # ==========================================================================
    # MONITORING CONFIGURATIONS
    # ==========================================================================
    
    NETWORK_INTERFACE = os.environ.get('NETWORK_INTERFACE', 'eth0')
    PACKET_CAPTURE_LIMIT = int(os.environ.get('PACKET_CAPTURE_LIMIT', 10000))
    CAPTURE_BATCH_SIZE = int(os.environ.get('CAPTURE_BATCH_SIZE', 100))
    
    HOST_MONITOR_INTERVAL = int(os.environ.get('HOST_MONITOR_INTERVAL', 3))
    PROCESS_HISTORY_LIMIT = int(os.environ.get('PROCESS_HISTORY_LIMIT', 1000))
    
    ANOMALY_THRESHOLD = float(os.environ.get('ANOMALY_THRESHOLD', 0.85))
    AI_MODEL_PATH = os.environ.get('AI_MODEL_PATH', str(BASE_DIR / 'models'))
    
    # ==========================================================================
    # DATA RETENTION
    # ==========================================================================
    
    RETENTION_DAYS = {
        'network_traffic': int(os.environ.get('RETENTION_NETWORK_DAYS', 30)),
        'host_activities': int(os.environ.get('RETENTION_HOST_DAYS', 30)),
        'alerts': int(os.environ.get('RETENTION_ALERTS_DAYS', 90)),
        'audit_logs': int(os.environ.get('RETENTION_AUDIT_DAYS', 365))
    }
    
    # ==========================================================================
    # TIMEZONE & LOCALIZATION
    # ==========================================================================
    
    TIMEZONE = os.environ.get('TIMEZONE', 'Africa/Nairobi')
    
    # ==========================================================================
    # LOGGING
    # ==========================================================================
    
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', str(BASE_DIR / 'logs' / 'app.log'))
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # ==========================================================================
    # WEBHOOKS & INTEGRATIONS
    # ==========================================================================
    
    SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL')
    TEAMS_WEBHOOK_URL = os.environ.get('TEAMS_WEBHOOK_URL')
    
    # ==========================================================================
    # FEATURE FLAGS
    # ==========================================================================
    
    ENABLE_MFA = os.environ.get('ENABLE_MFA', 'False').lower() == 'true'
    ENABLE_API_ACCESS = os.environ.get('ENABLE_API_ACCESS', 'True').lower() == 'true'
    ENABLE_AUTO_CLEANUP = os.environ.get('ENABLE_AUTO_CLEANUP', 'True').lower() == 'true'
    
    # ==========================================================================
    # SOCKET.IO
    # ==========================================================================
    
    SOCKETIO_MESSAGE_QUEUE = REDIS_URL
    SOCKETIO_PING_TIMEOUT = int(os.environ.get('SOCKETIO_PING_TIMEOUT', 60))
    SOCKETIO_PING_INTERVAL = int(os.environ.get('SOCKETIO_PING_INTERVAL', 25))


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    
    # Disable security for development
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False
    RATELIMIT_ENABLED = False
    
    # Use SQLite for development (simple)
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{BASE_DIR}/database.db'
    SQLALCHEMY_ENGINE_OPTIONS = {}
    
    # Development logging
    LOG_LEVEL = 'DEBUG'
    LOG_FILE = str(BASE_DIR / 'logs' / 'dev.log')
    
    # Development features
    ENABLE_MFA = False
    ENABLE_API_ACCESS = True


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = False
    
    # Use in-memory database for tests
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_ENGINE_OPTIONS = {}
    
    # Disable security for tests
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False
    RATELIMIT_ENABLED = False
    
    # Disable email for tests
    MAIL_SUPPRESS_SEND = True
    
    ENABLE_MFA = False
    ENABLE_API_ACCESS = True


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    
    # Enforce security
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    WTF_CSRF_ENABLED = True
    RATELIMIT_ENABLED = True
    
    # Production logging
    LOG_LEVEL = 'INFO'
    
    # Validate required settings
    @classmethod
    def init_app(cls, app):
        """Production-specific initialization"""
        # Ensure secret key is set
        if not os.environ.get('SECRET_KEY'):
            raise ValueError("SECRET_KEY must be set in production environment")
        
        # Ensure database URL is set
        if not os.environ.get('DATABASE_URL'):
            raise ValueError("DATABASE_URL must be set in production environment")
        
        # Ensure mail credentials are set
        if not os.environ.get('MAIL_USERNAME') or not os.environ.get('MAIL_PASSWORD'):
            app.logger.warning("Email credentials not set. Email alerts will not work.")


class StagingConfig(ProductionConfig):
    """Staging configuration"""
    DEBUG = True
    TESTING = False
    ENABLE_MFA = False


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'staging': StagingConfig,
    'default': DevelopmentConfig
}


def get_config():
    """Get configuration based on environment"""
    config_name = os.environ.get('FLASK_CONFIG', 'default')
    return config.get(config_name, DevelopmentConfig)
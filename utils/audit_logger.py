# utils/audit_logger.py
import logging
import json
from datetime import datetime
from flask import request, session
from functools import wraps
from models import UserAction, db

logger = logging.getLogger(__name__)

class AuditLogger:
    """Structured audit logging"""
    
    @staticmethod
    def log_action(user_id, action, category, details=None, ip_address=None, severity='info'):
        """Log an audit event"""
        try:
            audit_entry = UserAction(
                user_id=user_id,
                action=action,
                ip_address=ip_address or request.remote_addr,
                details=json.dumps({
                    'category': category,
                    'severity': severity,
                    'details': details,
                    'user_agent': request.user_agent.string if request else None,
                    'timestamp': datetime.utcnow().isoformat()
                })
            )
            db.session.add(audit_entry)
            db.session.commit()
            
            # Also log to file for security
            logger.info(f"AUDIT: user={user_id} action={action} ip={ip_address} details={details}")
            
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
    
    @staticmethod
    def audit_route(category, action_name=None):
        """Decorator to automatically audit routes"""
        def decorator(f):
            @wraps(f)
            def wrapped(*args, **kwargs):
                result = f(*args, **kwargs)
                
                if hasattr(request, 'user') and request.user:
                    action = action_name or f"{request.method} {request.endpoint}"
                    AuditLogger.log_action(
                        user_id=request.user.id,
                        action=action,
                        category=category,
                        ip_address=request.remote_addr
                    )
                
                return result
            return wrapped
        return decorator
# utils/__init__.py
"""
Utility modules for Riley Falcon IDPS
Contains all monitoring, detection, and reporting utilities
"""

from utils.ai_engine import AIEngine
from utils.alert_manager import AlertManager
from utils.network_monitor import NetworkMonitor
from utils.host_monitor import HostMonitor
from utils.report_generator import ReportGenerator
from utils.signature_detection import SignatureModel
from utils.anomalymodel import AnomalyModel
from utils.email_utils import EmailNotifier

__all__ = [
    'AIEngine',
    'AlertManager', 
    'NetworkMonitor',
    'HostMonitor',
    'ReportGenerator',
    'SignatureModel',
    'AnomalyModel',
    'EmailNotifier'
]

__version__ = '1.0.0'
__author__ = 'Riley Falcon Security Services IT Department'
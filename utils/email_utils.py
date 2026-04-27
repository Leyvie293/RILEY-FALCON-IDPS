# utils/email_utils.py
"""
Email notification utilities for IDPS
Handles sending alerts and reports via email
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import threading
import queue
from datetime import datetime
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EmailNotifier:
    def __init__(self):
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        self.sender_email = "security@rileyfalconsecurity.co.ke"
        self.sender_password = os.environ.get('EMAIL_PASSWORD', 'your-app-password')
        self.admin_emails = [
            "it-admin@rileyfalconsecurity.co.ke",
            "security-team@rileyfalconsecurity.co.ke",
            "soc@rileyfalconsecurity.co.ke"
        ]
        self.enabled = True
        self.email_queue = queue.Queue()
        self._start_worker()
        
    def _start_worker(self):
        """Start background thread to send emails"""
        def worker():
            while True:
                try:
                    email_data = self.email_queue.get(timeout=5)
                    self._send_email_sync(email_data)
                except queue.Empty:
                    continue
                except Exception as e:
                    logger.error(f"Email worker error: {e}")
        
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        logger.info("Email notifier initialized")
    
    def send_alert(self, alert):
        """Queue alert email for sending"""
        if not self.enabled:
            return
        
        subject = f"[{alert.severity.upper()}] Riley Falcon IDPS Alert - {alert.alert_type}"
        
        severity_colors = {
            'critical': '#e74a3b',
            'high': '#f6c23e',
            'medium': '#36b9cc',
            'low': '#1cc88a'
        }
        
        body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                .header {{ background-color: #4e73df; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; }}
                .alert-box {{ 
                    background-color: {severity_colors.get(alert.severity, '#858796')}; 
                    color: white; 
                    padding: 15px; 
                    border-radius: 5px;
                    margin-bottom: 20px;
                }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f8f9fc; }}
                .footer {{ margin-top: 30px; font-size: 12px; color: #666; text-align: center; }}
                .button {{
                    background-color: #4e73df;
                    border: none;
                    color: white;
                    padding: 10px 20px;
                    text-align: center;
                    text-decoration: none;
                    display: inline-block;
                    font-size: 14px;
                    margin: 4px 2px;
                    cursor: pointer;
                    border-radius: 5px;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>🛡️ Riley Falcon Security Services</h2>
                <h3>Intrusion Detection & Prevention System</h3>
            </div>
            
            <div class="content">
                <div class="alert-box">
                    <h3>⚠️ {alert.severity.upper()} SECURITY ALERT</h3>
                    <p>{alert.description}</p>
                </div>
                
                <table>
                    <tr>
                        <th>Alert Type</th>
                        <td>{alert.alert_type}</td>
                    </tr>
                    <tr>
                        <th>Severity</th>
                        <td>{alert.severity.upper()}</td>
                    </tr>
                    <tr>
                        <th>Source</th>
                        <td>{alert.source}</td>
                    </tr>
                    <tr>
                        <th>Time (EAT)</th>
                        <td>{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}</td>
                    </tr>
                    <tr>
                        <th>Description</th>
                        <td>{alert.description}</td>
                    </tr>
                    <tr>
                        <th>Details</th>
                        <td><pre style="background: #f4f4f4; padding: 10px; border-radius: 5px;">{alert.details}</pre></td>
                    </tr>
                </table>
                
                <div style="margin-top: 30px; text-align: center;">
                    <a href="http://localhost:5000/alerts" class="button" style="background-color: #4e73df;">View Dashboard</a>
                    <a href="http://localhost:5000/resolve_alert/{alert.id}" class="button" style="background-color: #1cc88a;">Resolve Alert</a>
                </div>
                
                <div style="margin-top: 30px; padding: 20px; background-color: #f8f9fc; border-radius: 5px;">
                    <h4>Recommended Actions:</h4>
                    <ul>
                        <li>Immediately investigate the affected systems</li>
                        <li>Isolate compromised systems if necessary</li>
                        <li>Check the IDPS dashboard for more details</li>
                        <li>Document the incident in the security log</li>
                        <li>Notify relevant team members</li>
                    </ul>
                </div>
            </div>
            
            <div class="footer">
                <p>This is an automated message from the Riley Falcon IDPS. Do not reply to this email.</p>
                <p>© 2024 Riley Falcon Security Services - IT Department | East Africa Time</p>
            </div>
        </body>
        </html>
        """
        
        email_data = {
            'to_emails': self.admin_emails,
            'subject': subject,
            'body': body,
            'is_html': True,
            'priority': 'high' if alert.severity in ['critical', 'high'] else 'normal'
        }
        
        self.email_queue.put(email_data)
        logger.info(f"Alert email queued: {alert.severity} - {alert.description[:50]}")
    
    def send_report(self, report_path, report_name, recipient_emails=None):
        """Send report via email with attachment"""
        if not self.enabled:
            return
        
        if recipient_emails is None:
            recipient_emails = self.admin_emails
        
        subject = f"Riley Falcon IDPS Report - {report_name}"
        
        # Get file size
        file_size = os.path.getsize(report_path) / (1024 * 1024)  # MB
        
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <h2 style="color: #4e73df;">Riley Falcon Security Services</h2>
            <h3>IDPS Security Report</h3>
            
            <p>Please find attached the requested security report:</p>
            
            <table style="border: 1px solid #ddd; padding: 10px; margin: 10px 0;">
                <tr>
                    <td><strong>Report Name:</strong></td>
                    <td>{report_name}</td>
                </tr>
                <tr>
                    <td><strong>Generated:</strong></td>
                    <td>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} (EAT)</td>
                </tr>
                <tr>
                    <td><strong>File Size:</strong></td>
                    <td>{file_size:.2f} MB</td>
                </tr>
                <tr>
                    <td><strong>Format:</strong></td>
                    <td>{os.path.splitext(report_path)[1].upper()}</td>
                </tr>
            </table>
            
            <p>The report contains detailed information about security events, 
            network traffic analysis, and host activities during the specified period.</p>
            
            <hr>
            <p><small>This is an automated message from the Riley Falcon IDPS. 
            For support, contact the IT Department.</small></p>
        </body>
        </html>
        """
        
        email_data = {
            'to_emails': recipient_emails,
            'subject': subject,
            'body': body,
            'is_html': True,
            'attachment': report_path
        }
        
        self.email_queue.put(email_data)
        logger.info(f"Report email queued: {report_name}")
    
    def _send_email_sync(self, email_data):
        """Synchronously send email"""
        try:
            msg = MIMEMultipart('alternative')
            msg['From'] = self.sender_email
            msg['To'] = ', '.join(email_data['to_emails'])
            msg['Subject'] = email_data['subject']
            
            # Add priority header if specified
            if email_data.get('priority') == 'high':
                msg['X-Priority'] = '1'
                msg['X-MSMail-Priority'] = 'High'
            
            # Attach body
            if email_data.get('is_html', False):
                part = MIMEText(email_data['body'], 'html')
            else:
                part = MIMEText(email_data['body'], 'plain')
            msg.attach(part)
            
            # Attach file if present
            if 'attachment' in email_data:
                with open(email_data['attachment'], 'rb') as f:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(f.read())
                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename="{os.path.basename(email_data["attachment"])}"'
                    )
                    msg.attach(part)
            
            # Send email
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.sender_email, self.sender_password)
            server.send_message(msg)
            server.quit()
            
            logger.info(f"✅ Email sent successfully to {len(email_data['to_emails'])} recipients")
            
        except Exception as e:
            logger.error(f"❌ Failed to send email: {e}")
    
    def test_connection(self):
        """Test email server connection"""
        try:
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.sender_email, self.sender_password)
            server.quit()
            return True, "Email server connection successful"
        except Exception as e:
            return False, str(e)
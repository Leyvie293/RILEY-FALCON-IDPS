# routes.py
from flask import render_template, redirect, url_for, flash, request, jsonify, send_file
from flask_login import login_user, current_user, logout_user, login_required
from __init__ import db, bcrypt, socketio, mail
from models import User, Alert, NetworkTraffic, HostActivity, Report, UserAction, PasswordResetToken
from forms import LoginForm, RegistrationForm, UpdateProfileForm, ReportForm, ForgotPasswordForm, ResetPasswordForm
from utils.report_generator import ComprehensiveReportGenerator as ReportGenerator
from utils.network_monitor import NetworkMonitor, set_broadcast_function as set_network_broadcast
from utils.host_monitor import HostMonitor, set_broadcast_function as set_host_broadcast
from utils.ai_engine import AIEngine
from utils.alert_manager import AlertManager, set_broadcast_function as set_alert_broadcast
from flask_socketio import emit
from datetime import datetime, timedelta
import pytz
import json
import os
import secrets
import csv
import tempfile
import subprocess
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from sqlalchemy import func

EAT = pytz.timezone('Africa/Nairobi')

# Password reset serializer
serializer = URLSafeTimedSerializer(os.environ.get('SECRET_KEY') or 'riley-falcon-security-secret-key-2024')

# Initialize monitors (will be fully initialized when app starts)
network_monitor = None
host_monitor = None
ai_engine = None
alert_manager = None

def register_routes(app):
    global network_monitor, host_monitor, ai_engine, alert_manager
    
    # Define broadcast function for real-time alerts
    def broadcast_new_alert(alert):
        """Broadcast new alert to all connected clients"""
        socketio.emit('new_alert', {
            'id': alert.id,
            'severity': alert.severity,
            'description': alert.description,
            'timestamp': alert.timestamp.strftime('%H:%M:%S'),
            'source': alert.source,
            'type': alert.alert_type,
            'details': alert.details
        })
        
        # Also update threat data
        emit_threat_update()
    
    def emit_threat_update():
        """Emit threat statistics to all connected clients"""
        try:
            last_24h = datetime.utcnow() - timedelta(hours=24)
            threats = db.session.query(
                Alert.description,
                db.func.count(Alert.id).label('count')
            ).filter(
                Alert.timestamp > last_24h
            ).group_by(
                Alert.description
            ).order_by(
                db.func.count(Alert.id).desc()
            ).limit(5).all()
            
            threat_list = [{'type': t[0], 'count': t[1]} for t in threats]
            socketio.emit('threat_update', {'threats': threat_list})
        except Exception as e:
            print(f"Error emitting threat update: {e}")
    
    @app.before_request
    def initialize_monitors_once():
        """Initialize monitoring components before first request"""
        global ai_engine, alert_manager, network_monitor, host_monitor
        if ai_engine is None:  # Only initialize once
            try:
                ai_engine = AIEngine()
                alert_manager = AlertManager()
                network_monitor = NetworkMonitor(ai_engine, alert_manager)
                host_monitor = HostMonitor(alert_manager)
                
                # CRITICAL: Set Flask app context for database operations in background threads
                network_monitor.set_app_context(app)
                host_monitor.set_app_context(app)
                
                # Set broadcast functions
                set_network_broadcast(broadcast_new_alert)
                set_host_broadcast(broadcast_new_alert)
                set_alert_broadcast(broadcast_new_alert)
                
                # Auto-start host monitoring
                if host_monitor:
                    host_monitor.start_monitoring(interval=3)
                    print("🖥️ Host monitoring auto-started")
                
                print("✅ Monitoring systems initialized with real-time alerts")
                print("📡 Network monitor ready - start capture from web interface")
                print("🖥️ Host monitor running - monitoring system processes")
            except Exception as e:
                print(f"⚠️ Error initializing monitors: {e}")
    
    @app.route('/')
    @app.route('/index')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
                login_user(user, remember=form.remember.data)
                user.last_login = datetime.utcnow()
                
                action = UserAction(
                    user_id=user.id,
                    action='Login',
                    ip_address=request.remote_addr,
                    details='User logged in successfully'
                )
                db.session.add(action)
                db.session.commit()
                
                flash('Login successful!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
            else:
                flash('Login unsuccessful. Please check email and password.', 'danger')
        
        return render_template('login.html', form=form, title='Login')

    @app.route('/forgot-password', methods=['GET', 'POST'])
    def forgot_password():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        
        form = ForgotPasswordForm()
        
        if form.validate_on_submit():
            email = form.email.data
            user = User.query.filter_by(email=email).first()
            
            if user:
                # Generate reset token
                token = serializer.dumps(email, salt='password-reset-salt')
                
                # Save token to database
                reset_token = PasswordResetToken(
                    user_id=user.id,
                    token=token,
                    expires_at=datetime.utcnow() + timedelta(hours=1)
                )
                db.session.add(reset_token)
                db.session.commit()
                
                # Send email
                reset_url = url_for('reset_password', token=token, _external=True)
                
                msg = Message(
                    subject='Riley Falcon IDPS - Password Reset Request',
                    recipients=[email],
                    sender=('Riley Falcon IDPS', 'security@rileyfalcon.com')
                )
                
                msg.html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                                  color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                        .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
                        .button {{ display: inline-block; padding: 12px 30px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                                  color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
                        .footer {{ text-align: center; margin-top: 30px; font-size: 12px; color: #999; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h2>🛡️ Riley Falcon IDPS</h2>
                            <p>Password Reset Request</p>
                        </div>
                        <div class="content">
                            <p>Hello {user.first_name},</p>
                            <p>We received a request to reset your password for the Riley Falcon Intrusion Detection & Prevention System.</p>
                            <p>Click the button below to reset your password. This link will expire in 1 hour.</p>
                            <div style="text-align: center;">
                                <a href="{reset_url}" class="button">Reset Password</a>
                            </div>
                            <p>If you didn't request this, please ignore this email or contact the IT department.</p>
                            <p>For security reasons, never share this link with anyone.</p>
                            <hr>
                            <p><strong>Important:</strong> This link will expire in 1 hour for security purposes.</p>
                        </div>
                        <div class="footer">
                            <p>© 2024 Riley Falcon Security Services - IT Department</p>
                            <p>East Africa Time (EAT)</p>
                        </div>
                    </div>
                </body>
                </html>
                """
                
                try:
                    mail.send(msg)
                    flash('Password reset instructions have been sent to your email.', 'success')
                except Exception as e:
                    flash('Error sending email. Please try again later.', 'danger')
                    print(f"Email error: {e}")
                
                return redirect(url_for('login'))
            else:
                flash('Email address not found in our system.', 'danger')
        
        return render_template('forgot_password.html', form=form)

    @app.route('/reset-password/<token>', methods=['GET', 'POST'])
    def reset_password(token):
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        
        form = ResetPasswordForm()
        
        try:
            # Verify token (expires after 1 hour)
            email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
        except SignatureExpired:
            flash('The password reset link has expired. Please request a new one.', 'danger')
            return redirect(url_for('forgot_password'))
        except:
            flash('Invalid password reset link.', 'danger')
            return redirect(url_for('forgot_password'))
        
        # Check if token exists in database
        reset_token = PasswordResetToken.query.filter_by(token=token).first()
        if not reset_token or reset_token.is_expired or reset_token.is_used:
            flash('This password reset link has already been used or is invalid.', 'danger')
            return redirect(url_for('forgot_password'))
        
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('forgot_password'))
        
        if form.validate_on_submit():
            # Update password
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user.password_hash = hashed_password
            
            # Mark token as used
            reset_token.is_used = True
            
            # Log action
            action = UserAction(
                user_id=user.id,
                action='Password Reset',
                ip_address=request.remote_addr,
                details='Password reset successfully'
            )
            db.session.add(action)
            db.session.commit()
            
            # Send confirmation email
            try:
                msg = Message(
                    subject='Riley Falcon IDPS - Password Reset Successful',
                    recipients=[user.email],
                    sender=('Riley Falcon IDPS', 'security@rileyfalcon.com')
                )
                msg.html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                        .header {{ background: linear-gradient(135deg, #28a745 0%, #20c997 100%); 
                                  color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                        .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
                        .footer {{ text-align: center; margin-top: 30px; font-size: 12px; color: #999; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h2>✅ Password Reset Successful</h2>
                        </div>
                        <div class="content">
                            <p>Hello {user.first_name},</p>
                            <p>Your password for Riley Falcon IDPS has been successfully reset.</p>
                            <p>You can now <a href="{url_for('login', _external=True)}">login</a> with your new password.</p>
                            <p>If you did not make this change, please contact the IT department immediately.</p>
                        </div>
                        <div class="footer">
                            <p>© 2024 Riley Falcon Security Services - IT Department</p>
                        </div>
                    </div>
                </body>
                </html>
                """
                mail.send(msg)
            except:
                pass  # Don't show error if confirmation email fails
            
            flash('Your password has been updated successfully! You can now login.', 'success')
            return redirect(url_for('login'))
        
        return render_template('reset_password.html', form=form, token=token)

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        
        form = RegistrationForm()
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(
                username=form.username.data,
                email=form.email.data,
                password_hash=hashed_password,
                first_name=form.first_name.data,
                last_name=form.last_name.data,
                phone_number=form.phone_number.data,
                department=form.department.data,
                role='staff'
            )
            db.session.add(user)
            db.session.commit()
            
            # Send welcome email
            try:
                msg = Message(
                    subject='Welcome to Riley Falcon IDPS',
                    recipients=[user.email],
                    sender=('Riley Falcon IDPS', 'security@rileyfalcon.com')
                )
                msg.html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                                  color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                        .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
                        .footer {{ text-align: center; margin-top: 30px; font-size: 12px; color: #999; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h2>🛡️ Welcome to Riley Falcon IDPS!</h2>
                        </div>
                        <div class="content">
                            <p>Hello {user.first_name},</p>
                            <p>Your account has been created successfully. You now have access to the Riley Falcon Intrusion Detection & Prevention System.</p>
                            <p><strong>Account Details:</strong></p>
                            <ul>
                                <li>Username: {user.username}</li>
                                <li>Email: {user.email}</li>
                                <li>Department: {user.department}</li>
                            </ul>
                            <p>You can now <a href="{url_for('login', _external=True)}">login</a> to access the system.</p>
                            <p>Please keep your credentials secure and never share them with anyone.</p>
                        </div>
                        <div class="footer">
                            <p>© 2024 Riley Falcon Security Services - IT Department</p>
                        </div>
                    </div>
                </body>
                </html>
                """
                mail.send(msg)
            except Exception as e:
                print(f"Welcome email error: {e}")
            
            flash('Your account has been created! You can now log in.', 'success')
            return redirect(url_for('login'))
        
        return render_template('register.html', form=form, title='Register')

    @app.route('/dashboard')
    @login_required
    def dashboard():
        current_time = datetime.utcnow().replace(tzinfo=pytz.UTC).astimezone(EAT)
        
        total_alerts = Alert.query.count()
        critical_alerts = Alert.query.filter_by(severity='critical', is_resolved=False).count()
        high_alerts = Alert.query.filter_by(severity='high', is_resolved=False).count()
        total_packets = NetworkTraffic.query.count()
        suspicious_packets = NetworkTraffic.query.filter_by(is_suspicious=True).count()
        
        recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()
        
        chart_labels = []
        chart_values = []
        for i in range(12):
            time_point = datetime.utcnow() - timedelta(hours=i)
            count = NetworkTraffic.query.filter(
                NetworkTraffic.timestamp.between(
                    time_point - timedelta(hours=1),
                    time_point
                )
            ).count()
            chart_labels.append(time_point.strftime('%H:00'))
            chart_values.append(count)
        
        return render_template('dashboard.html',
                             title='Dashboard',
                             current_time=current_time,
                             total_alerts=total_alerts,
                             critical_alerts=critical_alerts,
                             high_alerts=high_alerts,
                             total_packets=total_packets,
                             suspicious_packets=suspicious_packets,
                             recent_alerts=recent_alerts,
                             chart_labels=json.dumps(chart_labels[::-1]),
                             chart_values=json.dumps(chart_values[::-1]),
                             network_monitor=network_monitor,
                             host_monitor=host_monitor)

    @app.route('/network_monitor')
    @login_required
    def network_monitor():
        """Network monitor page with real-time traffic data"""
        page = request.args.get('page', 1, type=int)
        traffic = NetworkTraffic.query.order_by(NetworkTraffic.timestamp.desc()).paginate(page=page, per_page=50)
        
        total_traffic = NetworkTraffic.query.count()
        suspicious = NetworkTraffic.query.filter_by(is_suspicious=True).count()
        
        # FIX: Convert protocol data to JSON-serializable format
        protocol_results = db.session.query(
            NetworkTraffic.protocol, 
            db.func.count(NetworkTraffic.protocol).label('count')
        ).group_by(NetworkTraffic.protocol).all()
        
        # Convert Row objects to list of dictionaries
        protocols = [{'protocol': p[0] or 'Unknown', 'count': p[1]} for p in protocol_results] if protocol_results else []
        
        return render_template('network_monitor.html',
                             title='Network Monitor',
                             traffic=traffic,
                             total_traffic=total_traffic,
                             suspicious=suspicious,
                             protocols=protocols)

    @app.route('/api/network/interfaces')
    @login_required
    def get_network_interfaces():
        """Get available network interfaces for debugging"""
        try:
            from scapy.arch.windows import get_windows_if_list
            interfaces = get_windows_if_list()
            
            result = []
            for iface in interfaces:
                if iface['name'] and iface['ips']:
                    result.append({
                        'name': iface['name'],
                        'description': iface['description'],
                        'ips': iface['ips']
                    })
            
            return jsonify({
                'success': True,
                'interfaces': result,
                'timestamp': datetime.utcnow().isoformat()
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/network/wifi-status')
    @login_required
    def api_wifi_status():
        """Get current WiFi connection status"""
        global network_monitor
        try:
            if network_monitor:
                stats = network_monitor.get_statistics()
                wifi_info = stats.get('wifi', {})
                return jsonify({
                    'success': True,
                    'connected': wifi_info.get('connected', False),
                    'ssid': wifi_info.get('ssid'),
                    'signal': wifi_info.get('signal'),
                    'interface': wifi_info.get('interface'),
                    'ip': wifi_info.get('ip'),
                    'is_monitoring': network_monitor.is_monitoring
                })
            else:
                return jsonify({
                    'success': False,
                    'connected': False,
                    'message': 'Network monitor not initialized'
                })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/network/auto-interface')
    @login_required
    def api_auto_interface():
        """Auto-detect the active network interface"""
        global network_monitor
        try:
            if network_monitor:
                interface = network_monitor.get_active_interface()
                wifi_status = network_monitor.get_wifi_status()
                return jsonify({
                    'success': True,
                    'interface': interface,
                    'wifi': wifi_status
                })
            else:
                return jsonify({
                    'success': False,
                    'message': 'Network monitor not initialized'
                })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/network/scan-wifi')
    @login_required
    def scan_wifi_networks():
        """Scan for available WiFi networks"""
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'networks'], 
                                  capture_output=True, text=True, shell=True)
            
            networks = []
            current_ssid = None
            current_signal = None
            
            for line in result.stdout.split('\n'):
                if 'SSID' in line and ':' in line:
                    ssid = line.split(':')[1].strip()
                    if ssid and ssid not in [n['ssid'] for n in networks]:
                        current_ssid = ssid
                elif 'Signal' in line and ':' in line and current_ssid:
                    signal = line.split(':')[1].strip()
                    # Extract percentage
                    signal_percent = ''.join(filter(str.isdigit, signal))
                    networks.append({
                        'ssid': current_ssid,
                        'signal': signal_percent or '50',
                        'security': 'WPA2-Personal'  # Default, would need more parsing
                    })
                    current_ssid = None
                elif 'Authentication' in line and ':' in line and networks:
                    # Update last network's security
                    auth = line.split(':')[1].strip()
                    if networks:
                        networks[-1]['security'] = auth
            
            return jsonify({
                'success': True,
                'networks': networks,
                'count': len(networks),
                'timestamp': datetime.utcnow().isoformat()
            })
            
        except Exception as e:
            print(f"Error scanning WiFi: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/network/connect-wifi', methods=['POST'])
    @login_required
    def connect_to_wifi():
        """Connect to a WiFi network"""
        try:
            data = request.get_json()
            ssid = data.get('ssid')
            password = data.get('password')
            
            if not ssid:
                return jsonify({'success': False, 'error': 'SSID required'}), 400
            
            # Create WiFi profile XML
            profile = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>"""
            
            # Save profile to temp file
            profile_path = os.path.join(tempfile.gettempdir(), f'wifi_profile_{ssid}.xml')
            with open(profile_path, 'w', encoding='utf-8') as f:
                f.write(profile)
            
            # Add profile
            add_result = subprocess.run(
                ['netsh', 'wlan', 'add', 'profile', f'filename={profile_path}'],
                capture_output=True, text=True, shell=True
            )
            
            # Connect to network
            connect_result = subprocess.run(
                ['netsh', 'wlan', 'connect', f'name={ssid}'],
                capture_output=True, text=True, shell=True
            )
            
            # Clean up temp file
            try:
                os.remove(profile_path)
            except:
                pass
            
            if "Connection request was completed successfully" in connect_result.stdout:
                return jsonify({
                    'success': True,
                    'message': f'Connected to {ssid}',
                    'output': connect_result.stdout
                })
            else:
                return jsonify({
                    'success': False,
                    'error': connect_result.stdout or 'Failed to connect'
                })
            
        except Exception as e:
            print(f"Error connecting to WiFi: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/network/start', methods=['POST'])
    @login_required
    def start_network_capture():
        """Start network packet capture"""
        global network_monitor
        try:
            # Initialize network monitor if not already running
            if network_monitor is None:
                from utils.network_monitor import NetworkMonitor
                from utils.ai_engine import AIEngine
                from utils.alert_manager import AlertManager
                
                ai_engine = AIEngine()
                alert_manager = AlertManager()
                network_monitor = NetworkMonitor(ai_engine, alert_manager)
                network_monitor.set_app_context(app)  # Set app context for database operations
            
            # Get interface from request or use default
            data = request.get_json() or {}
            interface = data.get('interface', None)
            
            # Start monitoring
            success = network_monitor.start_monitoring(interface=interface)
            
            if success:
                # Log action
                action = UserAction(
                    user_id=current_user.id,
                    action='Start Network Capture',
                    ip_address=request.remote_addr,
                    details=f'Started network capture on interface {interface or "auto-detected"}'
                )
                db.session.add(action)
                db.session.commit()
                
                # Emit socket event
                socketio.emit('monitoring_started', {
                    'interface': interface or 'auto-detected',
                    'timestamp': datetime.utcnow().isoformat()
                })
                
                stats = network_monitor.get_statistics()
                wifi_info = stats.get('wifi', {})
                
                return jsonify({
                    'success': True,
                    'message': f'Network capture started on {interface or "auto-detected interface"}',
                    'stats': stats,
                    'wifi': wifi_info
                })
            else:
                return jsonify({
                    'success': False,
                    'message': 'Failed to start network capture. Make sure Npcap is installed and run as Administrator.'
                }), 500
                
        except Exception as e:
            return jsonify({
                'success': False,
                'message': str(e)
            }), 500

    @app.route('/api/network/stop', methods=['POST'])
    @login_required
    def stop_network_capture():
        """Stop network packet capture"""
        global network_monitor
        try:
            if network_monitor and network_monitor.is_monitoring:
                network_monitor.stop_monitoring()
                
                # Save all captured packets to database
                saved = network_monitor.save_all_packets_to_db()
                
                # Log action
                action = UserAction(
                    user_id=current_user.id,
                    action='Stop Network Capture',
                    ip_address=request.remote_addr,
                    details=f'Stopped network capture, saved {saved} packets to database'
                )
                db.session.add(action)
                db.session.commit()
                
                # Emit socket event
                socketio.emit('monitoring_stopped', {
                    'timestamp': datetime.utcnow().isoformat(),
                    'stats': network_monitor.get_statistics(),
                    'saved_packets': saved
                })
                
                return jsonify({
                    'success': True,
                    'message': f'Network capture stopped, saved {saved} packets to database',
                    'stats': network_monitor.get_statistics(),
                    'saved_packets': saved
                })
            else:
                return jsonify({
                    'success': False,
                    'message': 'Network monitor not running'
                }), 400
                
        except Exception as e:
            return jsonify({
                'success': False,
                'message': str(e)
            }), 500

    @app.route('/api/network/status')
    @login_required
    def network_status():
        """Get network monitor status with chart data"""
        global network_monitor
        try:
            if network_monitor and network_monitor.is_monitoring:
                stats = network_monitor.get_statistics()
                recent_packets = network_monitor.get_recent_packets(20)
                chart_data = network_monitor.get_chart_data() if hasattr(network_monitor, 'get_chart_data') else []
                
                return jsonify({
                    'is_monitoring': network_monitor.is_monitoring,
                    'stats': stats,
                    'recent_packets': recent_packets,
                    'chart_data': chart_data
                })
            else:
                # Still return database stats if available
                db_total = NetworkTraffic.query.count()
                db_suspicious = NetworkTraffic.query.filter_by(is_suspicious=True).count()
                
                return jsonify({
                    'is_monitoring': False,
                    'stats': {
                        'total_packets': db_total,
                        'suspicious_packets': db_suspicious,
                        'tcp_packets': NetworkTraffic.query.filter_by(protocol='TCP').count(),
                        'udp_packets': NetworkTraffic.query.filter_by(protocol='UDP').count(),
                        'icmp_packets': NetworkTraffic.query.filter_by(protocol='ICMP').count(),
                        'packets_per_second': 0,
                        'bytes_per_second': 0,
                        'total_bytes': 0
                    },
                    'recent_packets': [],
                    'chart_data': [0] * 20
                })
        except Exception as e:
            print(f"Error in network_status: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/network/recent')
    @login_required
    def recent_packets():
        """Get recent packets"""
        global network_monitor
        try:
            if network_monitor:
                packets = network_monitor.get_recent_packets(50)
                return jsonify(packets)
            else:
                # Get from database
                recent = NetworkTraffic.query.order_by(NetworkTraffic.timestamp.desc()).limit(50).all()
                packets = [{
                    'timestamp': p.timestamp.isoformat(),
                    'src_ip': p.source_ip,
                    'dst_ip': p.destination_ip,
                    'protocol': p.protocol,
                    'size': p.packet_size,
                    'suspicious': p.is_suspicious,
                    'score': p.anomaly_score
                } for p in recent]
                return jsonify(packets)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/network/protocol-details')
    @login_required
    def api_network_protocol_details():
        """Get detailed protocol statistics from the last hour"""
        global network_monitor
        try:
            if network_monitor:
                protocol_data = network_monitor.get_protocol_details()
                print(f"📊 Returning protocol data: {protocol_data}")
                return jsonify(protocol_data)
            else:
                # Get from database
                last_hour = datetime.utcnow() - timedelta(hours=1)
                
                tcp = NetworkTraffic.query.filter(
                    NetworkTraffic.timestamp > last_hour,
                    NetworkTraffic.protocol == 'TCP'
                ).count()
                
                udp = NetworkTraffic.query.filter(
                    NetworkTraffic.timestamp > last_hour,
                    NetworkTraffic.protocol == 'UDP'
                ).count()
                
                icmp = NetworkTraffic.query.filter(
                    NetworkTraffic.timestamp > last_hour,
                    NetworkTraffic.protocol == 'ICMP'
                ).count()
                
                http = NetworkTraffic.query.filter(
                    NetworkTraffic.timestamp > last_hour,
                    NetworkTraffic.protocol == 'TCP',
                    NetworkTraffic.destination_port.in_([80, 8080])
                ).count()
                
                https = NetworkTraffic.query.filter(
                    NetworkTraffic.timestamp > last_hour,
                    NetworkTraffic.protocol == 'TCP',
                    NetworkTraffic.destination_port.in_([443, 8443])
                ).count()
                
                dns = NetworkTraffic.query.filter(
                    NetworkTraffic.timestamp > last_hour,
                    NetworkTraffic.protocol == 'UDP',
                    NetworkTraffic.destination_port == 53
                ).count()
                
                return jsonify({
                    'tcp': tcp,
                    'udp': udp,
                    'icmp': icmp,
                    'http': http,
                    'https': https,
                    'dns': dns,
                    'other': NetworkTraffic.query.filter(
                        NetworkTraffic.timestamp > last_hour,
                        NetworkTraffic.protocol.notin_(['TCP', 'UDP', 'ICMP'])
                    ).count()
                })
        except Exception as e:
            print(f"❌ Error in protocol details endpoint: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({
                'tcp': 0,
                'udp': 0,
                'icmp': 0,
                'http': 0,
                'https': 0,
                'dns': 0,
                'other': 0
            })

    @app.route('/api/network/debug')
    @login_required
    def api_network_debug():
        """Debug endpoint to check network data"""
        global network_monitor
        try:
            debug_info = {
                'is_monitoring': network_monitor.is_monitoring if network_monitor else False,
                'packet_count': network_monitor.packet_count if network_monitor else 0,
                'captured_packets_count': len(network_monitor.captured_packets) if network_monitor else 0,
                'stats': network_monitor.stats if network_monitor else {},
                'database_counts': {
                    'total': NetworkTraffic.query.count(),
                    'last_hour': NetworkTraffic.query.filter(
                        NetworkTraffic.timestamp > (datetime.utcnow() - timedelta(hours=1))
                    ).count(),
                    'last_5_minutes': NetworkTraffic.query.filter(
                        NetworkTraffic.timestamp > (datetime.utcnow() - timedelta(minutes=5))
                    ).count()
                }
            }
            
            # Get sample of recent packets if available
            if network_monitor and len(network_monitor.captured_packets) > 0:
                debug_info['sample_packets'] = list(network_monitor.captured_packets)[-5:]
            
            return jsonify(debug_info)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/network/generate-test-data', methods=['POST'])
    @login_required
    def generate_test_data():
        """Generate test network data for debugging"""
        try:
            from random import randint, choice
            from datetime import datetime, timedelta
            
            protocols = ['TCP', 'UDP', 'ICMP']
            ips = ['192.168.1.1', '192.168.1.100', '8.8.8.8', '1.1.1.1']
            ports = [80, 443, 53, 8080, 22, 3389, 3306]
            
            count = 0
            for i in range(50):
                timestamp = datetime.utcnow() - timedelta(minutes=randint(0, 60))
                protocol = choice(protocols)
                dest_port = choice(ports)
                
                traffic = NetworkTraffic(
                    timestamp=timestamp,
                    source_ip=choice(ips),
                    destination_ip=choice(ips),
                    protocol=protocol,
                    source_port=randint(1024, 65535),
                    destination_port=dest_port,
                    packet_size=randint(64, 1500),
                    flags='A',
                    is_suspicious=randint(0, 10) > 8,
                    anomaly_score=randint(0, 100)/100
                )
                db.session.add(traffic)
                count += 1
            
            db.session.commit()
            return jsonify({'success': True, 'message': f'{count} test packets generated'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    # ================ HOST MONITOR ROUTES ================
    
    @app.route('/host_monitor')
    @login_required
    def host_monitor():
        # Auto-start host monitoring if not already running
        global host_monitor
        if host_monitor and not host_monitor.is_monitoring:
            host_monitor.start_monitoring(interval=3)
            print("🖥️ Host monitoring auto-started")
        
        page = request.args.get('page', 1, type=int)
        
        # Get filter parameters
        search = request.args.get('search', '')
        status = request.args.get('status', 'all')
        sort = request.args.get('sort', 'cpu')
        
        # Base query
        query = HostActivity.query
        
        # Apply search filter
        if search:
            query = query.filter(HostActivity.process_name.ilike(f'%{search}%'))
        
        # Apply status filter
        if status == 'suspicious':
            query = query.filter_by(is_suspicious=True)
        elif status == 'normal':
            query = query.filter_by(is_suspicious=False)
        
        # Apply sorting
        if sort == 'cpu':
            query = query.order_by(HostActivity.cpu_usage.desc())
        elif sort == 'memory':
            query = query.order_by(HostActivity.memory_usage.desc())
        else:
            query = query.order_by(HostActivity.timestamp.desc())
        
        # Paginate results
        activities = query.paginate(page=page, per_page=50)
        
        # Get total counts
        total_processes = HostActivity.query.count()
        suspicious_processes = HostActivity.query.filter_by(is_suspicious=True).count()
        
        # Get top CPU processes from the monitor if available
        top_cpu = []
        if host_monitor and hasattr(host_monitor, 'get_top_processes'):
            top_cpu = host_monitor.get_top_processes(limit=10, by='cpu')
            print(f"📊 Retrieved {len(top_cpu)} real-time processes")
        
        return render_template('host_monitor.html',
                             title='Host Monitor',
                             activities=activities,
                             total_processes=total_processes,
                             suspicious_processes=suspicious_processes,
                             top_cpu=top_cpu,
                             search=search,
                             status=status,
                             sort=sort)

    @app.route('/api/host/stats')
    @login_required
    def host_stats():
        """Get host statistics"""
        global host_monitor
        try:
            # Auto-start if not running
            if host_monitor and not host_monitor.is_monitoring:
                host_monitor.start_monitoring(interval=3)
            
            if host_monitor and hasattr(host_monitor, 'get_statistics'):
                stats = host_monitor.get_statistics()
                return jsonify(stats)
            else:
                return jsonify({
                    'cpu_percent': 0,
                    'memory_percent': 0,
                    'disk_percent': 0,
                    'uptime': '0d 0h 0m',
                    'total_processes': 0,
                    'suspicious_processes': 0,
                    'active_users': 0,
                    'is_monitoring': False,
                    'cpu_history': [0] * 20,
                    'memory_history': [0] * 20,
                    'disk_history': [0] * 20
                })
        except Exception as e:
            print(f"Error in host_stats: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/host/top-processes')
    @login_required
    def api_top_processes():
        """Get top CPU processes in real-time"""
        global host_monitor
        try:
            # Auto-start if not running
            if host_monitor and not host_monitor.is_monitoring:
                host_monitor.start_monitoring(interval=3)
            
            if host_monitor and hasattr(host_monitor, 'get_top_processes'):
                # Get top 10 processes by CPU usage
                top_processes = host_monitor.get_top_processes(limit=10, by='cpu')
                print(f"📊 API returning {len(top_processes)} real processes")
                
                # Format for template
                result = []
                for proc in top_processes:
                    result.append({
                        'process_name': proc.get('process_name', 'Unknown'),
                        'process_id': proc.get('process_id', 0),
                        'user': proc.get('user', 'Unknown'),
                        'cpu_usage': proc.get('cpu_usage', 0),
                        'memory_usage': proc.get('memory_usage', 0),
                        'is_suspicious': proc.get('is_suspicious', False)
                    })
                
                return jsonify(result)
            else:
                # Return empty list if no monitor available
                return jsonify([])
        except Exception as e:
            print(f"Error in top-processes: {e}")
            return jsonify([])

    @app.route('/api/host/process/<int:pid>')
    @login_required
    def get_process_details(pid):
        """Get process details"""
        global host_monitor
        try:
            if host_monitor and hasattr(host_monitor, 'get_process_details'):
                details = host_monitor.get_process_details(pid)
                return jsonify(details)
            else:
                return jsonify({'error': 'Host monitor not initialized'}), 500
        except Exception as e:
            print(f"Error getting process details: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/host/recent-activities')
    @login_required
    def api_recent_activities():
        """Get recent host activities for process monitor"""
        limit = request.args.get('limit', 50, type=int)
        activities = HostActivity.query.order_by(HostActivity.timestamp.desc()).limit(limit).all()
        
        result = []
        for a in activities:
            result.append({
                'id': a.id,
                'timestamp': a.timestamp.isoformat(),
                'process_name': a.process_name,
                'process_id': a.process_id,
                'user': a.user,
                'cpu_usage': a.cpu_usage,
                'memory_usage': a.memory_usage,
                'network_connections': a.network_connections,
                'open_files': a.open_files,
                'is_suspicious': a.is_suspicious
            })
        
        return jsonify(result)

    @app.route('/api/host/kill/<int:pid>', methods=['POST'])
    @login_required
    def kill_process(pid):
        """Kill a process"""
        global host_monitor
        try:
            if host_monitor and current_user.role == 'admin':
                success, message = host_monitor.kill_process(pid)
                
                if success:
                    # Log action
                    action = UserAction(
                        user_id=current_user.id,
                        action='Kill Process',
                        ip_address=request.remote_addr,
                        details=f'Killed process PID: {pid}'
                    )
                    db.session.add(action)
                    db.session.commit()
                    
                    # Emit socket event
                    socketio.emit('process_killed', {
                        'pid': pid,
                        'by': current_user.username,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
                    return jsonify({'success': True, 'message': message})
                else:
                    return jsonify({'success': False, 'error': message}), 400
            else:
                return jsonify({'success': False, 'error': 'Permission denied or monitor not initialized'}), 403
        except Exception as e:
            print(f"Error killing process: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/host/kill-suspicious', methods=['POST'])
    @login_required
    def kill_suspicious():
        """Kill all suspicious processes"""
        global host_monitor
        try:
            if host_monitor and current_user.role == 'admin':
                if hasattr(host_monitor, 'kill_suspicious_processes'):
                    result = host_monitor.kill_suspicious_processes()
                    
                    # Log action
                    action = UserAction(
                        user_id=current_user.id,
                        action='Kill Suspicious Processes',
                        ip_address=request.remote_addr,
                        details=f'Killed {result["count"]} suspicious processes'
                    )
                    db.session.add(action)
                    db.session.commit()
                    
                    return jsonify(result)
                else:
                    return jsonify({'success': False, 'error': 'Method not available'}), 400
            else:
                return jsonify({'success': False, 'error': 'Permission denied'}), 403
        except Exception as e:
            print(f"Error killing suspicious processes: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/host/start', methods=['POST'])
    @login_required
    def start_host_monitoring():
        """Start host monitoring"""
        global host_monitor
        try:
            if host_monitor and not host_monitor.is_monitoring:
                success = host_monitor.start_monitoring(interval=3)
                if success:
                    return jsonify({'success': True, 'message': 'Host monitoring started'})
            return jsonify({'success': False, 'message': 'Host monitor already running or not initialized'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/host/chart-data')
    @login_required
    def host_chart_data():
        """Get chart data for real-time updates"""
        global host_monitor
        try:
            if host_monitor and hasattr(host_monitor, 'get_chart_data'):
                return jsonify(host_monitor.get_chart_data())
            else:
                return jsonify({
                    'cpu': [0] * 20,
                    'memory': [0] * 20,
                    'disk': [0] * 20
                })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/host/test')
    @login_required
    def test_host_monitor():
        """Test endpoint to verify host monitor is working"""
        global host_monitor
        try:
            if host_monitor:
                # Try to get process list
                processes = host_monitor.get_top_processes(limit=5)
                stats = host_monitor.get_statistics()
                
                return jsonify({
                    'status': 'success',
                    'is_monitoring': host_monitor.is_monitoring,
                    'process_count': len(processes),
                    'processes': processes,
                    'stats': stats
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Host monitor not initialized'
                }), 500
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    # ================ ALERTS ROUTES ================

    @app.route('/alerts')
    @login_required
    def alerts():
        page = request.args.get('page', 1, type=int)
        severity = request.args.get('severity', 'all')
        alert_type = request.args.get('type', 'all')
        source = request.args.get('source', 'all')
        status = request.args.get('status', 'all')
        search = request.args.get('search', '')
        
        # Base query
        query = Alert.query
        
        # Apply filters
        if severity != 'all':
            query = query.filter_by(severity=severity)
        
        if alert_type != 'all':
            query = query.filter_by(alert_type=alert_type)
        
        if source != 'all':
            query = query.filter_by(source=source)
        
        if status == 'active':
            query = query.filter_by(is_resolved=False)
        elif status == 'resolved':
            query = query.filter_by(is_resolved=True)
        
        if search:
            query = query.filter(
                db.or_(
                    Alert.description.ilike(f'%{search}%'),
                    Alert.details.ilike(f'%{search}%')
                )
            )
        
        # Get counts for statistics
        critical_count = Alert.query.filter_by(severity='critical', is_resolved=False).count()
        high_count = Alert.query.filter_by(severity='high', is_resolved=False).count()
        medium_count = Alert.query.filter_by(severity='medium', is_resolved=False).count()
        low_count = Alert.query.filter_by(severity='low', is_resolved=False).count()
        
        # Get last hour counts for trend indicators
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        critical_last_hour = Alert.query.filter(
            Alert.severity == 'critical',
            Alert.timestamp > one_hour_ago,
            Alert.is_resolved == False
        ).count()
        high_last_hour = Alert.query.filter(
            Alert.severity == 'high',
            Alert.timestamp > one_hour_ago,
            Alert.is_resolved == False
        ).count()
        medium_last_hour = Alert.query.filter(
            Alert.severity == 'medium',
            Alert.timestamp > one_hour_ago,
            Alert.is_resolved == False
        ).count()
        low_last_hour = Alert.query.filter(
            Alert.severity == 'low',
            Alert.timestamp > one_hour_ago,
            Alert.is_resolved == False
        ).count()
        
        # Paginate results
        alerts = query.order_by(Alert.timestamp.desc()).paginate(page=page, per_page=50)
        
        return render_template('alerts.html',
                             title='Alerts',
                             alerts=alerts,
                             critical_count=critical_count,
                             high_count=high_count,
                             medium_count=medium_count,
                             low_count=low_count,
                             critical_last_hour=critical_last_hour,
                             high_last_hour=high_last_hour,
                             medium_last_hour=medium_last_hour,
                             low_last_hour=low_last_hour,
                             current_severity=severity,
                             current_type=alert_type,
                             current_source=source,
                             current_status=status,
                             search=search)

    @app.route('/resolve_alert/<int:alert_id>', methods=['POST'])
    @login_required
    def resolve_alert(alert_id):
        alert = Alert.query.get_or_404(alert_id)
        alert.is_resolved = True
        alert.resolved_at = datetime.utcnow()
        alert.resolved_by = current_user.id
        
        action = UserAction(
            user_id=current_user.id,
            action='Resolve Alert',
            ip_address=request.remote_addr,
            details=f'Resolved alert ID: {alert_id}'
        )
        db.session.add(action)
        db.session.commit()
        
        # Emit socket event for real-time update
        socketio.emit('alert_resolved', {
            'alert_id': alert_id,
            'resolved_by': current_user.username,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        return jsonify({'success': True, 'message': 'Alert resolved'})

    @app.route('/api/alerts/stats')
    @login_required
    def api_alerts_stats():
        """Get alert statistics for dashboard"""
        try:
            # Current counts
            critical = Alert.query.filter_by(severity='critical', is_resolved=False).count()
            high = Alert.query.filter_by(severity='high', is_resolved=False).count()
            medium = Alert.query.filter_by(severity='medium', is_resolved=False).count()
            low = Alert.query.filter_by(severity='low', is_resolved=False).count()
            total = critical + high + medium + low
            
            # Last hour counts for trends
            one_hour_ago = datetime.utcnow() - timedelta(hours=1)
            critical_last_hour = Alert.query.filter(
                Alert.severity == 'critical',
                Alert.timestamp > one_hour_ago,
                Alert.is_resolved == False
            ).count()
            high_last_hour = Alert.query.filter(
                Alert.severity == 'high',
                Alert.timestamp > one_hour_ago,
                Alert.is_resolved == False
            ).count()
            medium_last_hour = Alert.query.filter(
                Alert.severity == 'medium',
                Alert.timestamp > one_hour_ago,
                Alert.is_resolved == False
            ).count()
            low_last_hour = Alert.query.filter(
                Alert.severity == 'low',
                Alert.timestamp > one_hour_ago,
                Alert.is_resolved == False
            ).count()
            
            # Calculate trends
            critical_trend = critical - critical_last_hour
            high_trend = high - high_last_hour
            medium_trend = medium - medium_last_hour
            low_trend = low - low_last_hour
            
            return jsonify({
                'total': total,
                'critical': critical,
                'high': high,
                'medium': medium,
                'low': low,
                'critical_trend': critical_trend,
                'high_trend': high_trend,
                'medium_trend': medium_trend,
                'low_trend': low_trend,
                'critical_last_hour': critical_last_hour,
                'high_last_hour': high_last_hour,
                'medium_last_hour': medium_last_hour,
                'low_last_hour': low_last_hour,
                'timestamp': datetime.utcnow().isoformat()
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/alerts/trends')
    @login_required
    def api_alerts_trends():
        """Get alert trends for the last 12 hours"""
        try:
            labels = []
            critical_data = []
            high_data = []
            medium_data = []
            low_data = []
            
            for i in range(12, -1, -1):
                hour_start = datetime.utcnow() - timedelta(hours=i)
                hour_end = hour_start + timedelta(hours=1)
                
                labels.append(f'{hour_start.strftime("%H:00")}')
                
                critical_data.append(Alert.query.filter(
                    Alert.severity == 'critical',
                    Alert.timestamp.between(hour_start, hour_end)
                ).count())
                
                high_data.append(Alert.query.filter(
                    Alert.severity == 'high',
                    Alert.timestamp.between(hour_start, hour_end)
                ).count())
                
                medium_data.append(Alert.query.filter(
                    Alert.severity == 'medium',
                    Alert.timestamp.between(hour_start, hour_end)
                ).count())
                
                low_data.append(Alert.query.filter(
                    Alert.severity == 'low',
                    Alert.timestamp.between(hour_start, hour_end)
                ).count())
            
            return jsonify({
                'labels': labels,
                'critical': critical_data,
                'high': high_data,
                'medium': medium_data,
                'low': low_data
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/alerts/recent')
    @login_required
    def api_recent_alerts():
        """Get recent alerts for dashboard"""
        limit = request.args.get('limit', 5, type=int)
        alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(limit).all()
        
        result = []
        for a in alerts:
            result.append({
                'id': a.id,
                'severity': a.severity,
                'description': a.description,
                'timestamp': a.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'is_resolved': a.is_resolved,
                'type': a.alert_type,
                'source': a.source
            })
        
        return jsonify(result)

    @app.route('/api/alerts/resolve-all', methods=['POST'])
    @login_required
    def resolve_all_alerts():
        """Resolve all active alerts"""
        try:
            alerts = Alert.query.filter_by(is_resolved=False).all()
            count = len(alerts)
            
            for alert in alerts:
                alert.is_resolved = True
                alert.resolved_at = datetime.utcnow()
                alert.resolved_by = current_user.id
            
            db.session.commit()
            
            # Emit socket event
            socketio.emit('alerts_resolved_all', {
                'count': count,
                'by': current_user.username,
                'timestamp': datetime.utcnow().isoformat()
            })
            
            return jsonify({'success': True, 'count': count})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/alerts/clear-all', methods=['POST'])
    @login_required
    def clear_all_alerts():
        """Clear all alerts (admin only)"""
        if current_user.role != 'admin':
            return jsonify({'success': False, 'error': 'Permission denied'}), 403
        
        try:
            count = Alert.query.count()
            Alert.query.delete()
            db.session.commit()
            
            # Emit socket event
            socketio.emit('alerts_cleared', {
                'count': count,
                'by': current_user.username,
                'timestamp': datetime.utcnow().isoformat()
            })
            
            return jsonify({'success': True, 'count': count})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/alerts/<int:alert_id>')
    @login_required
    def get_alert_details(alert_id):
        """Get detailed information about a specific alert"""
        alert = Alert.query.get_or_404(alert_id)
        
        # Get related data based on source
        related_data = None
        if alert.source == 'network':
            # Find related network traffic
            related = NetworkTraffic.query.filter(
                NetworkTraffic.timestamp.between(
                    alert.timestamp - timedelta(minutes=5),
                    alert.timestamp + timedelta(minutes=5)
                )
            ).limit(10).all()
            
            related_data = [{
                'timestamp': r.timestamp.isoformat(),
                'source_ip': r.source_ip,
                'dest_ip': r.destination_ip,
                'protocol': r.protocol,
                'size': r.packet_size,
                'suspicious': r.is_suspicious
            } for r in related]
        
        elif alert.source == 'host':
            # Find related host activities
            related = HostActivity.query.filter(
                HostActivity.timestamp.between(
                    alert.timestamp - timedelta(minutes=5),
                    alert.timestamp + timedelta(minutes=5)
                )
            ).limit(10).all()
            
            related_data = [{
                'timestamp': r.timestamp.isoformat(),
                'process': r.process_name,
                'pid': r.process_id,
                'cpu': r.cpu_usage,
                'memory': r.memory_usage,
                'suspicious': r.is_suspicious
            } for r in related]
        
        return jsonify({
            'id': alert.id,
            'type': alert.alert_type,
            'severity': alert.severity,
            'source': alert.source,
            'description': alert.description,
            'details': alert.details,
            'timestamp': alert.timestamp.isoformat(),
            'is_resolved': alert.is_resolved,
            'resolved_at': alert.resolved_at.isoformat() if alert.resolved_at else None,
            'resolved_by': alert.resolved_by,
            'related_data': related_data
        })

    # ================ THREAT STATS ROUTE ================

    @app.route('/api/threats/stats')
    @login_required
    def api_threat_stats():
        """Get real-time threat statistics from database"""
        try:
            # Get alerts from last 24 hours
            last_24h = datetime.utcnow() - timedelta(hours=24)
            prev_24h = last_24h - timedelta(hours=24)
            
            # Query threat types from alerts
            threats = db.session.query(
                Alert.description,
                db.func.count(Alert.id).label('count')
            ).filter(
                Alert.timestamp > last_24h,
                Alert.severity.in_(['critical', 'high'])
            ).group_by(
                Alert.description
            ).order_by(
                db.func.count(Alert.id).desc()
            ).limit(5).all()
            
            # Get previous period counts for trends
            prev_threats = db.session.query(
                Alert.description,
                db.func.count(Alert.id).label('count')
            ).filter(
                Alert.timestamp.between(prev_24h, last_24h)
            ).group_by(
                Alert.description
            ).all()
            
            prev_counts = {t[0]: t[1] for t in prev_threats}
            
            # Format threat data
            threat_list = []
            threat_types = {
                'Port Scan': {'icon': 'search', 'severity': 'high'},
                'Brute Force': {'icon': 'fist-raised', 'severity': 'critical'},
                'SQL Injection': {'icon': 'database', 'severity': 'critical'},
                'Malware': {'icon': 'bug', 'severity': 'critical'},
                'DDoS': {'icon': 'server', 'severity': 'high'},
                'Ransomware': {'icon': 'skull', 'severity': 'critical'},
                'Phishing': {'icon': 'fish', 'severity': 'high'},
                'Man in Middle': {'icon': 'exchange-alt', 'severity': 'critical'},
                'Zero Day': {'icon': 'calendar-times', 'severity': 'critical'},
                'Botnet': {'icon': 'network-wired', 'severity': 'high'}
            }
            
            for threat in threats:
                threat_name = threat[0].split(':')[0].strip() if ':' in threat[0] else threat[0]
                current_count = threat[1]
                prev_count = prev_counts.get(threat[0], 0)
                
                # Calculate trend percentage
                if prev_count > 0:
                    trend = round(((current_count - prev_count) / prev_count) * 100)
                else:
                    trend = 100 if current_count > 0 else 0
                
                # Determine severity based on threat type or default to medium
                severity = 'medium'
                for key in threat_types:
                    if key.lower() in threat_name.lower():
                        severity = threat_types[key]['severity']
                        break
                
                threat_list.append({
                    'type': threat_name,
                    'count': current_count,
                    'trend': trend,
                    'severity': severity
                })
            
            return jsonify({
                'threats': threat_list,
                'total': sum(t['count'] for t in threat_list),
                'timestamp': datetime.utcnow().isoformat()
            })
            
        except Exception as e:
            print(f"Error in threat stats: {e}")
            return jsonify({
                'threats': [],
                'total': 0,
                'timestamp': datetime.utcnow().isoformat()
            })

    # ================ AI STATUS ROUTE ================

    @app.route('/api/ai/status')
    @login_required
    def api_ai_status():
        """Get AI engine status"""
        global ai_engine
        try:
            if ai_engine:
                return jsonify(ai_engine.get_model_info())
            else:
                return jsonify({
                    'models_loaded': False,
                    'last_training': None,
                    'training_samples': 0,
                    'has_anomaly_model': False,
                    'has_signature_model': False,
                    'has_scaler': False
                })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # ================ REPORTS ROUTES ================

    @app.route('/reports', methods=['GET', 'POST'])
    @login_required
    def reports():
        form = ReportForm()
        
        if form.validate_on_submit():
            generator = ReportGenerator()
            
            start_date = form.start_date.data
            end_date = form.end_date.data
            data_source = form.data_source.data if hasattr(form, 'data_source') else 'database'
            
            if form.report_type.data == 'csv':
                filepath = generator.generate_csv_report('custom', start_date, end_date, data_source)
            elif form.report_type.data == 'pdf':
                filepath = generator.generate_pdf_report('custom', start_date, end_date, data_source)
            else:
                filepath = generator.generate_ppt_report('custom', start_date, end_date, data_source)
            
            report = Report(
                name=f"Report_{start_date.strftime('%Y%m%d')}_{end_date.strftime('%Y%m%d')}",
                type='custom',
                format=form.report_type.data,
                generated_by=current_user.id,
                file_path=filepath,
                date_range_start=start_date,
                date_range_end=end_date
            )
            db.session.add(report)
            db.session.commit()
            
            flash('Report generated successfully!', 'success')
            return send_file(filepath, as_attachment=True)
        
        previous_reports = Report.query.filter_by(generated_by=current_user.id).order_by(Report.generated_at.desc()).limit(10).all()
        
        return render_template('reports.html',
                             title='Reports',
                             form=form,
                             previous_reports=previous_reports)

    @app.route('/quick_report/<string:report_type>')
    @login_required
    def quick_report(report_type):
        """Generate quick reports without form submission"""
        from datetime import datetime, timedelta
        
        end_date = datetime.utcnow()
        
        # Define date ranges based on report type
        if report_type == 'daily':
            start_date = end_date - timedelta(days=1)
            report_name = 'Daily_Report'
        elif report_type == 'weekly':
            start_date = end_date - timedelta(days=7)
            report_name = 'Weekly_Report'
        elif report_type == 'monthly':
            start_date = end_date - timedelta(days=30)
            report_name = 'Monthly_Report'
        elif report_type == 'incident':
            # Incident report looks at last 24 hours with focus on suspicious activity
            start_date = end_date - timedelta(days=1)
            report_name = 'Incident_Report'
        else:
            flash('Invalid report type', 'danger')
            return redirect(url_for('reports'))
        
        # Get format from query parameter, default to pdf
        format = request.args.get('format', 'pdf')
        data_source = request.args.get('source', 'database')  # Default to database for reports
        
        # Validate format
        if format not in ['csv', 'pdf', 'ppt']:
            format = 'pdf'
        
        try:
            generator = ReportGenerator()
            
            # Generate report based on format
            if format == 'csv':
                filepath = generator.generate_csv_report('quick', start_date, end_date, data_source)
            elif format == 'pdf':
                filepath = generator.generate_pdf_report('quick', start_date, end_date, data_source)
            else:  # ppt
                filepath = generator.generate_ppt_report('quick', start_date, end_date, data_source)
            
            # Save report record to database
            report = Report(
                name=f"{report_name}_{start_date.strftime('%Y%m%d')}_{end_date.strftime('%Y%m%d')}",
                type='quick',
                format=format,
                generated_by=current_user.id,
                file_path=filepath,
                date_range_start=start_date,
                date_range_end=end_date
            )
            db.session.add(report)
            db.session.commit()
            
            # Log the action
            action = UserAction(
                user_id=current_user.id,
                action='Generate Quick Report',
                ip_address=request.remote_addr,
                details=f'Generated {report_type} {format} report (source: {data_source})'
            )
            db.session.add(action)
            db.session.commit()
            
            flash(f'{report_type.title()} report generated successfully!', 'success')
            return send_file(filepath, as_attachment=True, download_name=os.path.basename(filepath))
            
        except Exception as e:
            flash(f'Error generating report: {str(e)}', 'danger')
            print(f"Quick report error: {e}")
            import traceback
            traceback.print_exc()
            return redirect(url_for('reports'))

    @app.route('/quick_report/<string:report_type>/<string:format>')
    @login_required
    def quick_report_with_format(report_type, format):
        """Alternative route with format in URL path"""
        return redirect(url_for('quick_report', report_type=report_type, format=format))

    @app.route('/download_report/<int:report_id>')
    @login_required
    def download_report(report_id):
        """Download a generated report"""
        report = Report.query.get_or_404(report_id)
        
        # Check if user has permission (either the one who generated or admin)
        if report.generated_by != current_user.id and current_user.role != 'admin':
            flash('You do not have permission to download this report.', 'danger')
            return redirect(url_for('reports'))
        
        # Check if file exists
        if not os.path.exists(report.file_path):
            flash('Report file not found.', 'danger')
            return redirect(url_for('reports'))
        
        return send_file(report.file_path, as_attachment=True, download_name=os.path.basename(report.file_path))

    @app.route('/report/<int:report_id>/email', methods=['POST'])
    @login_required
    def email_report(report_id):
        """Email a report"""
        report = Report.query.get_or_404(report_id)
        
        # Check if user has permission
        if report.generated_by != current_user.id and current_user.role != 'admin':
            return jsonify({'success': False, 'error': 'Permission denied'}), 403
        
        try:
            from utils.email_utils import EmailNotifier
            emailer = EmailNotifier()
            
            # Send email
            emailer.send_report(
                report_path=report.file_path,
                report_name=report.name,
                recipient_emails=[current_user.email]
            )
            
            return jsonify({'success': True, 'message': 'Report emailed successfully'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/report/<int:report_id>/delete', methods=['POST'])
    @login_required
    def delete_report(report_id):
        """Delete a report"""
        report = Report.query.get_or_404(report_id)
        
        # Check if user has permission
        if report.generated_by != current_user.id and current_user.role != 'admin':
            return jsonify({'success': False, 'error': 'Permission denied'}), 403
        
        try:
            # Delete file if it exists
            if os.path.exists(report.file_path):
                os.remove(report.file_path)
            
            # Delete database record
            db.session.delete(report)
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'Report deleted successfully'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    # ================ EXPORT ROUTES ================

    @app.route('/export/alerts')
    @login_required
    def export_alerts():
        """Export alerts to CSV"""
        from utils.report_generator import ComprehensiveReportGenerator as ReportGenerator
        
        severity = request.args.get('severity', 'all')
        data_source = request.args.get('source', 'database')
        
        # Get date range (default to last 30 days)
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)
        
        if request.args.get('start_date'):
            try:
                start_date = datetime.fromisoformat(request.args.get('start_date').replace('Z', '+00:00'))
            except:
                pass
        
        if request.args.get('end_date'):
            try:
                end_date = datetime.fromisoformat(request.args.get('end_date').replace('Z', '+00:00'))
            except:
                pass
        
        generator = ReportGenerator()
        
        # For alerts, we'll use the CSV generator with a special type
        filepath = generator.generate_csv_report(
            report_type='alerts_export',
            start_date=start_date,
            end_date=end_date,
            data_source=data_source
        )
        
        # Log the action
        action = UserAction(
            user_id=current_user.id,
            action='Export Alerts',
            ip_address=request.remote_addr,
            details=f'Exported alerts with severity {severity}'
        )
        db.session.add(action)
        db.session.commit()
        
        return send_file(
            filepath, 
            as_attachment=True, 
            download_name=f"alerts_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mimetype='text/csv'
        )

    @app.route('/export/network-traffic')
    @login_required
    def export_network_traffic():
        """Export network traffic to CSV"""
        from utils.report_generator import ComprehensiveReportGenerator as ReportGenerator
        
        # Get parameters
        data_source = request.args.get('source', 'database')  # Default to database for exports
        
        # Get date range (default to last 24 hours)
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(hours=24)
        
        # Override with query params if provided
        if request.args.get('start_date'):
            try:
                start_date = datetime.fromisoformat(request.args.get('start_date').replace('Z', '+00:00'))
            except:
                pass
        
        if request.args.get('end_date'):
            try:
                end_date = datetime.fromisoformat(request.args.get('end_date').replace('Z', '+00:00'))
            except:
                pass
        
        generator = ReportGenerator()
        
        # Generate report with appropriate data source
        filepath = generator.generate_csv_report(
            report_type='network_export',
            start_date=start_date,
            end_date=end_date,
            data_source=data_source
        )
        
        # Log the action
        action = UserAction(
            user_id=current_user.id,
            action='Export Network Traffic',
            ip_address=request.remote_addr,
            details=f'Exported network traffic ({data_source} source)'
        )
        db.session.add(action)
        db.session.commit()
        
        return send_file(
            filepath, 
            as_attachment=True, 
            download_name=f"network_traffic_{data_source}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mimetype='text/csv'
        )

    @app.route('/export/processes')
    @login_required
    def export_processes():
        """Export host processes to CSV"""
        from utils.report_generator import ComprehensiveReportGenerator as ReportGenerator
        
        data_source = request.args.get('source', 'database')
        
        # Get date range (default to last 24 hours)
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(hours=24)
        
        if request.args.get('start_date'):
            try:
                start_date = datetime.fromisoformat(request.args.get('start_date').replace('Z', '+00:00'))
            except:
                pass
        
        if request.args.get('end_date'):
            try:
                end_date = datetime.fromisoformat(request.args.get('end_date').replace('Z', '+00:00'))
            except:
                pass
        
        generator = ReportGenerator()
        
        filepath = generator.generate_csv_report(
            report_type='processes_export',
            start_date=start_date,
            end_date=end_date,
            data_source=data_source
        )
        
        # Log the action
        action = UserAction(
            user_id=current_user.id,
            action='Export Processes',
            ip_address=request.remote_addr,
            details=f'Exported process data ({data_source} source)'
        )
        db.session.add(action)
        db.session.commit()
        
        return send_file(
            filepath, 
            as_attachment=True, 
            download_name=f"processes_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mimetype='text/csv'
        )

    @app.route('/export/live-capture')
    @login_required
    def export_live_capture():
        """Quick export of live capture data (convenience endpoint)"""
        return redirect(url_for('export_network_traffic', source='live'))

    # ================ API ROUTES ================

    @app.route('/api/traffic/stats')
    @login_required
    def api_traffic_stats():
        """Get traffic statistics for dashboard"""
        last_minute = datetime.utcnow() - timedelta(minutes=1)
        traffic_count = NetworkTraffic.query.filter(NetworkTraffic.timestamp > last_minute).count()
        suspicious_count = NetworkTraffic.query.filter(NetworkTraffic.timestamp > last_minute, NetworkTraffic.is_suspicious==True).count()
        
        return jsonify({
            'traffic_per_minute': traffic_count,
            'suspicious_per_minute': suspicious_count,
            'timestamp': datetime.utcnow().isoformat()
        })

    # ================ INVESTIGATION ROUTES ================

    @app.route('/investigate/<int:alert_id>')
    @login_required
    def investigate_alert(alert_id):
        """Investigate an alert (redirect to relevant monitor)"""
        alert = Alert.query.get_or_404(alert_id)
        
        if alert.source == 'network':
            return redirect(url_for('network_monitor', alert_id=alert_id))
        else:
            return redirect(url_for('host_monitor', alert_id=alert_id))

    # ================ USER PROFILE ROUTES ================

    @app.route('/settings', methods=['GET', 'POST'])
    @login_required
    def settings():
        form = UpdateProfileForm()
        
        if form.validate_on_submit():
            current_user.username = form.username.data
            current_user.email = form.email.data
            current_user.first_name = form.first_name.data
            current_user.last_name = form.last_name.data
            current_user.phone_number = form.phone_number.data
            current_user.department = form.department.data
            
            if form.password.data:
                current_user.password_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            
            db.session.commit()
            flash('Your profile has been updated!', 'success')
            return redirect(url_for('settings'))
        
        elif request.method == 'GET':
            form.username.data = current_user.username
            form.email.data = current_user.email
            form.first_name.data = current_user.first_name
            form.last_name.data = current_user.last_name
            form.phone_number.data = current_user.phone_number
            form.department.data = current_user.department
        
        return render_template('settings.html', title='Settings', form=form)

    @app.route('/profile')
    @login_required
    def profile():
        return render_template('profile.html', title='Profile', user=current_user)

    @app.route('/logout')
    def logout():
        if current_user.is_authenticated:
            action = UserAction(
                user_id=current_user.id,
                action='Logout',
                ip_address=request.remote_addr,
                details='User logged out'
            )
            db.session.add(action)
            db.session.commit()
        
        logout_user()
        flash('You have been logged out.', 'info')
        return redirect(url_for('login'))

    # ================ DEBUG ROUTE ================

    @app.route('/api/debug/data-check')
    @login_required
    def debug_data_check():
        """Check what data exists in the system for debugging"""
        try:
            total_alerts = Alert.query.count()
            total_network = NetworkTraffic.query.count()
            total_host = HostActivity.query.count()
            
            # Get latest entries
            latest_alert = Alert.query.order_by(Alert.timestamp.desc()).first()
            latest_network = NetworkTraffic.query.order_by(NetworkTraffic.timestamp.desc()).first()
            latest_host = HostActivity.query.order_by(HostActivity.timestamp.desc()).first()
            
            # Get date range of data
            oldest_alert = Alert.query.order_by(Alert.timestamp.asc()).first()
            oldest_network = NetworkTraffic.query.order_by(NetworkTraffic.timestamp.asc()).first()
            oldest_host = HostActivity.query.order_by(HostActivity.timestamp.asc()).first()
            
            # Get counts by severity
            critical_alerts = Alert.query.filter_by(severity='critical').count()
            high_alerts = Alert.query.filter_by(severity='high').count()
            medium_alerts = Alert.query.filter_by(severity='medium').count()
            low_alerts = Alert.query.filter_by(severity='low').count()
            
            # Get suspicious counts
            suspicious_network = NetworkTraffic.query.filter_by(is_suspicious=True).count()
            suspicious_host = HostActivity.query.filter_by(is_suspicious=True).count()
            
            return jsonify({
                'success': True,
                'counts': {
                    'alerts': total_alerts,
                    'network_packets': total_network,
                    'host_activities': total_host,
                    'critical_alerts': critical_alerts,
                    'high_alerts': high_alerts,
                    'medium_alerts': medium_alerts,
                    'low_alerts': low_alerts,
                    'suspicious_network_packets': suspicious_network,
                    'suspicious_host_processes': suspicious_host
                },
                'latest': {
                    'alert': latest_alert.timestamp.isoformat() if latest_alert else None,
                    'network': latest_network.timestamp.isoformat() if latest_network else None,
                    'host': latest_host.timestamp.isoformat() if latest_host else None
                },
                'oldest': {
                    'alert': oldest_alert.timestamp.isoformat() if oldest_alert else None,
                    'network': oldest_network.timestamp.isoformat() if oldest_network else None,
                    'host': oldest_host.timestamp.isoformat() if oldest_host else None
                },
                'message': 'Use this data to verify your report date ranges cover when data exists'
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    # ================ SOCKET.IO EVENTS ================

    @socketio.on('connect')
    def handle_connect():
        if current_user.is_authenticated:
            emit('connected', {'message': 'Connected to real-time feed'})
            
            # Send initial data
            recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(5).all()
            emit('initial_alerts', [{
                'id': a.id,
                'severity': a.severity,
                'description': a.description,
                'timestamp': a.timestamp.strftime('%H:%M:%S')
            } for a in recent_alerts])
            
            # Send threat data
            emit_threat_update()

    @socketio.on('disconnect')
    def handle_disconnect():
        if current_user.is_authenticated:
            print(f'Client disconnected: {current_user.username}')

    @socketio.on('request_update')
    def handle_update_request():
        recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(5).all()
        emit('update', {
            'alerts': [{
                'id': a.id,
                'severity': a.severity,
                'description': a.description,
                'timestamp': a.timestamp.strftime('%H:%M:%S')
            } for a in recent_alerts]
        })

    # ================ ERROR HANDLERS ================

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('500.html'), 500


# For backward compatibility
init_routes = register_routes
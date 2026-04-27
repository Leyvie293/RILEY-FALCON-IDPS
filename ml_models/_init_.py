# routes.py
from flask import render_template, redirect, url_for, flash, request, jsonify, send_file
from flask_login import login_user, current_user, logout_user, login_required
from __init__ import app, db, bcrypt, socketio
from models import User, Alert, NetworkTraffic, HostActivity, Report, UserAction
from forms import LoginForm, RegistrationForm, UpdateProfileForm, ReportForm
from utils.report_generator import ReportGenerator
from flask_socketio import emit
from datetime import datetime, timedelta
import pytz
import json
import os

EAT = pytz.timezone('Africa/Nairobi')

def init_routes(app):
    
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
        
        last_hour = datetime.utcnow() - timedelta(hours=1)
        traffic_data = NetworkTraffic.query.filter(NetworkTraffic.timestamp > last_hour).all()
        
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
                             chart_values=json.dumps(chart_values[::-1]))

    @app.route('/network_monitor')
    @login_required
    def network_monitor():
        page = request.args.get('page', 1, type=int)
        traffic = NetworkTraffic.query.order_by(NetworkTraffic.timestamp.desc()).paginate(page=page, per_page=50)
        
        total_traffic = NetworkTraffic.query.count()
        suspicious = NetworkTraffic.query.filter_by(is_suspicious=True).count()
        protocols = db.session.query(NetworkTraffic.protocol, db.func.count(NetworkTraffic.protocol)).group_by(NetworkTraffic.protocol).all()
        
        return render_template('network_monitor.html',
                             title='Network Monitor',
                             traffic=traffic,
                             total_traffic=total_traffic,
                             suspicious=suspicious,
                             protocols=protocols)

    @app.route('/host_monitor')
    @login_required
    def host_monitor():
        page = request.args.get('page', 1, type=int)
        activities = HostActivity.query.order_by(HostActivity.timestamp.desc()).paginate(page=page, per_page=50)
        
        total_processes = HostActivity.query.count()
        suspicious_processes = HostActivity.query.filter_by(is_suspicious=True).count()
        
        top_cpu = HostActivity.query.order_by(HostActivity.cpu_usage.desc()).limit(10).all()
        
        return render_template('host_monitor.html',
                             title='Host Monitor',
                             activities=activities,
                             total_processes=total_processes,
                             suspicious_processes=suspicious_processes,
                             top_cpu=top_cpu)

    @app.route('/alerts')
    @login_required
    def alerts():
        page = request.args.get('page', 1, type=int)
        severity = request.args.get('severity', 'all')
        
        if severity != 'all':
            alerts = Alert.query.filter_by(severity=severity).order_by(Alert.timestamp.desc()).paginate(page=page, per_page=50)
        else:
            alerts = Alert.query.order_by(Alert.timestamp.desc()).paginate(page=page, per_page=50)
        
        critical_count = Alert.query.filter_by(severity='critical', is_resolved=False).count()
        high_count = Alert.query.filter_by(severity='high', is_resolved=False).count()
        medium_count = Alert.query.filter_by(severity='medium', is_resolved=False).count()
        low_count = Alert.query.filter_by(severity='low', is_resolved=False).count()
        
        return render_template('alerts.html',
                             title='Alerts',
                             alerts=alerts,
                             critical_count=critical_count,
                             high_count=high_count,
                             medium_count=medium_count,
                             low_count=low_count,
                             current_severity=severity)

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
        
        flash('Alert marked as resolved.', 'success')
        return redirect(url_for('alerts'))

    @app.route('/reports', methods=['GET', 'POST'])
    @login_required
    def reports():
        form = ReportForm()
        
        if form.validate_on_submit():
            generator = ReportGenerator()
            
            start_date = form.start_date.data
            end_date = form.end_date.data
            
            if form.report_type.data == 'csv':
                filepath = generator.generate_csv_report('custom', start_date, end_date)
            elif form.report_type.data == 'pdf':
                filepath = generator.generate_pdf_report('custom', start_date, end_date)
            else:
                filepath = generator.generate_ppt_report('custom', start_date, end_date)
            
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

    @app.route('/api/traffic/stats')
    @login_required
    def api_traffic_stats():
        last_minute = datetime.utcnow() - timedelta(minutes=1)
        traffic_count = NetworkTraffic.query.filter(NetworkTraffic.timestamp > last_minute).count()
        suspicious_count = NetworkTraffic.query.filter(NetworkTraffic.timestamp > last_minute, NetworkTraffic.is_suspicious==True).count()
        
        return jsonify({
            'traffic_per_minute': traffic_count,
            'suspicious_per_minute': suspicious_count,
            'timestamp': datetime.utcnow().isoformat()
        })

    @app.route('/api/alerts/recent')
    @login_required
    def api_recent_alerts():
        alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(5).all()
        return jsonify([{
            'id': a.id,
            'severity': a.severity,
            'description': a.description,
            'timestamp': a.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'is_resolved': a.is_resolved
        } for a in alerts])

    @socketio.on('connect')
    def handle_connect():
        if current_user.is_authenticated:
            emit('connected', {'message': 'Connected to real-time feed'})

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

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('500.html'), 500
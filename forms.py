# forms.py - PRODUCTION READY
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField, DateField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Regexp, Optional, NumberRange
from models import User
from datetime import datetime
import re

# Custom validators
def strong_password(form, field):
    """Validate password strength - 8 chars with lowercase, uppercase, symbols and digits"""
    password = field.data
    
    # Changed from 12 to 8 characters
    if len(password) < 8:
        raise ValidationError('Password must be at least 8 characters long.')
    
    if not re.search(r'[A-Z]', password):
        raise ValidationError('Password must contain at least one uppercase letter.')
    
    if not re.search(r'[a-z]', password):
        raise ValidationError('Password must contain at least one lowercase letter.')
    
    if not re.search(r'\d', password):
        raise ValidationError('Password must contain at least one number.')
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValidationError('Password must contain at least one special character.')

def no_special_chars(form, field):
    """Prevent special characters in username"""
    if re.search(r'[^a-zA-Z0-9_]', field.data):
        raise ValidationError('Username can only contain letters, numbers, and underscores.')

def validate_phone(form, field):
    """Validate phone number format"""
    if field.data:
        phone = re.sub(r'[\s\-\(\)]', '', field.data)
        if not re.match(r'^\+?[0-9]{10,15}$', phone):
            raise ValidationError('Invalid phone number format.')

class LoginForm(FlaskForm):
    """Enhanced login form with rate limiting support"""
    email = StringField('Email', validators=[
        DataRequired(message='Email is required.'),
        Email(message='Please enter a valid email address.'),
        Length(max=120)
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required.')
    ])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    """Enhanced registration form with strong password requirements"""
    username = StringField('Username', validators=[
        DataRequired(message='Username is required.'),
        Length(min=3, max=50, message='Username must be between 3 and 50 characters.'),
        no_special_chars
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email is required.'),
        Email(message='Please enter a valid email address.'),
        Length(max=120)
    ])
    first_name = StringField('First Name', validators=[
        DataRequired(message='First name is required.'),
        Length(min=2, max=50, message='First name must be between 2 and 50 characters.')
    ])
    last_name = StringField('Last Name', validators=[
        DataRequired(message='Last name is required.'),
        Length(min=2, max=50, message='Last name must be between 2 and 50 characters.')
    ])
    phone_number = StringField('Phone Number', validators=[
        Optional(),
        validate_phone
    ])
    department = SelectField('Department', choices=[
        ('IT', 'Information Technology'),
        ('Security', 'Security Operations'),
        ('Management', 'Management'),
        ('HR', 'Human Resources'),
        ('Finance', 'Finance'),
        ('Operations', 'Operations'),
        ('Other', 'Other')
    ], validators=[DataRequired(message='Please select a department.')])
    
    # Security questions for password recovery
    security_question_1 = SelectField('Security Question 1', choices=[
        ('', 'Select a question...'),
        ('pet', 'What was your first pet\'s name?'),
        ('mother', 'What is your mother\'s maiden name?'),
        ('school', 'What was your first school?'),
        ('city', 'In which city were you born?')
    ], validators=[DataRequired()])
    security_answer_1 = StringField('Answer 1', validators=[
        DataRequired(),
        Length(min=2, max=100)
    ])
    
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required.'),
        strong_password
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message='Please confirm your password.'),
        EqualTo('password', message='Passwords must match.')
    ])
    accept_terms = BooleanField('I accept the Terms and Conditions', validators=[
        DataRequired(message='You must accept the terms to register.')
    ])
    submit = SubmitField('Create Account')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken. Please choose another.')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data.lower()).first()
        if user:
            raise ValidationError('Email already registered. Please use another or login.')

class UpdateProfileForm(FlaskForm):
    """Profile update form with validation"""
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=50),
        no_special_chars
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email(),
        Length(max=120)
    ])
    first_name = StringField('First Name', validators=[
        DataRequired(),
        Length(min=2, max=50)
    ])
    last_name = StringField('Last Name', validators=[
        DataRequired(),
        Length(min=2, max=50)
    ])
    phone_number = StringField('Phone Number', validators=[
        Optional(),
        validate_phone
    ])
    department = SelectField('Department', choices=[
        ('IT', 'Information Technology'),
        ('Security', 'Security Operations'),
        ('Management', 'Management'),
        ('HR', 'Human Resources'),
        ('Finance', 'Finance'),
        ('Operations', 'Operations'),
        ('Other', 'Other')
    ])
    current_password = PasswordField('Current Password', validators=[
        DataRequired(message='Current password is required to update profile.')
    ])
    new_password = PasswordField('New Password', validators=[
        Optional(),
        strong_password
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        EqualTo('new_password', message='Passwords must match.')
    ])
    submit = SubmitField('Update Profile')
    
    def validate_username(self, username):
        if username.data != self._original_username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Username already taken.')
    
    def validate_email(self, email):
        if email.data != self._original_email:
            user = User.query.filter_by(email=email.data.lower()).first()
            if user:
                raise ValidationError('Email already registered.')
    
    def __init__(self, original_username, original_email, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._original_username = original_username
        self._original_email = original_email

class ReportForm(FlaskForm):
    """Report generation form with validation"""
    report_type = SelectField('Report Type', choices=[
        ('csv', 'CSV Format'),
        ('pdf', 'PDF Format'),
        ('ppt', 'PowerPoint Format')
    ], validators=[DataRequired()])
    
    data_source = SelectField('Data Source', choices=[
        ('database', 'Database (Historical)'),
        ('live', 'Live Monitor Data')
    ], validators=[DataRequired()])
    
    start_date = DateField('Start Date', validators=[DataRequired()], 
                          default=datetime.now, format='%Y-%m-%d')
    end_date = DateField('End Date', validators=[DataRequired()], 
                        default=datetime.now, format='%Y-%m-%d')
    
    include_network = BooleanField('Include Network Traffic', default=True)
    include_host = BooleanField('Include Host Activity', default=True)
    include_alerts = BooleanField('Include Alerts', default=True)
    include_summary_only = BooleanField('Summary Only (No Details)', default=False)
    
    submit = SubmitField('Generate Report')
    
    def validate_dates(self, field):
        if self.start_date.data and self.end_date.data:
            if self.start_date.data > self.end_date.data:
                raise ValidationError('Start date must be before end date.')
            
            date_range = (self.end_date.data - self.start_date.data).days
            if date_range > 365:
                raise ValidationError('Date range cannot exceed 365 days.')

class ForgotPasswordForm(FlaskForm):
    """Password reset request form"""
    email = StringField('Email', validators=[
        DataRequired(message='Email is required.'),
        Email(message='Please enter a valid email address.')
    ])
    submit = SubmitField('Send Reset Instructions')

class ResetPasswordForm(FlaskForm):
    """Password reset form with strength validation"""
    password = PasswordField('New Password', validators=[
        DataRequired(message='Password is required.'),
        strong_password
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(message='Please confirm your password.'),
        EqualTo('password', message='Passwords must match.')
    ])
    submit = SubmitField('Reset Password')

class MFAForm(FlaskForm):
    """Multi-factor authentication form"""
    token = StringField('Authentication Code', validators=[
        DataRequired(message='Authentication code is required.'),
        Length(min=6, max=6, message='Code must be 6 digits.'),
        Regexp(r'^\d+$', message='Code must contain only numbers.')
    ])
    submit = SubmitField('Verify')
    remember_device = BooleanField('Remember this device for 30 days')

class MFASetupForm(FlaskForm):
    """MFA setup form"""
    enable_mfa = BooleanField('Enable Two-Factor Authentication')
    verify_token = StringField('Verification Code', validators=[
        Optional(),
        Length(min=6, max=6),
        Regexp(r'^\d+$', message='Code must contain only numbers.')
    ])
    submit = SubmitField('Save MFA Settings')

class AlertFilterForm(FlaskForm):
    """Alert filtering form"""
    severity = SelectField('Severity', choices=[
        ('all', 'All Severities'),
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low')
    ])
    alert_type = SelectField('Type', choices=[
        ('all', 'All Types'),
        ('signature', 'Signature-Based'),
        ('anomaly', 'Anomaly-Based')
    ])
    source = SelectField('Source', choices=[
        ('all', 'All Sources'),
        ('network', 'Network'),
        ('host', 'Host')
    ])
    status = SelectField('Status', choices=[
        ('all', 'All'),
        ('active', 'Active'),
        ('resolved', 'Resolved')
    ])
    search = StringField('Search', validators=[Optional(), Length(max=100)])
    submit = SubmitField('Apply Filters')

class APITokenForm(FlaskForm):
    """API token management form"""
    name = StringField('Token Name', validators=[
        DataRequired(),
        Length(min=3, max=100)
    ])
    expires_days = IntegerField('Expires After (Days)', validators=[
        DataRequired(),
        NumberRange(min=1, max=365)
    ], default=90)
    permissions = SelectField('Permissions', choices=[
        ('read', 'Read Only'),
        ('read_write', 'Read & Write'),
        ('admin', 'Admin')
    ], default='read')
    submit = SubmitField('Generate API Token')

class DataRetentionForm(FlaskForm):
    """Data retention configuration form (admin only)"""
    network_traffic_days = IntegerField('Network Traffic (days)', validators=[
        DataRequired(),
        NumberRange(min=1, max=365)
    ], default=30)
    host_activities_days = IntegerField('Host Activities (days)', validators=[
        DataRequired(),
        NumberRange(min=1, max=365)
    ], default=30)
    alerts_days = IntegerField('Alerts (days)', validators=[
        DataRequired(),
        NumberRange(min=1, max=730)
    ], default=90)
    audit_logs_days = IntegerField('Audit Logs (days)', validators=[
        DataRequired(),
        NumberRange(min=1, max=1095)
    ], default=365)
    submit = SubmitField('Save Retention Settings')

class SystemSettingsForm(FlaskForm):
    """System settings form (admin only)"""
    # Monitoring settings
    network_monitor_enabled = BooleanField('Enable Network Monitor', default=True)
    host_monitor_enabled = BooleanField('Enable Host Monitor', default=True)
    network_interface = StringField('Network Interface', validators=[Optional()])
    monitor_interval = IntegerField('Monitor Interval (seconds)', validators=[
        DataRequired(),
        NumberRange(min=1, max=60)
    ], default=3)
    
    # Alert settings
    alert_email_enabled = BooleanField('Send Email Alerts', default=True)
    alert_slack_enabled = BooleanField('Send Slack Alerts', default=False)
    slack_webhook = StringField('Slack Webhook URL', validators=[Optional(), Length(max=500)])
    critical_alert_sound = BooleanField('Play Sound for Critical Alerts', default=True)
    
    # AI settings
    ai_enabled = BooleanField('Enable AI Detection', default=True)
    anomaly_threshold = StringField('Anomaly Threshold', default='0.85')
    
    # System settings
    debug_mode = BooleanField('Debug Mode', default=False)
    maintenance_mode = BooleanField('Maintenance Mode', default=False)
    
    submit = SubmitField('Save Settings')
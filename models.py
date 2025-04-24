from datetime import datetime
from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    
    # Relationships
    alerts = db.relationship('Alert', backref='user', lazy='dynamic')
    datasets = db.relationship('Dataset', backref='user', lazy='dynamic')
    activities = db.relationship('UserActivity', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Dataset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    file_path = db.Column(db.String(200), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    file_type = db.Column(db.String(20))
    file_size = db.Column(db.Integer)  # Size in bytes
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    analyses = db.relationship('Analysis', backref='dataset', lazy='dynamic')

class Analysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    analysis_type = db.Column(db.String(50), nullable=False)  # 'anomaly', 'behavior', 'vulnerability'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    result_summary = db.Column(db.Text)
    dataset_id = db.Column(db.Integer, db.ForeignKey('dataset.id'), nullable=False)
    
    # Relationships
    anomalies = db.relationship('Anomaly', backref='analysis', lazy='dynamic')

class Anomaly(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    severity = db.Column(db.String(20))  # low, medium, high, critical
    description = db.Column(db.Text)
    source_ip = db.Column(db.String(20))
    destination_ip = db.Column(db.String(20))
    analysis_id = db.Column(db.Integer, db.ForeignKey('analysis.id'), nullable=False)
    is_false_positive = db.Column(db.Boolean, default=False)
    remediation_steps = db.Column(db.Text)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20))  # low, medium, high, critical
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    related_anomaly_id = db.Column(db.Integer, db.ForeignKey('anomaly.id'))
    
    related_anomaly = db.relationship('Anomaly')

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20))  # low, medium, high, critical
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='open')  # open, in_progress, resolved, false_positive
    affected_system = db.Column(db.String(100))
    cve_id = db.Column(db.String(20))
    remediation_steps = db.Column(db.Text)

class IncidentResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20))  # low, medium, high, critical
    status = db.Column(db.String(20), default='open')  # open, in_progress, resolved, false_positive
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    resolution_summary = db.Column(db.Text)
    related_anomaly_id = db.Column(db.Integer, db.ForeignKey('anomaly.id'))
    
    related_anomaly = db.relationship('Anomaly')

class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    activity_type = db.Column(db.String(50), nullable=False)  # login, logout, file_upload, analysis, etc.
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(20))
    user_agent = db.Column(db.String(200))
    details = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

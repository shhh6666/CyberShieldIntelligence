from flask import render_template, current_app
from flask_mail import Message
from extensions import mail
import os

def send_email(subject, recipients, html_body):
    msg = Message(subject, recipients=recipients)
    msg.html = html_body
    
    try:
        mail.send(msg)
        return True
    except Exception as e:
        current_app.logger.error(f"Failed to send email: {str(e)}")
        return False

def send_welcome_email(user):
    """Send a welcome email to newly registered users."""
    subject = "Welcome to CyberTech - Cybersecurity Breach Detection System"
    recipients = [user.email]
    
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #1a1a2e; color: #e6e6e6; border-radius: 10px;">
        <h1 style="color: #4cc9f0;">Welcome to CyberTech!</h1>
        <p>Hello {user.username},</p>
        <p>Thank you for registering with CyberTech - your advanced cybersecurity breach detection system.</p>
        <p>Your account has been successfully created. You can now log in and start using our powerful security features:</p>
        <ul>
            <li>Real-time anomaly detection</li>
            <li>User behavior assessment</li>
            <li>Vulnerability management</li>
            <li>Automated incident response</li>
            <li>Enhanced security analytics</li>
        </ul>
        <p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p>
        <p>Best regards,<br>The CyberTech Team</p>
        <p style="font-size: 12px; margin-top: 30px; color: #a0a0a0;">© Simbarashe Chimbera. All rights reserved.</p>
    </div>
    """
    
    # Always copy to system administrator (as requested in requirements)
    all_recipients = recipients.copy()
    all_recipients.append("simbabhonto@gmail.com")
    
    return send_email(subject, all_recipients, html_body)

def send_anomaly_alert_email(user, count, analysis_name):
    """Send an alert email when critical anomalies are detected."""
    subject = f"ALERT: {count} Critical Anomalies Detected in CyberTech"
    recipients = [user.email]
    
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #1a1a2e; color: #e6e6e6; border-radius: 10px;">
        <h1 style="color: #f72585;">Security Alert!</h1>
        <p>Hello {user.username},</p>
        <p>Your recent analysis <strong>"{analysis_name}"</strong> has detected <strong>{count} critical anomalies</strong> that require immediate attention.</p>
        <p>Please log in to the CyberTech dashboard to review these anomalies and take appropriate action. Critical anomalies may indicate active security breaches or significant vulnerabilities in your systems.</p>
        <p style="background-color: #3a0ca3; padding: 15px; border-radius: 5px;">
            <strong>Recommendation:</strong> Review all detected anomalies as soon as possible and implement the suggested remediation steps.
        </p>
        <p>Best regards,<br>The CyberTech Security Team</p>
        <p style="font-size: 12px; margin-top: 30px; color: #a0a0a0;">© Simbarashe Chimbera. All rights reserved.</p>
    </div>
    """
    
    # Always copy to system administrator (as requested in requirements)
    all_recipients = recipients.copy()
    all_recipients.append("simbabhonto@gmail.com")
    
    return send_email(subject, all_recipients, html_body)

def send_vulnerability_alert_email(user, count, scan_name):
    """Send an alert email when critical vulnerabilities are detected."""
    subject = f"ALERT: {count} Critical Vulnerabilities Detected in CyberTech"
    recipients = [user.email]
    
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #1a1a2e; color: #e6e6e6; border-radius: 10px;">
        <h1 style="color: #f72585;">Vulnerability Alert!</h1>
        <p>Hello {user.username},</p>
        <p>Your recent vulnerability scan <strong>"{scan_name}"</strong> has detected <strong>{count} critical vulnerabilities</strong> that require immediate attention.</p>
        <p>Please log in to the CyberTech dashboard to review these vulnerabilities and take appropriate action to secure your systems.</p>
        <p style="background-color: #3a0ca3; padding: 15px; border-radius: 5px;">
            <strong>Recommendation:</strong> Address critical vulnerabilities immediately as they may be exploited by attackers to compromise your systems.
        </p>
        <p>Best regards,<br>The CyberTech Security Team</p>
        <p style="font-size: 12px; margin-top: 30px; color: #a0a0a0;">© Simbarashe Chimbera. All rights reserved.</p>
    </div>
    """
    
    # Always copy to system administrator (as requested in requirements)
    all_recipients = recipients.copy()
    all_recipients.append("simbabhonto@gmail.com")
    
    return send_email(subject, all_recipients, html_body)

def send_incident_response_email(user, incident):
    """Send an email notification when an incident is created."""
    subject = f"New Security Incident: {incident.title}"
    recipients = [user.email]
    
    severity_color = {
        'critical': '#f72585',
        'high': '#ff5400',
        'medium': '#ffbe0b',
        'low': '#06d6a0'
    }
    
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #1a1a2e; color: #e6e6e6; border-radius: 10px;">
        <h1 style="color: #4cc9f0;">New Security Incident</h1>
        <p>Hello,</p>
        <p>A new security incident has been created in the CyberTech system:</p>
        <div style="background-color: #16213e; padding: 15px; border-radius: 5px; margin: 15px 0;">
            <p><strong>Title:</strong> {incident.title}</p>
            <p><strong>Severity:</strong> <span style="color: {severity_color.get(incident.severity, '#ffffff')};">{incident.severity.upper()}</span></p>
            <p><strong>Created by:</strong> {user.username}</p>
            <p><strong>Created at:</strong> {incident.created_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Description:</strong> {incident.description}</p>
        </div>
        <p>Please log in to the CyberTech dashboard to review and respond to this incident.</p>
        <p>Best regards,<br>The CyberTech Security Team</p>
        <p style="font-size: 12px; margin-top: 30px; color: #a0a0a0;">© Simbarashe Chimbera. All rights reserved.</p>
    </div>
    """
    
    # Always copy to system administrator (as requested in requirements)
    all_recipients = recipients.copy()
    all_recipients.append("simbabhonto@gmail.com")
    
    return send_email(subject, all_recipients, html_body)

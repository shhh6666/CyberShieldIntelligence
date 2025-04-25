from flask import Blueprint, render_template, flash, redirect, url_for, request, jsonify
from flask_login import login_required, current_user
from extensions import db
from models import IncidentResponse, Anomaly, UserActivity
from forms import IncidentResponseForm
from utils.email import send_incident_response_email
from utils.sms import send_incident_sms
from datetime import datetime

incident_response = Blueprint('incident_response', __name__)

# Add global context processor to provide 'now' to all templates
@incident_response.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

@incident_response.route('/incident_response', methods=['GET', 'POST'])
@login_required
def manage_incidents():
    form = IncidentResponseForm()
    
    if form.validate_on_submit():
        # Create a new incident
        incident = IncidentResponse(
            title=form.title.data,
            description=form.description.data,
            severity=form.severity.data,
            status='open',
            affected_systems=form.affected_systems.data
        )
        db.session.add(incident)
        
        # Log activity
        activity = UserActivity(
            user_id=current_user.id,
            activity_type='incident_created',
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details=f'Created incident: {form.title.data}'
        )
        db.session.add(activity)
        db.session.commit()
        
        # Send notification email
        send_incident_response_email(current_user, incident)
        
        # Send SMS for critical/high severity incidents
        if incident.severity in ['critical', 'high']:
            sms_result = send_incident_sms(current_user, incident)
            if sms_result.get('success'):
                flash(f'Incident created successfully. SMS notification sent to {current_user.phone_number}.', 'success')
            else:
                if current_user.phone_number:
                    if 'User has not opted in to SMS notifications' in sms_result.get('error', ''):
                        flash(f'Incident created successfully. Email notification sent. To receive SMS alerts, enable SMS notifications in Settings.', 'success')
                    else:
                        flash(f'Incident created successfully. Email notification sent. SMS notification failed: {sms_result.get("error")}', 'warning')
                else:
                    flash(f'Incident created successfully. Email notification sent. To receive SMS alerts, add your phone number in Settings.', 'success')
        else:
            flash('Incident created successfully. Email notification sent.', 'success')
        return redirect(url_for('incident_response.manage_incidents'))
    
    # Get all incidents
    incidents = IncidentResponse.query.order_by(IncidentResponse.created_at.desc()).all()
    
    # Get counts by status
    open_count = IncidentResponse.query.filter_by(status='open').count()
    in_progress_count = IncidentResponse.query.filter_by(status='in_progress').count()
    resolved_count = IncidentResponse.query.filter_by(status='resolved').count()
    
    # Get counts by severity
    critical_count = IncidentResponse.query.filter_by(severity='critical').count()
    high_count = IncidentResponse.query.filter_by(severity='high').count()
    medium_count = IncidentResponse.query.filter_by(severity='medium').count()
    low_count = IncidentResponse.query.filter_by(severity='low').count()
    
    return render_template('dashboard/incident_response.html',
                          title='Incident Response',
                          form=form,
                          incidents=incidents,
                          open_count=open_count,
                          in_progress_count=in_progress_count,
                          resolved_count=resolved_count,
                          critical_count=critical_count,
                          high_count=high_count,
                          medium_count=medium_count,
                          low_count=low_count)

@incident_response.route('/update_incident_status/<int:incident_id>', methods=['POST'])
@login_required
def update_incident_status(incident_id):
    incident = IncidentResponse.query.get_or_404(incident_id)
    
    # Get the new status from the request
    status = request.json.get('status')
    if status not in ['open', 'in_progress', 'resolved']:
        return jsonify({'success': False, 'message': 'Invalid status'}), 400
    
    # Update incident status
    incident.status = status
    
    # If resolved, update the resolved_at timestamp
    if status == 'resolved':
        incident.resolved_at = datetime.utcnow()
    
    # Log activity
    activity = UserActivity(
        user_id=current_user.id,
        activity_type='incident_status_update',
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        details=f'Updated incident status: {incident.title} to {status}'
    )
    db.session.add(activity)
    db.session.commit()
    
    return jsonify({'success': True})

@incident_response.route('/incident_details/<int:incident_id>')
@login_required
def incident_details(incident_id):
    incident = IncidentResponse.query.get_or_404(incident_id)
    
    # If there's a related anomaly, get it
    related_anomaly = None
    if incident.related_anomaly_id:
        related_anomaly = Anomaly.query.get(incident.related_anomaly_id)
    
    return render_template('dashboard/incident_details.html',
                          title='Incident Details',
                          incident=incident,
                          related_anomaly=related_anomaly)

@incident_response.route('/create_incident_from_anomaly/<int:anomaly_id>', methods=['POST'])
@login_required
def create_incident_from_anomaly(anomaly_id):
    anomaly = Anomaly.query.get_or_404(anomaly_id)
    
    # Create a new incident based on the anomaly
    incident = IncidentResponse(
        title=f"Incident from anomaly: {anomaly.description[:50]}",
        description=f"This incident was automatically created from an anomaly.\n\n{anomaly.description}",
        severity=anomaly.severity,
        status='open',
        related_anomaly_id=anomaly.id
    )
    db.session.add(incident)
    
    # Log activity
    activity = UserActivity(
        user_id=current_user.id,
        activity_type='incident_created_from_anomaly',
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        details=f'Created incident from anomaly: {anomaly.id}'
    )
    db.session.add(activity)
    db.session.commit()
    
    # Send notification email
    send_incident_response_email(current_user, incident)
    
    # Send SMS for critical/high severity incidents
    if incident.severity in ['critical', 'high']:
        sms_result = send_incident_sms(current_user, incident)
        if sms_result.get('success'):
            flash(f'Incident created from anomaly successfully. SMS notification sent to {current_user.phone_number}.', 'success')
        else:
            if current_user.phone_number:
                if 'User has not opted in to SMS notifications' in sms_result.get('error', ''):
                    flash(f'Incident created from anomaly successfully. Email notification sent. To receive SMS alerts, enable SMS notifications in Settings.', 'success')
                else:
                    flash(f'Incident created from anomaly successfully. Email notification sent. SMS notification failed: {sms_result.get("error")}', 'warning')
            else:
                flash(f'Incident created from anomaly successfully. Email notification sent. To receive SMS alerts, add your phone number in Settings.', 'success')
    else:
        flash('Incident created from anomaly successfully. Email notification sent.', 'success')
    return redirect(url_for('incident_response.incident_details', incident_id=incident.id))

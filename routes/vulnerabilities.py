from flask import Blueprint, render_template, flash, redirect, url_for, request, jsonify
from flask_login import login_required, current_user
from extensions import db
from models import Vulnerability, UserActivity
from forms import VulnerabilityScanForm
from utils.vulnerability_scan import scan_for_vulnerabilities
from utils.email import send_vulnerability_alert_email
from datetime import datetime

vulnerabilities = Blueprint('vulnerabilities', __name__)

@vulnerabilities.route('/vulnerability_management', methods=['GET', 'POST'])
@login_required
def vulnerability_management():
    form = VulnerabilityScanForm()
    
    if form.validate_on_submit():
        # Log activity
        activity = UserActivity(
            user_id=current_user.id,
            activity_type='vulnerability_scan_start',
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details=f'Started vulnerability scan: {form.scan_name.data}'
        )
        db.session.add(activity)
        db.session.commit()
        
        # Parse target systems
        target_systems_data = form.target_systems.data or ""
        target_systems = [s.strip() for s in target_systems_data.split('\n') if s.strip()]
        
        # Run vulnerability scan
        vulnerabilities_found = scan_for_vulnerabilities(target_systems, form.scan_depth.data)
        
        # Add vulnerabilities to the database
        critical_count = 0
        for vuln_data in vulnerabilities_found:
            vulnerability = Vulnerability(
                name=vuln_data['name'],
                description=vuln_data['description'],
                severity=vuln_data['severity'],
                affected_system=vuln_data['affected_system'],
                cve_id=vuln_data.get('cve_id', ''),
                remediation_steps=vuln_data.get('remediation_steps', '')
            )
            db.session.add(vulnerability)
            
            if vuln_data['severity'] == 'critical':
                critical_count += 1
        
        # Send email if critical vulnerabilities were found
        if critical_count > 0:
            send_vulnerability_alert_email(current_user, critical_count, form.scan_name.data)
        
        db.session.commit()
        
        flash(f'Vulnerability scan completed. {len(vulnerabilities_found)} vulnerabilities detected.', 'success')
        return redirect(url_for('vulnerabilities.vulnerability_management'))
    
    # Get all vulnerabilities
    all_vulnerabilities = Vulnerability.query.order_by(
        Vulnerability.discovered_at.desc()
    ).all()
    
    # Get counts by severity
    critical_count = Vulnerability.query.filter_by(severity='critical', status='open').count()
    high_count = Vulnerability.query.filter_by(severity='high', status='open').count()
    medium_count = Vulnerability.query.filter_by(severity='medium', status='open').count()
    low_count = Vulnerability.query.filter_by(severity='low', status='open').count()
    
    # Get counts by status
    open_count = Vulnerability.query.filter_by(status='open').count()
    in_progress_count = Vulnerability.query.filter_by(status='in_progress').count()
    resolved_count = Vulnerability.query.filter_by(status='resolved').count()
    false_positive_count = Vulnerability.query.filter_by(status='false_positive').count()
    
    return render_template('dashboard/vulnerability_management.html',
                          title='Vulnerability Management',
                          form=form,
                          vulnerabilities=all_vulnerabilities,
                          critical_count=critical_count,
                          high_count=high_count,
                          medium_count=medium_count,
                          low_count=low_count,
                          open_count=open_count,
                          in_progress_count=in_progress_count,
                          resolved_count=resolved_count,
                          false_positive_count=false_positive_count)

@vulnerabilities.route('/update_vulnerability_status/<int:vuln_id>', methods=['POST'])
@login_required
def update_vulnerability_status(vuln_id):
    vulnerability = Vulnerability.query.get_or_404(vuln_id)
    
    # Get the new status from the request
    status = request.json.get('status')
    if status not in ['open', 'in_progress', 'resolved', 'false_positive']:
        return jsonify({'success': False, 'message': 'Invalid status'}), 400
    
    # Update vulnerability status
    vulnerability.status = status
    
    # Log activity
    activity = UserActivity(
        user_id=current_user.id,
        activity_type='vulnerability_status_update',
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        details=f'Updated vulnerability status: {vulnerability.name} to {status}'
    )
    db.session.add(activity)
    db.session.commit()
    
    return jsonify({'success': True})

@vulnerabilities.route('/vulnerability_details/<int:vuln_id>')
@login_required
def vulnerability_details(vuln_id):
    vulnerability = Vulnerability.query.get_or_404(vuln_id)
    
    return render_template('dashboard/vulnerability_details.html',
                          title='Vulnerability Details',
                          vulnerability=vulnerability)

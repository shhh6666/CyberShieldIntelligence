from flask import Blueprint, render_template, flash, redirect, url_for, request, jsonify
from flask_login import login_required, current_user
from extensions import db
from models import Dataset, Analysis, Anomaly, UserActivity, Alert
from forms import AnomalyDetectionForm
from utils.anomaly_detection import detect_anomalies
from utils.email import send_anomaly_alert_email
from datetime import datetime

analysis = Blueprint('analysis', __name__)

@analysis.route('/anomaly_detection', methods=['GET', 'POST'])
@login_required
def anomaly_detection():
    form = AnomalyDetectionForm()
    
    # Populate the dataset dropdown
    datasets = Dataset.query.filter_by(user_id=current_user.id).all()
    form.dataset.choices = [(d.id, d.name) for d in datasets]
    
    if form.validate_on_submit():
        # Get the selected dataset
        dataset = Dataset.query.get(form.dataset.data)
        
        if dataset and dataset.user_id == current_user.id:
            # Create a new analysis record
            analysis = Analysis(
                name=form.analysis_name.data,
                analysis_type='anomaly',
                status='running',
                dataset_id=dataset.id
            )
            db.session.add(analysis)
            
            # Log activity
            activity = UserActivity(
                user_id=current_user.id,
                activity_type='anomaly_analysis_start',
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string,
                details=f'Started anomaly detection: {form.analysis_name.data} on dataset {dataset.name}'
            )
            db.session.add(activity)
            db.session.commit()
            
            # Run anomaly detection algorithm
            anomalies = detect_anomalies(dataset.file_path, form.sensitivity.data)
            
            # Update the analysis record
            analysis.status = 'completed'
            analysis.completed_at = datetime.utcnow()
            analysis.result_summary = f'Detected {len(anomalies)} potential anomalies'
            
            # Add anomalies to the database
            critical_count = 0
            for anomaly_data in anomalies:
                anomaly = Anomaly(
                    severity=anomaly_data['severity'],
                    description=anomaly_data['description'],
                    source_ip=anomaly_data.get('source_ip', ''),
                    destination_ip=anomaly_data.get('destination_ip', ''),
                    analysis_id=analysis.id,
                    remediation_steps=anomaly_data.get('remediation', '')
                )
                db.session.add(anomaly)
                
                # Create an alert for critical anomalies
                if anomaly_data['severity'] == 'critical':
                    critical_count += 1
                    alert = Alert(
                        title=f'Critical anomaly detected: {anomaly_data["description"][:50]}',
                        description=anomaly_data['description'],
                        severity=anomaly_data['severity'],
                        user_id=current_user.id,
                        related_anomaly_id=anomaly.id
                    )
                    db.session.add(alert)
            
            # Send email if critical anomalies were found
            if critical_count > 0:
                send_anomaly_alert_email(current_user, critical_count, analysis.name)
            
            db.session.commit()
            
            flash(f'Anomaly detection completed. {len(anomalies)} potential anomalies detected.', 'success')
            return redirect(url_for('analysis.view_analysis_results', analysis_id=analysis.id))
        else:
            flash('Invalid dataset selected', 'danger')
    
    # Get recent analyses
    recent_analyses = Analysis.query.filter(
        Analysis.dataset_id.in_([d.id for d in datasets])
    ).order_by(Analysis.created_at.desc()).limit(10).all()
    
    return render_template('dashboard/anomaly_detection.html',
                          title='Anomaly Detection',
                          form=form,
                          recent_analyses=recent_analyses)

@analysis.route('/view_analysis_results/<int:analysis_id>')
@login_required
def view_analysis_results(analysis_id):
    analysis_obj = Analysis.query.get_or_404(analysis_id)
    
    # Verify the analysis belongs to a dataset owned by the current user
    dataset = Dataset.query.get(analysis_obj.dataset_id)
    if dataset.user_id != current_user.id:
        flash('You do not have permission to view this analysis', 'danger')
        return redirect(url_for('analysis.anomaly_detection'))
    
    # Get anomalies for this analysis
    anomalies = Anomaly.query.filter_by(analysis_id=analysis_id).order_by(
        Anomaly.severity.in_(['critical', 'high', 'medium', 'low']).desc()
    ).all()
    
    # Count anomalies by severity
    severity_counts = {
        'critical': Anomaly.query.filter_by(analysis_id=analysis_id, severity='critical').count(),
        'high': Anomaly.query.filter_by(analysis_id=analysis_id, severity='high').count(),
        'medium': Anomaly.query.filter_by(analysis_id=analysis_id, severity='medium').count(),
        'low': Anomaly.query.filter_by(analysis_id=analysis_id, severity='low').count()
    }
    
    return render_template('dashboard/analysis_results.html',
                          title='Analysis Results',
                          analysis=analysis_obj,
                          dataset=dataset,
                          anomalies=anomalies,
                          severity_counts=severity_counts)

@analysis.route('/user_behavior', methods=['GET'])
@login_required
def user_behavior():
    # Get user activities for the current user
    activities = UserActivity.query.filter_by(user_id=current_user.id).order_by(UserActivity.timestamp.desc()).limit(100).all()
    
    # Group activities by type for visualization
    activity_types = {}
    for activity in activities:
        if activity.activity_type in activity_types:
            activity_types[activity.activity_type] += 1
        else:
            activity_types[activity.activity_type] = 1
    
    return render_template('dashboard/user_behavior.html',
                          title='User Behavior Analysis',
                          activities=activities,
                          activity_types=activity_types)

@analysis.route('/mark_false_positive/<int:anomaly_id>', methods=['POST'])
@login_required
def mark_false_positive(anomaly_id):
    anomaly = Anomaly.query.get_or_404(anomaly_id)
    
    # Verify the anomaly belongs to an analysis on a dataset owned by the current user
    analysis = Analysis.query.get(anomaly.analysis_id)
    dataset = Dataset.query.get(analysis.dataset_id)
    
    if dataset.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Permission denied'}), 403
    
    # Mark as false positive
    anomaly.is_false_positive = True
    db.session.commit()
    
    return jsonify({'success': True})

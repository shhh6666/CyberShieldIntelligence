from flask import Blueprint, render_template, flash, redirect, url_for, request, jsonify
from flask_login import login_required, current_user
from app import db, app
from models import Alert, Dataset, Analysis, Anomaly, UserActivity, Vulnerability, IncidentResponse
from forms import UploadDatasetForm
from werkzeug.utils import secure_filename
import os
from datetime import datetime, timedelta

# Add global context processor to provide 'now' to all templates
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

dashboard = Blueprint('dashboard', __name__)

@dashboard.route('/')
@dashboard.route('/home')
def home():
    if current_user.is_authenticated:
        # Get recent alerts
        recent_alerts = Alert.query.filter_by(user_id=current_user.id, is_read=False).order_by(Alert.created_at.desc()).limit(5).all()
        
        # Get recent anomalies
        recent_anomalies = Anomaly.query.join(Analysis).order_by(Anomaly.timestamp.desc()).limit(5).all()
        
        # Get recent vulnerabilities
        recent_vulnerabilities = Vulnerability.query.order_by(Vulnerability.discovered_at.desc()).limit(5).all()
        
        # Get system statistics
        total_datasets = Dataset.query.count()
        total_analyses = Analysis.query.count()
        total_anomalies = Anomaly.query.count()
        total_vulnerabilities = Vulnerability.query.count()
        
        # Get anomalies by severity for chart
        critical_anomalies = Anomaly.query.filter_by(severity='critical').count()
        high_anomalies = Anomaly.query.filter_by(severity='high').count()
        medium_anomalies = Anomaly.query.filter_by(severity='medium').count()
        low_anomalies = Anomaly.query.filter_by(severity='low').count()
        
        # Get time series data for anomalies (last 7 days)
        anomaly_time_series = []
        for i in range(7):
            date = datetime.utcnow().date() - timedelta(days=i)
            count = Anomaly.query.filter(
                Anomaly.timestamp >= date,
                Anomaly.timestamp < date + timedelta(days=1)
            ).count()
            anomaly_time_series.append({
                'date': date.strftime('%Y-%m-%d'),
                'count': count
            })
        anomaly_time_series.reverse()  # Show oldest to newest
        
        return render_template('dashboard/home.html', 
                              title='Dashboard', 
                              recent_alerts=recent_alerts,
                              recent_anomalies=recent_anomalies,
                              recent_vulnerabilities=recent_vulnerabilities,
                              total_datasets=total_datasets,
                              total_analyses=total_analyses,
                              total_anomalies=total_anomalies,
                              total_vulnerabilities=total_vulnerabilities,
                              critical_anomalies=critical_anomalies,
                              high_anomalies=high_anomalies,
                              medium_anomalies=medium_anomalies,
                              low_anomalies=low_anomalies,
                              anomaly_time_series=anomaly_time_series)
    else:
        return render_template('index.html', title='Welcome to CyberTech')

@dashboard.route('/dataset_manager', methods=['GET', 'POST'])
@login_required
def dataset_manager():
    form = UploadDatasetForm()
    
    if form.validate_on_submit():
        # Create uploads directory if it doesn't exist
        uploads_dir = os.path.join('static', 'uploads', str(current_user.id))
        os.makedirs(uploads_dir, exist_ok=True)
        
        # Save the file
        filename = secure_filename(form.dataset_file.data.filename)
        file_path = os.path.join(uploads_dir, filename)
        form.dataset_file.data.save(file_path)
        
        # Create dataset record
        dataset = Dataset(
            name=form.name.data,
            description=form.description.data,
            file_path=file_path,
            file_type=filename.rsplit('.', 1)[1].lower(),
            file_size=os.path.getsize(file_path),
            user_id=current_user.id
        )
        
        db.session.add(dataset)
        
        # Log activity
        activity = UserActivity(
            user_id=current_user.id,
            activity_type='dataset_upload',
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details=f'Uploaded dataset: {form.name.data}'
        )
        db.session.add(activity)
        db.session.commit()
        
        flash('Dataset uploaded successfully!', 'success')
        return redirect(url_for('dashboard.dataset_manager'))
    
    # Get all datasets for current user
    datasets = Dataset.query.filter_by(user_id=current_user.id).order_by(Dataset.upload_date.desc()).all()
    
    return render_template('dashboard/dataset_manager.html', 
                          title='Dataset Manager',
                          form=form,
                          datasets=datasets)

@dashboard.route('/download_dataset/<int:dataset_id>')
@login_required
def download_dataset(dataset_id):
    dataset = Dataset.query.get_or_404(dataset_id)
    
    # Check if the dataset belongs to the current user
    if dataset.user_id != current_user.id:
        flash('You do not have permission to download this dataset', 'danger')
        return redirect(url_for('dashboard.dataset_manager'))
    
    # Log activity
    activity = UserActivity(
        user_id=current_user.id,
        activity_type='dataset_download',
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        details=f'Downloaded dataset: {dataset.name}'
    )
    db.session.add(activity)
    db.session.commit()
    
    # Return the file for download
    return redirect(url_for('static', filename=dataset.file_path.replace('static/', '')))

@dashboard.route('/delete_dataset/<int:dataset_id>', methods=['POST'])
@login_required
def delete_dataset(dataset_id):
    dataset = Dataset.query.get_or_404(dataset_id)
    
    # Check if the dataset belongs to the current user
    if dataset.user_id != current_user.id:
        flash('You do not have permission to delete this dataset', 'danger')
        return redirect(url_for('dashboard.dataset_manager'))
    
    # Delete the file
    if os.path.exists(dataset.file_path):
        os.remove(dataset.file_path)
    
    # Delete the dataset record
    db.session.delete(dataset)
    
    # Log activity
    activity = UserActivity(
        user_id=current_user.id,
        activity_type='dataset_delete',
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        details=f'Deleted dataset: {dataset.name}'
    )
    db.session.add(activity)
    db.session.commit()
    
    flash('Dataset deleted successfully', 'success')
    return redirect(url_for('dashboard.dataset_manager'))

@dashboard.route('/mark_alert_read/<int:alert_id>', methods=['POST'])
@login_required
def mark_alert_read(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    
    # Check if the alert belongs to the current user
    if alert.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Permission denied'}), 403
    
    # Mark alert as read
    alert.is_read = True
    db.session.commit()
    
    return jsonify({'success': True})

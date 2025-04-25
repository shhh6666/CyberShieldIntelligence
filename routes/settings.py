from flask import Blueprint, render_template, flash, redirect, url_for, request
from flask_login import login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from extensions import db
from models import User, UserActivity
from forms import SettingsForm
from utils.email import send_email
from datetime import datetime
import json

settings = Blueprint('settings', __name__)

@settings.route('/settings', methods=['GET', 'POST'])
@login_required
def user_settings():
    form = SettingsForm()
    
    # Pre-populate form with current values
    if request.method == 'GET':
        form.email.data = current_user.email
        form.phone_number.data = current_user.phone_number if current_user.phone_number else ""
        
        # Load notification preferences if they exist
        try:
            if current_user.notification_preferences:
                form.notification_preferences.data = json.loads(current_user.notification_preferences)
            else:
                form.notification_preferences.data = ['email_critical']
        except:
            form.notification_preferences.data = ['email_critical']
            
        # Load theme preference if it exists
        form.theme_preference.data = getattr(current_user, 'theme_preference', 'dark')
        form.mfa_enabled.data = getattr(current_user, 'mfa_enabled', False)
    
    if form.validate_on_submit():
        # Verify current password
        if not check_password_hash(current_user.password_hash, form.current_password.data):
            flash('Current password is incorrect', 'danger')
            return render_template('dashboard/settings.html', form=form, title='Settings')
        
        # Update email if changed
        if form.email.data != current_user.email:
            # Check if email already exists
            if User.query.filter_by(email=form.email.data).first() and form.email.data != current_user.email:
                flash('Email already in use', 'danger')
                return render_template('dashboard/settings.html', form=form, title='Settings')
            current_user.email = form.email.data
        
        # Update password if provided
        if form.new_password.data:
            current_user.password_hash = generate_password_hash(form.new_password.data)
        
        # Save notification preferences
        current_user.notification_preferences = json.dumps(form.notification_preferences.data)
        
        # Save theme preference
        current_user.theme_preference = form.theme_preference.data
        
        # Save MFA preference
        current_user.mfa_enabled = form.mfa_enabled.data
        
        # Save phone number for SMS notifications
        current_user.phone_number = form.phone_number.data
        
        # Log the settings change
        activity = UserActivity(
            activity_type='settings_update',
            timestamp=datetime.utcnow(),
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details='User updated settings',
            user_id=current_user.id
        )
        db.session.add(activity)
        
        # Save changes to database
        db.session.commit()
        
        flash('Settings updated successfully', 'success')
        return redirect(url_for('settings.user_settings'))
    
    return render_template('dashboard/settings.html', 
                          form=form, 
                          title='Settings')
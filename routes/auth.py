from flask import Blueprint, render_template, flash, redirect, url_for, request
from flask_login import login_user, logout_user, current_user, login_required
from extensions import db
from models import User, UserActivity
from forms import LoginForm, RegistrationForm
from utils.email import send_welcome_email

auth = Blueprint('auth', __name__)

# Add global context processor to provide 'now' to all templates
@auth.context_processor
def inject_now():
    from datetime import datetime
    return {'now': datetime.utcnow()}

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.home'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('auth.login'))
        
        login_user(user, remember=form.remember_me.data)
        
        # Log user activity
        activity = UserActivity(
            user_id=user.id,
            activity_type='login',
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details='User logged in'
        )
        db.session.add(activity)
        db.session.commit()
        
        next_page = request.args.get('next')
        if not next_page or url_for('auth.login') in next_page:
            next_page = url_for('dashboard.home')
        return redirect(next_page)
    
    return render_template('auth/login.html', title='Sign In', form=form)

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.home'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        
        # Send welcome email
        send_welcome_email(user)
        
        flash('Congratulations, you are now a registered user! Please check your email for confirmation.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/register.html', title='Register', form=form)

@auth.route('/logout')
@login_required
def logout():
    # Log user activity
    activity = UserActivity(
        user_id=current_user.id,
        activity_type='logout',
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        details='User logged out'
    )
    db.session.add(activity)
    db.session.commit()
    
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

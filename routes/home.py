from flask import Blueprint, render_template, redirect, url_for
from flask_login import current_user

# Create blueprint
home_bp = Blueprint('home', __name__)

@home_bp.route('/')
def index():
    """Home page route."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.home'))
    return render_template('home.html')

@home_bp.route('/offline')
def offline():
    """Offline page when user has no internet connection."""
    return render_template('offline.html')

@home_bp.route('/ping')
def ping():
    """Simple endpoint for checking connectivity."""
    return {'status': 'ok', 'message': 'Server is reachable'}
from flask import Blueprint, render_template, redirect, url_for, request
from flask_login import current_user, login_required
from datetime import datetime

# Create blueprint
home_bp = Blueprint('home', __name__)

# Add global context processor to provide 'now' to all templates
@home_bp.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

@home_bp.route('/')
def index():
    """Home page route."""
    # If user is logged in, we still show the home page
    # (unlike before where we redirected to dashboard)
    return render_template('home.html')

@home_bp.route('/offline')
def offline():
    """Offline page when user has no internet connection."""
    return render_template('offline.html')

@home_bp.route('/ping')
def ping():
    """Simple endpoint for checking connectivity."""
    return {'status': 'ok', 'message': 'Server is reachable'}
import os
import logging

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from extensions import db, login_manager, mail

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)  # needed for url_for to generate with https

# Configure the database
# Get database URL and fix it if needed
database_url = os.environ.get("DATABASE_URL")

# If DATABASE_URL is not set, use a default SQLite database for development
if not database_url:
    database_url = "sqlite:///cybersecurity.db"
    print(f"DATABASE_URL environment variable not found, using default: {database_url}")
# If URL starts with postgres://, SQLAlchemy in newer versions requires postgresql://
elif database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

print(f"Using database URL: {database_url}")
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Email configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@cybertech.com')
app.config['MAIL_SUPPRESS_SEND'] = os.environ.get('MAIL_USERNAME') is None

# Initialize extensions with the app
db.init_app(app)
mail.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
login_manager.login_message_category = 'info'

# Import models and initialize tables
with app.app_context():
    import models
    db.create_all()

# Register blueprints
from routes.auth import auth
from routes.dashboard import dashboard
from routes.analysis import analysis
from routes.vulnerabilities import vulnerabilities
from routes.incident_response import incident_response
from routes.home import home_bp

app.register_blueprint(auth, url_prefix='/auth')
app.register_blueprint(dashboard, url_prefix='/dashboard')
app.register_blueprint(analysis, url_prefix='/analysis')
app.register_blueprint(vulnerabilities, url_prefix='/vulnerabilities')
app.register_blueprint(incident_response, url_prefix='/incidents')
app.register_blueprint(home_bp)

# Add global context processor for 'now' variable
from datetime import datetime
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

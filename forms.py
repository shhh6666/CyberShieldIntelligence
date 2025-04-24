from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from models import User

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    password2 = PasswordField(
        'Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

class UploadDatasetForm(FlaskForm):
    name = StringField('Dataset Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description')
    dataset_file = FileField('Dataset File', validators=[
        FileRequired(),
        FileAllowed(['csv', 'json', 'pcap', 'log'], 'Only CSV, JSON, PCAP, and LOG files are allowed.')
    ])
    submit = SubmitField('Upload')

class AnomalyDetectionForm(FlaskForm):
    dataset = SelectField('Select Dataset', coerce=int, validators=[DataRequired()])
    analysis_name = StringField('Analysis Name', validators=[DataRequired(), Length(max=100)])
    sensitivity = SelectField('Detection Sensitivity', choices=[
        ('low', 'Low - Fewer alerts, higher confidence'),
        ('medium', 'Medium - Balanced detection'),
        ('high', 'High - More alerts, may include false positives')
    ], validators=[DataRequired()])
    submit = SubmitField('Start Analysis')

class VulnerabilityScanForm(FlaskForm):
    scan_name = StringField('Scan Name', validators=[DataRequired(), Length(max=100)])
    target_systems = TextAreaField('Target Systems (IP addresses or hostnames, one per line)', validators=[DataRequired()])
    scan_depth = SelectField('Scan Depth', choices=[
        ('basic', 'Basic - Quick scan for common vulnerabilities'),
        ('standard', 'Standard - Balanced scan depth'),
        ('deep', 'Deep - Thorough scan (takes longer)')
    ], validators=[DataRequired()])
    submit = SubmitField('Start Scan')

class IncidentResponseForm(FlaskForm):
    title = StringField('Incident Title', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Incident Description', validators=[DataRequired()])
    severity = SelectField('Severity', choices=[
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical')
    ], validators=[DataRequired()])
    affected_systems = TextAreaField('Affected Systems')
    submit = SubmitField('Create Incident')

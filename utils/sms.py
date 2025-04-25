import os
from flask import current_app
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException

def send_sms_notification(phone_number, message):
    """
    Send SMS notification using Twilio.
    Falls back gracefully if Twilio is not configured.
    
    Args:
        phone_number (str): The recipient's phone number in E.164 format (e.g., +1234567890)
        message (str): The message to send
        
    Returns:
        dict: Status of the operation with message_id if successful
    """
    # Check Twilio configuration
    account_sid = os.environ.get('TWILIO_ACCOUNT_SID')
    auth_token = os.environ.get('TWILIO_AUTH_TOKEN')
    from_number = os.environ.get('TWILIO_PHONE_NUMBER')
    
    if not (account_sid and auth_token and from_number):
        current_app.logger.warning(
            "Twilio not configured. SMS would have been sent to: " + phone_number
        )
        return {'success': False, 'error': 'Twilio not configured'}
    
    try:
        client = Client(account_sid, auth_token)
        
        # Send the message
        twilio_message = client.messages.create(
            body=message,
            from_=from_number,
            to=phone_number
        )
        
        current_app.logger.info(f"SMS sent to {phone_number}: {twilio_message.sid}")
        return {
            'success': True, 
            'message_id': twilio_message.sid
        }
        
    except TwilioRestException as e:
        current_app.logger.error(f"Twilio error: {str(e)}")
        return {
            'success': False, 
            'error': str(e)
        }
    except Exception as e:
        current_app.logger.error(f"Failed to send SMS: {str(e)}")
        return {
            'success': False, 
            'error': str(e)
        }

def send_incident_sms(user, incident):
    """
    Send SMS notification for critical or high severity incidents.
    
    Args:
        user (User): The user who created the incident
        incident (IncidentResponse): The incident that was created
        
    Returns:
        dict: Status of the operation
    """
    # Only send SMS for critical or high severity incidents
    if incident.severity not in ['critical', 'high']:
        return {'success': False, 'error': 'Incident severity too low for SMS notification'}
    
    # Check if phone number exists in user preferences
    # This would need to be added to the User model
    phone_number = getattr(user, 'phone_number', None)
    
    if not phone_number:
        current_app.logger.warning(f"No phone number available for user {user.username}")
        return {'success': False, 'error': 'No phone number available'}
    
    # Prepare the message
    severity_prefix = "⚠️ CRITICAL" if incident.severity == 'critical' else "⚠️ HIGH"
    message = f"{severity_prefix} SECURITY INCIDENT: {incident.title}\n\nCreated by {user.username} at {incident.created_at.strftime('%H:%M:%S')}. Please log in to the CyberTech system to respond."
    
    # Send the message
    return send_sms_notification(phone_number, message)
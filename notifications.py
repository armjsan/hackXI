import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from database import get_setting, get_user_by_id, log_event, mark_event_notified

logger = logging.getLogger(__name__)


def send_security_alert(user_id, event_type, event_id=None):
    user = get_user_by_id(user_id)
    if user is None:
        return

    if get_setting('smtp_enabled') == 'true':
        admin_email = get_setting('admin_email')
        if admin_email:
            try:
                subject = f"[Triple Auth] Security Alert: {event_type}"
                body = _format_alert_email(user, event_type)
                _send_email(admin_email, subject, body)
                if event_id:
                    mark_event_notified(event_id)
            except Exception as e:
                log_event(user_id, 'EMAIL_FAIL', f"Failed to send alert email: {str(e)}")


def send_welcome_email(email, username, dummy_password):
    """
    Send welcome email with username + temporary password to a new user.
    Falls back to console logging if SMTP is not configured.
    """
    if get_setting('smtp_enabled') == 'true':
        from_email = get_setting('smtp_from_email')
        if from_email:
            try:
                subject = "[Triple Auth] Your Account Credentials"
                body = _format_welcome_email(username, dummy_password)
                _send_email(email, subject, body)
                logger.info(f"Welcome email sent to {email}")
                return {'sent': True, 'method': 'email'}
            except Exception as e:
                logger.error(f"Failed to send welcome email to {email}: {e}")

    # Mock fallback - log credentials for admin to deliver manually
    logger.info(
        f"[MOCK EMAIL] To: {email} | Username: {username} | "
        f"Temp Password: {dummy_password}"
    )
    return {'sent': False, 'method': 'mock'}


def _send_email(to, subject, body):
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = get_setting('smtp_from_email')
    msg['To'] = to
    msg.attach(MIMEText(body, 'html'))

    server = smtplib.SMTP(get_setting('smtp_server'), int(get_setting('smtp_port')))
    server.starttls()
    server.login(get_setting('smtp_username'), get_setting('smtp_password'))
    server.sendmail(msg['From'], [to], msg.as_string())
    server.quit()


def _format_alert_email(user, event_type):
    colors = {
        'A_LOCKOUT': '#dc3545',
        'B_FAIL': '#dc3545',
        'DUMMY_REUSE': '#dc3545',
        'USER_CREATED': '#17a2b8',
        'PASSWORD_CHANGED': '#28a745',
        'REGISTRATION_REQUEST': '#17a2b8',
        'REGISTRATION_APPROVED': '#28a745',
        'REGISTRATION_REJECTED': '#ffc107',
    }
    color = colors.get(event_type, '#ffc107')
    return f"""
    <html>
    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #1e3a5f; color: white; padding: 20px; text-align: center;">
            <h1 style="margin: 0;">Triple Auth Security Alert</h1>
        </div>
        <div style="background: {color}; color: white; padding: 10px 20px;">
            <strong>Event: {event_type}</strong>
        </div>
        <div style="padding: 20px; background: #f8f9fa;">
            <table style="width: 100%; border-collapse: collapse;">
                <tr><td style="padding: 8px; font-weight: bold;">Username:</td><td style="padding: 8px;">{user['username']}</td></tr>
                <tr><td style="padding: 8px; font-weight: bold;">Email:</td><td style="padding: 8px;">{user['email']}</td></tr>
                <tr><td style="padding: 8px; font-weight: bold;">Event Type:</td><td style="padding: 8px;">{event_type}</td></tr>
            </table>
        </div>
        <div style="padding: 20px; text-align: center; color: #6c757d; font-size: 12px;">
            Log in to the admin dashboard to take action.
        </div>
    </body>
    </html>
    """


def _format_welcome_email(username, dummy_password):
    return f"""
    <html>
    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #1e3a5f; color: white; padding: 20px; text-align: center;">
            <h1 style="margin: 0;">Welcome to Triple Auth</h1>
        </div>
        <div style="background: #28a745; color: white; padding: 10px 20px;">
            <strong>Your account has been created</strong>
        </div>
        <div style="padding: 20px; background: #f8f9fa;">
            <p>Your account credentials:</p>
            <table style="width: 100%; border-collapse: collapse;">
                <tr><td style="padding: 8px; font-weight: bold;">Username:</td><td style="padding: 8px;">{username}</td></tr>
                <tr><td style="padding: 8px; font-weight: bold;">Temporary Password:</td><td style="padding: 8px; font-family: monospace;">{dummy_password}</td></tr>
            </table>
            <p style="margin-top: 16px; color: #dc3545; font-weight: bold;">
                This password is temporary and must be changed on first login.
            </p>
            <p>After logging in, you will be prompted to set a new password.
               Your verification password (Password B) will be available on your account page.</p>
        </div>
        <div style="padding: 20px; text-align: center; color: #6c757d; font-size: 12px;">
            If you did not request this account, please ignore this email.
        </div>
    </body>
    </html>
    """

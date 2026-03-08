import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from database import get_setting, get_user_by_id, log_event, mark_event_notified


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

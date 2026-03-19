"""
PropApp.signals
────────────────────────────────────────────────────────────────
Only authentication events are captured here.
All other system actions are logged directly in views.py via syslog().
"""

from django.contrib.auth.signals import (
    user_logged_in,
    user_logged_out,
    user_login_failed,
)
from django.dispatch import receiver


@receiver(user_logged_in)
def on_user_login(sender, request, user, **kwargs):
    try:
        from PropApp.log_service import syslog
        syslog(
            'AUTH',
            f"User '{user.username}' logged in (role: {getattr(user, 'role', 'unknown')})",
            user=user,
            request=request,
        )
    except Exception:
        pass


@receiver(user_logged_out)
def on_user_logout(sender, request, user, **kwargs):
    try:
        from PropApp.log_service import syslog
        username = user.username if user else 'unknown'
        syslog('AUTH', f"User '{username}' logged out", user=user, request=request)
    except Exception:
        pass


@receiver(user_login_failed)
def on_login_failed(sender, credentials, request, **kwargs):
    try:
        from PropApp.log_service import syslog
        attempted = credentials.get('username', '?')
        syslog(
            'SECURITY',
            f"Failed login attempt for '{attempted}'",
            level='WARNING',
            request=request,
            attempted_username=attempted,
        )
    except Exception:
        pass

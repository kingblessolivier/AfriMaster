from django.db.models import Count

from .models import Message, Tenant, Owner


def global_context(request):
    """Provide common template context: unread message counts and role flags.

    Returns:
        dict: { 'message_total': int, 'unread_messages': int, 'is_tenant': bool, 'is_owner': bool }
    """
    user = getattr(request, 'user', None)
    message_total = 0
    unread_messages = 0
    is_tenant = False
    is_owner = False

    if user and user.is_authenticated:
        # total messages received by the user
        message_total = Message.objects.filter(recipient=user).count()
        unread_messages = Message.objects.filter(recipient=user, is_read=False).count()
        is_tenant = hasattr(user, 'tenant_profile')
        is_owner = hasattr(user, 'owner_profile')

    return {
        'message_total': message_total,
        'unread_messages': unread_messages,
        'is_tenant': is_tenant,
        'is_owner': is_owner,
    }

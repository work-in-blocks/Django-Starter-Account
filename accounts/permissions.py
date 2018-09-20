from rest_framework import permissions
from django.utils.translation import gettext as _


class AdminUser(permissions.BasePermission):
    """
        Verify if user to realize this request is admin or belong to staff member
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_staff

    def _get_error_message(self, model_class, method_name, action_method_name):
        """
        Get assertion error message depending if there are actions permissions methods defined.
        """
        return "Only Super Admins allowed"


def is_active_user(func):
    """
        Decorator function for services to test whether the user who uses
        the service is active
    """

    def decorator(*args, **kwargs):
        """
            if "user" not in kwargs:
            raise ValueError("A 'user' named argument must be provided")
        """
        user = kwargs['user']

        if user is None:
            raise ValueError('{"detail":"' + str(_("User can't be None")) + '"}')

        if user.is_active is False:
            raise ValueError('{"detail":"' + str(_("Inactive user")) + '"}')

        return func(*args, **kwargs)

    return decorator


def is_admin_user(func):
    """
        Decorator function for services to test whether the user
        who uses the service is Admin
    """

    def decorator(*args, **kwargs):
        if "user" not in kwargs:
            raise ValueError('{"detail":"' + str(_("A 'user' named argument must be provided")) + '"}')

        user = kwargs['user']

        if user.is_staff is False:
            raise ValueError('{"detail":"' + str(_("User is not Admin")) + '"}')

        return func(*args, **kwargs)

    return decorator

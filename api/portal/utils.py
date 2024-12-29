from services.account_service import AccountService
from portal.config import portal_settings
from werkzeug.exceptions import NotFound
from portal.auth import get_user_from_token
from functools import wraps
from flask import request, jsonify
import logging

logger = logging.getLogger(__name__)

def get_admin_service_account():
    admin_email = portal_settings.ADMIN_EMAIL
    account_id = AccountService.get_account_id_by_email(admin_email)
    if not account_id:
        raise NotFound(f"Admin account with email {admin_email} not found.")
    return AccountService.load_user(account_id)

def has_direct_permission(user, action, resource, resource_id=None):
    """
    Check if the user has direct permissions for the given action, resource, and resource_id.
    """
    for perm in user.permissions:
        if (perm.action == action and perm.resource == resource and
            (perm.resource_id == resource_id or perm.resource_id is None)):
            return True
    return False

def has_role_permission(user, action, resource):
    if user.role:
        for permission in user.role.permissions:
            if permission.action == action and permission.resource == resource:
                return True
    return False

def has_team_permission(user, action, resource, resource_id=None):
    """
    Check if the user has permissions through their teams.
    """
    for team in user.teams:
        for perm in team.permissions:
            if (
                perm.action == action and
                perm.resource == resource and
                (perm.resource_id == resource_id or perm.resource_id is None)
            ):
                return True
    return False

def has_permission(user, action, resource, resource_id=None):
    """
    Check if the user has permissions through direct assignment, role, or teams.
    """
    #import pdb; pdb.set_trace()
    return (
        has_direct_permission(user, action, resource, resource_id) or
        has_role_permission(user, action, resource) or
        has_team_permission(user, action, resource, resource_id)
    )

def requires_perm(action, resource):
    """
    Decorator to check if the user has the required permission for the given action and resource.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return {"error": "Unauthorized, no auth token passed"}, 401

            token = auth_header.split(" ")[1]
            user = get_user_from_token(token)
            if not user:
                return {"error": "Unauthorized, User doesn't exist"}, 401

            resource_id = kwargs.get('resource_id')  # Adjust as necessary

            if not has_permission(user, action, resource, resource_id=resource_id):
                logger.warning(f"User {user.username} does not have permission to {action} {resource}")
                return {"error": f"Forbidden: User {user.username} does not have permission to {action} {resource}"}, 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator
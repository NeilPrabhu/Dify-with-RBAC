from flask import Blueprint, jsonify, request, g

from flask_restful import Resource, Api
from portal.models import User, Role, Permission
from portal.services.permission_service import PermissionService
from portal.services.dataset_service import DatasetService
from portal.services.team_service import TeamService

from extensions.ext_database import db
from portal.utils import requires_perm
from portal.auth import login_required
from pydantic import BaseModel
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)

user_bp = Blueprint('users', __name__)
api = Api(user_bp)

class UpdateUserSchema(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    ldap_uid: Optional[str] = None
    role: Optional[str] = None

@user_bp.route('/users/me', methods=['GET'])
@login_required
def get_me():
    if g.portal_user:
        return jsonify(g.portal_user.to_dict()), 200
    return jsonify({"error": "User not authenticated"}), 401

class UsersListAPI(Resource):
    @requires_perm('read', 'user')
    def get(self):
        try:
            users = User.query.all()
            return [user.to_dict() for user in users], 200
        except Exception as e:
            return {"error": "Error returning list of users: " + str(e)}, 500

class UsersByIdAPI(Resource):
    # Update user's role or any other attributes other than perms 
    @requires_perm('read', 'user')
    def get(self, id):
        try:
            user = User.query.get(id)
            if user is None:
                return {"error": "User not found"}, 404
            return user.to_dict(), 200
        except Exception as e:
            return {"error": str(e)}, 500

    @requires_perm('update', 'user')
    def patch(self, id):
        try:
            user = User.query.get(id)
            if user is None:
                return {"error": "User not found"}, 404
            data = request.get_json()
            update_data = UpdateUserSchema(**data)
            # Update fields except roles
            for key, value in update_data.dict(exclude_none=True).items():
                if key not in ["roles", "roles_operation"]:
                    setattr(user, key, value)

            # Handle roles update
            if update_data.roles is not None:
                operation = update_data.roles_operation or 'replace'
                roles = Role.query.filter(Role.name.in_(update_data.roles)).all()
                if len(roles) != len(update_data.roles):
                    return {"error": "One or more roles not found"}, 400

                if operation == 'add':
                    for role in roles:
                        if role not in user.roles:
                            user.roles.append(role)
                elif operation == 'remove':
                    for role in roles:
                        if role in user.roles:
                            user.roles.remove(role)
                elif operation == 'replace':
                    user.roles = roles
                else:
                    return {"error": "Invalid roles_operation value"}, 400

            db.session.commit()
            return user.to_dict(), 200
        except Exception as e:
            return {"error": "Error updating user: " + str(e)}, 500

class UserByUsernameAPI(Resource):
    # This is to make updates to User's role or any other attributes other than perms
    @requires_perm('read', 'user')
    def get(self, username):
        try:
            user = User.query.filter_by(username=username).first()
            if user is None:
                return {"error": "User not found"}, 404
            return user.to_dict(), 200
        except Exception as e:
            return {"error": str(e)}, 500

    @requires_perm('update', 'user')
    def patch(self, username):
        try:
            user = User.query.filter_by(username=username).first()
            if user is None:
                return {"error": "User not found"}, 404
            data = request.get_json()
            update_data = UpdateUserSchema(**data)
            # Update fields except role
            for key, value in update_data.dict(exclude_none=True).items():
                if key != "role":
                    setattr(user, key, value)

            # TODO - Handle role update in roles.py
            if update_data.role is not None:
                role = Role.query.filter_by(name=update_data.role).first()
                if role is None:
                    return {"error": "Role not found"}, 400
                user.role = role

            db.session.commit()
            return user.to_dict(), 200
        except Exception as e:
            return {"error": "Error updating user: " + str(e)}, 500

    @requires_perm('delete', 'user')
    def delete(self, username):
        try:
            user = User.query.filter_by(username=username).first()
            if user is None:
                return {"error": "User not found"}, 404
            db.session.delete(user)
            db.session.commit()
            return {"message": "User deleted"}, 200
        except Exception as e:
            return {"error": "Error deleting user: " + str(e)}, 500
        
class UserPermissionsByUsernameAPI(Resource):
    # This is to make updates to User's perms
    @requires_perm('create', 'permission')
    def post(self, username):
        try:
            user = User.query.filter_by(username=username).first()
            if user is None:
                return {"error": "User not found"}, 404

            data = request.get_json()
            resource = data.get('resource')
            resource_id = data.get('resource_id')
            dataset_name = data.get('dataset_name', '')
            actions = data.get('actions', [])

            if not resource or not actions:
                return {"error": "Resource and actions are required"}, 400

            if resource == 'dataset':
                if not resource_id and dataset_name:
                    dataset = DatasetService.get_dataset_by_name(dataset_name)
                    if not dataset:
                        return {"error": "Dataset not found"}, 404
                    resource_id = dataset.id
                elif not resource_id:
                    return {"error": "Resource ID or dataset name is required"}, 400


            PermissionService.create_permissions_for_user(user, resource, resource_id, actions)

            return user.to_dict(), 200
        except Exception as e:
            return {"error": "Error adding permissions: " + str(e)}, 500

    @requires_perm('read', 'permission')
    def get(self, username):
        try:
            user = User.query.filter_by(username=username).first()
            if user is None:
                return {"error": "User not found"}, 404

            permissions = PermissionService.get_permissions_for_user(user)
            return {"permissions": permissions}, 200
        except Exception as e:
            return {"error": "Error retrieving permissions: " + str(e)}, 500
    '''
    @requires_perm('update', 'permission')
    def put(self, username):
        try:
            user = User.query.filter_by(username=username).first()
            if user is None:
                return {"error": "User not found"}, 404

            data = request.get_json()
            resource = data.get('resource')
            resource_id = data.get('resource_id')
            actions = data.get('actions', [])

            if not resource or not actions:
                return {"error": "Resource and actions are required"}, 400

            PermissionService.modify_permissions_for_user(user, resource, resource_id, actions)

            return user.to_dict(), 200
        except Exception as e:
            return {"error": "Error modifying permissions: " + str(e)}, 500
    '''
    @requires_perm('update', 'permission')
    def put(self, username):
        try:
            user = User.query.filter_by(username=username).first()
            if user is None:
                return {"error": "User not found"}, 404

            data = request.get_json()
            resource = data.get('resource')
            resource_id = data.get('resource_id')
            dataset_name = data.get('dataset_name')
            actions = data.get('actions', [])

            if not resource or not actions:
                return {"error": "Resource and actions are required"}, 400

            if resource == 'dataset':
                if not resource_id and dataset_name:
                    dataset = DatasetService.get_dataset_by_name(dataset_name)
                    if not dataset:
                        return {"error": "Dataset not found"}, 404
                    resource_id = dataset.id
                elif not resource_id:
                    return {"error": "Resource ID or dataset name is required"}, 400

            PermissionService.modify_permissions_for_user(user, resource, resource_id, actions)

            return user.to_dict(), 200
        except Exception as e:
            return {"error": "Error modifying permissions: " + str(e)}, 500

    @requires_perm('delete', 'permission')
    def delete(self, username):
        try:
            user = User.query.filter_by(username=username).first()
            if user is None:
                return {"error": "User not found"}, 404

            data = request.get_json()
            resource = data.get('resource')
            resource_id = data.get('resource_id')
            dataset_name = data.get('dataset_name')
            actions = data.get('actions', [])

            if not resource or not actions:
                return {"error": "Resource and actions are required"}, 400

            if resource == 'dataset':
                if not resource_id and dataset_name:
                    dataset = DatasetService.get_dataset_by_name(dataset_name)
                    if not dataset:
                        return {"error": "Dataset not found"}, 404
                    resource_id = dataset.id
                elif not resource_id:
                    return {"error": "Resource ID or dataset name is required"}, 400

            PermissionService.delete_permissions_for_user(user, resource, resource_id, actions)

            return {"message": "Permissions deleted"}, 200
        except Exception as e:
            return {"error": "Error deleting permissions: " + str(e)}, 500
        
class UserTeamsByUsernameAPI(Resource):
    @requires_perm('read', 'team')
    def get(self, username):
        try:
            result = TeamService.get_teams_for_user_by_username(username)
            if "error" in result:
                return result, 400
            return result, 200
        except Exception as e:
            logger.error(f"Error retrieving teams for user by username: {e}")
            return {"error": "Error retrieving teams for user by username: " + str(e)}, 500

class UserTeamsAPI(Resource):
    @login_required
    @requires_perm('manage', 'team')
    def post(self):
        try:
            user = g.portal_user
            # Add a user to multiple teams
            data = request.get_json()
            #user_id = data.get('user_id')
            team_names = data.get('team_names')
            result = TeamService.add_member_to_teams(user.id, team_names)
            if "error" in result:
                return result, 400
            return result, 200
        except Exception as e:
            logger.error(f"Error adding user to multiple teams: {e}")
            return {"error": "Error adding user to multiple teams: " + str(e)}, 500

    @login_required
    @requires_perm('manage', 'team')
    def delete(self):
        try:
            # Remove a user from multiple teams
            user = g.portal_user
            data = request.get_json()
            team_names = data.get('team_names')
            result = TeamService.remove_member_from_teams(user.id, team_names)
            if "error" in result:
                return result, 400
            return result, 200
        except Exception as e:
            logger.error(f"Error removing user from multiple teams: {e}")
            return {"error": "Error removing user from multiple teams: " + str(e)}, 500

# Add the routes at the bottom
api.add_resource(UsersListAPI, "/users")
api.add_resource(UsersByIdAPI, "/users/<int:id>")
api.add_resource(UserByUsernameAPI, "/users/username/<string:username>")
api.add_resource(UserPermissionsByUsernameAPI, "/users/username/<string:username>/permissions")
api.add_resource(UserTeamsByUsernameAPI, "/users/username/<string:username>/teams")
api.add_resource(UserTeamsAPI, "/users/teams")

from flask import Blueprint, jsonify, request
from flask_restful import Resource, Api
from portal.models import Role, User, Permission, VALID_RESOURCES, VALID_ACTIONS
from extensions.ext_database import db
from portal.auth import login_required, get_user_from_token
from portal.utils import requires_perm

roles_bp = Blueprint('roles', __name__)
api = Api(roles_bp)

class RolesListAPI(Resource):
    @requires_perm('read', 'role')
    def get(self):
        try:
            roles = Role.query.all()
            return [role.to_dict() for role in roles], 200
        except Exception as e:
            return {"error": "Error returning list of roles: " + str(e)}, 500   

    @requires_perm('create', 'role')
    def post(self):
        try:
            data = request.get_json()
            name = data.get('name')
            permissions = data.get('permissions', [])

            if not name:
                return {"error": "Role name is required"}, 400

            role = Role(name=name)
            db.session.add(role)
            db.session.commit()

            # Add permissions to the role
            for perm in permissions:
                resource = perm.get('resource')
                action = perm.get('action')
                resource_id = perm.get('resource_id')

                if not resource or not action:
                    return {"error": "Permission resource and action are required"}, 400

                if resource not in VALID_RESOURCES:
                    return {"error": f"Invalid resource. Valid resources are: {', '.join(VALID_RESOURCES)}"}, 400

                existing_permission = Permission.query.filter_by(resource=resource, action=action, resource_id=resource_id).first()
                if not existing_permission:
                    existing_permission = Permission(resource=resource, action=action, resource_id=resource_id)
                    db.session.add(existing_permission)
                    db.session.commit()

                role.permissions.append(existing_permission)

            db.session.commit()
            return role.to_dict(), 201
        except Exception as e:
            return {"error": "Error creating role: " + str(e)}, 500

class RolesAPI(Resource):
    @requires_perm('read', 'role')
    def get(self, id):
        try:
            role = Role.query.get(id)  
            if role is None:
                return {"error": "Role not found"}, 404  
            return role.to_dict(), 200
        except Exception as e:
            return {"error": str(e)}, 500  

    @requires_perm('update', 'role')
    def patch(self, id):
        try:
            role = Role.query.get(id)
            if role is None:
                return {"error": "Role not found"}, 404
            data = request.get_json()
            if 'name' in data:
                role.name = data['name']

            if 'permissions' in data:
                role.permissions.clear()
                permissions = data['permissions']
                for perm in permissions:
                    resource = perm.get('resource')
                    action = perm.get('action')
                    resource_id = perm.get('resource_id')

                    if not resource or not action:
                        return {"error": "Permission resource and action are required"}, 400

                    if resource not in VALID_RESOURCES:
                        return {"error": f"Invalid resource. Valid resources are: {', '.join(VALID_RESOURCES)}"}, 400

                    existing_permission = Permission.query.filter_by(resource=resource, action=action, resource_id=resource_id).first()
                    if not existing_permission:
                        existing_permission = Permission(resource=resource, action=action, resource_id=resource_id)
                        db.session.add(existing_permission)
                        db.session.commit()

                    role.permissions.append(existing_permission)

            db.session.commit()
            return role.to_dict(), 200
        except Exception as e:
            return {"error": "Error updating role: " + str(e)}, 500

    @requires_perm('delete', 'role')
    def delete(self, id):
        try:
            role = Role.query.get(id)
            if role is None:
                return {"error": "Role not found"}, 404
            db.session.delete(role)
            db.session.commit()
            return {"message": "Role deleted"}, 200
        except Exception as e:
            return {"error": "Error deleting role: " + str(e)}, 500

class RoleByNameAPI(Resource):
    @requires_perm('read', 'role')
    def get(self, name):
        try:
            role = Role.query.filter_by(name=name).first()
            if role is None:
                return {"error": "Role not found"}, 404
            return role.to_dict(), 200
        except Exception as e:
            return {"error": str(e)}, 500

    @requires_perm('update', 'role')
    def patch(self, name):
        try:
            role = Role.query.filter_by(name=name).first()
            if role is None:
                return {"error": "Role not found"}, 404
            data = request.get_json()
            if 'name' in data:
                role.name = data['name']

            if 'permissions' in data:
                #role.permissions.clear()
                permissions = data['permissions']
                for perm in permissions:
                    resource = perm.get('resource')
                    action = perm.get('action')
                    resource_id = perm.get('resource_id')

                    if not resource or not action:
                        return {"error": "Permission resource and action are required"}, 400

                    if resource not in VALID_RESOURCES:
                        return {"error": f"Invalid resource. Valid resources are: {', '.join(VALID_RESOURCES)}"}, 400

                    if action not in VALID_ACTIONS:
                        return {"error": f"Invalid action. Valid actions are: {', '.join(VALID_ACTIONS)}"}, 400

                    existing_permission = Permission.query.filter_by(resource=resource, action=action, resource_id=resource_id).first()
                    if not existing_permission:
                        existing_permission = Permission(resource=resource, action=action, resource_id=resource_id)
                        db.session.add(existing_permission)
                        db.session.commit()

                    role.permissions.append(existing_permission)

            db.session.commit()
            return role.to_dict(), 200
        except Exception as e:
            return {"error": "Error updating role: " + str(e)}, 500
        
    @requires_perm('delete', 'role')
    def delete(self, name):
        try:
            role = Role.query.filter_by(name=name).first()
            if role is None:
                return {"error": "Role not found"}, 404
            db.session.delete(role)
            db.session.commit()
            return {"message": "Role deleted"}, 200
        except Exception as e:
            return {"error": "Error deleting role: " + str(e)}, 500

class RolePermissionDeleteAPI(Resource):
    @requires_perm('delete', 'role')
    def delete(self, name):
        try:
            role = Role.query.filter_by(name=name).first()
            if role is None:
                return {"error": "Role not found"}, 404

            data = request.get_json()
            resource = data.get('resource')
            action = data.get('action')
            resource_id = data.get('resource_id')

            if not resource or not action:
                return {"error": "Permission resource and action are required"}, 400

            if resource not in VALID_RESOURCES:
                return {"error": f"Invalid resource. Valid resources are: {', '.join(VALID_RESOURCES)}"}, 400

            if action not in VALID_ACTIONS:
                return {"error": f"Invalid action. Valid actions are: {', '.join(VALID_ACTIONS)}"}, 400

            if resource_id:
                #TODO check if resource_id is valid
                permission = Permission.query.filter_by(resource=resource, action=action, resource_id=resource_id).first()
            else:
                permission = Permission.query.filter_by(resource=resource, action=action).first()

            if not permission:
                return {"error": "Permission not found"}, 404

            if permission in role.permissions:
                role.permissions.remove(permission)
                db.session.commit()

            return {"message": "Permission removed from role"}, 200
        except Exception as e:
            return {"error": "Error removing permission from role: " + str(e)}, 500

# Add the routes at the bottom
api.add_resource(RolesListAPI, "/roles")
api.add_resource(RolesAPI, "/roles/<int:id>")
api.add_resource(RoleByNameAPI, "/roles/name/<string:name>")
api.add_resource(RolePermissionDeleteAPI, "/roles/name/<string:name>/permissions")
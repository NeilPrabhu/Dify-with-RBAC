from portal.models import Permission, User, Role, VALID_RESOURCES, VALID_ACTIONS
from portal.auth import get_user_from_token
from portal.utils import requires_perm, has_permission
import logging

from models.dataset import (
    AppDatasetJoin,
    Dataset,
    DatasetCollectionBinding,
    DatasetPermissionEnum,
    DatasetProcessRule,
    DatasetQuery,
    Document,
    DocumentSegment,
    ExternalKnowledgeBindings,
)

from extensions.ext_database import db
from flask import Blueprint, jsonify, request
from flask_restful import Resource, marshal, marshal_with, fields, Api, reqparse

permissions_bp = Blueprint('permissions', __name__)
api = Api(permissions_bp)
logger = logging.getLogger(__name__)

class PermissionsListAPI(Resource):
    @requires_perm('read', 'permission')
    def get(self):
        try:
            permissions = Permission.query.all()
            result = [permission.to_dict() for permission in permissions]
            return result, 200
        except Exception as e:
            logger.exception("Error returning list of permissions")

            return {"error": f"Error returning list of permissions: {str(e)}"}, 500

    @requires_perm('create', 'permission')
    def post(self):
        try:
            data = request.get_json()
            resource = data.get('resource')
            action = data.get('action')
            resource_id = data.get('resource_id')  # Optional

            if not resource or not action:
                return {"error": "Permission resource and action are required"}, 400

            if resource not in VALID_RESOURCES:
                return {"error": f"Invalid resource. Valid resources are: {', '.join(VALID_RESOURCES)}"}, 400

            # Check if the resource exists
            if resource_id:
                if resource == 'dataset':
                    dataset = Dataset.query.get(resource_id)
                    if not dataset:
                        return {"error": "Dataset not found"}, 404
                elif resource == 'document':
                    document = Document.query.get(resource_id)
                    if not document:
                        return {"error": "Document not found"}, 404
                elif resource == 'user':
                    user = User.query.get(resource_id)
                    if not user:
                        return {"error": "User not found"}, 404
                elif resource == 'role':
                    role = Role.query.get(resource_id)
                    if not role:
                        return {"error": "Role not found"}, 404

            existing_permission = Permission.query.filter_by(resource=resource, action=action, resource_id=resource_id).first()
            if existing_permission:
                logger.error("Permission already exists")
                return {"error": "Permission already exists"}, 409

            permission = Permission(resource=resource, action=action, resource_id=resource_id)
            db.session.add(permission)
            db.session.commit()
            return permission.to_dict(), 201
        except Exception as e:
            return {"error": "Error creating permission: " + str(e)}, 500

class PermissionsAPI(Resource):
    @requires_perm('read', 'permission')
    def get(self, id):
        try:
            permission = Permission.query.get(id)
            if permission is None:
                return {"error": "Permission not found"}, 404
            return permission.to_dict(), 200
        except Exception as e:
            return {"error": str(e)}, 500

    @requires_perm('update', 'permission')
    def patch(self, id):
        try:
            permission = Permission.query.get(id)
            if permission is None:
                return {"error": "Permission not found"}, 404
            data = request.get_json()
            
            resource = data.get('resource')
            if resource and resource not in VALID_RESOURCES:
                return {"error": f"Invalid resource. Valid resources are: {', '.join(VALID_RESOURCES)}"}, 400
            
            action = data.get('action')
            if action and action not in VALID_ACTIONS:
                return {"error": f"Invalid action. Valid actions are: {', '.join(VALID_ACTIONS)}"}, 400

            # Check if the resource exists if resource_id is provided
            if 'resource_id' in data:
                resource_id = data['resource_id']
                if resource == 'dataset':
                    dataset = Dataset.query.get(resource_id)
                    if not dataset:
                        return {"error": "Dataset not found"}, 404
                elif resource == 'document':
                    document = Document.query.get(resource_id)
                    if not document:
                        return {"error": "Document not found"}, 404
                elif resource == 'user':
                    user = User.query.get(resource_id)
                    if not user:
                        return {"error": "User not found"}, 404
                elif resource == 'role':
                    role = Role.query.get(resource_id)
                    if not role:
                        return {"error": "Role not found"}, 404

            if 'resource' in data:
                permission.resource = data['resource']
            if 'action' in data:
                permission.action = data['action']
            if 'resource_id' in data:
                permission.resource_id = data['resource_id']
            db.session.commit()
            return permission.to_dict(), 200
        except Exception as e:
            return {"error": "Error updating permission: " + str(e)}, 500

    @requires_perm('delete', 'permission')
    def delete(self, id):
        try:
            permission = Permission.query.get(id)
            if permission is None:
                return {"error": "Permission not found"}, 404
            db.session.delete(permission)
            db.session.commit()
            return {"message": "Permission deleted"}, 200
        except Exception as e:
            return {"error": "Error deleting permission: " + str(e)}, 500

# Add the routes at the bottom
api.add_resource(PermissionsListAPI, "/permissions")
api.add_resource(PermissionsAPI, "/permissions/<int:id>")
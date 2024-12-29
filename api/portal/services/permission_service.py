from portal.models import Permission, User, users_permissions_association
from extensions.ext_database import db

class PermissionService:
    @staticmethod
    def create_permissions_for_user(user: User, resource: str, resource_id: str, actions: list):
        if not user.role:
            raise ValueError("User does not have a role assigned")

        role_permissions = {perm.action for perm in user.role.permissions if perm.resource == resource}
        # to bring any important actions to front
        action = actions.sort()
        for action in actions:
            # Check if the user's role is not admin and they are trying to assign the create action
            if user.role.name != 'admin' and action == 'create':
                raise ValueError("Non-admin users cannot assign the 'create' action")

            if action not in role_permissions:
                raise ValueError(f"User {user.username} with Role '{user.role.name}' does not have permission for action '{action}' on resource '{resource}'")

            existing_permission = Permission.query.filter_by(
                resource=resource, action=action, resource_id=resource_id
            ).first()
            if not existing_permission:
                permission = Permission(resource=resource, action=action, resource_id=resource_id)
                db.session.add(permission)
                db.session.commit()
                user.permissions.append(permission)
            else:
                if existing_permission not in user.permissions:
                    user.permissions.append(existing_permission)
        db.session.commit()

    @staticmethod
    def delete_permissions_for_user(user: User, resource: str, resource_id: str, actions: list):
        for action in actions:
            permission = Permission.query.filter_by(
                resource=resource, action=action, resource_id=resource_id
            ).first()
            if permission and permission in user.permissions:
                user.permissions.remove(permission)
                db.session.commit()

    @staticmethod
    def modify_permissions_for_user(user: User, resource: str, resource_id: str, actions: list):
        existing_permissions = Permission.query.filter_by(resource=resource, resource_id=resource_id).all()
        for permission in existing_permissions:
            if permission in user.permissions:
                user.permissions.remove(permission)

        PermissionService.create_permissions_for_user(user, resource, resource_id, actions)

    @staticmethod
    def get_permissions_for_user(user: User):
        return [perm.to_dict() for perm in user.permissions]
    
    @staticmethod
    def delete_permissions_by_resource_id(resource: str, resource_id: str):
        """
        Delete all permissions and user-permission associations for a given resource and resource_id.

        :param resource: The resource type (e.g., 'dataset').
        :param resource_id: The ID of the resource.
        """
        # Get all permissions matching the resource and resource_id
        permissions = Permission.query.filter_by(resource=resource, resource_id=resource_id).all()

        if permissions:
            permission_ids = [perm.id for perm in permissions]

            # Delete associations from users_permissions_association based on permission_id
            db.session.execute(
                users_permissions_association.delete().where(
                    users_permissions_association.c.permission_id.in_(permission_ids)
                )
            )

            # Commit the transaction to ensure the associations are deleted
            db.session.commit()

            # Delete from permissions table
            Permission.query.filter(Permission.id.in_(permission_ids)).delete(synchronize_session=False)

            # Commit the transaction to ensure the permissions are deleted
            db.session.commit()
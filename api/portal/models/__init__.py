import json
import enum
from json import JSONDecodeError
from typing import List, Set
from extensions.ext_database import db
from sqlalchemy.orm import Mapped, relationship
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy.ext.associationproxy import AssociationProxy
from sqlalchemy import func
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, UniqueConstraint, Index
from sqlalchemy.dialects.postgresql import JSONB
from core.rag.retrieval.retrieval_methods import RetrievalMethod
from .types import StringUUID

VALID_RESOURCES = {'document', 'dataset', 'user', 'role', 'permission'}
VALID_ACTIONS = {'create', 'read', 'update', 'delete'}
VALID_ROLES = {'admin', 'editor', 'viewer'}
DEFAULT_DATASETS = ['BaaS', 'AVA-KB', 'EngReady', 'Evo']
ALLOW_CREATE_APP_MODES = ["chat", "agent-chat", "advanced-chat", "workflow", "completion"]

# Association table for users and teams
users_teams_association = db.Table(
    'users_teams_association',
    db.metadata,
    Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('team_id', Integer, ForeignKey('teams.id'), primary_key=True)
)
users_permissions_association = db.Table(
    'users_permissions_association',
    db.metadata,
    Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('permission_id', Integer, ForeignKey('permissions.id'), primary_key=True),
    Column('resource_id', String, nullable=True)
)
roles_permissions_association = db.Table(
    'roles_permissions_association',
    db.metadata,
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True),
    Column('permission_id', Integer, ForeignKey('permissions.id'), primary_key=True)
)
# Association table for teams and permissions
teams_permissions_association = db.Table(
    'teams_permissions_association',
    db.metadata,
    Column('team_id', Integer, ForeignKey('teams.id'), primary_key=True),
    Column('permission_id', Integer, ForeignKey('permissions.id'), primary_key=True)
)

class Permission(db.Model):
    __tablename__ = 'permissions'
    id = Column(Integer, primary_key=True)
    action = Column(String(64), nullable=False)
    resource = Column(String(64), nullable=False)
    resource_id = Column(String, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.current_timestamp())
    updated_at = Column(DateTime, nullable=False, server_default=func.current_timestamp())
    __table_args__ = (
        UniqueConstraint('action', 'resource', 'resource_id', name='_action_resource_resource_id_uc'),
    )

    # Relationships
    roles = relationship(
        "Role",
        secondary=roles_permissions_association,
        back_populates='permissions'
    )
    teams = relationship(
        "Team",
        secondary=teams_permissions_association,
        back_populates='permissions'
    )
    users = relationship(
        "User",
        secondary=users_permissions_association,
        back_populates='permissions'
    )

    def to_dict(self):
        return {
            "id": self.id,
            "action": self.action,
            "resource": self.resource,
            "resource_id": self.resource_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

class Role(db.Model):
    __tablename__ = 'roles'
    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    created_at = Column(DateTime, nullable=False, server_default=func.current_timestamp())
    updated_at = Column(DateTime, nullable=False, server_default=func.current_timestamp())

    # Relationships
    permissions = relationship(
        "Permission",
        secondary=roles_permissions_association,
        back_populates='roles'
    )

    users = relationship('User', back_populates='role')

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "permissions": [permission.to_dict() for permission in self.permissions]
        }

class User(db.Model):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    first_name = Column(String(64), nullable=False)
    last_name = Column(String(64), nullable=False)
    email = Column(String(64), nullable=False)
    profile_image_url = Column(String(256), nullable=False)
    ldap_uid = Column(String(64), unique=True, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.current_timestamp())
    updated_at = Column(DateTime, nullable=False, server_default=func.current_timestamp())
    last_active_at = Column(DateTime, nullable=False, server_default=func.current_timestamp())


    # Moving roles to 1 to 1 relationship with User as it causes issues w/ permissions
    '''
    roles: Mapped[List[Role]] = relationship(
        "Role",
        secondary=user_role_association,
        backref='users'
    )
    '''
    role_id = Column(Integer, ForeignKey('roles.id'))
    role = relationship("Role", back_populates='users')

    # Many-to-Many relationship with Teams
    teams = relationship(
        'Team',
        secondary='users_teams_association',
        back_populates='users'
    )

    # Permissions directly assigned to the user
    permissions = relationship(
        "Permission",
        secondary=users_permissions_association,
        back_populates='users'
    )

    __table_args__ = (Index('idx_username', 'username'),)


    def is_admin(self):
        return self.role and self.role.name == 'admin' or (self.role.name == 'super-admin')

    def is_editor(self):
        return self.role and self.role.name == 'editor'

    def is_viewer(self):
        return self.role and self.role.name == 'viewer'

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "ldap_uid": self.ldap_uid,
            "profile_image_url": self.profile_image_url,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            #"roles": [role.to_dict() for role in self.roles],
            "role": self.role.to_dict() if self.role else None,
            "permissions": [permission.to_dict() for permission in self.permissions]
        }

class Team(db.Model):
    __tablename__ = 'teams'
    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    description = Column(String(256), nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.current_timestamp())
    updated_at = Column(DateTime, nullable=False, server_default=func.current_timestamp())

    # Many-to-Many relationship with Users
    users = relationship(
        'User',
        secondary='users_teams_association',
        back_populates='teams'
    )

    # Permissions associated with the team
    permissions = relationship(
        "Permission",
        secondary='teams_permissions_association',
        back_populates='teams'
    )

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "users": [user.to_dict() for user in self.users],
            "permissions": [permission.to_dict() for permission in self.permissions]
        }
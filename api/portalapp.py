import os
import sys
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
if os.environ.get("DEBUG", "false").lower() != "true":
    from gevent import monkey

    monkey.patch_all()

    import grpc.experimental.gevent

    grpc.experimental.gevent.init_gevent()

import json
import logging
import threading
import time
import warnings
from logging.handlers import RotatingFileHandler
import requests

from flask import Flask, Response, request
from flask_cors import CORS
from werkzeug.exceptions import Unauthorized, BadRequest
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPExceptionError, LDAPBindError

import contexts
from commands import register_commands
from configs import dify_config
from core.model_runtime.errors.validate import CredentialsValidateFailedError
# from portal.config import *
# DO NOT REMOVE BELOW
from events import event_handlers  # noqa: F401
from extensions import (
    ext_celery,
    ext_code_based_extension,
    ext_compress,
    ext_database,
    ext_hosting_provider,
    ext_login,
    ext_mail,
    ext_migrate,
    ext_proxy_fix,
    ext_redis,
    ext_sentry,
    ext_storage,
)
from extensions.ext_database import db
from extensions.ext_login import login_manager
from libs.passport import PassportService

from portal.config import portal_settings
from portal.auth import create_access_token, login_required
# TODO: Find a way to avoid importing models here
from models.model import DifySetup
from models.dataset import Dataset, DatasetPermissionEnum
from portal.models import Role, User, Permission
from portal.services.dataset_service import DatasetService
from services.account_service import AccountService, RegisterService
from services.model_provider_service import ModelProviderService
from services.model_load_balancing_service import ModelLoadBalancingService
from controllers.console.setup import SetupApi

from portal.datasets import datasets_bp
from portal.roles import roles_bp
from portal.users import user_bp
from portal.permissions import permissions_bp
from portal.setup import setup_bp
from portal.models_controller import models_bp
from portal.model_providers import model_providers_bp
from portal.hit_testing import hit_testing_bp
from portal.datasets_segments import segments_bp
from portal.teams import teams_bp
from portal.utils import get_admin_service_account

# DO NOT REMOVE ABOVE
os.environ["TZ"] = "UTC"
# windows platform not support tzset
if hasattr(time, "tzset"):
    time.tzset()

logger = logging.getLogger(__name__)

class PortalApp(Flask):
    pass


# -------------
# Configuration
# -------------


config_type = os.getenv("EDITION", default="SELF_HOSTED")  # ce edition first


# ----------------------------
# Application Factory Function
# ----------------------------

def setup_model_provider(account, credentials, provider, model_type, model_name):

    model_provider_service = ModelProviderService()

    try:
        # Validate Model Credentials
        model_provider_service.model_credentials_validate(
            tenant_id=account.current_tenant_id,
            provider=provider,
            model=model_name,
            model_type=model_type,
            credentials=credentials,
        )
    except CredentialsValidateFailedError as ex:
        logging.exception(f"Error validating credentials: {ex}")
        raise ValueError(str(ex))

    # Enable Model Provider Model
    model_provider_service.enable_model(
        tenant_id=account.current_tenant_id,
        provider=provider,
        model=model_name,
        model_type=model_type,
    )

    # Disable Model Load Balancing
    model_load_balancing_service = ModelLoadBalancingService()
    model_load_balancing_service.disable_model_load_balancing(
        tenant_id=account.current_tenant_id,
        provider=provider,
        model=model_name,
        model_type=model_type,
    )

    # Save Model Credentials
    try:
        model_provider_service.save_model_credentials(
            tenant_id=account.current_tenant_id,
            provider=provider,
            model=model_name,
            model_type=model_type,
            credentials=credentials,
        )
    except CredentialsValidateFailedError as ex:
        logging.exception(f"Save model credentials error: {ex}")
        raise ValueError(str(ex))

    # Update Default Model
    try:
        model_provider_service.update_default_model_of_model_type(
            tenant_id=account.current_tenant_id,
            model_type=model_type,
            provider=provider,
            model=model_name,
        )
    except Exception as ex:
        logging.exception(f"{model_type} save error: {ex}")
        raise ex

def create_flask_app_with_configs() -> Flask:
    """
    create a raw flask app
    with configs loaded from .env file
    """
    dify_app = PortalApp(__name__)
    dify_app.config.from_mapping(dify_config.model_dump())
    # SQLALCHEMY_BINDS = {
    # "ava": "sqlite:////path/to/meta.db"
    # }
    # populate configs into system environment variables
    for key, value in dify_app.config.items():
        if isinstance(value, str):
            os.environ[key] = value
        elif isinstance(value, int | float | bool):
            os.environ[key] = str(value)
        elif value is None:
            os.environ[key] = ""

    return dify_app

# portalapp.py

def initial_setup():
    admin_email = "admin-dify@admin.net"
    name = "Admin User"
    password = "SecurePassword123"
    ip_address = "127.0.0.1"

    # Initial setup for Dify
    if not db.session.query(DifySetup).first():
        RegisterService.setup(
            email=admin_email, name=name, password=password, ip_address=ip_address
        )
    account = get_admin_service_account()

    # Create roles
    roles = {}
    role_names = ['super-admin', 'admin', 'editor', 'viewer']
    for role_name in role_names:
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            role = Role(name=role_name)
            db.session.add(role)
        roles[role_name] = role
    db.session.commit()

    # Create the admin-dify user if it doesn't exist
    admin_user = User.query.filter_by(email=admin_email).first()
    if not admin_user:
        admin_user = User(
            username='admin-dify',
            first_name='Admin',
            last_name='User',
            email=admin_email,
            profile_image_url='',
            role=roles['super-admin']  # Assign super-admin role
            # No teams assigned to this user
        )
        db.session.add(admin_user)
        db.session.commit()

    # Create permissions
    permissions_data = [
        # Permissions for apps, datasets, documents
        {'action': 'create', 'resource': 'app', 'resource_id': None},
        {'action': 'read', 'resource': 'app', 'resource_id': None},
        {'action': 'update', 'resource': 'app', 'resource_id': None},
        {'action': 'delete', 'resource': 'app', 'resource_id': None},
        {'action': 'create', 'resource': 'dataset', 'resource_id': None},
        {'action': 'read', 'resource': 'dataset', 'resource_id': None},
        {'action': 'update', 'resource': 'dataset', 'resource_id': None},
        {'action': 'delete', 'resource': 'dataset', 'resource_id': None},
        {'action': 'create', 'resource': 'document', 'resource_id': None},
        {'action': 'read', 'resource': 'document', 'resource_id': None},
        {'action': 'update', 'resource': 'document', 'resource_id': None},
        {'action': 'delete', 'resource': 'document', 'resource_id': None},
        {'action': 'create', 'resource': 'permission', 'resource_id': None},
        {'action': 'read', 'resource': 'permission', 'resource_id': None},
        {'action': 'update', 'resource': 'permission', 'resource_id': None},
        {'action': 'delete', 'resource': 'permission', 'resource_id': None},
        {'action': 'create', 'resource': 'role', 'resource_id': None},
        {'action': 'read', 'resource': 'role', 'resource_id': None},
        {'action': 'update', 'resource': 'role', 'resource_id': None},
        {'action': 'delete', 'resource': 'role', 'resource_id': None},

        # Permissions for users (excluding team management)
        {'action': 'read', 'resource': 'user', 'resource_id': None},
        {'action': 'update', 'resource': 'user', 'resource_id': None},
        {'action': 'delete', 'resource': 'user', 'resource_id': None},

    ]

    # Create team management permissions separately
    team_permissions_data = [
        {'action': 'create', 'resource': 'team', 'resource_id': None},
        {'action': 'read', 'resource': 'team', 'resource_id': None},
        {'action': 'update', 'resource': 'team', 'resource_id': None},
        {'action': 'delete', 'resource': 'team', 'resource_id': None},
        {'action': 'manage', 'resource': 'team', 'resource_id': None},
    ]

    # Add all permissions to the database
    permissions = []
    for perm_data in permissions_data + team_permissions_data:
        existing_permission = Permission.query.filter_by(
            action=perm_data['action'],
            resource=perm_data['resource'],
            resource_id=perm_data['resource_id']
        ).first()
        if not existing_permission:
            perm = Permission(**perm_data)
            permissions.append(perm)
    db.session.add_all(permissions)
    db.session.commit()

    # Assign permissions to roles
    super_admin_role = roles['super-admin']
    admin_role = roles['admin']
    editor_role = roles['editor']
    viewer_role = roles['viewer']

    # Super Admin gets all permissions
    super_admin_role.permissions.extend(permissions)
    db.session.commit()

    # Admin role permissions (excluding team management)
    admin_permissions = [
        p for p in permissions if
        p.action in ['create', 'read', 'update', 'delete'] and
        p.resource in ['app', 'dataset', 'document', 'user']
        and p not in team_permissions_data  # Exclude team permissions
    ]
    admin_role.permissions.extend(admin_permissions)
    db.session.commit()

    # Editor role permissions
    editor_permissions = [
        p for p in permissions if
        (p.action in ['read', 'update'] and
         p.resource in ['app', 'dataset', 'document']) or
        (p.action == 'read' and p.resource == 'user')
    ]
    editor_role.permissions.extend(editor_permissions)
    db.session.commit()

    # Viewer role permissions
    viewer_permissions = [
        p for p in permissions if
        p.action == 'read' and
        p.resource in ['dataset', 'document']
    ]
    viewer_role.permissions.extend(viewer_permissions)
    db.session.commit()

    # Setup model providers (existing code)
    embedding_credentials = {"base_url": "http://qnc-genai-g01:11435", "context_size": "4096"}
    embedding_provider = "ollama"
    embedding_model_type = "text-embedding"
    embedding_model_name = "mxbai-embed-large"

    setup_model_provider(
        account,
        embedding_credentials,
        embedding_provider,
        embedding_model_type,
        embedding_model_name
    )

    llm_credentials = {"base_url": "http://qnc-genai-g01:11435", "mode": "chat",
                       "context_size": "4096", "max_tokens": "4096", "vision_support": "false"}
    llm_provider = "ollama"
    llm_model_type = "llm"
    llm_model_name = "llama3.1:latest"

    setup_model_provider(
        account,
        llm_credentials,
        llm_provider,
        llm_model_type,
        llm_model_name
    )

    # TODO - add re-ranker model
    #rerank_credentials = {"server_url": "SFlCUklEOhlIHtflCrUbnGqbhu0djQREQt/7FcIcJLJwUG7cjxFOkABCvDkn5TigYvUkFAJy8FZNjbad9n/IEc4kTCysP5AGVoNyMxlx2v7Ef5I9gmO97I/q6UfxAvw2MXOAQC2bpoon4KGuyZPEwd0dODMjRB1MsEcmEQDpEfMWGN6a9hX8tn0ALM2KpEqXGLYdZNMO3nCynwXMU8amCkLALtyaZ4wEHT7UTmsgIYqDmp46VlXJdqfpwLekjn+w8LElgmc51R4ciITZg2HvZEQcexyZp31+vfV80mumBhiWkn9JdqodGfgI5gsLsCB3nJdBQxfacPxGr+JikRms4WrKG1T4wRJ1DAkUMknNih3+W+wbiAhfqZ1TPI9CRw+/LHm6nJh0iHlufA2gjGSwTsK336vUyxjjXysI6H6WS7lxioU00LHHnloyQcM=", "context_size": 512}
    #rerank_provider = "huggingface_tei"
    #rerank_model_type = "rerank"
    #rerank_model_name = "BAAI/bge-reranker-large"
    #setup_model_provider(account, rerank_credentials, rerank_provider, \
    #                    rerank_model_type, rerank_model_name)

    # Create hardcoded datasets if they don't already exist
    dataset_names = ['BaaS', 'AVA-KB', 'EngReady', 'Evo']
    for name in dataset_names:
        existing_dataset = Dataset.query.filter_by(name=name).first()
        if not existing_dataset:
            ds = DatasetService.create_empty_dataset(
                account.current_tenant_id,
                name=name,
                indexing_technique="high_quality",
                account=account,
                permission=DatasetPermissionEnum.ALL_TEAM,
                provider="vendor",
            )
            db.session.add(ds)
    db.session.commit()

def create_app() -> Flask:
    app = create_flask_app_with_configs()

    #app.secret_key = app.config["SECRET_KEY"]

    log_handlers = None
    log_file = app.config.get("LOG_FILE")
    if log_file:
        log_dir = os.path.dirname(log_file)
        os.makedirs(log_dir, exist_ok=True)
        log_handlers = [
            RotatingFileHandler(
                filename=log_file,
                maxBytes=1024 * 1024 * 1024,
                backupCount=5,
            ),
            logging.StreamHandler(sys.stdout),
        ]

    logging.basicConfig(
        level=app.config.get("LOG_LEVEL"),
        format=app.config.get("LOG_FORMAT"),
        datefmt=app.config.get("LOG_DATEFORMAT"),
        handlers=log_handlers,
        force=True,
    )
    log_tz = app.config.get("LOG_TZ")
    if log_tz:
        from datetime import datetime

        import pytz

        timezone = pytz.timezone(log_tz)

        def time_converter(seconds):
            return datetime.utcfromtimestamp(seconds).astimezone(timezone).timetuple()

        for handler in logging.root.handlers:
            handler.formatter.converter = time_converter
    initialize_extensions(app)

    with app.app_context():
        if not os.getenv('MIGRATIONS_RUNNING'):
            initial_setup()

    return app


def initialize_extensions(app):
    # Since the application instance is now created, pass it to each Flask
    # extension instance to bind it to the Flask application instance (app)
    # ext_compress.init_app(app)
    # ext_code_based_extension.init()
    ext_database.init_app(app)
    ext_migrate.init(app, db)
    ext_redis.init_app(app)
    ext_storage.init_app(app)
    ext_celery.init_app(app)
    ext_login.init_app(app)
    # ext_mail.init_app(app)
    # ext_hosting_provider.init_app(app)
    # ext_sentry.init_app(app)
    # ext_proxy_fix.init_app(app)



# Flask-Login configuration
# change to fetch user from portal users table!
@login_manager.request_loader
def load_user_from_request(request_from_flask_login):
    return get_admin_service_account()

@login_manager.unauthorized_handler
def unauthorized_handler():
    pass


# create app
app = create_app()
CORS(app)
celery = app.extensions["celery"]

if app.config.get("TESTING"):
    print("App is running in TESTING mode")


@app.after_request
def after_request(response):
    """Add Version headers to the response."""
    response.set_cookie("remember_token", "", expires=0)
    response.headers.add("X-Version", app.config["CURRENT_VERSION"])
    response.headers.add("X-Env", app.config["DEPLOY_ENV"])
    return response


@app.route("/health")
def health():
    return Response(
        json.dumps({"pid": os.getpid(), "status": "ok", "version": app.config["CURRENT_VERSION"]}),
        status=200,
        content_type="application/json",
    )


@app.route("/threads")
def threads():
    num_threads = threading.active_count()
    threads = threading.enumerate()

    thread_list = []
    for thread in threads:
        thread_name = thread.name
        thread_id = thread.ident
        is_alive = thread.is_alive()

        thread_list.append(
            {
                "name": thread_name,
                "id": thread_id,
                "is_alive": is_alive,
            }
        )

    return {
        "pid": os.getpid(),
        "thread_num": num_threads,
        "threads": thread_list,
    }


@app.route("/db-pool-stat")
def pool_stat():
    engine = db.engine
    return {
        "pid": os.getpid(),
        "pool_size": engine.pool.size(),
        "checked_in_connections": engine.pool.checkedin(),
        "checked_out_connections": engine.pool.checkedout(),
        "overflow_connections": engine.pool.overflow(),
        "connection_timeout": engine.pool.timeout(),
        "recycle_time": db.engine.pool._recycle,
    }


@app.route("/dify-users")
def dify_users():
    # import services.account_service.py 
    return {}


@app.post('/login/access-token')
def login_access_token():
    try:
        request_body = request.get_json()
    except Exception as e:
        logger.info(f"Exception parsing request body: {e}")
        request_body = request.form

    username = request_body.get("username")
    password = request_body.get("password")
    username = username.split("@")[0]

    if username == "admin-dify":
        user = db.session.query(User).filter(User.username == username).first()
        if not user:
            return Response(json.dumps({"error": "User not found"}), status=404, content_type="application/json")
        if password == "SecurePassword123":
            token = create_access_token(subject=username)
            return Response(json.dumps({"token": token, "token_type": "bearer"}), status=200, content_type="application/json")
        else:
            return Response(json.dumps({"error": "Invalid credentials"}), status=401, content_type="application/json")
        
    if username == "test":
        # Bypass authentication for test user
        user = db.session.query(User).filter(User.username == username).first()
        if not user:
            # Create the test user if it doesn't exist
            role = db.session.query(Role).filter_by(name="viewer").first()
            user = User(
                username="test",
                first_name="Test",
                last_name="User",
                email="test@example.com",
                role=role
            )
            db.session.add(user)
            db.session.commit()

        # Generate a token for the test user
        token = create_access_token(subject=username)
        return {"access_token": token}, 200

    # Authenticate with LDAP
    conn = ldap_check(username, password)
    if conn is None:
        return Response(json.dumps({"error": "Invalid credentials"}), status=401, content_type="application/json")

    user = db.session.query(User).filter(User.username == username).first()

    if user is None:
        # Fetch LDAP user info
        search_filter = f"(&(objectClass=user)(sAMAccountName={username}))"
        conn.search("DC=jnpr,DC=net", search_filter, SUBTREE, attributes=["givenName", "displayName", "sn", "mail", "uidNumber"])
        if conn.entries:
            entry = conn.entries[0].entry_attributes_as_dict

            # Assign default 'viewer' role
            viewer_role = db.session.query(Role).filter_by(name='viewer').first()
            if not viewer_role:
                return Response(json.dumps({"error": "Viewer role not found"}), status=500, content_type="application/json")

            user = User(email=entry["mail"][0],
                first_name=entry["givenName"][0],
                last_name=entry["sn"][0],
                ldap_uid=entry["uidNumber"][0],
                username=username,
                role=viewer_role,
            )
            db.session.add(user)
            db.session.commit()
            # TODO - Assign permissions appropriately, for now just assign all permissions
            # eventually we want to provide create, delete for datasets and grant ability
            # to assign permssions for these datasets
            '''
            # Assign permissions based on roles
            for role in user.roles:
                for perm in role.permissions:
                    if perm not in user.permissions:
                        user.permissions.append(perm)
            '''
            db.session.commit()
        else:
            return Response(json.dumps({"error": "User not found in LDAP"}), status=404, content_type="application/json")

    # Generate access token
    token = create_access_token(subject=username)
    return Response(json.dumps({"token": token, "token_type": "bearer"}), status=200, content_type="application/json")

@app.post("/users/invite")
def user_invite():
    request_body = request.get_json()
    username = request_body.get("username")
    password = request_body.get("password")
    username = username.split("@")[0]
    role = request_body.get("role", "")
    permissions = request_body.get("permissions", [])

    if username == "test":
        # Bypass LDAP authentication and password storage for test user
        user = db.session.query(User).filter(User.username == username).first()
        if user:
            return Response(json.dumps({"error": "User already exists"}), status=409, content_type="application/json")

        if role == "":
            role = "viewer"
        role_name = role.lower()
        user_role = db.session.query(Role).filter_by(name=role_name).first()
        if not user_role:
            return Response(
                json.dumps({"error": f"Role '{role_name}' not found"}),
                status=400,
                content_type="application/json"
            )

        # Create the test user without password
        user = User(
            username=username,
            first_name="Test",
            last_name="User",
            email="test@example.com",
            role=user_role
        )
        db.session.add(user)
        db.session.commit()

        # Generate a token for the test user
        access_token = create_access_token(identity=user.username)
        return Response(json.dumps({"message": "Test user created successfully", "token": access_token}), status=201, content_type="application/json")

    # Authenticate with LDAP
    conn = ldap_check(username, password)
    if conn is None:
        return Response(json.dumps({"error": "Invalid credentials"}), status=401, content_type="application/json")

    user = db.session.query(User).filter(User.username == username).first()
    if user:
        return Response(json.dumps({"error": "User already exists"}), status=409, content_type="application/json")

    # Fetch LDAP user info
    search_filter = f"(&(objectClass=user)(sAMAccountName={username}))"
    conn.search("DC=jnpr,DC=net", search_filter, SUBTREE, attributes=["givenName", "displayName", "sn", "mail", "uidNumber"])
    if not conn.entries:
        return Response(json.dumps({"error": "User not found in LDAP"}), status=404, content_type="application/json")

    entry = conn.entries[0].entry_attributes_as_dict
    if role == "":
        role = "viewer"
    # Retrieve the role from the database
    role_name = role.lower()
    user_role = db.session.query(Role).filter_by(name=role_name).first()
    if not user_role:
        return Response(
            json.dumps({"error": f"Role '{role_name}' not found"}),
            status=400,
            content_type="application/json"
        )

    # Create the user
    user = User(
        email=entry["mail"][0],
        first_name=entry.get("givenName", [""])[0],
        last_name=entry.get("sn", [""])[0],
        ldap_uid=entry.get("uidNumber", [0])[0],
        username=username,
        role=user_role
    )
    db.session.add(user)
    db.session.commit()

    # TODO - Assign permissions appropriately, for now just assign all permissions
    # eventually we want to provide create, delete for datasets and grant ability
    # to assign permssions for these datasets
    # Assign permissions based on roles
    '''
    for role in user.roles:
        for perm in role.permissions:
            if perm not in user.permissions:
                user.permissions.append(perm)
    db.session.commit()
    '''
    # Assign additional permissions if provided
    if permissions:
        for perm in permissions:
            action = perm.get("action")
            resource = perm.get("resource")
            resource_id = perm.get("resource_id")

            # Check if permission exists
            permission = db.session.query(Permission).filter_by(
                action=action,
                resource=resource,
                resource_id=resource_id
            ).first()

            # Create permission if it doesn't exist
            if not permission:
                permission = Permission(action=action, resource=resource, resource_id=resource_id)
                db.session.add(permission)
                db.session.commit()

            if permission not in user.permissions:
                user.permissions.append(permission)
        db.session.commit()

    return Response(json.dumps({"message": "User invited successfully"}), status=201, content_type="application/json")

    

app.register_blueprint(datasets_bp)
app.register_blueprint(roles_bp)
app.register_blueprint(user_bp)
app.register_blueprint(permissions_bp)
app.register_blueprint(setup_bp)
app.register_blueprint(models_bp)
app.register_blueprint(model_providers_bp)
app.register_blueprint(hit_testing_bp)
app.register_blueprint(segments_bp)
app.register_blueprint(teams_bp)


@app.route("/needs_login")
@login_required
def needs_login():
    return Response(json.dumps({"status": "Success"}))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)

'''


import os
import sys
import pytest
from flask import Flask
from portalapp import create_app
from extensions.ext_database import db as _db
from extensions.ext_redis import redis_client
print("Current working directory:", os.getcwd())
# Add the project directory to the Python path
#sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..')))
from tests.unit_tests.configs.config import Config, TestConfig
from sqlalchemy.orm import scoped_session, sessionmaker

@pytest.fixture(scope='session')
def app():
    app = create_app()
    app.config.from_object(Config)
    with app.app_context():
        yield app

@pytest.fixture(scope='session')
def client(app):
    return app.test_client()

@pytest.fixture(scope='session')
def db(app):
    _db.app = app
    _db.create_all()
    yield _db
    _db.drop_all()

@pytest.fixture(scope='function', autouse=True)
def session(db):
    connection = db.engine.connect()
    transaction = connection.begin()

    # Use scoped_session and sessionmaker to create a session
    session_factory = sessionmaker(bind=connection)
    Session = scoped_session(session_factory)
    db.session = Session()

    yield Session

    transaction.rollback()
    connection.close()
    Session.remove()
'''


import pytest
from extensions.ext_database import db
from portalapp import create_app

@pytest.fixture
def app():
    app = create_app()
    # Set up the additional configurations here
    app.config["TESTING"] = False
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["REDIS_URL"] = "redis://localhost:6379/0"
    app.config["SERVER_NAME"] = "localhost"

    with app.app_context():
        db.create_all()  # Create tables
    yield app
    db.drop_all()  # Clean up tables after the tests

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def runner(app):
    return app.test_cli_runner()

from datetime import datetime, timedelta
from typing import Any, Union, Optional
from jose import jwt, JWTError
from flask import request, Response, g
from portal.config import portal_settings
from portal.models import User
from extensions.ext_database import db
from functools import wraps
import logging

logger = logging.getLogger(__name__)

ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

def create_access_token(subject: Union[str,Any], expires_delta=None):
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode={"exp": expire, "sub" : str(subject)}
    encoded_jwt = jwt.encode(to_encode, portal_settings.SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_jwt(token: str):
    payload_decode=jwt.decode(token, portal_settings.SECRET_KEY)
    #placeholder for validation code
    return payload_decode["sub"]

def get_token():
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer"):
        return auth_header.split(" ")[1]
    else:
         raise Exception("No Auth")
    
def decode_token(token):
    try:
        payload = jwt.decode(token, portal_settings.SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def get_user_from_token(token):
    try:
        payload = decode_token(token)
        username = payload.get('sub')
        if not username:
            return None
        user = User.query.filter_by(username=username).first()
        return user
    except Exception as e:
        return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            token = get_token()
            username = decode_jwt(token)
        except JWTError as e:
            logger.info(f"invalid jwt - {e}")
            return Response("Unauthorized - invalid jwt", status=401)
        except Exception as e:
            logger.error(f"Unexpected exception on decoding jwt - {e}")
            #logger.error(f"token - {token}")
            return Response("Unauthorized", status=401)
        user = db.session.query(User).filter(User.username == username).first()
        if user is None:
            return Response(f"Unauthorized - no user - {username} {token}", status=401)
        g.portal_user = user
        logger.info(g)
        return f(*args, **kwargs)     
    return decorated_function

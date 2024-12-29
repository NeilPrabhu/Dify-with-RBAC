from functools import wraps

from flask import request, Blueprint
from flask_restful import Resource, reqparse, Api

from configs import dify_config
from libs.helper import StrLen, email, get_remote_ip
from libs.password import valid_password
from models.model import DifySetup
from services.account_service import RegisterService, TenantService

setup_bp = Blueprint("setup_blueprint", __name__)
api = Api(setup_bp)

class SetupApi(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("email", type=email, required=True, location="json")
        parser.add_argument("name", type=StrLen(30), required=True, location="json")
        parser.add_argument("password", type=valid_password, required=True, location="json")
        args = parser.parse_args()

        # setup
        RegisterService.setup(
            email=args["email"], name=args["name"], password=args["password"], ip_address=get_remote_ip(request)
        )
        return {"result": "success"}, 201


api.add_resource(SetupApi, "/setup")
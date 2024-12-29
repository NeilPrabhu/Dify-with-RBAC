from portal.models import Role, User, Permission, DEFAULT_DATASETS, ALLOW_CREATE_APP_MODES
from portal.auth import login_required
from portal.utils import get_admin_service_account, requires_perm, has_permission
from models.dataset import Dataset, Document, DocumentSegment, DatasetPermissionEnum, AppDatasetJoin
from models.model import ApiToken
from models.model import Site

from extensions.ext_database import db
from flask import Blueprint, jsonify, request, g
from flask_login import current_user
from flask_restful import Resource, marshal, marshal_with, fields, Api, reqparse
from argparse import ArgumentTypeError
from transformers.hf_argparser import string_to_bool
from sqlalchemy import asc, desc
from functools import wraps

import services
from portal.services.dataset_service import DatasetPermissionService, DatasetService, DocumentService
from portal.services.permission_service import PermissionService
from services.account_service import AccountService
from services.workflow_service import WorkflowService
from services.app_dsl_service import AppDslService
from services.app_service import AppService


from services.file_service import FileService
from werkzeug.exceptions import Forbidden, NotFound
from configs import dify_config
from core.errors.error import (
    LLMBadRequestError,
    ModelCurrentlyNotSupportError,
    ProviderTokenNotInitError,
    QuotaExceededError,
)
from controllers.console.datasets.error import (
    FileTooLargeError,
    NoFileUploadedError,
    TooManyFilesError,
    UnsupportedFileTypeError,
)
from controllers.console.datasets.error import (
    ArchivedDocumentImmutableError,
    DocumentAlreadyFinishedError,
    DocumentIndexingError,
    IndexingEstimateError,
    InvalidActionError,
    InvalidMetadataError,
)
from controllers.console.app.error import (
    ProviderModelCurrentlyNotSupportError,
    ProviderNotInitializeError,
    ProviderQuotaExceededError,
)
from controllers.console.apikey import api_key_fields
from libs.helper import TimestampField
from fields.dataset_fields import dataset_fields, dataset_detail_fields
from fields.app_fields import app_detail_fields
from fields.file_fields import file_fields, upload_config_fields
from fields.document_fields import (
    dataset_and_document_fields,
    document_fields,
    document_status_fields,
    document_with_segments_fields,
)

datasets_bp = Blueprint("datasets_blueprint", __name__)
api = Api(datasets_bp)

import logging
import yaml

logger = logging.getLogger(__name__)

# see api/controllers/console/datasets/datasets

# current_user should be an admin account i.e. model Account that is used by everybody

# fields we want to output from the api
# dataset_fields = {
#     "id": fields.String,
#     "name": fields.String,
#     "description": fields.String,
#     "permission": fields.String,
#     "data_source_type": fields.String,
#     "indexing_technique": fields.String,
#     "created_by": fields.String,
#     "created_at": TimestampField,
# }
#  fields we want to output when it's a list of results
# dataset_list_fields = {
#     "data": fields.List(fields.Nested(dataset_fields)),
# }

def create_api_key_for_app(app, account):
    # Maximum number of API keys allowed per resource
    MAX_KEYS = 10

    # Check current number of API keys for the app
    current_key_count = (
        db.session.query(ApiToken)
        .filter(
            ApiToken.type == 'app',
            ApiToken.app_id == str(app.id)
        )
        .count()
    )

    if current_key_count >= MAX_KEYS:
        raise Exception(f"Cannot create more than {MAX_KEYS} API keys for this app.")

    # Generate API key
    key = ApiToken.generate_api_key('app-', 24)

    # Create and save the new API token
    api_token = ApiToken()
    api_token.app_id = str(app.id)
    api_token.tenant_id = account.current_tenant_id
    api_token.token = key
    api_token.type = 'app'
    db.session.add(api_token)
    db.session.commit()

    return api_token

def _validate_name(name):
    if not name or len(name) < 1 or len(name) > 40:
        raise ValueError("Name must be between 1 to 40 characters.")
    return name


def _validate_description_length(description):
    if len(description) > 400:
        raise ValueError("Description cannot exceed 400 characters.")
    return description

def serialize(model):
    return {c.name: getattr(model, c.name) for c in model.__table__.columns}

def sqlalchemy_to_json(q):
    output = []
    for o in q:
        output.append(serialize(o))
    return jsonify(output)

# AccountService.load_user()
class DatasetsListAPI(Resource):
    @login_required
    @requires_perm('read', 'dataset')
    def get(self):
        account = get_admin_service_account()
        page = request.args.get("page", default=1, type=int)
        limit = request.args.get("limit", default=20, type=int)
        ids = request.args.getlist("ids")
        datasets, count = DatasetService.get_datasets(
                page, limit, account.current_tenant_id, account, None, None
        )
        logger.info(f"Showing datasets for {g.portal_user.username}")

        # Filter datasets based on user permissions
        accessible_datasets = []
        if g.portal_user.is_admin():
            accessible_datasets = datasets
        else:
            # Get dataset IDs the user has 'read' permission for
            permitted_dataset_ids = [
                perm.resource_id for perm in g.portal_user.permissions
                if perm.action == 'read' and perm.resource == 'dataset'
            ]

            # Filter datasets to include only default datasets and permitted datasets
            for dataset in datasets:
                if dataset.name in DEFAULT_DATASETS or dataset.id in permitted_dataset_ids:
                    accessible_datasets.append(dataset)

        logger.info(f"Accessible Datasets- {accessible_datasets}")

        return marshal(accessible_datasets, dataset_detail_fields)
    '''
    @login_required
    @requires_perm('read', 'dataset')
    def get(self):
        account = get_admin_service_account()
        page = request.args.get("page", default=1, type=int)
        limit = request.args.get("limit", default=20, type=int)
        ids = request.args.getlist("ids")
        datasets, count = DatasetService.get_datasets(
                page, limit, account.current_tenant_id, account, None, None
        )
        logger.info(f"Showing datasets for {g.portal_user.username}")
        if g.portal_user.username == "bryanb":
            datasets = DatasetService.get_dataset("c9a13a9e-0e1e-49ac-bc73-f2b0b6027c95")
        elif g.portal_user.username == "hpogadadanda":
            datasets = DatasetService.get_dataset("b88aded5-9c89-446e-9d88-df821043535e")
        elif g.portal_user.username == "neilp":
            datasets = DatasetService.get_dataset("b88aded5-9c89-446e-9d88-df821043535e")
        #elif g.portal_user.username == "_ai-builder":
        #    datasets = DatasetService.get_dataset("61b90bbc-b6e6-4be2-adc6-ad984d64ffa4")
            
        else:
            pass

        logger.info(f"Datasets- {datasets}")

        return marshal(datasets, dataset_detail_fields)'''
    @login_required
    @requires_perm('create', 'dataset')
    def post(self):
        try:
            if not g.portal_user.is_admin():
                raise Forbidden()
            account = get_admin_service_account()
            parser = reqparse.RequestParser()
            parser.add_argument(
                "name",
                nullable=False,
                help="type is required. Name must be between 1 to 40 characters.",
                type=_validate_name,
            )

            parser.add_argument("data", type=str, required=False, nullable=False, location="json")
            parser.add_argument("app_name", type=str, required=False, location="json")
            parser.add_argument("description", type=str, location="json")
            parser.add_argument("icon_type", type=str, location="json")
            parser.add_argument("icon", type=str, location="json")
            parser.add_argument("icon_background", type=str, location="json")
            args = parser.parse_args()
            dataset_name = args["name"]

            ds = DatasetService.create_empty_dataset(
                account.current_tenant_id,
                name=args["name"],
                indexing_technique="high_quality",
                account=account,
                permission=DatasetPermissionEnum.ALL_TEAM,
                provider="vendor",
            )
            args["indexing_technique"] = "high_quality"
            args["embedding_model"] = "mxbai-embed-large"
            args["embedding_model_provider"] = "ollama"

            args["retrieval_model"] = {
                                            "search_method": "hybrid_search",
                                            "reranking_enable": True,
                                            "reranking_mode": "weighted_score",
                                            "reranking_model": {
                                                "reranking_provider_name": "",
                                                "reranking_model_name": ""
                                            },
                                            "weights": {
                                                "keyword_setting": {
                                                "keyword_weight": 0.3
                                                },
                                                "vector_setting": {
                                                "vector_weight": 0.7,
                                                "embedding_model_name": "",
                                                "embedding_provider_name": ""
                                                }
                                            },
                                            "top_k": 2,
                                            "score_threshold_enabled": False,
                                            "score_threshold": 0
                                        }
            # Create permissions for the user who created the dataset
            #user = g.portal_user
            #actions = ["read", "update", "delete","create"]
            #PermissionService.create_permissions_for_user(user, "dataset", ds.id, actions)

            # TODO: improve to pick up the default model from the tenant settings
            # TODO: make one call to create workflow and app
            knowledge_retrieval_model_provider = "ollama"
            knowledge_retrieval_model_name = "mxbai-embed-large"
            llm_model_name = "llama3.1:latest"
            llm_model_provider = "ollama"

            #if "mode" not in args or args["mode"] is None:
            #    args["mode"] = 'chat'
            if "app_name" not in args or args["app_name"] is None:
                args["name"] = g.portal_user.username+": "+dataset_name
            else:
                args["name"] = args["app_name"]
            if "data" not in args or args["data"] is None:
                args["data"] = f"app:\n  icon: \"\\U0001F4D1\"\n  icon_background: '#EFF1F5'\n  mode: advanced-chat\n  name: '{args['name']} '\nkind: app\nversion: 0.1.0\nworkflow:\n  conversation_variables: []\n  environment_variables: []\n  features:\n    file_upload:\n      image:\n        enabled: false\n        number_limits: 3\n        transfer_methods:\n        - local_file\n        - remote_url\n    opening_statement: ''\n    retriever_resource:\n      enabled: false\n    sensitive_word_avoidance:\n      enabled: false\n    speech_to_text:\n      enabled: false\n    suggested_questions: []\n    suggested_questions_after_answer:\n      enabled: false\n    text_to_speech:\n      enabled: false\n      language: ''\n      voice: ''\n  graph:\n    edges:\n    - data:\n        sourceType: start\n        targetType: knowledge-retrieval\n      id: 1711528914102-1711528915811\n      source: '1711528914102'\n      sourceHandle: source\n      target: '1711528915811'\n      targetHandle: target\n      type: custom\n    - data:\n        sourceType: knowledge-retrieval\n        targetType: llm\n      id: 1711528915811-1711528917469\n      source: '1711528915811'\n      sourceHandle: source\n      target: '1711528917469'\n      targetHandle: target\n      type: custom\n    - data:\n        sourceType: llm\n        targetType: answer\n      id: 1711528917469-1711528919501\n      source: '1711528917469'\n      sourceHandle: source\n      target: '1711528919501'\n      targetHandle: target\n      type: custom\n    nodes:\n    - data:\n        desc: ''\n        selected: true\n        title: Start\n        type: start\n        variables: []\n      height: 53\n      id: '1711528914102'\n      position:\n        x: 79.5\n        y: 2634.5\n      positionAbsolute:\n        x: 79.5\n        y: 2634.5\n      selected: true\n      sourcePosition: right\n      targetPosition: left\n      type: custom\n      width: 243\n    - data:\n        dataset_ids:\n        - {{ds.id}}\n        desc: Allows you to query text content related to user questions from the\n          Knowledge\n        query_variable_selector:\n        - '1711528914102'\n        - sys.query\n        retrieval_mode: single\n        selected: false\n        single_retrieval_config:\n          model:\n            completion_params:\n              frequency_penalty: 0\n              max_tokens: 512\n              presence_penalty: 0\n              temperature: 0\n              top_p: 1\n            mode: chat\n            name: {knowledge_retrieval_model_name}\n            provider: {knowledge_retrieval_model_provider}\n        title: Knowledge Retrieval\n        type: knowledge-retrieval\n      dragging: false\n      height: 101\n      id: '1711528915811'\n      position:\n        x: 362.5\n        y: 2634.5\n      positionAbsolute:\n        x: 362.5\n        y: 2634.5\n      selected: false\n      sourcePosition: right\n      targetPosition: left\n      type: custom\n      width: 243\n    - data:\n        context:\n          enabled: false\n          variable_selector: []\n        desc: Invoking large language models to answer questions or process natural\n          language\n        memory:\n          role_prefix:\n            assistant: ''\n            user: ''\n          window:\n            enabled: false\n            size: 50\n        model:\n          completion_params:\n            frequency_penalty: 0\n            max_tokens: 512\n            presence_penalty: 0\n            temperature: 0.7\n            top_p: 1\n          mode: chat\n          name: {llm_model_name}\n          provider: {llm_model_provider}\n        prompt_template:\n        - role: system\n          text: \"You are a helpful assistant. \\nUse the following context as your\\\n            \\ learned knowledge, inside <context></context> XML tags.\\n<context>\\n\\\n            {{#context#}}\\n</context>\\nWhen answer to user:\\n- If you don't know,\\\n            \\ just say that you don't know.\\n- If you don't know when you are not\\\n            \\ sure, ask for clarification.\\nAvoid mentioning that you obtained the\\\n            \\ information from the context.\\nAnd answer according to the language\\\n            \\ of the user's question.\"\n        selected: false\n        title: LLM\n        type: llm\n        variables: []\n        vision:\n          enabled: false\n      height: 163\n      id: '1711528917469'\n      position:\n        x: 645.5\n        y: 2634.5\n      positionAbsolute:\n        x: 645.5\n        y: 2634.5\n      selected: false\n      sourcePosition: right\n      targetPosition: left\n      type: custom\n      width: 243\n    - data:\n        answer: '{{#LLM.text#}}'\n        desc: ''\n        selected: false\n        title: Answer\n        type: answer\n        variables: []\n      height: 105\n      id: '1711528919501'\n      position:\n        x: 928.5\n        y: 2634.5\n      positionAbsolute:\n        x: 928.5\n        y: 2634.5\n      selected: false\n      sourcePosition: right\n      targetPosition: left\n      type: custom\n      width: 243\n    viewport:\n      x: 86.31278232100044\n      y: -2276.452137533831\n      zoom: 0.9753554615276419\n"
            app = AppDslService.import_and_create_new_app(
                tenant_id=account.current_tenant_id, data=args["data"], args=args, account=account
            )
            # add nodes, knowledge retrieval and reranker and model provider to app 
            api_key = create_api_key_for_app(app, account)
            d = {}
            d["indexing_technique"] = "high_quality"
            d["embedding_model"] = "mxbai-embed-large"
            d["embedding_model_provider"] = "ollama"

            d["retrieval_model"] = {
                                            "search_method": "hybrid_search",
                                            "reranking_enable": True,
                                            "reranking_mode": "weighted_score",
                                            "reranking_model": {
                                                "reranking_provider_name": "",
                                                "reranking_model_name": ""
                                            },
                                            "weights": {
                                                "keyword_setting": {
                                                "keyword_weight": 0.3
                                                },
                                                "vector_setting": {
                                                "vector_weight": 0.7,
                                                "embedding_model_name": "",
                                                "embedding_provider_name": ""
                                                }
                                            },
                                            "top_k": 2,
                                            "score_threshold_enabled": False,
                                            "score_threshold": 0
                                        }

            DatasetService.update_dataset(ds.id, d, account)
            workflow_data = {
                                "version": "0.1.2",
                                "kind": "app",
                                "app": {
                                    "name": app.name,
                                    "mode": app.mode,
                                    "icon": app.icon,
                                    "icon_background": app.icon_background,
                                    "description": app.description,
                                    "use_icon_as_answer_icon": app.use_icon_as_answer_icon,
                                },
                                "workflow": {
                                    "graph": {
                                        "nodes": [
                                            {
                                                "data": {
                                                    "desc": "",
                                                    "selected": False,
                                                    "title": "Start",
                                                    "type": "start",
                                                    "variables": []
                                                },
                                                "height": 53,
                                                "id": "1711528914102",
                                                "position": {
                                                    "x": 79.5,
                                                    "y": 2634.5
                                                },
                                                "positionAbsolute": {
                                                    "x": 79.5,
                                                    "y": 2634.5
                                                },
                                                "selected": False,
                                                "sourcePosition": "right",
                                                "targetPosition": "left",
                                                "type": "custom",
                                                "width": 244
                                            },
                                            {
                                                "data": {
                                                    "dataset_ids": [
                                                        ds.id
                                                    ],
                                                    "desc": "Allows you to query text content related to user questions from the Knowledge",
                                                    "query_variable_selector": [
                                                        "1711528914102",
                                                        "sys.query"
                                                    ],
                                                    "retrieval_mode": "multiple",
                                                    "selected": False,
                                                    "single_retrieval_config": {
                                                        "model": {
                                                            "completion_params": {
                                                                "frequency_penalty": 0,
                                                                "max_tokens": 512,
                                                                "presence_penalty": 0,
                                                                "temperature": 0,
                                                                "top_p": 1
                                                            },
                                                            "mode": "chat",
                                                            "name": "mxbai-embed-large",
                                                            "provider": "ollama"
                                                        }
                                                    },
                                                    "title": "Knowledge Retrieval",
                                                    "type": "knowledge-retrieval",
                                                    "multiple_retrieval_config": {
                                                        "top_k": 6,
                                                        "score_threshold": 0.8,
                                                        "reranking_mode": "weighted_score",
                                                        "reranking_model": {
                                                            "provider": "",
                                                            "model": ""
                                                        },
                                                        "weights": {
                                                            "vector_setting": {
                                                                "vector_weight": 0.7,
                                                                "embedding_provider_name": "ollama",
                                                                "embedding_model_name": "mxbai-embed-large"
                                                            },
                                                            "keyword_setting": {
                                                                "keyword_weight": 0.3
                                                            }
                                                        },
                                                        "reranking_enable": True
                                                    }
                                                },
                                                "dragging": False,
                                                "height": 151,
                                                "id": "1711528915811",
                                                "position": {
                                                    "x": 362.5,
                                                    "y": 2634.5
                                                },
                                                "positionAbsolute": {
                                                    "x": 362.5,
                                                    "y": 2634.5
                                                },
                                                "selected": False,
                                                "sourcePosition": "right",
                                                "targetPosition": "left",
                                                "type": "custom",
                                                "width": 244
                                            },
                                            {
                                                "data": {
                                                    "context": {
                                                        "enabled": False,
                                                        "variable_selector": []
                                                    },
                                                    "desc": "Invoking large language models to answer questions or process natural language",
                                                    "memory": {
                                                        "role_prefix": {
                                                            "assistant": "",
                                                            "user": ""
                                                        },
                                                        "window": {
                                                            "enabled": False,
                                                            "size": 50
                                                        }
                                                    },
                                                    "model": {
                                                        "completion_params": {
                                                            "frequency_penalty": 0,
                                                            "max_tokens": 512,
                                                            "presence_penalty": 0,
                                                            "temperature": 0.7,
                                                            "top_p": 1
                                                        },
                                                        "mode": "chat",
                                                        "name": "llama3.1:latest",
                                                        "provider": "ollama"
                                                    },
                                                    "prompt_template": [
                                                        {
                                                            "role": "system",
                                                            "text": "You are a helpful assistant. \nUse the following context as your learned knowledge, inside <context></context> XML tags.\n<context>\n{#context#}\n</context>\nWhen answer to user:\n- If you don't know, just say that you don't know.\n- If you don't know when you are not sure, ask for clarification.\nAvoid mentioning that you obtained the information from the context.\nAnd answer according to the language of the user's question."
                                                        }
                                                    ],
                                                    "selected": False,
                                                    "title": "LLM",
                                                    "type": "llm",
                                                    "variables": [],
                                                    "vision": {
                                                        "enabled": False
                                                    }
                                                },
                                                "height": 157,
                                                "id": "1711528917469",
                                                "position": {
                                                    "x": 645.5,
                                                    "y": 2634.5
                                                },
                                                "positionAbsolute": {
                                                    "x": 645.5,
                                                    "y": 2634.5
                                                },
                                                "selected": False,
                                                "sourcePosition": "right",
                                                "targetPosition": "left",
                                                "type": "custom",
                                                "width": 244
                                            },
                                            {
                                                "data": {
                                                    "answer": "{{#1711528917469.text#}}\n",
                                                    "desc": "",
                                                    "selected": False,
                                                    "title": "Answer",
                                                    "type": "answer",
                                                    "variables": []
                                                },
                                                "height": 105,
                                                "id": "1711528919501",
                                                "position": {
                                                    "x": 928.5,
                                                    "y": 2634.5
                                                },
                                                "positionAbsolute": {
                                                    "x": 928.5,
                                                    "y": 2634.5
                                                },
                                                "selected": True,
                                                "sourcePosition": "right",
                                                "targetPosition": "left",
                                                "type": "custom",
                                                "width": 244
                                            }
                                        ],
                                        "edges": [
                                            {
                                                "data": {
                                                    "sourceType": "start",
                                                    "targetType": "knowledge-retrieval"
                                                },
                                                "id": "1711528914102-1711528915811",
                                                "source": "1711528914102",
                                                "sourceHandle": "source",
                                                "target": "1711528915811",
                                                "targetHandle": "target",
                                                "type": "custom"
                                            },
                                            {
                                                "data": {
                                                    "sourceType": "knowledge-retrieval",
                                                    "targetType": "llm"
                                                },
                                                "id": "1711528915811-1711528917469",
                                                "source": "1711528915811",
                                                "sourceHandle": "source",
                                                "target": "1711528917469",
                                                "targetHandle": "target",
                                                "type": "custom"
                                            },
                                            {
                                                "data": {
                                                    "sourceType": "llm",
                                                    "targetType": "answer"
                                                },
                                                "id": "1711528917469-1711528919501",
                                                "source": "1711528917469",
                                                "sourceHandle": "source",
                                                "target": "1711528919501",
                                                "targetHandle": "target",
                                                "type": "custom"
                                            }
                                        ],
                                        "viewport": {
                                            "x": 48.674785778756814,
                                            "y": -1520.486930988133,
                                            "zoom": 0.7090700212086635
                                        }
                                    },
                                    "features": {
                                        "opening_statement": "",
                                        "suggested_questions": [],
                                        "suggested_questions_after_answer": {
                                            "enabled": False
                                        },
                                        "text_to_speech": {
                                            "enabled": False,
                                            "voice": "",
                                            "language": ""
                                        },
                                        "speech_to_text": {
                                            "enabled": False
                                        },
                                        "retriever_resource": {
                                            "enabled": False
                                        },
                                        "sensitive_word_avoidance": {
                                            "enabled": False
                                        },
                                        "file_upload": {
                                            "image": {
                                                "enabled": False,
                                                "number_limits": 3,
                                                "transfer_methods": [
                                                    "local_file",
                                                    "remote_url"
                                                ]
                                            }
                                        }
                                    }
                                },
                                "environment_variables": [],
                                "conversation_variables": [],
                                "hash": "61ef19a0828e5da1aa5f2e720390e885837a5a3d61c4d1538ffa4f3ac44244bd",  # Provide the correct hash if applicable
                            }

            workflow_data_yaml = yaml.dump(workflow_data, allow_unicode=True)
            AppDslService.import_and_overwrite_workflow(
                app_model=app,
                data=workflow_data_yaml,
                account=account
            )
            workflow_service = WorkflowService()
            workflow_service.publish_workflow(app_model=app, account=account)

            site = db.session.query(Site).filter(Site.app_id == app.id).first()
            if not site:
                response_data = {
                    'dataset': marshal(ds, dataset_detail_fields),
                    'app': marshal(app, app_detail_fields),
                    'api_key': marshal(api_key, api_key_fields)  # Ensure api_key_fields are defined
                }
            else:
                response_data = {
                    'dataset': marshal(ds, dataset_detail_fields),
                    'app': marshal(app, app_detail_fields),
                    'api_key': marshal(api_key, api_key_fields),  # Ensure api_key_fields are defined
                    'site_code': site.code  # Include the site code in the response
                }
            #response_data = {
            #    'dataset': marshal(ds, dataset_detail_fields),
            #    'app': marshal(app, app_detail_fields)
            #}
            #return marshal(ds, dataset_detail_fields), 201
            return response_data, 201

        except ValueError as e:
            logger.error(f"Error creating dataset or app: {e}")
            return {"error": str(e)}, 400
        except Exception as e:
            logger.error(f"Unexpected error creating dataset or app: {e}")
            return {"error": f"{e}"}, 500

class DatasetIndexingStatusApi(Resource):
    #@setup_required
    #@login_required
    #@account_initialization_required
    @requires_perm('read', 'dataset')
    def get(self, dataset_id):
        account = get_admin_service_account()
        dataset_id = str(dataset_id)
        documents = (
            db.session.query(Document)
            .filter(Document.dataset_id == dataset_id, Document.tenant_id == account.current_tenant_id)
            .all()
        )
        documents_status = []
        for document in documents:
            completed_segments = DocumentSegment.query.filter(
                DocumentSegment.completed_at.isnot(None),
                DocumentSegment.document_id == str(document.id),
                DocumentSegment.status != "re_segment",
            ).count()
            total_segments = DocumentSegment.query.filter(
                DocumentSegment.document_id == str(document.id), DocumentSegment.status != "re_segment"
            ).count()
            document.completed_segments = completed_segments
            document.total_segments = total_segments
            documents_status.append(marshal(document, document_status_fields))
        data = {"data": documents_status}
        return data

class DatasetsAPI(Resource):

    @requires_perm('read', 'dataset')
    def get(self, dataset_id):
        dataset_id_str = str(dataset_id)
        dataset = DatasetService.get_dataset(dataset_id_str)
        return marshal(dataset, dataset_detail_fields)
        
    @requires_perm('update', 'dataset')
    def patch(self, dataset_id):
        account = get_admin_service_account()
        dataset_id_str = str(dataset_id)
        dataset = DatasetService.get_dataset(dataset_id_str)
        if dataset is None:
            raise NotFound("Dataset not found.")
        # assert_user_owns_dataset(dataset)

        parser = reqparse.RequestParser()
        parser.add_argument(
            "name",
            nullable=False,
            help="type is required. Name must be between 1 to 40 characters.",
            type=_validate_name,
        )
        parser.add_argument("description", location="json", store_missing=False, type=_validate_description_length)
        parser.add_argument(
            "indexing_technique",
            type=str,
            location="json",
            choices=Dataset.INDEXING_TECHNIQUE_LIST,
            nullable=True,
            help="Invalid indexing technique.",
        )
        parser.add_argument(
            "permission",
            type=str,
            location="json",
            choices=(DatasetPermissionEnum.ONLY_ME, DatasetPermissionEnum.ALL_TEAM, DatasetPermissionEnum.PARTIAL_TEAM),
            help="Invalid permission.",
        )
        parser.add_argument("embedding_model", type=str, location="json", help="Invalid embedding model.")
        parser.add_argument(
            "embedding_model_provider", type=str, location="json", help="Invalid embedding model provider."
        )
        parser.add_argument("retrieval_model", type=dict, location="json", help="Invalid retrieval model.")
        parser.add_argument("partial_member_list", type=list, location="json", help="Invalid parent user list.")

        parser.add_argument(
            "external_retrieval_model",
            type=dict,
            required=False,
            nullable=True,
            location="json",
            help="Invalid external retrieval model.",
        )

        parser.add_argument(
            "external_knowledge_id",
            type=str,
            required=False,
            nullable=True,
            location="json",
            help="Invalid external knowledge id.",
        )

        parser.add_argument(
            "external_knowledge_api_id",
            type=str,
            required=False,
            nullable=True,
            location="json",
            help="Invalid external knowledge api id.",
        )
        args = parser.parse_args()
        data = request.get_json()

        # check embedding model setting
        if data.get("indexing_technique") == "high_quality":
            DatasetService.check_embedding_model_setting(
                dataset.tenant_id, data.get("embedding_model_provider"), data.get("embedding_model")
            )

        # The role of the current user in the ta table must be admin, owner, editor, or dataset_operator
        #DatasetPermissionService.check_permission(
        #    current_user, dataset, data.get("permission"), data.get("partial_member_list")
        #)

        dataset = DatasetService.update_dataset(dataset_id_str, args, account)
        
        # DatasetService.update_dataset()
        result_data = marshal(dataset, dataset_detail_fields)
        return result_data, 200

    @login_required
    @requires_perm('delete', 'dataset')
    def delete(self, dataset_id):
        dataset_id_str = str(dataset_id)

        try:
            dataset = DatasetService.get_dataset(dataset_id_str)
            if not dataset:
                return {"error": "Dataset not found."}, 404

            #if not has_permission(g.portal_user, 'delete', 'dataset', resource_id=dataset.id):
            #    return {"error": "You do not have permission to delete this dataset."}, 403

            # Check if there is an associated app
            app_dataset_join = db.session.query(AppDatasetJoin).filter(AppDatasetJoin.dataset_id == dataset_id_str).first()
            if app_dataset_join:
                app_id = app_dataset_join.app_id
                app_service = AppService()
                app = app_service.get_app_with_id(app_id)
                if app:
                    # Delete the app
                    app_service.delete_app(app)


            if DatasetService.delete_dataset(dataset_id_str, g.portal_user):
                # Delete permissions associated with the dataset
                PermissionService.delete_permissions_by_resource_id("dataset", dataset_id_str)
                return {"result": "success"}, 204
            else:
                return {"error": "Dataset unable to be deleted, check logs."}, 404
        except Exception as e:
            logger.error(f"Error deleting dataset: {e}")
            return {"error": "An unexpected error occurred while deleting the dataset."}, 500
 

class DatasetByNameApi(Resource):
    @login_required
    @requires_perm('delete', 'dataset')
    def delete(self, dataset_name):
        try:
            dataset = DatasetService.get_dataset_by_name(dataset_name)
            if not dataset:
                return {"error": "Dataset not found."}, 404
            dataset_id = dataset.id
            #if not has_permission(g.portal_user, 'delete', 'dataset', resource_id=dataset.id):
            #    return {"error": "You do not have permission to delete this dataset."}, 403


            # Check if there is an associated app
            app_dataset_join = db.session.query(AppDatasetJoin).filter(AppDatasetJoin.dataset_id == str(dataset_id)).first()
            if app_dataset_join:
                app_id = app_dataset_join.app_id
                app_service = AppService()
                app = app_service.get_app_with_id(app_id)
                if app:
                    # Delete the app
                    app_service.delete_app(app)

            if DatasetService.delete_dataset(dataset.id, g.portal_user):
                # Delete permissions associated with the dataset
                PermissionService.delete_permissions_by_resource_id("dataset", dataset_id)
                return {"result": "success"}, 204
            else:
                return {"error": "Dataset unable to be deleted, check logs."}, 404
        except Exception as e:
            logger.error(f"Error deleting dataset: {e}")
            return {"error": "An unexpected error occurred while deleting the dataset."}, 500

class DatasetSiteByNameApi(Resource):
    @login_required
    @requires_perm('read', 'app')
    def get(self, dataset_name):
        try:
            # Get the dataset by name
            dataset = DatasetService.get_dataset_by_name(dataset_name)
            if not dataset:
                return {'error': 'Dataset not found.'}, 404

            dataset_id = dataset.id

            # Check user's permission to access the dataset
            #DatasetService.check_dataset_permission(dataset, g.portal_user)

            # Find the app associated with this dataset
            app_dataset_join = db.session.query(AppDatasetJoin).filter_by(dataset_id=dataset_id).first()
            if not app_dataset_join:
                return {'error': 'No app associated with this dataset.'}, 404

            app_id = app_dataset_join.app_id

            # Get the site associated with this app
            site = db.session.query(Site).filter_by(app_id=app_id).first()
            if not site:
                return {'error': 'Site not found for the app.'}, 404

            # Return the site code
            return {'site_code': site.code}, 200

        except services.errors.account.NoPermissionError as e:
            logger.error(f"No permission to access dataset: {e}")
            return {'error': 'You do not have permission to access this dataset.'}, 403
        except Exception as e:
            logger.error(f"Error retrieving site code: {e}")
            return {'error': 'An unexpected error occurred.'}, 500

class FileAPI(Resource):
    @marshal_with(upload_config_fields)
    def get(self):
        file_size_limit = dify_config.UPLOAD_FILE_SIZE_LIMIT
        batch_count_limit = dify_config.UPLOAD_FILE_BATCH_LIMIT
        image_file_size_limit = dify_config.UPLOAD_IMAGE_FILE_SIZE_LIMIT
        return {
            "file_size_limit": file_size_limit,
            "batch_count_limit": batch_count_limit,
            "image_file_size_limit": image_file_size_limit,
        }, 200

    # TODO - need to add permission check for this
    @marshal_with(file_fields)
    def post(self):
        account = get_admin_service_account()
        # get file from request
        file = request.files["file"]
        # check file
        if "file" not in request.files:
            raise NoFileUploadedError()
        if len(request.files) > 1:
            raise TooManyFilesError()
        try:
            upload_file = FileService.upload_file(file, account)
        except services.errors.file.FileTooLargeError as file_too_large_error:
            raise FileTooLargeError(file_too_large_error.description)
        except services.errors.file.UnsupportedFileTypeError:
            raise UnsupportedFileTypeError()
        return upload_file, 201

class DocumentsListAPI(Resource):
    @requires_perm('read', 'document')
    def get(self, dataset_id):
        account = get_admin_service_account()
        dataset_id = str(dataset_id)
        page = request.args.get("page", default=1, type=int)
        limit = request.args.get("limit", default=20, type=int)
        search = request.args.get("keyword", default=None, type=str)
        sort = request.args.get("sort", default="-created_at", type=str)
        # "yes", "true", "t", "y", "1" convert to True, while others convert to False.
        try:
            fetch = string_to_bool(request.args.get("fetch", default="false"))
        except (ArgumentTypeError, ValueError, Exception) as e:
            fetch = False
        dataset = DatasetService.get_dataset(dataset_id)
        if not dataset:
            raise NotFound("Dataset not found.")

        try:
            DatasetService.check_dataset_permission(dataset, account)
        except services.errors.account.NoPermissionError as e:
            raise Forbidden(str(e))

        query = Document.query.filter_by(dataset_id=str(dataset_id), tenant_id=account.current_tenant_id)

        if search:
            search = f"%{search}%"
            query = query.filter(Document.name.like(search))

        if sort.startswith("-"):
            sort_logic = desc
            sort = sort[1:]
        else:
            sort_logic = asc

        if sort == "hit_count":
            sub_query = (
                db.select(DocumentSegment.document_id, db.func.sum(DocumentSegment.hit_count).label("total_hit_count"))
                .group_by(DocumentSegment.document_id)
                .subquery()
            )

            query = query.outerjoin(sub_query, sub_query.c.document_id == Document.id).order_by(
                sort_logic(db.func.coalesce(sub_query.c.total_hit_count, 0)),
                sort_logic(Document.position),
            )
        elif sort == "created_at":
            query = query.order_by(
                sort_logic(Document.created_at),
                sort_logic(Document.position),
            )
        else:
            query = query.order_by(
                desc(Document.created_at),
                desc(Document.position),
            )

        paginated_documents = query.paginate(page=page, per_page=limit, max_per_page=100, error_out=False)
        documents = paginated_documents.items
        if fetch:
            for document in documents:
                completed_segments = DocumentSegment.query.filter(
                    DocumentSegment.completed_at.isnot(None),
                    DocumentSegment.document_id == str(document.id),
                    DocumentSegment.status != "re_segment",
                ).count()
                total_segments = DocumentSegment.query.filter(
                    DocumentSegment.document_id == str(document.id), DocumentSegment.status != "re_segment"
                ).count()
                document.completed_segments = completed_segments
                document.total_segments = total_segments
            data = marshal(documents, document_with_segments_fields)
        else:
            data = marshal(documents, document_fields)
        response = {
            "data": data,
            "has_more": len(documents) == limit,
            "limit": limit,
            "total": paginated_documents.total,
            "page": page,
        }

        return response

    # TODO need to add permission check for documents as user can have read-only acccess
    @requires_perm('create', 'document')
    def post(self, dataset_id):
        account = get_admin_service_account()
        dataset = DatasetService.get_dataset(dataset_id)
        # {"data_source":{"type":"upload_file","info_list":{"data_source_type":"upload_file","file_info_list":{"file_ids":["ec4626f3-2e4f-4e17-9994-3081e09b2727"]}}},"indexing_technique":"economy","process_rule":{"rules":{},"mode":"automatic"},"doc_form":"text_model","doc_language":"English","retrieval_model":{"search_method":"semantic_search","reranking_enable":false,"reranking_mode":null,"reranking_model":{"reranking_provider_name":"","reranking_model_name":""},"weights":null,"top_k":2,"score_threshold_enabled":false,"score_threshold":null},"embedding_model":"","embedding_model_provider":""}
        # inject these basics into the args
        parser = reqparse.RequestParser()
        parser.add_argument(
            "indexing_technique", type=str, choices=Dataset.INDEXING_TECHNIQUE_LIST, nullable=False, location="json"
        )
        parser.add_argument("data_source", type=dict, required=False, location="json")
        parser.add_argument("process_rule", type=dict, required=False, location="json")
        parser.add_argument("duplicate", type=bool, default=True, nullable=False, location="json")
        parser.add_argument("original_document_id", type=str, required=False, location="json")
        parser.add_argument("doc_form", type=str, default="text_model", required=False, nullable=False, location="json")
        parser.add_argument(
            "doc_language", type=str, default="English", required=False, nullable=False, location="json"
        )
        parser.add_argument("retrieval_model", type=dict, required=False, nullable=False, location="json")
        args = parser.parse_args()
        try:
            documents, batch = DocumentService.save_document_with_dataset_id(dataset, args, account)
        except ProviderTokenNotInitError as ex:
            raise ProviderNotInitializeError(ex.description)
        except QuotaExceededError:
            raise ProviderQuotaExceededError()
        except ModelCurrentlyNotSupportError:
            raise ProviderModelCurrentlyNotSupportError()
        documents = marshal(documents, document_fields)
        return {"documents": documents, "batch": batch}

class DocumentAPI(Resource):
    @requires_perm('read', 'document')
    def get(self, dataset_id: str, document_id: str) -> Document:
        account = get_admin_service_account()
        # document = DocumentService.get_document(dataset_id, document_id)
        dataset = DatasetService.get_dataset(dataset_id)
        if not dataset:
            raise NotFound("Dataset not found.")

        try:
            DatasetService.check_dataset_permission(dataset, account)
        except services.errors.account.NoPermissionError as e:
            raise Forbidden(str(e))

        document = DocumentService.get_document(dataset_id, document_id)

        if not document:
            raise NotFound("Document not found.")
        document = marshal(document, document_fields)
        return document, 200
    
    def get_document(self, dataset_id: str, document_id: str) -> Document:
        account = get_admin_service_account()
        dataset = DatasetService.get_dataset(dataset_id)
        if not dataset:
            raise NotFound("Dataset not found.")

        try:
            DatasetService.check_dataset_permission(dataset, account)
        except services.errors.account.NoPermissionError as e:
            raise Forbidden(str(e))

        document = DocumentService.get_document(dataset_id, document_id)

        if not document:
            raise NotFound("Document not found.")

        if document.tenant_id != account.current_tenant_id:
            raise Forbidden("No permission.")

        return document

    @requires_perm('delete', 'document')
    def delete(self, dataset_id, document_id):

        dataset_id = str(dataset_id)
        document_id = str(document_id)
        dataset = DatasetService.get_dataset(dataset_id)
        if dataset is None:
            raise NotFound("Dataset not found.")
        # check user's model setting
        DatasetService.check_dataset_model_setting(dataset)

        document = self.get_document(dataset_id, document_id)

        try:
            DocumentService.delete_document(document)
        except services.errors.document.DocumentIndexingError:
            raise DocumentIndexingError("Cannot delete document during indexing.")

        return {"result": "success"}, 204
    
    # query = Document.query.filter_by(dataset_id=str(dataset_id), tenant_id=current_user.current_tenant_id)

class DocumentIndexingStatusApi(Resource):
    def get(self, dataset_id, batch):
        account = get_admin_service_account()
        dataset_id = str(dataset_id)
        batch = str(batch)
        tenant_id = account.current_tenant_id

        # get dataset
        dataset = db.session.query(Dataset).filter(Dataset.tenant_id == tenant_id, Dataset.id == dataset_id).first()
        if not dataset:
            raise NotFound("Dataset not found.")
        # get documents
        documents = DocumentService.get_batch_documents(dataset_id, batch, tenant_id)
        if not documents:
            raise NotFound("Documents not found.")
        documents_status = []
        for document in documents:
            completed_segments = DocumentSegment.query.filter(
                DocumentSegment.completed_at.isnot(None),
                DocumentSegment.document_id == str(document.id),
                DocumentSegment.status != "re_segment",
            ).count()
            total_segments = DocumentSegment.query.filter(
                DocumentSegment.document_id == str(document.id), DocumentSegment.status != "re_segment"
            ).count()
            document.completed_segments = completed_segments
            document.total_segments = total_segments
            if document.is_paused:
                document.indexing_status = "paused"
            documents_status.append(marshal(document, document_status_fields))
        data = {"data": documents_status}
        return data

api.add_resource(DatasetsListAPI, "/datasets/")
api.add_resource(DatasetsAPI, "/datasets/<uuid:dataset_id>")
api.add_resource(DatasetByNameApi, "/datasets/name/<string:dataset_name>")
api.add_resource(DatasetSiteByNameApi, "/datasets/site-by-name/<string:dataset_name>")
api.add_resource(DocumentAPI, "/datasets/<uuid:dataset_id>/documents/<uuid:document_id>")
api.add_resource(DocumentsListAPI, "/datasets/<uuid:dataset_id>/documents")
api.add_resource(DatasetIndexingStatusApi, "/datasets/<uuid:dataset_id>/indexing-status")
api.add_resource(DocumentIndexingStatusApi, "/datasets/<uuid:dataset_id>/documents/<string:batch>/indexing-status")
api.add_resource(FileAPI, "/files/")

import os
import sys
from enum import Enum
from sqlalchemy import text

sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from extensions.ext_database import db
from portalapp import create_app
from models.dataset import Dataset, DatasetProcessRule, Document, DocumentSegment, DatasetKeywordTable, Embedding, DatasetCollectionBinding, DatasetQuery, AppDatasetJoin, DatasetPermission
from models.account import Account, Tenant, TenantAccountJoin  # Import the Account, Tenant, and TenantAccountJoin models
from models.workflow import Workflow, WorkflowNodeExecution, WorkflowRun
from models.model import DifySetup, UploadFile, App, AppModelConfig, Site, InstalledApp, EndUser, Conversation, Message, ApiToken
from portal.models import User, Role, Permission, roles_permissions_association, users_permissions_association
from models.provider import Provider, ProviderModel, ProviderModelSetting, TenantDefaultModel


def clear_tables():
    app = create_app()
    with app.app_context():
        # Delete from dependent tables first
        db.session.query(DatasetPermission).delete()
        db.session.query(AppDatasetJoin).delete()
        db.session.query(DatasetQuery).delete()
        db.session.query(DatasetKeywordTable).delete()
        db.session.query(DocumentSegment).delete()
        db.session.query(Document).delete()
        db.session.query(DatasetProcessRule).delete()
        db.session.query(DatasetCollectionBinding).delete()
        db.session.query(Embedding).delete()
        db.session.query(Dataset).delete()
        
        
        # Delete from association tables
        db.session.execute(text('DELETE FROM users_permissions_association'))
        db.session.execute(text('DELETE FROM roles_permissions_association'))
        
        # Delete from main tables
        db.session.query(App).delete()
        db.session.query(AppModelConfig).delete()
        db.session.query(User).delete()
        db.session.query(Role).delete()
        db.session.query(Permission).delete()

        # Delete from dify_setups table
        db.session.query(DifySetup).delete()

        # Delete from tenant_account_joins, accounts, and tenants tables
        db.session.query(TenantAccountJoin).delete()
        db.session.query(Account).delete()
        db.session.query(Tenant).delete()
        db.session.query(UploadFile).delete()
        db.session.query(ProviderModel).delete()
        db.session.query(ProviderModelSetting).delete()
        db.session.query(Provider).delete()
        db.session.query(TenantDefaultModel).delete()
        db.session.query(Workflow).delete()
        db.session.query(Site).delete()
        db.session.query(InstalledApp).delete()
        db.session.query(EndUser).delete()
        db.session.query(Conversation).delete()
        db.session.query(WorkflowNodeExecution).delete()
        db.session.query(WorkflowRun).delete()
        db.session.query(Message).delete()
        db.session.query(ApiToken).delete()
        
        db.session.commit()

if __name__ == "__main__":
    clear_tables()
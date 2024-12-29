import pytest
from flask import url_for
from unittest.mock import patch, MagicMock
from models.dataset import Dataset, Document
from portal.models import User, Role, DatasetPermission
from extensions.ext_database import db
import uuid

@pytest.fixture
def user(db):
    user = User(
        id=str(uuid.uuid4()),  # Generate a valid UUID
        username='testuser',
        email='testuser@example.com',
        first_name='Test',
        last_name='User',
        profile_image_url='http://example.com/image.png'
    )
    db.session.add(user)
    db.session.commit()
    return user

@pytest.fixture
def role(db):
    role = Role(
        id=str(uuid.uuid4()),  # Generate a valid UUID
        name='testrole'
    )
    db.session.add(role)
    db.session.commit()
    return role

@pytest.fixture
def dataset(db, user):
    dataset = Dataset(
        id=str(uuid.uuid4()),  # Generate a valid UUID
        tenant_id=str(uuid.uuid4()),  # Generate a valid UUID for tenant_id
        name='Test Dataset',
        description='A test dataset',
        created_by=user.id,
        permission='only_me'
    )
    db.session.add(dataset)
    db.session.commit()
    return dataset

@pytest.fixture
def document(db, dataset, user):
    document = Document(
        id=str(uuid.uuid4()),  # Generate a valid UUID
        tenant_id=str(uuid.uuid4()),  # Generate a valid UUID for tenant_id
        dataset_id=dataset.id,
        position=1,
        data_source_type='upload_file',
        batch='batch1',
        name='Test Document',
        created_from='test_source',
        created_by=user.id,
        indexing_status='waiting',
        enabled=True,
        archived=False,
        content='Test content',
        word_count=100
    )
    db.session.add(document)
    db.session.commit()
    return document

@pytest.fixture
def dataset_permission(db, user, dataset):
    permission = DatasetPermission(
        id=str(uuid.uuid4()),  # Generate a valid UUID
        dataset_id=dataset.id,
        user_id=user.id,
        has_permission=True
    )
    db.session.add(permission)
    db.session.commit()
    return permission

@patch('services.dataset_service.DatasetService.get_user_datasets')
def test_get_datasets(mock_get_user_datasets, client, dataset, dataset_permission):
    mock_get_user_datasets.return_value = [dataset]
    response = client.get(url_for('datasets.datasetslistapi'))
    assert response.status_code == 200
    assert response.json[0]['name'] == 'Test Dataset'

@patch('services.dataset_service.DatasetService.create_empty_dataset')
def test_create_dataset(mock_create_empty_dataset, client):
    mock_create_empty_dataset.return_value = Dataset(name='New Dataset')
    response = client.post(url_for('datasets'), json={
        'name': 'New Dataset',
        'description': 'A new dataset'
    })
    assert response.status_code == 201
    assert response.json['name'] == 'New Dataset'

@patch('services.dataset_service.DatasetService.get_dataset')
def test_get_dataset(mock_get_dataset, client, dataset, dataset_permission):
    mock_get_dataset.return_value = dataset
    response = client.get(url_for('datasets/%s'%str(dataset.id), dataset_id=dataset.id))
    assert response.status_code == 200
    assert response.json['name'] == dataset.name

@patch('services.dataset_service.DatasetService.update_dataset')
def test_update_dataset(mock_update_dataset, client, dataset, dataset_permission):
    mock_update_dataset.return_value = Dataset(name='Updated Dataset')
    response = client.patch(url_for('datasets.datasetsapi', dataset_id=dataset.id), json={
        'name': 'Updated Dataset',
        'description': 'An updated dataset'
    })
    assert response.status_code == 200
    assert response.json['name'] == 'Updated Dataset'

@patch('services.dataset_service.DatasetService.delete_dataset')
def test_delete_dataset(mock_delete_dataset, client, dataset, dataset_permission):
    mock_delete_dataset.return_value = True
    response = client.delete(url_for('datasets.datasetsapi', dataset_id=dataset.id))
    assert response.status_code == 204

@patch('services.document_service.DocumentService.get_user_documents')
def test_get_documents(mock_get_user_documents, client, dataset, document, dataset_permission):
    mock_get_user_documents.return_value = [document]
    response = client.get(url_for('datasets.documentslistapi', dataset_id=dataset.id))
    assert response.status_code == 200
    assert response.json[0]['content'] == document.content

@patch('services.document_service.DocumentService.create_document')
def test_create_document(mock_create_document, client, dataset, dataset_permission):
    mock_create_document.return_value = Document(content='New Document')
    response = client.post(url_for('datasets.documentslistapi', dataset_id=dataset.id), json={
        'data_source': 'Test Source',
        'indexing_technique': 'Test Technique',
        'process_rule': {}
    })
    assert response.status_code == 201
    assert response.json['content'] == 'New Document'

@patch('services.document_service.DocumentService.get_document')
def test_get_document(mock_get_document, client, dataset, document, dataset_permission):
    mock_get_document.return_value = document
    response = client.get(url_for('datasets.documentapi', dataset_id=dataset.id, document_id=document.id))
    assert response.status_code == 200
    assert response.json['content'] == document.content

@patch('services.document_service.DocumentService.update_document_metadata')
def test_update_document(mock_update_document_metadata, client, dataset, document, dataset_permission):
    mock_update_document_metadata.return_value = Document(content='Updated Document', metadata={'key': 'value'})
    response = client.patch(url_for('datasets.documentapi', dataset_id=dataset.id, document_id=document.id), json={
        'metadata': {'key': 'value'}
    })
    assert response.status_code == 200
    assert response.json['metadata']['key'] == 'value'

@patch('services.document_service.DocumentService.delete_document')
def test_delete_document(mock_delete_document, client, dataset, document, dataset_permission):
    mock_delete_document.return_value = True
    response = client.delete(url_for('datasets.documentapi', dataset_id=dataset.id, document_id=document.id))
    assert response.status_code == 204
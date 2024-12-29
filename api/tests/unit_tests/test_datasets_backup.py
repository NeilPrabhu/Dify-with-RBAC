import pytest
from flask import url_for
from unittest.mock import patch, MagicMock
from models.dataset import Dataset, Document#, DatasetPermission
from portal.models import User, DatasetPermission
from extensions.ext_database import db

@pytest.fixture
def user(db):
    # Create a test user
    user = User(username='testuser', email='testuser@example.com')
    db.session.add(user)
    db.session.commit()
    return user

@pytest.fixture
def dataset(db, user):
    # Create a test dataset
    dataset = Dataset(name='Test Dataset', description='A test dataset', owner_id=user.id)
    db.session.add(dataset)
    db.session.commit()
    return dataset

@pytest.fixture
def document(db, dataset):
    # Create a test document
    document = Document(dataset_id=dataset.id, content='Test content')
    db.session.add(document)
    db.session.commit()
    return document

@pytest.fixture
def permission(db, user, dataset):
    # Create a test permission
    permission = DatasetPermission(dataset_id=dataset.id, user_id=user.id, has_permission=True)
    db.session.add(permission)
    db.session.commit()
    return permission

@patch('services.dataset_service.DatasetService.get_user_datasets')
def test_get_datasets(mock_get_user_datasets, client, user, permission):
    # Mock the return value of get_user_datasets
    mock_get_user_datasets.return_value = [Dataset(name='Mock Dataset')]

    # Test retrieving datasets
    response = client.get(url_for('datasetslistapi'))
    assert response.status_code == 200
    assert response.json[0]['name'] == 'Mock Dataset'

@patch('services.dataset_service.DatasetService.create_empty_dataset')
def test_create_dataset(mock_create_empty_dataset, client, user):
    # Mock the return value of create_empty_dataset
    mock_create_empty_dataset.return_value = Dataset(name='New Dataset')

    # Test creating a dataset
    response = client.post(url_for('datasetslistapi'), json={
        'name': 'New Dataset',
        'description': 'A new dataset'
    })
    assert response.status_code == 201
    assert response.json['name'] == 'New Dataset'

@patch('services.dataset_service.DatasetService.get_dataset')
def test_get_dataset(mock_get_dataset, client, user, dataset, permission):
    # Mock the return value of get_dataset
    mock_get_dataset.return_value = dataset

    # Test retrieving a specific dataset
    response = client.get(url_for('datasetsapi', dataset_id=dataset.id))
    assert response.status_code == 200
    assert response.json['name'] == dataset.name

@patch('services.dataset_service.DatasetService.update_dataset')
def test_update_dataset(mock_update_dataset, client, user, dataset, permission):
    # Mock the return value of update_dataset
    mock_update_dataset.return_value = Dataset(name='Updated Dataset')

    # Test updating a dataset
    response = client.patch(url_for('datasetsapi', dataset_id=dataset.id), json={
        'name': 'Updated Dataset',
        'description': 'An updated dataset'
    })
    assert response.status_code == 200
    assert response.json['name'] == 'Updated Dataset'

@patch('services.dataset_service.DatasetService.delete_dataset')
def test_delete_dataset(mock_delete_dataset, client, user, dataset, permission):
    # Mock the return value of delete_dataset
    mock_delete_dataset.return_value = True

    # Test deleting a dataset
    response = client.delete(url_for('datasetsapi', dataset_id=dataset.id))
    assert response.status_code == 204

@patch('services.document_service.DocumentService.get_user_documents')
def test_get_documents(mock_get_user_documents, client, user, dataset, document, permission):
    # Mock the return value of get_user_documents
    mock_get_user_documents.return_value = [document]

    # Test retrieving documents within a dataset
    response = client.get(url_for('documentslistapi', dataset_id=dataset.id))
    assert response.status_code == 200
    assert response.json[0]['content'] == document.content

@patch('services.document_service.DocumentService.create_document')
def test_create_document(mock_create_document, client, user, dataset, permission):
    # Mock the return value of create_document
    mock_create_document.return_value = Document(content='New Document')

    # Test creating a document
    response = client.post(url_for('documentslistapi', dataset_id=dataset.id), json={
        'data_source': 'Test Source',
        'indexing_technique': 'Test Technique',
        'process_rule': {}
    })
    assert response.status_code == 201
    assert response.json['content'] == 'New Document'

@patch('services.document_service.DocumentService.get_document')
def test_get_document(mock_get_document, client, user, dataset, document, permission):
    # Mock the return value of get_document
    mock_get_document.return_value = document

    # Test retrieving a specific document
    response = client.get(url_for('documentapi', dataset_id=dataset.id, document_id=document.id))
    assert response.status_code == 200
    assert response.json['content'] == document.content

@patch('services.document_service.DocumentService.update_document_metadata')
def test_update_document(mock_update_document_metadata, client, user, dataset, document, permission):
    # Mock the return value of update_document_metadata
    mock_update_document_metadata.return_value = Document(content='Updated Document', metadata={'key': 'value'})

    # Test updating a document
    response = client.patch(url_for('documentapi', dataset_id=dataset.id, document_id=document.id), json={
        'metadata': {'key': 'value'}
    })
    assert response.status_code == 200
    assert response.json['metadata']['key'] == 'value'

@patch('services.document_service.DocumentService.delete_document')
def test_delete_document(mock_delete_document, client, user, dataset, document, permission):
    # Mock the return value of delete_document
    mock_delete_document.return_value = True

    # Test deleting a document
    response = client.delete(url_for('documentapi', dataset_id=dataset.id, document_id=document.id))
    assert response.status_code == 204
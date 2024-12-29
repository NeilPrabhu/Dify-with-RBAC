def test_get_documents(client):
    response = client.get("/datasets/1/documents")
    assert response.status_code == 200
    data = response.get_json()
    assert "data" in data  # Assuming 'data' contains the documents list

def test_create_document(client):
    response = client.post(
        "/datasets/1/documents",
        json={"indexing_technique": "high_quality", "doc_form": "text_model"}
    )
    assert response.status_code == 201
    data = response.get_json()
    assert "documents" in data

def test_get_document_by_id(client):
    # Assuming a document with id 1 exists for simplicity
    response = client.get("/datasets/1/documents/1")
    assert response.status_code == 200
    data = response.get_json()
    assert data["id"] == 1

def test_delete_document(client):
    response = client.delete("/datasets/1/documents/1")
    assert response.status_code == 204

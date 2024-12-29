def test_get_datasets(client):
    response = client.get("/datasets/")
    assert response.status_code == 200
    data = response.get_json()
    assert "data" in data  # Assuming 'data' contains the datasets

def test_create_dataset(client):
    response = client.post("/datasets/", json={"name": "New Dataset"})
    assert response.status_code == 201
    data = response.get_json()
    assert "id" in data  # Check for an ID in the response

def test_get_dataset_by_id(client):
    # Assuming a dataset with id 1 exists for simplicity
    response = client.get("/datasets/1")
    assert response.status_code == 200
    data = response.get_json()
    assert data["id"] == 1

def test_update_dataset(client):
    response = client.patch("/datasets/1", json={"name": "Updated Dataset"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["name"] == "Updated Dataset"

def test_delete_dataset(client):
    response = client.delete("/datasets/1")
    assert response.status_code == 204

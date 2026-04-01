import pytest
from fastapi.testclient import TestClient
from src.api import app

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert "Security Intelligence Platform" in response.text

@pytest.mark.asyncio
async def test_scan_endpoint():
    response = client.post("/scan", json={"days": 3, "results_per_page": 5})
    assert response.status_code == 200
    data = response.json()
    assert "total_cves" in data
    assert "scan_timestamp" in data

def test_knowledge_query():
    response = client.post("/knowledge/query", json={
        "query": "What are best practices for preventing injection attacks?",
        "n_results": 2
    })
    assert response.status_code == 200
    assert "results" in response.json()
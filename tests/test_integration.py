import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_check():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["status"] in ["HEALTHY", "DEGRADED"]

def test_dashboard_overview():
    # Use mock token for ANALYST
    headers = {"Authorization": "Bearer token-analyst"}
    response = client.get("/api/v1/dashboard/overview", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "security_overview" in data
    assert "system_health" in data

def test_global_search():
    headers = {"Authorization": "Bearer token-analyst"}
    response = client.get("/api/v1/search?q=test", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "incidents" in data

def test_audit_log_access():
    # Admin should succeed
    admin_headers = {"Authorization": "Bearer token-admin"}
    response = client.get("/api/v1/audit/", headers=admin_headers)
    assert response.status_code == 200
    
    # Analyst should fail (forbidden)
    analyst_headers = {"Authorization": "Bearer token-analyst"}
    response = client.get("/api/v1/audit/", headers=analyst_headers)
    assert response.status_code == 403

def test_demo_seed_execution():
    from app.demo.seed import run_demo
    # Just verify it doesn't crash
    run_demo()

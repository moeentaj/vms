# ================================
# TESTS
# ================================

# tests/__init__.py
# Empty file to make it a Python package

# tests/test_main.py
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["message"] == "Vulnerability Management System API"

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_api_docs():
    response = client.get("/docs")
    assert response.status_code == 200

# Test user registration
def test_user_registration():
    response = client.post(
        "/api/v1/auth/register",
        json={
            "username": "testuser",
            "email": "test@example.com",
            "password": "testpass123",
            "first_name": "Test",
            "last_name": "User",
            "role": "analyst"
        }
    )
"""Unit tests for ShieldLens Flask application routes."""

import pytest
from app import app


@pytest.fixture
def client():
    """Flask test client fixture."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_index_route(client):
    """Test index page returns status 200 and renders HTML."""
    response = client.get("/")
    assert response.status_code == 200
    assert b"ShieldLens" in response.data


def test_health_check_route(client):
    """Test health check route returns JSON with status ok and phase 1."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data is not None
    assert data["status"] == "ok"
    assert data["app"] == "ShieldLens"
    assert data["phase"] == 10
    assert "featherless_configured" in data

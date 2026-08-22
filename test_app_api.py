"""Unit tests for ShieldLens Flask REST API endpoints including Phase 7 Decision Intelligence endpoints."""

import json
import pytest
from app import app


@pytest.fixture
def client():
    """Flask test client fixture."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_get_organizations_endpoint(client):
    """Test GET /api/organizations returns list of official organization profiles."""
    response = client.get("/api/organizations")
    assert response.status_code == 200
    data = response.get_json()
    assert isinstance(data, list)
    assert len(data) >= 3
    org_ids = [org["org_id"] for org in data]
    assert "ORG-001" in org_ids
    assert "ORG-002" in org_ids
    assert "ORG-003" in org_ids


def test_get_ranking_endpoint(client):
    """Test GET /api/ranking/<org_id> returns production Top-5 ranking candidates."""
    response = client.get("/api/ranking/ORG-001")
    assert response.status_code == 200
    data = response.get_json()
    assert data["org_id"] == "ORG-001"
    assert "eligible_candidate_count" in data
    assert isinstance(data["top5_ranking"], list)
    assert len(data["top5_ranking"]) <= 5
    if len(data["top5_ranking"]) > 0:
        item = data["top5_ranking"][0]
        assert "rank" in item
        assert "risk_score" in item
        assert "score_breakdown" in item


def test_get_ranking_invalid_org_returns_404(client):
    """Test GET /api/ranking/<invalid_org> returns 404 status code."""
    response = client.get("/api/ranking/INVALID_ORG_999")
    assert response.status_code == 404
    data = response.get_json()
    assert "error" in data


def test_get_evaluation_endpoint(client):
    """Test GET /api/evaluation/<org_id> returns Gold-Set evaluation metrics."""
    response = client.get("/api/evaluation/ORG-001")
    assert response.status_code == 200
    data = response.get_json()
    assert data["org_id"] == "ORG-001"
    assert "relative_top1_agreement" in data
    assert "global_top1_agreement" in data


def test_post_explain_endpoint(client):
    """Test POST /api/explain returns structured explanation JSON without API key leakage."""
    payload = {"cve_id": "CVE-2025-1111", "org_id": "ORG-001"}
    response = client.post("/api/explain", json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert "cve_id" in data
    assert "executive_summary" in data
    assert "why_prioritized" in data

    # Verify no secret API key is present in JSON output
    data_str = json.dumps(data)
    assert "FEATHERLESS_API_KEY" not in data_str


def test_post_explain_missing_fields_returns_400(client):
    """Test POST /api/explain returns 400 when cve_id or org_id is missing."""
    response = client.post("/api/explain", json={"cve_id": "CVE-2025-1111"})
    assert response.status_code == 400


# ==================================================
# PHASE 7 ENDPOINT TESTS
# ==================================================

def test_post_simulate_endpoint_valid_weights(client):
    """Test POST /api/simulate/<org_id> with valid weights returns simulation JSON."""
    payload = {"cvss_weight": 0.2, "cisa_kev_weight": 0.3, "first_epss_weight": 0.5}
    response = client.post("/api/simulate/ORG-001", json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data["org_id"] == "ORG-001"
    assert "simulated_rankings" in data
    assert "SIMULATION" in data["simulation_status"]


def test_post_simulate_endpoint_invalid_weights_sum(client):
    """Test POST /api/simulate/<org_id> with invalid weights sum returns 400."""
    payload = {"cvss_weight": 0.5, "cisa_kev_weight": 0.5, "first_epss_weight": 0.5}
    response = client.post("/api/simulate/ORG-001", json=payload)
    assert response.status_code == 400
    data = response.get_json()
    assert "error" in data


def test_get_stability_endpoint(client):
    """Test GET /api/stability/<org_id> returns decision stability array."""
    response = client.get("/api/stability/ORG-001")
    assert response.status_code == 200
    data = response.get_json()
    assert isinstance(data, list)
    if len(data) > 0:
        assert "stability_category" in data[0]
        assert "stability_percentage" in data[0]


def test_get_verification_queue_endpoint(client):
    """Test GET /api/verification/<org_id> returns verification queue items."""
    response = client.get("/api/verification/ORG-001")
    assert response.status_code == 200
    data = response.get_json()
    assert isinstance(data, list)
    if len(data) > 0:
        assert "verification_reason" in data[0]
        assert "recommended_actions" in data[0]


def test_post_audit_endpoint(client):
    """Test POST /api/audit returns structured AI Decision Audit JSON."""
    payload = {"cve_id": "CVE-2025-1111", "org_id": "ORG-001"}
    response = client.post("/api/audit", json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert "cve_id" in data
    assert "audit_label" in data
    assert data["audit_label"] == "AI AUDIT — EXPLANATORY ONLY"
    assert "decision_summary" in data

    # Verify no secret API key is present in JSON output
    data_str = json.dumps(data)
    assert "FEATHERLESS_API_KEY" not in data_str

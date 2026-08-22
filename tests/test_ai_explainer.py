"""Unit tests for ShieldLens Featherless AI Explainer service."""

import json
import os
import pytest
from unittest.mock import patch, MagicMock

from engine.models import Vulnerability, Profile, WeightModifiers, EvidenceStatus, EvidenceResult, RiskScoreResult, ScoreBreakdown
from engine.explainer import FeatherlessExplainer


class TestFeatherlessExplainer:
    """Test suite covering Featherless AI explainer service, prompt safety, error fallbacks, and security."""

    @pytest.fixture
    def vuln(self):
        return Vulnerability(cve_id="CVE-2025-1111", product_name="Core Banking Framework", cvss_base_score=9.8, cisa_kev=True, first_epss=0.95)

    @pytest.fixture
    def profile(self):
        return Profile(org_id="ORG-001", name="Global Retail Bank", weight_modifiers=WeightModifiers(cvss_weight=0.3, cisa_kev_weight=0.45, first_epss_weight=0.25))

    @pytest.fixture
    def evidence_res(self):
        return EvidenceResult(
            cve_id="CVE-2025-1111",
            org_id="ORG-001",
            vulnerability_product="Core Banking Framework",
            matched_profile_product="Core Banking Framework",
            product_match_status=EvidenceStatus.MATCH,
            version_evidence_status=EvidenceStatus.NEEDS_VERIFICATION,
            overall_evidence_status=EvidenceStatus.NEEDS_VERIFICATION,
            reason="Product matches critical product, missing version information."
        )

    @pytest.fixture
    def risk_res(self):
        bd = ScoreBreakdown(
            cvss_normalized=0.98, cvss_weight=0.3, cvss_contribution=0.294,
            kev_normalized=1.0, kev_weight=0.45, kev_contribution=0.45,
            epss_value=0.95, epss_weight=0.25, epss_contribution=0.2375,
            final_risk_score=0.9815
        )
        return RiskScoreResult(
            cve_id="CVE-2025-1111",
            product_name="Core Banking Framework",
            org_id="ORG-001",
            risk_score=0.9815,
            priority="CRITICAL",
            evidence_status="NEEDS_VERIFICATION",
            score_breakdown=bd
        )

    # --- Test 1: Missing API Key Fallback ---
    @patch.dict(os.environ, {"FEATHERLESS_API_KEY": ""})
    def test_missing_api_key_returns_safe_fallback(self, vuln, profile, risk_res, evidence_res):
        explainer = FeatherlessExplainer(api_key="")
        res = explainer.explain_vulnerability(vuln, profile, risk_res, evidence_res)

        assert res["ai_available"] is False
        assert "Featherless AI key is not configured" in res["executive_summary"]
        assert "recommended_action" in res

    # --- Test 2: Timeout Fallback ---
    @patch("urllib.request.urlopen")
    def test_api_timeout_returns_safe_fallback(self, mock_urlopen, vuln, profile, risk_res, evidence_res):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("Connection timed out")

        explainer = FeatherlessExplainer(api_key="mock_secret_key_12345")
        res = explainer.explain_vulnerability(vuln, profile, risk_res, evidence_res)

        assert res["ai_available"] is False
        assert "timed out" in res["executive_summary"].lower() or "failed" in res["executive_summary"].lower()

    # --- Test 3: Malformed Response Fallback ---
    @patch("urllib.request.urlopen")
    def test_malformed_response_returns_safe_fallback(self, mock_urlopen, vuln, profile, risk_res, evidence_res):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"choices": [{"message": {"content": "INVALID_NON_JSON_CONTENT"}}]}'
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        explainer = FeatherlessExplainer(api_key="mock_secret_key_12345")
        res = explainer.explain_vulnerability(vuln, profile, risk_res, evidence_res)

        assert res["ai_available"] is False

    # --- Test 4: Successful Mocked Response ---
    @patch("urllib.request.urlopen")
    def test_successful_ai_response(self, mock_urlopen, vuln, profile, risk_res, evidence_res):
        ai_json_content = json.dumps({
            "executive_summary": "High risk vulnerability targeting core banking API.",
            "why_prioritized": "High CVSS and active CISA KEV status.",
            "evidence_interpretation": "Product matches critical infrastructure.",
            "verification_needed": "Confirm installed build version.",
            "recommended_action": "Apply emergency patch immediately."
        })
        mock_resp_data = json.dumps({
            "choices": [{"message": {"content": ai_json_content}}]
        }).encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = mock_resp_data
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        explainer = FeatherlessExplainer(api_key="mock_secret_key_12345")
        res = explainer.explain_vulnerability(vuln, profile, risk_res, evidence_res)

        assert res["ai_available"] is True
        assert res["executive_summary"] == "High risk vulnerability targeting core banking API."
        assert res["recommended_action"] == "Apply emergency patch immediately."

    # --- Test 5: API Key Security (Never Leaked in Response) ---
    def test_api_key_never_leaked_in_response(self, vuln, profile, risk_res, evidence_res):
        secret_key = "sk-FEATHERLESS-SECRET-99999999"
        explainer = FeatherlessExplainer(api_key=secret_key)
        res = explainer.explain_vulnerability(vuln, profile, risk_res, evidence_res)

        res_str = json.dumps(res)
        assert secret_key not in res_str

"""Unit tests for ShieldLens Phase 7 Decision Intelligence Layer."""

import json
import os
import pytest
from unittest.mock import patch, MagicMock

from engine.models import Vulnerability, Profile, WeightModifiers, SimulatedWeightInput, EvidenceStatus, EvidenceResult, RiskScoreResult, ScoreBreakdown
from engine.loader import DataLoader
from engine.ranker import Top5Ranker
from engine.intelligence import DecisionIntelligenceEngine
from engine.explainer import FeatherlessExplainer


class TestDecisionIntelligenceLayer:
    """Test suite covering Risk What-If Simulator, Decision Stability, Verification Queue, and AI Decision Audit."""

    @pytest.fixture
    def bank_profile(self):
        return Profile(
            org_id="ORG-001",
            name="Global Retail Bank",
            weight_modifiers=WeightModifiers(cvss_weight=0.3, cisa_kev_weight=0.45, first_epss_weight=0.25),
            critical_products=["Core Banking Framework", "Identity Provider SaaS"],
        )

    @pytest.fixture
    def vulns(self):
        return [
            Vulnerability(cve_id="CVE-2025-1111", product_name="Core Banking Framework", cvss_base_score=9.8, cisa_kev=True, first_epss=0.95),
            Vulnerability(cve_id="CVE-2025-4444", product_name="Identity Provider SaaS", cvss_base_score=5.0, cisa_kev=True, first_epss=0.45),
            Vulnerability(cve_id="CVE-2024-5555", product_name="Enterprise Router OS", cvss_base_score=6.8, cisa_kev=False, first_epss=0.0012),
        ]

    # --- 1. SIMULATOR TESTS ---
    def test_simulate_risk_weights_valid_input(self, vulns, bank_profile):
        sim_input = SimulatedWeightInput(cvss_weight=0.2, cisa_kev_weight=0.3, first_epss_weight=0.5)
        res = DecisionIntelligenceEngine.simulate_risk_weights(vulns, bank_profile, sim_input)

        assert res.org_id == "ORG-001"
        assert res.simulated_weights.cvss_weight == 0.2
        assert "SIMULATION — does not modify official production results" in res.simulation_status
        assert len(res.simulated_rankings) == 2  # 2 eligible candidates for bank_profile

    def test_simulate_risk_weights_invalid_negative_weight(self, vulns, bank_profile):
        with pytest.raises(Exception):
            SimulatedWeightInput(cvss_weight=-0.1, cisa_kev_weight=0.6, first_epss_weight=0.5)

    def test_simulate_risk_weights_invalid_sum(self, vulns, bank_profile):
        sim_input = SimulatedWeightInput(cvss_weight=0.5, cisa_kev_weight=0.5, first_epss_weight=0.5)  # Sum 1.5
        with pytest.raises(ValueError, match="must sum to 1.0"):
            DecisionIntelligenceEngine.simulate_risk_weights(vulns, bank_profile, sim_input)

    def test_simulate_risk_weights_non_mutation_guarantee(self, vulns, bank_profile):
        orig_cvss_w = bank_profile.weight_modifiers.cvss_weight
        sim_input = SimulatedWeightInput(cvss_weight=0.9, cisa_kev_weight=0.05, first_epss_weight=0.05)

        DecisionIntelligenceEngine.simulate_risk_weights(vulns, bank_profile, sim_input)

        # Profile weight_modifiers MUST remain untouched
        assert bank_profile.weight_modifiers.cvss_weight == orig_cvss_w

    def test_simulate_risk_weights_production_ranking_unmodified(self, vulns, bank_profile):
        ranker = Top5Ranker()
        prod_before = ranker.rank_vulnerabilities(vulns, bank_profile, top_n=5)

        sim_input = SimulatedWeightInput(cvss_weight=0.8, cisa_kev_weight=0.1, first_epss_weight=0.1)
        DecisionIntelligenceEngine.simulate_risk_weights(vulns, bank_profile, sim_input)

        prod_after = ranker.rank_vulnerabilities(vulns, bank_profile, top_n=5)
        assert [r.risk_score for r in prod_before] == [r.risk_score for r in prod_after]

    def test_simulate_risk_weights_deterministic_repeated_execution(self, vulns, bank_profile):
        sim_input = SimulatedWeightInput(cvss_weight=0.2, cisa_kev_weight=0.3, first_epss_weight=0.5)
        res1 = DecisionIntelligenceEngine.simulate_risk_weights(vulns, bank_profile, sim_input)
        res2 = DecisionIntelligenceEngine.simulate_risk_weights(vulns, bank_profile, sim_input)

        assert res1.simulated_rankings[0].simulated_score == res2.simulated_rankings[0].simulated_score

    # --- 2. DECISION STABILITY TESTS ---
    def test_analyze_decision_stability_deterministic_scenarios(self, vulns, bank_profile):
        items = DecisionIntelligenceEngine.analyze_decision_stability(vulns, bank_profile)

        assert len(items) == 2
        for it in items:
            assert it.scenarios_tested == 5
            assert it.scenarios_eligible == 5
            assert 1 <= it.min_rank <= it.max_rank <= 5
            assert it.stability_category in ("HIGH", "MEDIUM", "LOW")

    def test_analyze_decision_stability_zero_randomness(self, vulns, bank_profile):
        items1 = DecisionIntelligenceEngine.analyze_decision_stability(vulns, bank_profile)
        items2 = DecisionIntelligenceEngine.analyze_decision_stability(vulns, bank_profile)

        for i1, i2 in zip(items1, items2):
            assert i1.stability_percentage == i2.stability_percentage
            assert i1.stability_category == i2.stability_category

    # --- 3. VERIFICATION QUEUE TESTS ---
    def test_build_verification_queue_needs_verification_included(self, vulns, bank_profile):
        queue = DecisionIntelligenceEngine.build_verification_queue(vulns, bank_profile)

        assert len(queue) == 2
        for q in queue:
            assert q.evidence_status == EvidenceStatus.NEEDS_VERIFICATION.value
            assert "Affected-version evidence is not supplied" in q.verification_reason
            assert len(q.recommended_actions) >= 4

    def test_build_verification_queue_exclude_candidates_excluded(self, vulns, bank_profile):
        queue = DecisionIntelligenceEngine.build_verification_queue(vulns, bank_profile)
        cve_ids = [q.cve_id for q in queue]

        # CVE-2024-5555 (Enterprise Router OS) is EXCLUDE for bank_profile
        assert "CVE-2024-5555" not in cve_ids

    def test_build_verification_queue_no_fabricated_evidence(self, vulns, bank_profile):
        queue = DecisionIntelligenceEngine.build_verification_queue(vulns, bank_profile)
        for q in queue:
            assert "not supplied" in q.verification_reason.lower()

    # --- 4. AI DECISION AUDIT TESTS ---
    @patch.dict(os.environ, {"FEATHERLESS_API_KEY": ""})
    def test_audit_decision_missing_api_key_fallback(self, vulns, bank_profile):
        vuln = vulns[0]
        risk_res = RiskScoreResult(
            cve_id="CVE-2025-1111", product_name="Core Banking Framework", org_id="ORG-001",
            risk_score=0.9815, priority="CRITICAL", evidence_status="NEEDS_VERIFICATION",
            score_breakdown=ScoreBreakdown(cvss_normalized=0.98, cvss_weight=0.3, cvss_contribution=0.294, kev_normalized=1.0, kev_weight=0.45, kev_contribution=0.45, epss_value=0.95, epss_weight=0.25, epss_contribution=0.2375, final_risk_score=0.9815)
        )
        evidence_res = EvidenceResult(cve_id="CVE-2025-1111", org_id="ORG-001", vulnerability_product="Core Banking Framework", matched_profile_product="Core Banking Framework", product_match_status=EvidenceStatus.MATCH, version_evidence_status=EvidenceStatus.NEEDS_VERIFICATION, overall_evidence_status=EvidenceStatus.NEEDS_VERIFICATION, reason="Product match.")

        explainer = FeatherlessExplainer(api_key="")
        res = explainer.audit_decision(vuln, bank_profile, risk_res, evidence_res)

        assert res["ai_available"] is False
        assert res["audit_label"] == "AI AUDIT — EXPLANATORY ONLY"
        assert "Featherless AI key is not configured" in res["decision_summary"]

    @patch("urllib.request.urlopen")
    def test_audit_decision_mocked_successful_response(self, mock_urlopen, vulns, bank_profile):
        ai_json_content = json.dumps({
            "decision_summary": "Deterministic priority CRITICAL (0.9815) verified.",
            "why_prioritized": "High CVSS and KEV status.",
            "evidence_supporting_decision": "Product match confirmed.",
            "missing_evidence": "Version range absent.",
            "assumptions": "Active component.",
            "verification_required": "Confirm build version.",
            "recommended_analyst_action": "Apply patch.",
            "audit_confidence": "HIGH"
        })
        mock_resp_data = json.dumps({"choices": [{"message": {"content": ai_json_content}}]}).encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = mock_resp_data
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        risk_res = RiskScoreResult(
            cve_id="CVE-2025-1111", product_name="Core Banking Framework", org_id="ORG-001",
            risk_score=0.9815, priority="CRITICAL", evidence_status="NEEDS_VERIFICATION",
            score_breakdown=ScoreBreakdown(cvss_normalized=0.98, cvss_weight=0.3, cvss_contribution=0.294, kev_normalized=1.0, kev_weight=0.45, kev_contribution=0.45, epss_value=0.95, epss_weight=0.25, epss_contribution=0.2375, final_risk_score=0.9815)
        )
        evidence_res = EvidenceResult(cve_id="CVE-2025-1111", org_id="ORG-001", vulnerability_product="Core Banking Framework", matched_profile_product="Core Banking Framework", product_match_status=EvidenceStatus.MATCH, version_evidence_status=EvidenceStatus.NEEDS_VERIFICATION, overall_evidence_status=EvidenceStatus.NEEDS_VERIFICATION, reason="Product match.")

        explainer = FeatherlessExplainer(api_key="mock_key")
        res = explainer.audit_decision(vulns[0], bank_profile, risk_res, evidence_res)

        assert res["ai_available"] is True
        assert res["audit_label"] == "AI AUDIT — EXPLANATORY ONLY"
        assert res["audit_confidence"] == "HIGH"

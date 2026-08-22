"""Unit tests for ShieldLens Phase 4 Profile-Specific Risk Scoring Engine."""

import os
import pytest

from engine.models import Vulnerability, Profile, WeightModifiers, EvidenceStatus
from engine.scorer import RiskScorer
from engine.loader import DataLoader


class TestRiskScorer:
    """Test suite covering Phase 4 scoring math, determinism, profile-specific weighting, and candidate filtering."""

    @pytest.fixture
    def scorer(self):
        return RiskScorer()

    @pytest.fixture
    def sample_vuln(self):
        return Vulnerability(
            cve_id="CVE-2025-1111",
            product_name="Core Banking Framework",
            cvss_base_score=9.8,
            cisa_kev=True,
            first_epss=0.95,
        )

    @pytest.fixture
    def bank_profile(self):
        return Profile(
            org_id="ORG-001",
            name="Global Retail Bank",
            weight_modifiers=WeightModifiers(
                cvss_weight=0.3,
                cisa_kev_weight=0.45,
                first_epss_weight=0.25,
            ),
            critical_products=["Core Banking Framework"],
        )

    @pytest.fixture
    def startup_profile(self):
        return Profile(
            org_id="ORG-002",
            name="Agile Cloud Tech Startup",
            weight_modifiers=WeightModifiers(
                cvss_weight=0.2,
                cisa_kev_weight=0.2,
                first_epss_weight=0.6,
            ),
            critical_products=["Core Banking Framework"],
        )

    # --- Test 1: CVSS Normalisation ---
    def test_cvss_normalisation(self, scorer, sample_vuln, bank_profile):
        res = scorer.score_vulnerability(sample_vuln, bank_profile)
        assert res.score_breakdown.cvss_normalized == 0.98

    # --- Test 2: KEV Normalisation ---
    def test_kev_normalisation(self, scorer, bank_profile):
        vuln_kev_true = Vulnerability(cve_id="CVE-1", product_name="Test", cvss_base_score=5.0, cisa_kev=True, first_epss=0.1)
        vuln_kev_false = Vulnerability(cve_id="CVE-2", product_name="Test", cvss_base_score=5.0, cisa_kev=False, first_epss=0.1)

        res_true = scorer.score_vulnerability(vuln_kev_true, bank_profile)
        res_false = scorer.score_vulnerability(vuln_kev_false, bank_profile)

        assert res_true.score_breakdown.kev_normalized == 1.0
        assert res_false.score_breakdown.kev_normalized == 0.0

    # --- Test 3: EPSS Handling ---
    def test_epss_handling(self, scorer, sample_vuln, bank_profile):
        res = scorer.score_vulnerability(sample_vuln, bank_profile)
        assert res.score_breakdown.epss_value == 0.95

    # --- Test 4 & 5: Weight Application & Weighted Score Calculation ---
    def test_weighted_score_calculation(self, scorer, sample_vuln, bank_profile):
        # cvss_contrib = 0.98 * 0.3 = 0.294
        # kev_contrib  = 1.0  * 0.45 = 0.45
        # epss_contrib = 0.95 * 0.25 = 0.2375
        # sum = 0.294 + 0.45 + 0.2375 = 0.9815
        res = scorer.score_vulnerability(sample_vuln, bank_profile)
        assert res.risk_score == pytest.approx(0.9815, abs=1e-4)

    # --- Test 6: Score Breakdown Structure ---
    def test_score_breakdown_structure(self, scorer, sample_vuln, bank_profile):
        res = scorer.score_vulnerability(sample_vuln, bank_profile)
        bd = res.score_breakdown
        assert bd.cvss_normalized == 0.98
        assert bd.cvss_weight == 0.3
        assert bd.cvss_contribution == pytest.approx(0.294, abs=1e-4)
        assert bd.kev_normalized == 1.0
        assert bd.kev_weight == 0.45
        assert bd.kev_contribution == 0.45
        assert bd.epss_value == 0.95
        assert bd.epss_weight == 0.25
        assert bd.epss_contribution == pytest.approx(0.2375, abs=1e-4)
        assert bd.final_risk_score == res.risk_score

    # --- Test 7: Deterministic Repeated Calculation ---
    def test_deterministic_repeated_calculation(self, scorer, sample_vuln, bank_profile):
        res1 = scorer.score_vulnerability(sample_vuln, bank_profile)
        res2 = scorer.score_vulnerability(sample_vuln, bank_profile)
        assert res1.risk_score == res2.risk_score
        assert res1.priority == res2.priority
        assert res1.score_breakdown == res2.score_breakdown

    # --- Test 8: Different Profile Weights Produce Different Scores ---
    def test_different_profile_weights_produce_different_scores(self, scorer, sample_vuln, bank_profile, startup_profile):
        bank_res = scorer.score_vulnerability(sample_vuln, bank_profile)
        startup_res = scorer.score_vulnerability(sample_vuln, startup_profile)

        # Bank weight: (0.3, 0.45, 0.25) -> score 0.9815
        # Startup weight: (0.2, 0.2, 0.6) -> 0.98*0.2 + 1.0*0.2 + 0.95*0.6 = 0.196 + 0.2 + 0.57 = 0.966
        assert bank_res.risk_score != startup_res.risk_score
        assert bank_res.risk_score == pytest.approx(0.9815, abs=1e-4)
        assert startup_res.risk_score == pytest.approx(0.966, abs=1e-4)

    # --- Test 9: EXCLUDE Candidates Not Entering Ranking ---
    def test_exclude_candidates_filtered_out(self, scorer, bank_profile):
        matched_vuln = Vulnerability(cve_id="CVE-2025-1111", product_name="Core Banking Framework", cvss_base_score=9.8)
        excluded_vuln = Vulnerability(cve_id="CVE-2024-5555", product_name="Enterprise Router OS", cvss_base_score=6.8)

        candidates = scorer.score_profile_vulnerabilities([matched_vuln, excluded_vuln], bank_profile)
        cve_ids = [c.cve_id for c in candidates]

        assert "CVE-2025-1111" in cve_ids
        assert "CVE-2024-5555" not in cve_ids

    # --- Test 10: NEEDS_VERIFICATION Candidates Retain Evidence Status ---
    def test_needs_verification_retains_status(self, scorer, bank_profile):
        matched_vuln = Vulnerability(cve_id="CVE-2025-1111", product_name="Core Banking Framework", cvss_base_score=9.8)

        candidates = scorer.score_profile_vulnerabilities([matched_vuln], bank_profile)
        assert len(candidates) == 1
        assert candidates[0].evidence_status == EvidenceStatus.NEEDS_VERIFICATION.value

    # --- Test 11: Practitioner Ranks Do Not Affect Score ---
    def test_practitioner_ranks_do_not_affect_score(self, scorer, bank_profile):
        vuln1 = Vulnerability(cve_id="CVE-1", product_name="Core Banking Framework", cvss_base_score=9.8, cisa_kev=True, first_epss=0.95, practitioner_rank_bank=1)
        vuln2 = Vulnerability(cve_id="CVE-2", product_name="Core Banking Framework", cvss_base_score=9.8, cisa_kev=True, first_epss=0.95, practitioner_rank_bank=99)

        res1 = scorer.score_vulnerability(vuln1, bank_profile)
        res2 = scorer.score_vulnerability(vuln2, bank_profile)

        assert res1.risk_score == res2.risk_score

    # --- Test 12: Official Organiser Dataset Evaluation ---
    def test_official_dataset_scoring(self, scorer):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        vuln_path = os.path.join(base_dir, "data", "vulnerabilities.csv")
        profile_path = os.path.join(base_dir, "data", "profiles.json")

        vulns = DataLoader.load_vulnerabilities(vuln_path)
        profiles = DataLoader.load_profiles(profile_path)

        bank_profile = next(p for p in profiles if p.org_id == "ORG-001")
        startup_profile = next(p for p in profiles if p.org_id == "ORG-002")

        bank_results = scorer.score_profile_vulnerabilities(vulns, bank_profile)
        startup_results = scorer.score_profile_vulnerabilities(vulns, startup_profile)

        assert len(bank_results) >= 1
        assert len(startup_results) >= 1

    # --- Test 13: Boundary Values ---
    def test_boundary_values(self, scorer, bank_profile):
        # Minimum boundaries: CVSS=0, EPSS=0, KEV=False
        min_vuln = Vulnerability(cve_id="CVE-MIN", product_name="Core Banking Framework", cvss_base_score=0.0, cisa_kev=False, first_epss=0.0)
        min_res = scorer.score_vulnerability(min_vuln, bank_profile)
        assert min_res.risk_score == 0.0
        assert min_res.priority == "LOW"

        # Maximum boundaries: CVSS=10, EPSS=1, KEV=True
        max_vuln = Vulnerability(cve_id="CVE-MAX", product_name="Core Banking Framework", cvss_base_score=10.0, cisa_kev=True, first_epss=1.0)
        max_res = scorer.score_vulnerability(max_vuln, bank_profile)
        # (1.0*0.3) + (1.0*0.45) + (1.0*0.25) = 1.0
        assert max_res.risk_score == 1.0
        assert max_res.priority == "CRITICAL"

    # --- Test 14: Out-of-Range Values Rejected Safely ---
    def test_out_of_range_values_rejected(self, scorer, bank_profile):
        with pytest.raises(ValueError):
            vuln_bad_cvss = Vulnerability(cve_id="CVE-BAD1", product_name="Test", cvss_base_score=15.0)
            scorer.score_vulnerability(vuln_bad_cvss, bank_profile)

        with pytest.raises(ValueError):
            vuln_bad_epss = Vulnerability(cve_id="CVE-BAD2", product_name="Test", cvss_base_score=5.0, first_epss=1.5)
            scorer.score_vulnerability(vuln_bad_epss, bank_profile)

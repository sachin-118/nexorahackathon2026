"""Unit tests for ShieldLens Phase 5 Top-5 Ranking Pipeline, Gold-Set Evaluator, and Negative Test."""

import io
import os
import pytest

from engine.models import Vulnerability, Profile, WeightModifiers, EvidenceStatus, GoldSetEntry, RankedVulnerability, ScoreBreakdown
from engine.ranker import Top5Ranker
from engine.evaluator import GoldSetEvaluator
from engine.loader import DataLoader


class TestTop5RankingAndEvaluation:
    """Test suite covering Top-5 ranking, tie-breaking, Gold-Set evaluation, and synthetic negative testing."""

    @pytest.fixture
    def ranker(self):
        return Top5Ranker()

    @pytest.fixture
    def bank_profile(self):
        return Profile(
            org_id="ORG-001",
            name="Global Retail Bank",
            weight_modifiers=WeightModifiers(cvss_weight=0.3, cisa_kev_weight=0.45, first_epss_weight=0.25),
            critical_products=["Core Banking Framework", "Identity Provider SaaS"],
        )

    @pytest.fixture
    def startup_profile(self):
        return Profile(
            org_id="ORG-002",
            name="Agile Cloud Tech Startup",
            weight_modifiers=WeightModifiers(cvss_weight=0.2, cisa_kev_weight=0.2, first_epss_weight=0.6),
            critical_products=["Cloud Database Engine", "Web Application Firewall"],
        )

    @pytest.fixture
    def sample_vulns(self):
        return [
            Vulnerability(cve_id="CVE-2025-1111", product_name="Core Banking Framework", cvss_base_score=9.8, cisa_kev=True, first_epss=0.95),
            Vulnerability(cve_id="CVE-2026-2222", product_name="Cloud Database Engine", cvss_base_score=7.5, cisa_kev=False, first_epss=0.91),
            Vulnerability(cve_id="CVE-2024-3333", product_name="Embedded IoT Gateway", cvss_base_score=9.0, cisa_kev=True, first_epss=0.02),
            Vulnerability(cve_id="CVE-2025-4444", product_name="Identity Provider SaaS", cvss_base_score=5.0, cisa_kev=True, first_epss=0.45),
            Vulnerability(cve_id="CVE-2024-5555", product_name="Enterprise Router OS", cvss_base_score=6.8, cisa_kev=False, first_epss=0.0012),
            Vulnerability(cve_id="CVE-2025-6666", product_name="Core Banking Framework", cvss_base_score=8.0, cisa_kev=False, first_epss=0.50),
        ]

    # --- Test 1: Max 5 Results ---
    def test_ranking_returns_at_most_five_results(self, ranker, sample_vulns, bank_profile):
        ranking = ranker.rank_vulnerabilities(sample_vulns, bank_profile, top_n=5)
        assert len(ranking) <= 5

    # --- Test 2: Sorted Descending by Risk Score ---
    def test_ranking_sorted_descending_by_risk_score(self, ranker, sample_vulns, bank_profile):
        ranking = ranker.rank_vulnerabilities(sample_vulns, bank_profile, top_n=5)
        scores = [item.risk_score for item in ranking]
        assert scores == sorted(scores, reverse=True)

    # --- Test 3: Deterministic Tie-Breaking ---
    def test_deterministic_tie_breaking(self, ranker, bank_profile):
        vuln1 = Vulnerability(cve_id="CVE-A", product_name="Core Banking Framework", cvss_base_score=5.0, cisa_kev=False, first_epss=0.5)
        vuln2 = Vulnerability(cve_id="CVE-B", product_name="Core Banking Framework", cvss_base_score=5.0, cisa_kev=True, first_epss=0.5)

        ranking = ranker.rank_vulnerabilities([vuln1, vuln2], bank_profile, top_n=5)
        assert ranking[0].cve_id == "CVE-B"
        assert ranking[1].cve_id == "CVE-A"

    # --- Test 4: EXCLUDE Candidates Never Appear in Top 5 ---
    def test_exclude_candidates_never_appear(self, ranker, bank_profile):
        matched_vuln = Vulnerability(cve_id="CVE-2025-1111", product_name="Core Banking Framework", cvss_base_score=9.8)
        excluded_vuln = Vulnerability(cve_id="CVE-2024-5555", product_name="Enterprise Router OS", cvss_base_score=9.9)

        ranking = ranker.rank_vulnerabilities([matched_vuln, excluded_vuln], bank_profile, top_n=5)
        cve_ids = [r.cve_id for r in ranking]

        assert "CVE-2025-1111" in cve_ids
        assert "CVE-2024-5555" not in cve_ids

    # --- Test 5: NEEDS_VERIFICATION Status Retained ---
    def test_needs_verification_retained(self, ranker, bank_profile):
        vuln = Vulnerability(cve_id="CVE-2025-1111", product_name="Core Banking Framework", cvss_base_score=9.8)
        ranking = ranker.rank_vulnerabilities([vuln], bank_profile, top_n=5)
        assert ranking[0].evidence_status == EvidenceStatus.NEEDS_VERIFICATION.value

    # --- Test 6: Score Breakdown Appears in Every Result ---
    def test_score_breakdown_appears_in_every_result(self, ranker, sample_vulns, bank_profile):
        ranking = ranker.rank_vulnerabilities(sample_vulns, bank_profile, top_n=5)
        for r in ranking:
            assert r.score_breakdown is not None
            assert hasattr(r.score_breakdown, "final_risk_score")

    # --- Test 7: Ranking Reason is Deterministic ---
    def test_ranking_reason_is_deterministic(self, ranker, sample_vulns, bank_profile):
        ranking1 = ranker.rank_vulnerabilities(sample_vulns, bank_profile, top_n=5)
        ranking2 = ranker.rank_vulnerabilities(sample_vulns, bank_profile, top_n=5)
        for r1, r2 in zip(ranking1, ranking2):
            assert r1.reason == r2.reason
            assert "CVSS contributed" in r1.reason

    # --- Test 8: Two Official Profiles Produce Different Rankings ---
    def test_two_official_profiles_produce_different_rankings(self, ranker, sample_vulns, bank_profile, startup_profile):
        bank_ranking = ranker.rank_vulnerabilities(sample_vulns, bank_profile, top_n=5)
        startup_ranking = ranker.rank_vulnerabilities(sample_vulns, startup_profile, top_n=5)

        bank_cves = [r.cve_id for r in bank_ranking]
        startup_cves = [r.cve_id for r in startup_ranking]

        assert bank_cves != startup_cves

    # --- Test 9: Arbitrary Valid Profile Processed Cleanly ---
    def test_arbitrary_valid_profile_ranked(self, ranker, sample_vulns):
        arbitrary_profile = Profile(
            org_id="ORG-999",
            name="Custom Sector Firm",
            weight_modifiers=WeightModifiers(cvss_weight=0.5, cisa_kev_weight=0.3, first_epss_weight=0.2),
            critical_products=["Embedded IoT Gateway"],
        )
        ranking = ranker.rank_vulnerabilities(sample_vulns, arbitrary_profile, top_n=5)
        assert len(ranking) == 1
        assert ranking[0].cve_id == "CVE-2024-3333"

    # --- Test 10: Practitioner Ranks Do Not Influence Production Ranking ---
    def test_practitioner_ranks_do_not_influence_production_ranking(self, ranker, bank_profile):
        v1 = Vulnerability(cve_id="CVE-1", product_name="Core Banking Framework", cvss_base_score=9.0, practitioner_rank_bank=5)
        v2 = Vulnerability(cve_id="CVE-2", product_name="Core Banking Framework", cvss_base_score=5.0, practitioner_rank_bank=1)

        ranking = ranker.rank_vulnerabilities([v1, v2], bank_profile, top_n=5)
        assert ranking[0].cve_id == "CVE-1"

    # --- Test 11: Gold-Set Evaluation Separate From Production Ranking ---
    def test_gold_set_evaluation_is_separate(self, ranker, bank_profile, sample_vulns):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        gold_path = os.path.join(base_dir, "data", "gold_set.csv")
        gold_entries = DataLoader.load_gold_set(gold_path)

        ranking = ranker.rank_vulnerabilities(sample_vulns, bank_profile, top_n=5)
        metrics = GoldSetEvaluator.evaluate(ranking, gold_entries, org_id="ORG-001")

        assert metrics.org_id == "ORG-001"
        assert hasattr(metrics, "relative_top1_agreement")
        assert hasattr(metrics, "global_top1_agreement")

    # --- Test 12, 13, 14: Top-1, Top-3, Top-5 Evaluation ---
    def test_top_k_evaluation_metrics(self, ranker, bank_profile, sample_vulns):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        gold_path = os.path.join(base_dir, "data", "gold_set.csv")
        gold_entries = DataLoader.load_gold_set(gold_path)

        ranking = ranker.rank_vulnerabilities(sample_vulns, bank_profile, top_n=5)
        metrics = GoldSetEvaluator.evaluate(ranking, gold_entries, org_id="ORG-001")

        assert isinstance(metrics.relative_top1_agreement, bool)
        assert 0.0 <= metrics.relative_top3_overlap <= 1.0
        assert 0.0 <= metrics.relative_top5_overlap <= 1.0

    # --- Test 15: Negative Test (Synthetic Profile Produces Zero False Positives) ---
    def test_synthetic_negative_profile_no_false_positives(self, ranker, sample_vulns):
        synthetic_negative_profile = Profile(
            org_id="ORG-SYNTHETIC-NEGATIVE",
            name="Non-Existent Tech Org",
            weight_modifiers=WeightModifiers(cvss_weight=0.33, cisa_kev_weight=0.33, first_epss_weight=0.34),
            critical_products=["Legacy Mainframe COBOL OS 1980"],
        )

        ranking = ranker.rank_vulnerabilities(sample_vulns, synthetic_negative_profile, top_n=5)
        assert len(ranking) == 0

    # --- Test 16: Official Organiser Dataset End-to-End Ranking ---
    def test_official_organiser_dataset_end_to_end_ranking(self, ranker):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        vuln_path = os.path.join(base_dir, "data", "vulnerabilities.csv")
        profile_path = os.path.join(base_dir, "data", "profiles.json")

        vulns = DataLoader.load_vulnerabilities(vuln_path)
        profiles = DataLoader.load_profiles(profile_path)

        for p in profiles:
            ranking = ranker.rank_vulnerabilities(vulns, p, top_n=5)
            assert isinstance(ranking, list)
            for r in ranking:
                assert r.rank >= 1
                assert r.risk_score >= 0.0

    # --- Test 17: Fewer Than 5 Eligible Vulnerabilities Handled Safely ---
    def test_fewer_than_five_eligible_handled_safely(self, ranker, bank_profile):
        two_vulns = [
            Vulnerability(cve_id="CVE-1", product_name="Core Banking Framework", cvss_base_score=9.0),
            Vulnerability(cve_id="CVE-2", product_name="Core Banking Framework", cvss_base_score=7.0),
        ]
        ranking = ranker.rank_vulnerabilities(two_vulns, bank_profile, top_n=5)
        assert len(ranking) == 2
        assert ranking[0].rank == 1
        assert ranking[1].rank == 2

    # --- Test 18: Empty Candidate Set Handled Safely ---
    def test_empty_candidate_set_handled_safely(self, ranker, bank_profile):
        ranking = ranker.rank_vulnerabilities([], bank_profile, top_n=5)
        assert ranking == []

    # --- Refinement Test 19: Organization-Specific Filtering ---
    def test_evaluator_organization_specific_filtering(self, ranker, bank_profile, sample_vulns):
        gold_entries = [
            GoldSetEntry(cve_id="CVE-2025-1111", product_name="Core Banking Framework", practitioner_rank_bank=1),
            GoldSetEntry(cve_id="CVE-2025-4444", product_name="Identity Provider SaaS", practitioner_rank_bank=2),
            GoldSetEntry(cve_id="CVE-2024-3333", product_name="Embedded IoT Gateway", practitioner_rank_bank=3),
        ]
        ranking = ranker.rank_vulnerabilities(sample_vulns, bank_profile, top_n=5)
        metrics = GoldSetEvaluator.evaluate(ranking, gold_entries, org_id="ORG-001")

        # sample_vulns has 3 matching items for bank_profile: CVE-2025-1111, CVE-2025-4444, CVE-2025-6666
        assert metrics.eligible_candidate_count == 3
        assert metrics.relative_top1_agreement is True

    # --- Refinement Test 20: Global vs Relative Rank Distinction ---
    def test_evaluator_global_vs_relative_rank_distinction(self, ranker):
        utility_profile = Profile(
            org_id="ORG-003",
            name="Municipal Utility Provider",
            weight_modifiers=WeightModifiers(cvss_weight=0.5, cisa_kev_weight=0.4, first_epss_weight=0.1),
            critical_products=["Embedded IoT Gateway", "Enterprise Router OS"],
        )
        vulns = [
            Vulnerability(cve_id="CVE-2024-3333", product_name="Embedded IoT Gateway", cvss_base_score=9.0, cisa_kev=True, first_epss=0.02),
            Vulnerability(cve_id="CVE-2024-5555", product_name="Enterprise Router OS", cvss_base_score=6.8, cisa_kev=False, first_epss=0.0012),
        ]
        gold_entries = [
            GoldSetEntry(cve_id="CVE-2025-1111", product_name="Core Banking Framework", practitioner_rank_bank=1),
            GoldSetEntry(cve_id="CVE-2024-3333", product_name="Embedded IoT Gateway", practitioner_rank_bank=3),
            GoldSetEntry(cve_id="CVE-2024-5555", product_name="Enterprise Router OS", practitioner_rank_bank=5),
        ]

        ranking = ranker.rank_vulnerabilities(vulns, utility_profile, top_n=5)
        metrics = GoldSetEvaluator.evaluate(ranking, gold_entries, org_id="ORG-003")

        assert metrics.relative_top1_agreement is True   # Prod #1 CVE-2024-3333 matches relative gold #1 CVE-2024-3333
        assert metrics.global_top1_agreement is False   # Prod #1 CVE-2024-3333 does NOT match global gold #1 CVE-2025-1111

    # --- Refinement Test 21: One Candidate Spearman is None ---
    def test_evaluator_one_candidate_spearman_is_none(self, ranker, startup_profile):
        vuln = Vulnerability(cve_id="CVE-2026-2222", product_name="Cloud Database Engine", cvss_base_score=7.5)
        gold_entries = [GoldSetEntry(cve_id="CVE-2026-2222", product_name="Cloud Database Engine", practitioner_rank_startup=1)]

        ranking = ranker.rank_vulnerabilities([vuln], startup_profile, top_n=5)
        metrics = GoldSetEvaluator.evaluate(ranking, gold_entries, org_id="ORG-002")

        assert metrics.eligible_candidate_count == 1
        assert metrics.spearman_rank_correlation is None

    # --- Refinement Test 22: Two-Candidate Reversed Ordering Spearman ---
    def test_evaluator_two_candidate_reversed_ordering_spearman(self):
        dummy_bd = ScoreBreakdown(cvss_normalized=0.5, cvss_weight=0.5, cvss_contribution=0.25, kev_normalized=0.0, kev_weight=0.0, kev_contribution=0.0, epss_value=0.0, epss_weight=0.0, epss_contribution=0.0, final_risk_score=0.25)
        ranked = [
            RankedVulnerability(rank=1, cve_id="CVE-B", product_name="Prod", risk_score=0.8, priority="HIGH", evidence_status="MATCH", reason="test", score_breakdown=dummy_bd),
            RankedVulnerability(rank=2, cve_id="CVE-A", product_name="Prod", risk_score=0.4, priority="MEDIUM", evidence_status="MATCH", reason="test", score_breakdown=dummy_bd),
        ]
        gold_entries = [
            GoldSetEntry(cve_id="CVE-A", product_name="Prod", practitioner_rank_bank=1),
            GoldSetEntry(cve_id="CVE-B", product_name="Prod", practitioner_rank_bank=2),
        ]

        metrics = GoldSetEvaluator.evaluate(ranked, gold_entries, org_id="ORG-001")
        assert metrics.spearman_rank_correlation == -1.0

    # --- Refinement Test 23: Two-Candidate Matching Ordering Spearman ---
    def test_evaluator_two_candidate_matching_ordering_spearman(self):
        dummy_bd = ScoreBreakdown(cvss_normalized=0.5, cvss_weight=0.5, cvss_contribution=0.25, kev_normalized=0.0, kev_weight=0.0, kev_contribution=0.0, epss_value=0.0, epss_weight=0.0, epss_contribution=0.0, final_risk_score=0.25)
        ranked = [
            RankedVulnerability(rank=1, cve_id="CVE-A", product_name="Prod", risk_score=0.8, priority="HIGH", evidence_status="MATCH", reason="test", score_breakdown=dummy_bd),
            RankedVulnerability(rank=2, cve_id="CVE-B", product_name="Prod", risk_score=0.4, priority="MEDIUM", evidence_status="MATCH", reason="test", score_breakdown=dummy_bd),
        ]
        gold_entries = [
            GoldSetEntry(cve_id="CVE-A", product_name="Prod", practitioner_rank_bank=1),
            GoldSetEntry(cve_id="CVE-B", product_name="Prod", practitioner_rank_bank=2),
        ]

        metrics = GoldSetEvaluator.evaluate(ranked, gold_entries, org_id="ORG-001")
        assert metrics.spearman_rank_correlation == 1.0

    # --- Refinement Test 24: Fewer Than Five Candidate Precision/Recall ---
    def test_evaluator_fewer_than_five_candidate_precision_recall(self, ranker, bank_profile):
        vuln = Vulnerability(cve_id="CVE-2025-1111", product_name="Core Banking Framework", cvss_base_score=9.8)
        gold_entries = [
            GoldSetEntry(cve_id="CVE-2025-1111", product_name="Core Banking Framework", practitioner_rank_bank=1),
            GoldSetEntry(cve_id="CVE-2025-4444", product_name="Identity Provider SaaS", practitioner_rank_bank=2),
        ]
        ranking = ranker.rank_vulnerabilities([vuln], bank_profile, top_n=5)
        metrics = GoldSetEvaluator.evaluate(ranking, gold_entries, org_id="ORG-001")

        assert metrics.eligible_candidate_count == 1
        assert metrics.precision_at_5 == 1.0  # 1 matched / 1 retrieved candidate
        assert metrics.recall_at_5 == 1.0     # 1 matched / 1 relative gold item

    # --- Refinement Test 25: Practitioner Rank Isolation ---
    def test_evaluator_practitioner_rank_isolation(self, ranker, bank_profile):
        v1 = Vulnerability(cve_id="CVE-1", product_name="Core Banking Framework", cvss_base_score=9.8, practitioner_rank_bank=99)
        v2 = Vulnerability(cve_id="CVE-2", product_name="Core Banking Framework", cvss_base_score=5.0, practitioner_rank_bank=1)

        ranking = ranker.rank_vulnerabilities([v1, v2], bank_profile, top_n=5)
        assert ranking[0].cve_id == "CVE-1"
        assert ranking[1].cve_id == "CVE-2"

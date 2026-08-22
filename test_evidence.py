"""Unit tests for ShieldLens Phase 3 Context Validation and Evidence Handling module."""

import os
import pytest

from engine.models import Vulnerability, Profile, EvidenceStatus, EvidenceResult
from engine.matcher import ContextValidator, TechnologyMatcher, MatchStatus
from engine.loader import DataLoader


class TestContextValidation:
    """Test suite covering context validation, honest evidence status handling, and official dataset tests."""

    # --- Test 1: Exact Product Match ---
    def test_exact_product_match(self):
        vuln = Vulnerability(
            cve_id="CVE-2025-1111",
            product_name="Core Banking Framework",
            cvss_base_score=9.8,
        )
        profile = Profile(
            org_id="ORG-001",
            name="Global Retail Bank",
            critical_products=["Core Banking Framework"],
        )

        res = ContextValidator.validate_evidence(vuln, profile)
        assert res.product_match_status == EvidenceStatus.MATCH
        assert res.matched_profile_product == "Core Banking Framework"

    # --- Test 2: Case-Insensitive Product Match ---
    def test_case_insensitive_product_match(self):
        vuln = Vulnerability(
            cve_id="CVE-2026-2222",
            product_name="CLOUD DATABASE ENGINE",
            cvss_base_score=7.5,
        )
        profile = Profile(
            org_id="ORG-002",
            name="Agile Cloud Tech Startup",
            critical_products=["cloud database engine"],
        )

        res = ContextValidator.validate_evidence(vuln, profile)
        assert res.product_match_status == EvidenceStatus.MATCH

    # --- Test 3: Whitespace-Normalised Product Match ---
    def test_whitespace_normalised_product_match(self):
        vuln = Vulnerability(
            cve_id="CVE-2024-3333",
            product_name="   Embedded   IoT   Gateway   ",
            cvss_base_score=9.0,
        )
        profile = Profile(
            org_id="ORG-003",
            name="Municipal Utility Provider",
            critical_products=["Embedded IoT Gateway"],
        )

        res = ContextValidator.validate_evidence(vuln, profile)
        assert res.product_match_status == EvidenceStatus.MATCH

    # --- Test 4: Product Mismatch ---
    def test_product_mismatch_returns_exclude(self):
        vuln = Vulnerability(
            cve_id="CVE-2024-5555",
            product_name="Enterprise Router OS",
            cvss_base_score=6.8,
        )
        profile = Profile(
            org_id="ORG-001",
            name="Global Retail Bank",
            critical_products=["Core Banking Framework"],
        )

        res = ContextValidator.validate_evidence(vuln, profile)
        assert res.product_match_status == EvidenceStatus.EXCLUDE
        assert res.version_evidence_status == EvidenceStatus.EXCLUDE
        assert res.overall_evidence_status == EvidenceStatus.EXCLUDE

    # --- Test 5: Ambiguous Product Relationship ---
    def test_ambiguous_product_relationship(self):
        # Technology mismatch returns EXCLUDE
        vuln = Vulnerability(
            cve_id="CVE-2025-9999",
            product_name="Generic Framework Component",
            cvss_base_score=5.0,
        )
        profile = Profile(
            org_id="ORG-001",
            name="Global Retail Bank",
            critical_products=["Identity Provider SaaS"],
        )

        res = ContextValidator.validate_evidence(vuln, profile)
        assert res.overall_evidence_status in (EvidenceStatus.EXCLUDE, EvidenceStatus.NEEDS_VERIFICATION)

    # --- Test 6: Missing Version Evidence ---
    def test_missing_version_evidence_handling(self):
        vuln = Vulnerability(
            cve_id="CVE-2025-1111",
            product_name="Core Banking Framework",
            cvss_base_score=9.8,
        )
        profile = Profile(
            org_id="ORG-001",
            name="Global Retail Bank",
            critical_products=["Core Banking Framework"],
        )

        res = ContextValidator.validate_evidence(vuln, profile)
        assert res.product_match_status == EvidenceStatus.MATCH
        assert res.version_evidence_status == EvidenceStatus.NEEDS_VERIFICATION

    # --- Test 7: NEEDS_VERIFICATION Status ---
    def test_overall_needs_verification_status(self):
        vuln = Vulnerability(
            cve_id="CVE-2025-1111",
            product_name="Core Banking Framework",
            cvss_base_score=9.8,
        )
        profile = Profile(
            org_id="ORG-001",
            name="Global Retail Bank",
            critical_products=["Core Banking Framework"],
        )

        res = ContextValidator.validate_evidence(vuln, profile)
        assert res.overall_evidence_status == EvidenceStatus.NEEDS_VERIFICATION
        assert "contains no affected-version information" in res.reason

    # --- Test 8: Evidence Object Creation ---
    def test_evidence_object_structure(self):
        vuln = Vulnerability(
            cve_id="CVE-2025-1111",
            product_name="Core Banking Framework",
            cvss_base_score=9.8,
        )
        profile = Profile(
            org_id="ORG-001",
            name="Global Retail Bank",
            critical_products=["Core Banking Framework"],
        )

        res = ContextValidator.validate_evidence(vuln, profile)
        assert isinstance(res, EvidenceResult)
        assert res.cve_id == "CVE-2025-1111"
        assert res.org_id == "ORG-001"
        assert res.vulnerability_product == "Core Banking Framework"
        assert res.matched_profile_product == "Core Banking Framework"

    # --- Test 9: Official Organiser Dataset ---
    def test_official_dataset_context_validation(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        vuln_path = os.path.join(base_dir, "data", "vulnerabilities.csv")
        profile_path = os.path.join(base_dir, "data", "profiles.json")

        vulns = DataLoader.load_vulnerabilities(vuln_path)
        profiles = DataLoader.load_profiles(profile_path)

        bank_profile = next(p for p in profiles if p.org_id == "ORG-001")
        bank_cve = next(v for v in vulns if v.cve_id == "CVE-2025-1111")

        res = ContextValidator.validate_evidence(bank_cve, bank_profile)
        assert res.cve_id == "CVE-2025-1111"
        assert res.org_id == "ORG-001"
        assert res.product_match_status == EvidenceStatus.MATCH
        assert res.version_evidence_status == EvidenceStatus.NEEDS_VERIFICATION
        assert res.overall_evidence_status == EvidenceStatus.NEEDS_VERIFICATION

    # --- Test 10: Practitioner Ranks Not Affecting Matching ---
    def test_practitioner_ranks_do_not_affect_matching(self):
        # Two vulnerabilities with identical product_name but completely different practitioner_ranks
        vuln1 = Vulnerability(
            cve_id="CVE-2025-1111",
            product_name="Core Banking Framework",
            cvss_base_score=9.8,
            practitioner_rank_bank=1,
            practitioner_rank_startup=5,
        )
        vuln2 = Vulnerability(
            cve_id="CVE-2025-9999",
            product_name="Core Banking Framework",
            cvss_base_score=5.0,
            practitioner_rank_bank=5,
            practitioner_rank_startup=1,
        )
        profile = Profile(
            org_id="ORG-001",
            name="Global Retail Bank",
            critical_products=["Core Banking Framework"],
        )

        res1 = ContextValidator.validate_evidence(vuln1, profile)
        res2 = ContextValidator.validate_evidence(vuln2, profile)

        assert res1.product_match_status == res2.product_match_status == EvidenceStatus.MATCH
        assert res1.version_evidence_status == res2.version_evidence_status == EvidenceStatus.NEEDS_VERIFICATION
        assert res1.overall_evidence_status == res2.overall_evidence_status == EvidenceStatus.NEEDS_VERIFICATION

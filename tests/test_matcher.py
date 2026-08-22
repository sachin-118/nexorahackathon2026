"""Unit tests for ShieldLens TechnologyMatcher module."""

import os
from engine.models import Vulnerability, Profile
from engine.matcher import TechnologyMatcher, MatchStatus
from engine.loader import DataLoader


class TestTechnologyMatcher:
    """Test suite covering technology matching, rule evaluations, and dataset validations."""

    def test_valid_technology_match(self):
        vuln = Vulnerability(
            cve_id="CVE-2025-1111",
            product_name="Core Banking Framework",
            cvss_base_score=9.8,
        )
        profile = Profile(
            org_id="ORG-001",
            name="Global Retail Bank",
            critical_products=["Core Banking Framework", "Identity Provider SaaS"],
        )

        result = TechnologyMatcher.match(vuln, profile)
        assert result.status == MatchStatus.MATCH
        assert result.vendor_matched is True
        assert result.product_matched is True
        assert result.reason == "Matching vendor and product"

    def test_case_differences_match(self):
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

        result = TechnologyMatcher.match(vuln, profile)
        assert result.status == MatchStatus.MATCH
        assert result.vendor_matched is True
        assert result.product_matched is True

    def test_whitespace_differences_match(self):
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

        result = TechnologyMatcher.match(vuln, profile)
        assert result.status == MatchStatus.MATCH
        assert result.vendor_matched is True
        assert result.product_matched is True

    def test_alias_match(self):
        vuln = Vulnerability(
            cve_id="CVE-2025-4444",
            product_name="IDP",  # Alias for identity provider saas
            cvss_base_score=5.0,
        )
        profile = Profile(
            org_id="ORG-001",
            name="Global Retail Bank",
            critical_products=["Identity Provider SaaS"],
        )

        result = TechnologyMatcher.match(vuln, profile)
        assert result.status == MatchStatus.MATCH
        assert result.vendor_matched is True
        assert result.product_matched is True

    def test_vendor_mismatch_returns_exclude(self):
        vuln = Vulnerability(
            cve_id="CVE-2024-5555",
            product_name="Oracle Enterprise Database",
            cvss_base_score=6.8,
        )
        profile = Profile(
            org_id="ORG-001",
            name="Global Retail Bank",
            critical_products=["Core Banking Framework"],
        )

        result = TechnologyMatcher.match(vuln, profile)
        assert result.status == MatchStatus.EXCLUDE
        assert result.vendor_matched is False
        assert result.product_matched is False
        assert result.reason == "Vendor mismatch"

    def test_product_mismatch_returns_exclude(self):
        vuln = Vulnerability(
            cve_id="CVE-2025-9999",
            product_name="Core Banking Analytics Plugin",
            cvss_base_score=7.0,
        )
        profile = Profile(
            org_id="ORG-001",
            name="Global Retail Bank",
            critical_products=["Identity Provider SaaS"],
        )

        result = TechnologyMatcher.match(vuln, profile)
        assert result.status == MatchStatus.EXCLUDE
        assert result.reason == "Vendor mismatch" or result.reason == "Product mismatch"

    def test_matching_on_official_datasets(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        vuln_path = os.path.join(base_dir, "data", "vulnerabilities.csv")
        profile_path = os.path.join(base_dir, "data", "profiles.json")

        vulns = DataLoader.load_vulnerabilities(vuln_path)
        profiles = DataLoader.load_profiles(profile_path)

        bank_profile = next(p for p in profiles if p.org_id == "ORG-001")
        bank_cve = next(v for v in vulns if v.cve_id == "CVE-2025-1111")

        result = TechnologyMatcher.match(bank_cve, bank_profile)
        assert result.status == MatchStatus.MATCH
        assert result.cve_id == "CVE-2025-1111"
        assert result.org_id == "ORG-001"

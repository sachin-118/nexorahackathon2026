"""Unit tests for ShieldLens DataLoader module supporting official hackathon datasets."""

import io
import os
import pytest

from engine.loader import (
    DataLoader,
    FileNotFoundDataError,
    MissingColumnError,
    MalformedDataError,
)
from engine.models import Vulnerability, Profile, GoldSetEntry


class TestDataLoader:
    """Test suite covering official hackathon data loading, schema validation, error handling, and optional values."""

    # --- 1. CSV Loading Tests ---

    def test_load_vulnerabilities_valid_csv(self):
        csv_data = (
            "cve_id,product_name,cvss_base_score,cisa_kev,first_epss,practitioner_rank_bank,practitioner_rank_startup\n"
            "CVE-2025-1111,Core Banking Framework,9.8,True,0.95,1,2\n"
        )
        stream = io.StringIO(csv_data)
        vulns = DataLoader.load_vulnerabilities(stream)

        assert len(vulns) == 1
        v = vulns[0]
        assert isinstance(v, Vulnerability)
        assert v.cve_id == "CVE-2025-1111"
        assert v.product_name == "Core Banking Framework"
        assert v.cvss_base_score == 9.8
        assert v.cisa_kev is True
        assert v.first_epss == 0.95
        assert v.practitioner_rank_bank == 1
        assert v.practitioner_rank_startup == 2

    def test_load_gold_set_valid_csv(self):
        csv_data = (
            "cve_id,product_name,practitioner_rank_bank,practitioner_rank_startup\n"
            "CVE-2025-1111,Core Banking Framework,1,2\n"
        )
        stream = io.StringIO(csv_data)
        entries = DataLoader.load_gold_set(stream)

        assert len(entries) == 1
        entry = entries[0]
        assert isinstance(entry, GoldSetEntry)
        assert entry.cve_id == "CVE-2025-1111"
        assert entry.product_name == "Core Banking Framework"
        assert entry.practitioner_rank_bank == 1
        assert entry.practitioner_rank_startup == 2

    def test_load_from_actual_official_data_files(self):
        # Load from official files in data/
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        vuln_path = os.path.join(base_dir, "data", "vulnerabilities.csv")
        profile_path = os.path.join(base_dir, "data", "profiles.json")
        gold_path = os.path.join(base_dir, "data", "gold_set.csv")

        vulns = DataLoader.load_vulnerabilities(vuln_path)
        assert len(vulns) == 5
        assert vulns[0].cve_id == "CVE-2025-1111"
        assert vulns[0].product_name == "Core Banking Framework"
        assert vulns[0].cvss_base_score == 9.8
        assert vulns[0].cisa_kev is True
        assert vulns[0].first_epss == 0.95

        profiles = DataLoader.load_profiles(profile_path)
        assert len(profiles) == 3
        assert profiles[0].org_id == "ORG-001"
        assert profiles[0].name == "Global Retail Bank"
        assert profiles[0].sector == "Financial Services"
        assert profiles[0].weight_modifiers.cvss_weight == 0.3
        assert "Core Banking Framework" in profiles[0].critical_products

        gold_entries = DataLoader.load_gold_set(gold_path)
        assert len(gold_entries) == 5
        assert gold_entries[0].cve_id == "CVE-2025-1111"
        assert gold_entries[0].practitioner_rank_bank == 1

    # --- 2. JSON Loading Tests ---

    def test_load_profiles_valid_json(self):
        json_data = """
        {
            "$schema_description": "Defines contextual risk weights",
            "organizations": [
                {
                    "org_id": "ORG-001",
                    "name": "Global Retail Bank",
                    "sector": "Financial Services",
                    "risk_appetite": "Low",
                    "weight_modifiers": {
                        "cvss_weight": 0.3,
                        "cisa_kev_weight": 0.45,
                        "first_epss_weight": 0.25
                    },
                    "critical_products": [
                        "Core Banking Framework"
                    ]
                }
            ]
        }
        """
        stream = io.StringIO(json_data)
        profiles = DataLoader.load_profiles(stream)

        assert len(profiles) == 1
        p = profiles[0]
        assert isinstance(p, Profile)
        assert p.org_id == "ORG-001"
        assert p.name == "Global Retail Bank"
        assert p.sector == "Financial Services"
        assert p.risk_appetite == "Low"
        assert p.weight_modifiers.cvss_weight == 0.3
        assert p.critical_products == ["Core Banking Framework"]

    # --- 3. Missing File Tests ---

    def test_missing_file_raises_not_found(self):
        with pytest.raises(FileNotFoundDataError) as exc_info:
            DataLoader.load_vulnerabilities("non_existent_file_path_12345.csv")
        assert "not found" in str(exc_info.value).lower()

    # --- 4. Missing Required Columns Tests ---

    def test_vulnerabilities_missing_cve_id(self):
        csv_data = "product_name,cvss_base_score\nTest Product,5.0\n"
        stream = io.StringIO(csv_data)
        with pytest.raises(MissingColumnError) as exc_info:
            DataLoader.load_vulnerabilities(stream)
        assert "cve_id" in str(exc_info.value)

    def test_profiles_missing_required_key(self):
        json_data = '[{"org_id": "ORG-100"}]'
        stream = io.StringIO(json_data)
        with pytest.raises(MissingColumnError) as exc_info:
            DataLoader.load_profiles(stream)
        assert "name" in str(exc_info.value)

    def test_gold_set_missing_cve_id(self):
        csv_data = "product_name,practitioner_rank_bank\nTest Product,1\n"
        stream = io.StringIO(csv_data)
        with pytest.raises(MissingColumnError) as exc_info:
            DataLoader.load_gold_set(stream)
        assert "cve_id" in str(exc_info.value)

    # --- 5. Malformed Data Tests ---

    def test_malformed_json_syntax(self):
        json_data = '[{"org_id": "ORG-100", "name": unquoted_value}]'
        stream = io.StringIO(json_data)
        with pytest.raises(MalformedDataError) as exc_info:
            DataLoader.load_profiles(stream)
        assert "invalid json" in str(exc_info.value).lower()

    def test_malformed_non_numeric_cvss(self):
        csv_data = (
            "cve_id,product_name,cvss_base_score\n"
            "CVE-2025-0001,Test Product,NOT_A_NUMBER\n"
        )
        stream = io.StringIO(csv_data)
        with pytest.raises(MalformedDataError) as exc_info:
            DataLoader.load_vulnerabilities(stream)
        assert "numeric" in str(exc_info.value).lower()

    def test_empty_file_raises_malformed(self):
        stream = io.StringIO("")
        with pytest.raises(MalformedDataError) as exc_info:
            DataLoader.load_vulnerabilities(stream)
        assert "empty" in str(exc_info.value).lower()

    # --- 6. Missing Optional Values Tests ---

    def test_vulnerabilities_optional_values_default_safely(self):
        csv_data = (
            "cve_id,product_name,cvss_base_score\n"
            "CVE-2025-9999,Minimal Product,3.2\n"
        )
        stream = io.StringIO(csv_data)
        vulns = DataLoader.load_vulnerabilities(stream)

        assert len(vulns) == 1
        v = vulns[0]
        assert v.cve_id == "CVE-2025-9999"
        assert v.product_name == "Minimal Product"
        assert v.cisa_kev is False
        assert v.first_epss == 0.0
        assert v.practitioner_rank_bank is None
        assert v.practitioner_rank_startup is None

    def test_profiles_optional_values_default_safely(self):
        json_data = '[{"org_id": "ORG-MINIMAL", "name": "Minimal Profile"}]'
        stream = io.StringIO(json_data)
        profiles = DataLoader.load_profiles(stream)

        assert len(profiles) == 1
        p = profiles[0]
        assert p.org_id == "ORG-MINIMAL"
        assert p.name == "Minimal Profile"
        assert p.sector is None
        assert p.risk_appetite is None
        assert p.weight_modifiers is None
        assert p.critical_products == []

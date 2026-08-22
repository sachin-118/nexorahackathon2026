"""Unit tests for ShieldLens Normalizer module."""

from engine.normalizer import Normalizer, ParsedTechnology


class TestNormalizer:
    """Test suite for string normalisation, whitespace handling, and transparent alias mappings."""

    def test_case_differences(self):
        assert Normalizer.normalize_string("Core Banking Framework") == "core banking framework"
        assert Normalizer.normalize_string("CLOUD DATABASE ENGINE") == "cloud database engine"

    def test_whitespace_handling(self):
        assert Normalizer.normalize_string("  Embedded   IoT   Gateway  ") == "embedded iot gateway"
        assert Normalizer.normalize_string("\tEnterprise\nRouter   OS\t") == "enterprise router os"

    def test_alias_resolution(self):
        assert Normalizer.apply_alias("postgres") == "postgresql"
        assert Normalizer.apply_alias("k8s") == "kubernetes"
        assert Normalizer.apply_alias("py") == "python"
        assert Normalizer.apply_alias("cloud db") == "cloud database engine"
        assert Normalizer.apply_alias("idp") == "identity provider saas"

    def test_parse_technology(self):
        parsed = Normalizer.parse_technology(" Core Banking Framework ")
        assert isinstance(parsed, ParsedTechnology)
        assert parsed.normalized == "core banking framework"
        assert parsed.vendor == "core banking"
        assert parsed.product == "core banking framework"

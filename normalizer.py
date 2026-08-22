"""Technology normalisation module for ShieldLens engine."""

import re
from typing import Dict, List, Tuple, Optional
from pydantic import BaseModel, Field


class ParsedTechnology(BaseModel):
    """Normalized technology component containing vendor and product information."""
    raw: str
    normalized: str
    vendor: str
    product: str


class Normalizer:
    """Provides vendor/product normalisation, alias resolution, and tech parsing."""

    # Small, transparent alias table mapping common abbreviations & variations to canonical terms
    ALIAS_TABLE: Dict[str, str] = {
        "postgres": "postgresql",
        "postgresql": "postgresql",
        "k8s": "kubernetes",
        "kubernetes": "kubernetes",
        "py": "python",
        "python": "python",
        "js": "javascript",
        "javascript": "javascript",
        "react": "reactjs",
        "reactjs": "reactjs",
        "node": "nodejs",
        "nodejs": "nodejs",
        "core banking": "core banking framework",
        "cloud db": "cloud database engine",
        "cloud database": "cloud database engine",
        "iot gateway": "embedded iot gateway",
        "idp": "identity provider saas",
        "identity provider": "identity provider saas",
        "router os": "enterprise router os",
        "waf": "web application firewall",
    }

    @classmethod
    def normalize_string(cls, text: Optional[str]) -> str:
        """Lowercase, strip whitespace, collapse multi-spaces, and remove excess punctuation."""
        if not text:
            return ""
        # Lowercase
        cleaned = text.strip().lower()
        # Replace hyphens & underscores with spaces for uniform comparison
        cleaned = re.sub(r"[\-_]+", " ", cleaned)
        # Collapse multiple spaces into a single space
        cleaned = re.sub(r"\s+", " ", cleaned)
        return cleaned

    @classmethod
    def apply_alias(cls, term: str) -> str:
        """Apply transparent alias mapping to a normalized term if present."""
        norm = cls.normalize_string(term)
        return cls.ALIAS_TABLE.get(norm, norm)

    @classmethod
    def normalize_vendor(cls, vendor: Optional[str]) -> str:
        """Normalize vendor name using string cleaning and alias lookup."""
        norm = cls.normalize_string(vendor)
        return cls.apply_alias(norm)

    @classmethod
    def normalize_product(cls, product: Optional[str]) -> str:
        """Normalize product name using string cleaning and alias lookup."""
        norm = cls.normalize_string(product)
        return cls.apply_alias(norm)

    @classmethod
    def parse_technology(cls, tech_input: str) -> ParsedTechnology:
        """Parse a technology string into a ParsedTechnology object containing vendor and product."""
        norm = cls.normalize_string(tech_input)
        aliased = cls.apply_alias(norm)

        # Infer vendor and product from phrase tokens
        tokens = aliased.split()
        if len(tokens) == 0:
            vendor = ""
            product = ""
        elif len(tokens) == 1:
            vendor = tokens[0]
            product = tokens[0]
        else:
            # If 2 or more words (e.g. "core banking framework"), vendor is prefix, product is full phrase
            vendor = " ".join(tokens[:-1])
            product = aliased

        return ParsedTechnology(
            raw=tech_input,
            normalized=aliased,
            vendor=vendor,
            product=product,
        )

    @classmethod
    def parse_profile_technologies(cls, profile_critical_products: List[str], profile_tech_stack: List[str]) -> List[ParsedTechnology]:
        """Extract and normalize all technologies from a profile's critical products and tech stack."""
        results = []
        combined = list(profile_critical_products) + list(profile_tech_stack)
        seen = set()
        for item in combined:
            if item and item.strip():
                parsed = cls.parse_technology(item)
                if parsed.normalized not in seen:
                    seen.add(parsed.normalized)
                    results.append(parsed)
        return results

    @classmethod
    def parse_vulnerability_technology(cls, product_name: str, affected_components: Optional[List[str]] = None) -> List[ParsedTechnology]:
        """Extract and normalize technologies from a vulnerability's product_name and affected components."""
        results = []
        seen = set()

        if product_name and product_name.strip():
            parsed = cls.parse_technology(product_name)
            seen.add(parsed.normalized)
            results.append(parsed)

        if affected_components:
            for comp in affected_components:
                if comp and comp.strip():
                    parsed = cls.parse_technology(comp)
                    if parsed.normalized not in seen:
                        seen.add(parsed.normalized)
                        results.append(parsed)

        return results

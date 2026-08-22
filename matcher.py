"""Technology matching and context evidence validation engine for ShieldLens."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel

from engine.models import Vulnerability, Profile, EvidenceStatus, EvidenceResult
from engine.normalizer import Normalizer, ParsedTechnology


class MatchStatus(str, Enum):
    """Technology match outcome status."""
    MATCH = "MATCH"
    EXCLUDE = "EXCLUDE"
    NEEDS_VERIFICATION = "NEEDS_VERIFICATION"


class MatchResult(BaseModel):
    """Structured result of technology matching evaluation."""
    cve_id: str
    org_id: str
    status: MatchStatus
    vendor_matched: bool
    product_matched: bool
    matched_technology: Optional[str] = None
    reason: str


class TechnologyMatcher:
    """Generic technology matching engine operating on any valid Vulnerability and Profile."""

    @classmethod
    def match_technologies(cls, vuln_tech: ParsedTechnology, profile_tech: ParsedTechnology) -> tuple[bool, bool]:
        """Compare a single vulnerability technology against a profile technology. Return (vendor_match, product_match)."""
        v_norm = vuln_tech.normalized
        p_norm = profile_tech.normalized
        v_vendor = vuln_tech.vendor
        p_vendor = profile_tech.vendor

        if v_norm == p_norm:
            return True, True

        vendor_match = False
        if v_vendor and p_vendor:
            if v_vendor == p_vendor or v_vendor in p_norm or p_vendor in v_norm:
                vendor_match = True

        product_match = False
        if v_norm == p_norm or (vendor_match and (vuln_tech.product in profile_tech.product or profile_tech.product in vuln_tech.product)):
            product_match = True

        return vendor_match, product_match

    @classmethod
    def match(cls, vulnerability: Vulnerability, profile: Profile) -> MatchResult:
        """Evaluate vendor and product matching between a vulnerability and an environment profile."""
        cve_id = vulnerability.cve_id
        org_id = profile.org_id or profile.profile_id or "UNKNOWN"

        vuln_techs = Normalizer.parse_vulnerability_technology(
            product_name=vulnerability.product_name,
            affected_components=vulnerability.affected_components,
        )

        profile_techs = Normalizer.parse_profile_technologies(
            profile_critical_products=profile.critical_products,
            profile_tech_stack=profile.tech_stack,
        )

        if not vuln_techs or not profile_techs:
            return MatchResult(
                cve_id=cve_id,
                org_id=org_id,
                status=MatchStatus.EXCLUDE,
                vendor_matched=False,
                product_matched=False,
                reason="Missing technology information in vulnerability or profile",
            )

        any_vendor_match = False
        best_match_tech: Optional[str] = None
        exact_product_match = False

        for v_tech in vuln_techs:
            for p_tech in profile_techs:
                v_matched, p_matched = cls.match_technologies(v_tech, p_tech)

                if v_matched:
                    any_vendor_match = True

                if v_matched and p_matched:
                    exact_product_match = True
                    best_match_tech = p_tech.raw
                    break

            if exact_product_match:
                break

        if not any_vendor_match:
            return MatchResult(
                cve_id=cve_id,
                org_id=org_id,
                status=MatchStatus.EXCLUDE,
                vendor_matched=False,
                product_matched=False,
                reason="Vendor mismatch",
            )

        if any_vendor_match and not exact_product_match:
            return MatchResult(
                cve_id=cve_id,
                org_id=org_id,
                status=MatchStatus.EXCLUDE,
                vendor_matched=True,
                product_matched=False,
                reason="Product mismatch",
            )

        return MatchResult(
            cve_id=cve_id,
            org_id=org_id,
            status=MatchStatus.MATCH,
            vendor_matched=True,
            product_matched=True,
            matched_technology=best_match_tech,
            reason="Matching vendor and product",
        )


class ContextValidator:
    """Phase 3 Honest Evidence Handling and Context Validation Engine."""

    @classmethod
    def validate_evidence(cls, vulnerability: Vulnerability, profile: Profile) -> EvidenceResult:
        """Validate context evidence between a vulnerability and an organization profile.
        
        Honest evidence rule:
        - Product mismatch -> product_match=EXCLUDE, version=EXCLUDE, overall=EXCLUDE
        - Product match -> product_match=MATCH, version=NEEDS_VERIFICATION (dataset has no version fields), overall=NEEDS_VERIFICATION
        - Ambiguous -> product_match=NEEDS_VERIFICATION, version=NEEDS_VERIFICATION, overall=NEEDS_VERIFICATION
        """
        cve_id = vulnerability.cve_id
        org_id = profile.org_id or profile.profile_id or "UNKNOWN"
        vuln_product = vulnerability.product_name

        match_res = TechnologyMatcher.match(vulnerability, profile)

        if match_res.status == MatchStatus.EXCLUDE:
            return EvidenceResult(
                cve_id=cve_id,
                org_id=org_id,
                vulnerability_product=vuln_product,
                matched_profile_product=None,
                product_match_status=EvidenceStatus.EXCLUDE,
                version_evidence_status=EvidenceStatus.EXCLUDE,
                overall_evidence_status=EvidenceStatus.EXCLUDE,
                reason=f"Technology evaluation excluded: {match_res.reason}",
            )

        if match_res.status == MatchStatus.NEEDS_VERIFICATION:
            return EvidenceResult(
                cve_id=cve_id,
                org_id=org_id,
                vulnerability_product=vuln_product,
                matched_profile_product=match_res.matched_technology,
                product_match_status=EvidenceStatus.NEEDS_VERIFICATION,
                version_evidence_status=EvidenceStatus.NEEDS_VERIFICATION,
                overall_evidence_status=EvidenceStatus.NEEDS_VERIFICATION,
                reason="Ambiguous product relationship requires manual verification",
            )

        # Product matches (MATCH)
        # Because the official dataset contains no explicit affected-version fields, version evidence cannot be verified
        return EvidenceResult(
            cve_id=cve_id,
            org_id=org_id,
            vulnerability_product=vuln_product,
            matched_profile_product=match_res.matched_technology,
            product_match_status=EvidenceStatus.MATCH,
            version_evidence_status=EvidenceStatus.NEEDS_VERIFICATION,
            overall_evidence_status=EvidenceStatus.NEEDS_VERIFICATION,
            reason="Product matches the organisation's critical product, but the supplied dataset contains no affected-version information.",
        )

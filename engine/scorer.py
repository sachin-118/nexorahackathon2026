"""Profile-specific vulnerability risk scoring engine for ShieldLens."""

from typing import Dict, List, Optional
from engine.models import Vulnerability, Profile, ScoreBreakdown, RiskScoreResult, EvidenceStatus
from engine.matcher import ContextValidator


class RiskScorer:
    """Deterministic, transparent, profile-specific vulnerability risk scoring engine."""

    DEFAULT_THRESHOLDS: Dict[str, float] = {
        "CRITICAL": 0.70,
        "HIGH": 0.50,
        "MEDIUM": 0.30,
        "LOW": 0.0,
    }

    def __init__(self, priority_thresholds: Optional[Dict[str, float]] = None):
        self.priority_thresholds = priority_thresholds or dict(self.DEFAULT_THRESHOLDS)

    @staticmethod
    def validate_vulnerability_signals(cvss_base_score: float, first_epss: float):
        """Reject out-of-range or invalid signal values safely."""
        if cvss_base_score < 0.0 or cvss_base_score > 10.0:
            raise ValueError(f"cvss_base_score '{cvss_base_score}' is out of range [0.0, 10.0]")
        if first_epss < 0.0 or first_epss > 1.0:
            raise ValueError(f"first_epss '{first_epss}' is out of range [0.0, 1.0]")

    def determine_priority(self, score: float) -> str:
        """Map risk score to priority band based on configured thresholds."""
        if score >= self.priority_thresholds.get("CRITICAL", 0.70):
            return "CRITICAL"
        elif score >= self.priority_thresholds.get("HIGH", 0.50):
            return "HIGH"
        elif score >= self.priority_thresholds.get("MEDIUM", 0.30):
            return "MEDIUM"
        return "LOW"

    def score_vulnerability(
        self,
        vulnerability: Vulnerability,
        profile: Profile,
        evidence_status: str = EvidenceStatus.MATCH.value
    ) -> RiskScoreResult:
        """Calculate profile-specific risk score and score breakdown for a vulnerability."""
        # 1. Signal validation
        self.validate_vulnerability_signals(vulnerability.cvss_base_score, vulnerability.first_epss)

        # 2. Extract profile weight modifiers
        wm = profile.weight_modifiers
        cvss_w = wm.cvss_weight if wm else 0.0
        kev_w = wm.cisa_kev_weight if wm else 0.0
        epss_w = wm.first_epss_weight if wm else 0.0

        # 3. Signal normalisation
        cvss_norm = round(vulnerability.cvss_base_score / 10.0, 4)
        kev_norm = 1.0 if vulnerability.cisa_kev is True else 0.0
        epss_val = round(vulnerability.first_epss, 4)

        # 4. Contribution calculation
        cvss_contrib = round(cvss_norm * cvss_w, 4)
        kev_contrib = round(kev_norm * kev_w, 4)
        epss_contrib = round(epss_val * epss_w, 4)

        raw_score = cvss_contrib + kev_contrib + epss_contrib
        final_score = round(raw_score, 4)

        priority = self.determine_priority(final_score)

        breakdown = ScoreBreakdown(
            cvss_normalized=cvss_norm,
            cvss_weight=round(cvss_w, 4),
            cvss_contribution=cvss_contrib,
            kev_normalized=kev_norm,
            kev_weight=round(kev_w, 4),
            kev_contribution=kev_contrib,
            epss_value=epss_val,
            epss_weight=round(epss_w, 4),
            epss_contribution=epss_contrib,
            final_risk_score=final_score,
        )

        org_id = profile.org_id or profile.profile_id or "UNKNOWN"

        return RiskScoreResult(
            cve_id=vulnerability.cve_id,
            product_name=vulnerability.product_name,
            org_id=org_id,
            risk_score=final_score,
            priority=priority,
            evidence_status=evidence_status,
            score_breakdown=breakdown,
        )

    def score_profile_vulnerabilities(
        self,
        vulnerabilities: List[Vulnerability],
        profile: Profile
    ) -> List[RiskScoreResult]:
        """Score all candidate vulnerabilities for a profile, filtering out EXCLUDE status candidates."""
        results = []
        for vuln in vulnerabilities:
            evidence = ContextValidator.validate_evidence(vuln, profile)

            # Rule: EXCLUDE candidates do not enter ranking candidates
            if evidence.overall_evidence_status == EvidenceStatus.EXCLUDE:
                continue

            # NEEDS_VERIFICATION and MATCH remain available
            score_res = self.score_vulnerability(
                vulnerability=vuln,
                profile=profile,
                evidence_status=evidence.overall_evidence_status.value
            )
            results.append(score_res)

        return results

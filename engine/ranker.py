"""Production ranking engine for ShieldLens."""

from typing import List, Optional
from engine.models import Vulnerability, Profile, RiskScoreResult, RankedVulnerability, EvidenceStatus
from engine.scorer import RiskScorer


class Top5Ranker:
    """Production vulnerability ranking engine with deterministic tie-breaking and transparent explanation generation."""

    def __init__(self, scorer: Optional[RiskScorer] = None):
        self.scorer = scorer or RiskScorer()

    @staticmethod
    def generate_explanation_reason(item: RiskScoreResult, profile_name: str) -> str:
        """Generate deterministic natural language explanation from score breakdown components."""
        bd = item.score_breakdown
        return (
            f"{item.priority} priority (score {item.risk_score:.4f}) under {profile_name} weighting profile: "
            f"CVSS contributed {bd.cvss_contribution:.4f} (weight {bd.cvss_weight}), "
            f"KEV contributed {bd.kev_contribution:.4f} (weight {bd.kev_weight}), and "
            f"EPSS contributed {bd.epss_contribution:.4f} (weight {bd.epss_weight})."
        )

    def rank_vulnerabilities(
        self,
        vulnerabilities: List[Vulnerability],
        profile: Profile,
        top_n: int = 5
    ) -> List[RankedVulnerability]:
        """Rank eligible vulnerabilities for a profile and return Top N results."""
        if not vulnerabilities or not profile:
            return []

        # 1. Score eligible candidate vulnerabilities (EXCLUDE items filtered out by scorer)
        scored_candidates = self.scorer.score_profile_vulnerabilities(vulnerabilities, profile)
        if not scored_candidates:
            return []

        # Map cve_id -> Vulnerability object for tie-breaker attributes
        vuln_map = {v.cve_id: v for v in vulnerabilities}

        # 2. Sort candidates with strict deterministic tie-breaker:
        # 1) risk_score descending
        # 2) cisa_kev = True before False
        # 3) first_epss descending
        # 4) cvss_base_score descending
        # 5) cve_id ascending
        def tie_breaker_key(item: RiskScoreResult):
            v = vuln_map.get(item.cve_id)
            cisa_kev_flag = 0 if (v and v.cisa_kev) else 1
            epss_val = v.first_epss if v else 0.0
            cvss_val = v.cvss_base_score if v else 0.0
            cve_val = v.cve_id if v else item.cve_id
            return (
                -item.risk_score,
                cisa_kev_flag,
                -epss_val,
                -cvss_val,
                cve_val,
            )

        sorted_candidates = sorted(scored_candidates, key=tie_breaker_key)

        # 3. Limit to top_n candidates
        top_candidates = sorted_candidates[:top_n]

        # 4. Construct RankedVulnerability objects
        ranked_results = []
        for rank_idx, item in enumerate(top_candidates, start=1):
            reason_text = self.generate_explanation_reason(item, profile.name)
            ranked_item = RankedVulnerability(
                rank=rank_idx,
                cve_id=item.cve_id,
                product_name=item.product_name,
                risk_score=item.risk_score,
                priority=item.priority,
                evidence_status=item.evidence_status,
                reason=reason_text,
                score_breakdown=item.score_breakdown,
            )
            ranked_results.append(ranked_item)

        return ranked_results

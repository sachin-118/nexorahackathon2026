"""Decision Intelligence Layer module for ShieldLens.

Implements:
1. Risk What-If Simulator
2. Deterministic Decision Stability Analysis
3. Honest Verification Queue

Strict Architectural Principles:
- Reuses existing Top5Ranker / RiskScorer logic.
- Does NOT mutate official datasets, profiles.json, or production rankings.
- Zero random numbers or non-deterministic behavior.
- Practitioner ranks remain isolated.
"""

from typing import List, Dict, Any, Optional
import copy

from engine.models import (
    Vulnerability,
    Profile,
    WeightModifiers,
    SimulatedWeightInput,
    SimulationRankItem,
    SimulationResult,
    DecisionStabilityItem,
    VerificationQueueItem,
    RankedVulnerability,
)
from engine.ranker import Top5Ranker
from engine.scorer import RiskScorer


class DecisionIntelligenceEngine:
    """Decision Intelligence Layer providing scenario simulation, decision stability analysis, and verification queue management."""

    @classmethod
    def simulate_risk_weights(
        cls,
        vulnerabilities: List[Vulnerability],
        profile: Profile,
        simulated_input: SimulatedWeightInput
    ) -> SimulationResult:
        """Simulate vulnerability ranking under alternative risk weight modifiers without modifying production data."""
        # 1. Validate weights
        cvss_w = float(simulated_input.cvss_weight)
        kev_w = float(simulated_input.cisa_kev_weight)
        epss_w = float(simulated_input.first_epss_weight)

        if cvss_w < 0.0 or kev_w < 0.0 or epss_w < 0.0:
            raise ValueError("All weight values must be non-negative (>= 0.0).")

        weight_sum = cvss_w + kev_w + epss_w
        if abs(weight_sum - 1.0) > 0.01:
            raise ValueError(f"Weight values must sum to 1.0 (current sum: {weight_sum:.4f}).")

        # 2. Non-mutation guarantee: Copy profile and set simulated weights
        simulated_weights = WeightModifiers(
            cvss_weight=cvss_w,
            cisa_kev_weight=kev_w,
            first_epss_weight=epss_w
        )

        sim_profile = Profile(
            org_id=profile.org_id,
            name=profile.name,
            sector=profile.sector,
            risk_appetite=profile.risk_appetite,
            weight_modifiers=simulated_weights,
            critical_products=list(profile.critical_products),
        )

        ranker = Top5Ranker()

        # 3. Compute original production ranking vs simulated ranking
        original_ranking = ranker.rank_vulnerabilities(vulnerabilities, profile, top_n=5)
        simulated_ranking = ranker.rank_vulnerabilities(vulnerabilities, sim_profile, top_n=5)

        sim_map = {item.cve_id: item for item in simulated_ranking}

        comparison_items = []
        for orig in original_ranking:
            sim_match = sim_map.get(orig.cve_id)
            if sim_match:
                sim_rank = sim_match.rank
                sim_score = sim_match.risk_score
            else:
                sim_rank = 99
                sim_score = 0.0

            rank_change = sim_rank - orig.rank
            score_change = round(sim_score - orig.risk_score, 4)

            comparison_items.append(
                SimulationRankItem(
                    cve_id=orig.cve_id,
                    product_name=orig.product_name,
                    original_rank=orig.rank,
                    simulated_rank=sim_rank,
                    rank_change=rank_change,
                    original_score=orig.risk_score,
                    simulated_score=sim_score,
                    score_change=score_change,
                    evidence_status=orig.evidence_status,
                    epss_score=orig.score_breakdown.epss_value,
                )
            )

        orig_wm = profile.weight_modifiers or WeightModifiers()

        return SimulationResult(
            org_id=profile.org_id,
            org_name=profile.name,
            original_weights=orig_wm,
            simulated_weights=simulated_weights,
            simulation_status="SIMULATION — does not modify official production results",
            simulated_rankings=comparison_items,
        )

    @classmethod
    def analyze_decision_stability(
        cls,
        vulnerabilities: List[Vulnerability],
        profile: Profile
    ) -> List[DecisionStabilityItem]:
        """Perform deterministic scenario-based decision stability analysis for an organization profile."""
        orig_wm = profile.weight_modifiers or WeightModifiers(cvss_weight=0.34, cisa_kev_weight=0.33, first_epss_weight=0.33)

        # Construct 5 deterministic scenario weight profiles
        scenarios = [
            ("Current", orig_wm),
            ("CVSS-Heavy", WeightModifiers(cvss_weight=0.60, cisa_kev_weight=0.20, first_epss_weight=0.20)),
            ("KEV-Heavy", WeightModifiers(cvss_weight=0.20, cisa_kev_weight=0.60, first_epss_weight=0.20)),
            ("EPSS-Heavy", WeightModifiers(cvss_weight=0.20, cisa_kev_weight=0.20, first_epss_weight=0.60)),
            ("Balanced", WeightModifiers(cvss_weight=0.34, cisa_kev_weight=0.33, first_epss_weight=0.33)),
        ]

        ranker = Top5Ranker()
        prod_ranking = ranker.rank_vulnerabilities(vulnerabilities, profile, top_n=5)

        if not prod_ranking:
            return []

        # Run ranking across all 5 scenarios
        scenario_rankings: List[List[RankedVulnerability]] = []
        for name, wm in scenarios:
            scen_profile = Profile(
                org_id=profile.org_id,
                name=profile.name,
                sector=profile.sector,
                risk_appetite=profile.risk_appetite,
                weight_modifiers=wm,
                critical_products=list(profile.critical_products),
            )
            scen_rank = ranker.rank_vulnerabilities(vulnerabilities, scen_profile, top_n=5)
            scenario_rankings.append(scen_rank)

        stability_items = []
        for item in prod_ranking:
            ranks = []
            for scen_rank in scenario_rankings:
                match = next((r for r in scen_rank if r.cve_id == item.cve_id), None)
                if match:
                    ranks.append(match.rank)
                else:
                    ranks.append(99)

            scenarios_tested = len(scenarios)
            scenarios_eligible = sum(1 for r in ranks if r < 99)
            min_r = min(ranks)
            max_r = max(ranks)
            avg_r = round(sum(ranks) / len(ranks), 2)

            # Count how many scenarios maintain the same rank or Top-1
            same_rank_count = sum(1 for r in ranks if r == item.rank)
            top1_count = sum(1 for r in ranks if r == 1)
            stability_pct = round((same_rank_count / float(scenarios_tested)) * 100.0, 1)

            if stability_pct >= 80.0:
                cat = "HIGH"
            elif stability_pct >= 50.0:
                cat = "MEDIUM"
            else:
                cat = "LOW"

            stability_items.append(
                DecisionStabilityItem(
                    cve_id=item.cve_id,
                    product_name=item.product_name,
                    current_rank=item.rank,
                    scenarios_tested=scenarios_tested,
                    scenarios_eligible=scenarios_eligible,
                    min_rank=min_r,
                    max_rank=max_r,
                    average_rank=avg_r,
                    top1_stable_count=top1_count,
                    stability_percentage=stability_pct,
                    stability_category=cat,
                )
            )

        return stability_items

    @classmethod
    def _generate_org_specific_verification(
        cls,
        r: RankedVulnerability,
        profile: Profile
    ) -> tuple[str, List[str]]:
        """Generate organization-aware and vulnerability-specific verification reason and workflow action steps."""
        org_id = profile.org_id
        org_name = profile.name
        product = r.product_name
        cve = r.cve_id
        sector = profile.sector or "Enterprise"
        risk_app = profile.risk_appetite or "Standard"

        reason = (
            f"Affected-version evidence is not supplied for {product} in {org_name}'s asset inventory. "
            f"Because {cve} is ranked #{r.rank} ({r.priority}) under {org_name}'s {risk_app} risk appetite ({sector} sector), "
            f"exact version compliance must be verified before issuing a patch directive."
        )

        if org_id == "ORG-001":
            actions = [
                f"1. Audit {org_name}'s {sector} asset registry to confirm installed build version of {product}.",
                f"2. Inspect vendor advisories for {cve} to verify if {org_name}'s active deployment falls within the vulnerable version range.",
                f"3. Validate whether {product} handles core banking or payment data traffic subject to financial compliance regulations.",
                f"4. Confirm remediation priority #{r.rank} ({r.priority}) with the banking SEC operations team and execute emergency patch approval if exposed."
            ]
        elif org_id == "ORG-002":
            actions = [
                f"1. Query {org_name}'s CI/CD pipeline and container registry for deployed build versions of {product}.",
                f"2. Cross-reference {cve} patch release notes against {org_name}'s cloud infrastructure environment.",
                f"3. Verify if perimeter firewalls or WAF gateway rules mitigate exploitation attempts targeting {product}.",
                f"4. Schedule automated hotfix deployment for priority #{r.rank} ({r.priority}) and update {org_name}'s risk log upon version verification."
            ]
        elif org_id == "ORG-003":
            actions = [
                f"1. Perform air-gapped asset inspection across {org_name}'s OT/SCADA network for installed version of {product}.",
                f"2. Analyze {cve} vendor security bulletins for firmwares operating in critical infrastructure environments.",
                f"3. Assess physical and network isolation controls defending {product} against remote exploitation.",
                f"4. Enforce Zero-Tolerance safety protocol: verify patch compatibility before deploying updates to priority #{r.rank} ({r.priority}) utility systems."
            ]
        else:
            actions = [
                f"1. Audit {org_name}'s asset inventory for active deployments and exact version of {product}.",
                f"2. Compare installed version against official vendor advisory vulnerability ranges for {cve}.",
                f"3. Confirm whether {product} is exposed to untrusted network traffic within {sector} environment.",
                f"4. Recalculate or confirm remediation priority decision #{r.rank} ({r.priority}) post-verification."
            ]

        return reason, actions

    @classmethod
    def build_verification_queue(
        cls,
        vulnerabilities: List[Vulnerability],
        profile: Profile
    ) -> List[VerificationQueueItem]:
        """Collect vulnerabilities requiring version or evidence verification."""
        ranker = Top5Ranker()
        ranking = ranker.rank_vulnerabilities(vulnerabilities, profile, top_n=5)

        queue = []
        for r in ranking:
            if r.evidence_status == "NEEDS_VERIFICATION":
                reason, actions = cls._generate_org_specific_verification(r, profile)
                queue.append(
                    VerificationQueueItem(
                        cve_id=r.cve_id,
                        product_name=r.product_name,
                        org_id=profile.org_id,
                        org_name=profile.name,
                        risk_score=r.risk_score,
                        priority=r.priority,
                        current_rank=r.rank,
                        evidence_status=r.evidence_status,
                        verification_reason=reason,
                        recommended_actions=actions,
                    )
                )

        return queue

"""Isolated organization-aware benchmark evaluation module for ShieldLens."""

from typing import List, Optional, Tuple
from engine.models import RankedVulnerability, GoldSetEntry, GoldSetEvaluationMetrics


class GoldSetEvaluator:
    """Evaluates production vulnerability rankings against benchmark gold set entries without modifying production ranking logic."""

    @staticmethod
    def _get_practitioner_rank(entry: GoldSetEntry, org_id: str) -> Optional[int]:
        """Get practitioner rank for a specific organization."""
        if org_id == "ORG-001" or "bank" in org_id.lower():
            return entry.practitioner_rank_bank
        elif org_id == "ORG-002" or "startup" in org_id.lower():
            return entry.practitioner_rank_startup
        else:
            return entry.practitioner_rank_bank or entry.practitioner_rank_startup

    @staticmethod
    def _compute_spearman_correlation(rank_pairs: List[Tuple[int, int]]) -> Optional[float]:
        """Compute Spearman's rank correlation coefficient for paired ranks. Return None if N < 2."""
        n = len(rank_pairs)
        if n < 2:
            return None

        prod_ranks = [p[0] for p in rank_pairs]
        gold_ranks = [p[1] for p in rank_pairs]

        # Convert to relative ranks (1..n)
        def to_relative_ranks(vals: List[int]) -> List[int]:
            sorted_unique = sorted(set(vals))
            rank_map = {val: i + 1 for i, val in enumerate(sorted_unique)}
            return [rank_map[val] for val in vals]

        rel_prod = to_relative_ranks(prod_ranks)
        rel_gold = to_relative_ranks(gold_ranks)

        d_sq_sum = sum((r1 - r2) ** 2 for r1, r2 in zip(rel_prod, rel_gold))
        denom = n * (n ** 2 - 1)
        if denom == 0:
            return None
        rho = 1.0 - (6.0 * d_sq_sum / denom)
        return round(rho, 4)

    @classmethod
    def evaluate(
        cls,
        production_ranking: List[RankedVulnerability],
        gold_set_entries: List[GoldSetEntry],
        org_id: str
    ) -> GoldSetEvaluationMetrics:
        """Evaluate a production ranking against gold set benchmark entries for an organization using relative and global benchmarks."""
        eligible_count = len(production_ranking)

        if eligible_count == 0 or not gold_set_entries:
            return GoldSetEvaluationMetrics(
                org_id=org_id,
                eligible_candidate_count=eligible_count,
                relative_top1_agreement=False,
                relative_top3_overlap=0.0,
                relative_top5_overlap=0.0,
                precision_at_5=0.0,
                recall_at_5=0.0,
                spearman_rank_correlation=None,
                global_top1_agreement=False,
                global_top3_overlap=0.0,
                global_top5_overlap=0.0,
                evaluation_notes="Empty production candidate ranking or empty gold set dataset.",
            )

        # 1. Global benchmark items sorted by global practitioner rank
        global_gold_ranked = []
        for entry in gold_set_entries:
            gr = cls._get_practitioner_rank(entry, org_id)
            if gr is not None:
                global_gold_ranked.append((entry.cve_id, gr))
        global_gold_ranked.sort(key=lambda x: x[1])

        global_top1_cve = global_gold_ranked[0][0] if global_gold_ranked else None
        global_top3_cves = set(x[0] for x in global_gold_ranked[:3])
        global_top5_cves = set(x[0] for x in global_gold_ranked[:5])

        # 2. Production eligible candidate set
        prod_top1_cve = production_ranking[0].cve_id if production_ranking else None
        prod_cves = set(x.cve_id for x in production_ranking)

        # 3. Organization-Relative Gold Set (filtered to eligible candidate set)
        relative_gold_ranked = [item for item in global_gold_ranked if item[0] in prod_cves]
        relative_gold_ranked.sort(key=lambda x: x[1])

        relative_top1_cve = relative_gold_ranked[0][0] if relative_gold_ranked else None
        relative_top3_cves = set(x[0] for x in relative_gold_ranked[:3])
        relative_top5_cves = set(x[0] for x in relative_gold_ranked[:5])

        # 4. Organization-Relative Metrics Calculation
        rel_top1_agree = (prod_top1_cve == relative_top1_cve) if (prod_top1_cve and relative_top1_cve) else False

        rel_top3_denom = min(len(relative_top3_cves), 3)
        rel_top3_overlap_val = len(prod_cves.intersection(relative_top3_cves)) / rel_top3_denom if rel_top3_denom > 0 else 0.0

        rel_top5_denom = min(len(relative_top5_cves), 5)
        rel_top5_overlap_val = len(prod_cves.intersection(relative_top5_cves)) / rel_top5_denom if rel_top5_denom > 0 else 0.0

        precision_5 = len(prod_cves.intersection(relative_top5_cves)) / eligible_count if eligible_count > 0 else 0.0
        recall_5 = len(prod_cves.intersection(relative_top5_cves)) / len(relative_top5_cves) if relative_top5_cves else 0.0

        # Spearman correlation (N/A if eligible_count < 2)
        spearman_corr = None
        if eligible_count >= 2 and len(relative_gold_ranked) >= 2:
            gold_rel_map = {cve: rank for cve, rank in relative_gold_ranked}
            paired_ranks = []
            for p_item in production_ranking:
                if p_item.cve_id in gold_rel_map:
                    paired_ranks.append((p_item.rank, gold_rel_map[p_item.cve_id]))
            spearman_corr = cls._compute_spearman_correlation(paired_ranks)

        # 5. Global Secondary Diagnostic Metrics
        glob_top1_agree = (prod_top1_cve == global_top1_cve) if (prod_top1_cve and global_top1_cve) else False
        glob_top3_denom = min(len(global_top3_cves), 3)
        glob_top3_overlap_val = len(prod_cves.intersection(global_top3_cves)) / glob_top3_denom if glob_top3_denom > 0 else 0.0
        glob_top5_denom = min(len(global_top5_cves), 5)
        glob_top5_overlap_val = len(prod_cves.intersection(global_top5_cves)) / glob_top5_denom if glob_top5_denom > 0 else 0.0

        notes = (
            f"Evaluated {eligible_count} eligible production candidate items for org '{org_id}' "
            f"against {len(relative_gold_ranked)} relative gold set benchmark entries (out of {len(global_gold_ranked)} global benchmark entries)."
        )

        return GoldSetEvaluationMetrics(
            org_id=org_id,
            eligible_candidate_count=eligible_count,
            relative_top1_agreement=rel_top1_agree,
            relative_top3_overlap=round(rel_top3_overlap_val, 4),
            relative_top5_overlap=round(rel_top5_overlap_val, 4),
            precision_at_5=round(precision_5, 4),
            recall_at_5=round(recall_5, 4),
            spearman_rank_correlation=spearman_corr,
            global_top1_agreement=glob_top1_agree,
            global_top3_overlap=round(glob_top3_overlap_val, 4),
            global_top5_overlap=round(glob_top5_overlap_val, 4),
            evaluation_notes=notes,
        )

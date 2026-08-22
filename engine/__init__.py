"""ShieldLens Core Engine Package."""

from engine.models import (
    Vulnerability,
    Profile,
    GoldSetEntry,
    WeightModifiers,
    EvidenceStatus,
    EvidenceResult,
    ScoreBreakdown,
    RiskScoreResult,
    RankedVulnerability,
    GoldSetEvaluationMetrics,
)
from engine.loader import (
    DataLoader,
    ShieldLensDataError,
    FileNotFoundDataError,
    MissingColumnError,
    MalformedDataError,
)
from engine.normalizer import Normalizer, ParsedTechnology
from engine.matcher import TechnologyMatcher, ContextValidator, MatchStatus
from engine.scorer import RiskScorer
from engine.ranker import Top5Ranker
from engine.evaluator import GoldSetEvaluator

__all__ = [
    "Vulnerability",
    "Profile",
    "GoldSetEntry",
    "WeightModifiers",
    "EvidenceStatus",
    "EvidenceResult",
    "ScoreBreakdown",
    "RiskScoreResult",
    "RankedVulnerability",
    "GoldSetEvaluationMetrics",
    "DataLoader",
    "ShieldLensDataError",
    "FileNotFoundDataError",
    "MissingColumnError",
    "MalformedDataError",
    "Normalizer",
    "ParsedTechnology",
    "TechnologyMatcher",
    "ContextValidator",
    "MatchStatus",
    "RiskScorer",
    "Top5Ranker",
    "GoldSetEvaluator",
]

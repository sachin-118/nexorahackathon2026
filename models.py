"""Data models for ShieldLens engine updated with Phase 7 Decision Intelligence Layer schemas."""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, field_validator


class WeightModifiers(BaseModel):
    """Weight modifiers for contextual scoring."""
    cvss_weight: float = 0.0
    cisa_kev_weight: float = 0.0
    first_epss_weight: float = 0.0


class Vulnerability(BaseModel):
    """Data model representing a vulnerability record."""
    cve_id: str
    product_name: str
    cvss_base_score: float = Field(..., ge=0.0, le=10.0)
    cisa_kev: bool = False
    first_epss: float = Field(0.0, ge=0.0, le=1.0)
    
    # Optional / legacy fields for full backwards compatibility
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    affected_components: List[str] = Field(default_factory=list)
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    
    # Ground truth practitioner ranks (used strictly for benchmark evaluation)
    practitioner_rank_bank: Optional[int] = None
    practitioner_rank_startup: Optional[int] = None

    @field_validator("cve_id", "product_name")
    @classmethod
    def must_not_be_empty(cls, v: str, info) -> str:
        if not v or not str(v).strip():
            raise ValueError(f"Field '{info.field_name}' must not be empty or blank.")
        return str(v).strip()


class Profile(BaseModel):
    """Data model representing an organization / target system environment profile."""
    org_id: str
    name: str
    sector: Optional[str] = None
    risk_appetite: Optional[str] = None
    weight_modifiers: Optional[WeightModifiers] = None
    critical_products: List[str] = Field(default_factory=list)
    
    # Optional / legacy compatibility fields
    profile_id: Optional[str] = None
    description: Optional[str] = None
    environment: Optional[str] = None
    asset_criticality: Optional[str] = None
    tech_stack: List[str] = Field(default_factory=list)
    network_exposure: Optional[str] = None
    compliance_requirements: List[str] = Field(default_factory=list)

    @field_validator("org_id", "name")
    @classmethod
    def must_not_be_empty(cls, v: str, info) -> str:
        if not v or not str(v).strip():
            raise ValueError(f"Field '{info.field_name}' must not be empty or blank.")
        return str(v).strip()


class GoldSetEntry(BaseModel):
    """Data model representing official benchmark gold set entries."""
    cve_id: str
    product_name: str
    practitioner_rank_bank: Optional[int] = None
    practitioner_rank_startup: Optional[int] = None
    
    # Legacy fields
    profile_id: Optional[str] = None
    expected_risk_level: Optional[str] = None
    expected_score: Optional[float] = None
    notes: Optional[str] = None

    @field_validator("cve_id", "product_name")
    @classmethod
    def must_not_be_empty(cls, v: str, info) -> str:
        if not v or not str(v).strip():
            raise ValueError(f"Field '{info.field_name}' must not be empty or blank.")
        return str(v).strip()


class EvidenceStatus(str, Enum):
    """Status for evidence validation."""
    MATCH = "MATCH"
    EXCLUDE = "EXCLUDE"
    NEEDS_VERIFICATION = "NEEDS_VERIFICATION"


class EvidenceResult(BaseModel):
    """Structured evidence object representing vulnerability-profile relationship validation."""
    cve_id: str
    org_id: str
    vulnerability_product: str
    matched_profile_product: Optional[str] = None
    product_match_status: EvidenceStatus
    version_evidence_status: EvidenceStatus
    overall_evidence_status: EvidenceStatus
    reason: str


class ScoreBreakdown(BaseModel):
    """Detailed mathematical breakdown of score components for UI transparency and auditability."""
    cvss_normalized: float
    cvss_weight: float
    cvss_contribution: float
    kev_normalized: float
    kev_weight: float
    kev_contribution: float
    epss_value: float
    epss_weight: float
    epss_contribution: float
    final_risk_score: float


class RiskScoreResult(BaseModel):
    """Profile-specific vulnerability risk score evaluation result."""
    cve_id: str
    product_name: str
    org_id: str
    risk_score: float
    priority: str
    evidence_status: str
    score_breakdown: ScoreBreakdown


class RankedVulnerability(BaseModel):
    """Production top-ranked vulnerability item with transparent explanation reason."""
    rank: int
    cve_id: str
    product_name: str
    risk_score: float
    priority: str
    evidence_status: str
    reason: str
    score_breakdown: ScoreBreakdown


class GoldSetEvaluationMetrics(BaseModel):
    """Refined organization-aware benchmark evaluation metrics comparing production rankings against ground truth gold set."""
    org_id: str
    eligible_candidate_count: int
    relative_top1_agreement: bool
    relative_top3_overlap: float
    relative_top5_overlap: float
    precision_at_5: float
    recall_at_5: float
    spearman_rank_correlation: Optional[float] = None
    global_top1_agreement: bool
    global_top3_overlap: float
    global_top5_overlap: float
    evaluation_notes: str


# ==================================================
# PHASE 7 DECISION INTELLIGENCE LAYER MODELS
# ==================================================

class SimulatedWeightInput(BaseModel):
    """Input parameters for Risk What-If Simulator."""
    cvss_weight: float = Field(..., ge=0.0, le=1.0)
    cisa_kev_weight: float = Field(..., ge=0.0, le=1.0)
    first_epss_weight: float = Field(..., ge=0.0, le=1.0)


class SimulationRankItem(BaseModel):
    """Individual item comparison between production and simulated ranking."""
    cve_id: str
    product_name: str
    original_rank: int
    simulated_rank: int
    rank_change: int
    original_score: float
    simulated_score: float
    score_change: float
    evidence_status: str
    epss_score: float = 0.0



class SimulationResult(BaseModel):
    """Complete result object for Risk What-If Simulator."""
    org_id: str
    org_name: str
    original_weights: WeightModifiers
    simulated_weights: WeightModifiers
    simulation_status: str = "SIMULATION — does not modify official production results"
    simulated_rankings: List[SimulationRankItem]


class DecisionStabilityItem(BaseModel):
    """Deterministic scenario-based decision stability metrics for a vulnerability."""
    cve_id: str
    product_name: str
    current_rank: int
    scenarios_tested: int
    scenarios_eligible: int
    min_rank: int
    max_rank: int
    average_rank: float
    top1_stable_count: int
    stability_percentage: float
    stability_category: str  # "HIGH", "MEDIUM", "LOW"


class VerificationQueueItem(BaseModel):
    """Item requiring manual version or context verification."""
    cve_id: str
    product_name: str
    org_id: str
    org_name: str
    risk_score: float
    priority: str
    current_rank: int
    evidence_status: str
    verification_reason: str
    recommended_actions: List[str]

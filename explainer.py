"""Featherless AI explanation and decision audit integration module for ShieldLens."""

import json
import os
import re
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

from engine.models import Vulnerability, Profile, RiskScoreResult, EvidenceResult, DecisionStabilityItem


class FeatherlessExplainer:
    """Provides natural language explanations and security recommendations via Featherless AI.
    
    Strict Safety Rules:
    - AI does NOT calculate risk scores.
    - AI does NOT perform technology matching.
    - AI does NOT override evidence statuses.
    - AI does NOT access practitioner ranks.
    - Deterministic engine remains 100% authoritative.
    """

    API_URL = "https://api.featherless.ai/v1/chat/completions"
    DEFAULT_MODEL = "Qwen/Qwen2.5-7B-Instruct"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key if api_key is not None else os.getenv("FEATHERLESS_API_KEY", "")

    def get_fallback_explanation(
        self,
        cve_id: str,
        org_name: str,
        priority: str,
        risk_score: float,
        reason_msg: str = "Featherless AI key is not configured or service is unconfigured."
    ) -> Dict[str, Any]:
        """Return safe, structured fallback explanation if AI service is unavailable."""
        return {
            "cve_id": cve_id,
            "org_name": org_name,
            "ai_available": False,
            "executive_summary": f"{reason_msg} {cve_id} is evaluated as {priority} priority (score {risk_score:.4f}).",
            "why_prioritized": f"Vulnerability {cve_id} was prioritized deterministically based on organizational risk appetite and signal weights.",
            "evidence_interpretation": "Product match evaluated against organizational critical product inventory.",
            "verification_needed": "Manual confirmation of exact installed version required due to missing version fields in dataset.",
            "recommended_action": "Audit asset inventory and verify component patch level against vendor advisories.",
        }

    def get_fallback_audit(
        self,
        cve_id: str,
        org_name: str,
        priority: str,
        risk_score: float,
        reason_msg: str = "Featherless AI key is not configured or service is unconfigured."
    ) -> Dict[str, Any]:
        """Return safe, structured fallback decision audit if AI service is unavailable."""
        return {
            "cve_id": cve_id,
            "org_name": org_name,
            "ai_available": False,
            "audit_label": "AI AUDIT — EXPLANATORY ONLY",
            "decision_summary": f"Deterministic Engine assigned {priority} priority (score {risk_score:.4f}). {reason_msg}",
            "why_prioritized": f"Prioritized deterministically using organizational signal weighting.",
            "evidence_supporting_decision": "Matched mission-critical software product in organizational profile.",
            "missing_evidence": "Exact installed version and version range constraints absent in dataset.",
            "assumptions": "Assumed component is actively deployed in organizational environment.",
            "verification_required": "Confirm component build version against vendor security advisories.",
            "recommended_analyst_action": "Verify asset exposure and schedule patch deployment.",
            "audit_confidence": "HIGH",
        }

    def explain_vulnerability(
        self,
        vulnerability: Vulnerability,
        profile: Profile,
        risk_result: RiskScoreResult,
        evidence_result: EvidenceResult
    ) -> Dict[str, Any]:
        """Generate structured AI explanation for a deterministic vulnerability risk assessment."""
        org_name = profile.name
        cve_id = vulnerability.cve_id

        if not self.api_key or not self.api_key.strip():
            return self.get_fallback_explanation(
                cve_id=cve_id,
                org_name=org_name,
                priority=risk_result.priority,
                risk_score=risk_result.risk_score,
                reason_msg="Featherless AI key is not configured."
            )

        bd = risk_result.score_breakdown
        wm = profile.weight_modifiers

        system_prompt = (
            "You are an expert application-security analyst explaining an already-calculated deterministic vulnerability prioritization. "
            "You must NOT recalculate scores, change evidence statuses, or invent unsupplied data. "
            "Return ONLY a raw valid JSON object matching this schema without markdown code blocks:\n"
            "{\n"
            '  "executive_summary": "...",\n'
            '  "why_prioritized": "...",\n'
            '  "evidence_interpretation": "...",\n'
            '  "verification_needed": "...",\n'
            '  "recommended_action": "..."\n'
            "}"
        )

        user_prompt = (
            f"Organization: {profile.name} (Sector: {profile.sector or 'N/A'}, Risk Appetite: {profile.risk_appetite or 'N/A'})\n"
            f"Vulnerability: {vulnerability.cve_id} (Product: {vulnerability.product_name})\n"
            f"Deterministic Risk Score: {risk_result.risk_score:.4f} (Priority: {risk_result.priority})\n"
            f"Score Breakdown: CVSS contrib {bd.cvss_contribution:.4f} (weight {wm.cvss_weight if wm else 0}), "
            f"KEV contrib {bd.kev_contribution:.4f} (weight {wm.cisa_kev_weight if wm else 0}), "
            f"EPSS contrib {bd.epss_contribution:.4f} (weight {wm.first_epss_weight if wm else 0}).\n"
            f"Evidence Status: {evidence_result.overall_evidence_status.value} ({evidence_result.reason}).\n\n"
            "Provide an executive summary, why it is prioritized, evidence interpretation, what needs verification, and recommended action."
        )

        payload = {
            "model": self.DEFAULT_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 500,
        }

        try:
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.API_URL,
                data=req_data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key.strip()}",
                    "User-Agent": "Mozilla/5.0"
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=6) as resp:
                if resp.status == 200:
                    resp_body = resp.read().decode("utf-8")
                    data = json.loads(resp_body)
                    content_str = data["choices"][0]["message"]["content"].strip()

                    content_str = re.sub(r"^```(json)?", "", content_str, flags=re.IGNORECASE).strip()
                    content_str = re.sub(r"```$", "", content_str).strip()

                    parsed = json.loads(content_str)

                    return {
                        "cve_id": cve_id,
                        "org_name": org_name,
                        "ai_available": True,
                        "executive_summary": parsed.get("executive_summary", "Explanation generated by Featherless AI."),
                        "why_prioritized": parsed.get("why_prioritized", f"Prioritized at {risk_result.priority} priority."),
                        "evidence_interpretation": parsed.get("evidence_interpretation", evidence_result.reason),
                        "verification_needed": parsed.get("verification_needed", "Verify component installed version."),
                        "recommended_action": parsed.get("recommended_action", "Audit systems and apply vendor patches."),
                    }
        except Exception as e:
            return self.get_fallback_explanation(
                cve_id=cve_id,
                org_name=org_name,
                priority=risk_result.priority,
                risk_score=risk_result.risk_score,
                reason_msg=f"Featherless AI request failed: {str(e)}."
            )

        return self.get_fallback_explanation(
            cve_id=cve_id,
            org_name=org_name,
            priority=risk_result.priority,
            risk_score=risk_result.risk_score,
        )

    def audit_decision(
        self,
        vulnerability: Vulnerability,
        profile: Profile,
        risk_result: RiskScoreResult,
        evidence_result: EvidenceResult,
        stability_item: Optional[DecisionStabilityItem] = None
    ) -> Dict[str, Any]:
        """Perform an independent AI Decision Audit of an authoritative deterministic decision package."""
        org_name = profile.name
        cve_id = vulnerability.cve_id

        if not self.api_key or not self.api_key.strip():
            return self.get_fallback_audit(
                cve_id=cve_id,
                org_name=org_name,
                priority=risk_result.priority,
                risk_score=risk_result.risk_score,
                reason_msg="Featherless AI key is not configured."
            )

        bd = risk_result.score_breakdown
        wm = profile.weight_modifiers

        system_prompt = (
            "You are an independent cybersecurity decision auditor. "
            "The supplied risk score, ranking, product matching, and evidence status are authoritative. "
            "Do not recalculate, alter, or override them. "
            "Your role is only to: 1. explain why the deterministic system prioritized this CVE, "
            "2. identify missing evidence, 3. identify assumptions, 4. identify potential verification requirements, "
            "5. provide concise analyst recommendations. Never invent vulnerability facts that are not present in the supplied input. "
            "Return ONLY a raw valid JSON object matching this schema without markdown code blocks:\n"
            "{\n"
            '  "decision_summary": "...",\n'
            '  "why_prioritized": "...",\n'
            '  "evidence_supporting_decision": "...",\n'
            '  "missing_evidence": "...",\n'
            '  "assumptions": "...",\n'
            '  "verification_required": "...",\n'
            '  "recommended_analyst_action": "...",\n'
            '  "audit_confidence": "HIGH"\n'
            "}"
        )

        stability_info = ""
        if stability_item:
            stability_info = f"Decision Stability: {stability_item.stability_category} ({stability_item.stability_percentage}% stable, range #{stability_item.min_rank}-#{stability_item.max_rank} across {stability_item.scenarios_tested} scenarios)."

        user_prompt = (
            f"Authoritative Decision Package:\n"
            f"Organization: {profile.name} (Sector: {profile.sector or 'N/A'})\n"
            f"Vulnerability: {vulnerability.cve_id} (Product: {vulnerability.product_name})\n"
            f"Risk Score: {risk_result.risk_score:.4f} (Priority: {risk_result.priority})\n"
            f"Score Breakdown: CVSS {bd.cvss_contribution:.4f}, KEV {bd.kev_contribution:.4f}, EPSS {bd.epss_contribution:.4f}\n"
            f"Evidence Status: {evidence_result.overall_evidence_status.value} ({evidence_result.reason})\n"
            f"{stability_info}\n\n"
            "Audit this decision package and return structured audit JSON."
        )

        payload = {
            "model": self.DEFAULT_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 600,
        }

        try:
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.API_URL,
                data=req_data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key.strip()}",
                    "User-Agent": "Mozilla/5.0"
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=6) as resp:
                if resp.status == 200:
                    resp_body = resp.read().decode("utf-8")
                    data = json.loads(resp_body)
                    content_str = data["choices"][0]["message"]["content"].strip()

                    content_str = re.sub(r"^```(json)?", "", content_str, flags=re.IGNORECASE).strip()
                    content_str = re.sub(r"```$", "", content_str).strip()

                    parsed = json.loads(content_str)

                    return {
                        "cve_id": cve_id,
                        "org_name": org_name,
                        "ai_available": True,
                        "audit_label": "AI AUDIT — EXPLANATORY ONLY",
                        "decision_summary": parsed.get("decision_summary", f"Audited deterministic risk score {risk_result.risk_score:.4f}."),
                        "why_prioritized": parsed.get("why_prioritized", f"Prioritized at {risk_result.priority} priority."),
                        "evidence_supporting_decision": parsed.get("evidence_supporting_decision", "Matched critical product inventory."),
                        "missing_evidence": parsed.get("missing_evidence", "Missing explicit affected version range."),
                        "assumptions": parsed.get("assumptions", "Assumed component is active in environment."),
                        "verification_required": parsed.get("verification_required", "Verify build version."),
                        "recommended_analyst_action": parsed.get("recommended_analyst_action", "Audit assets and apply patches."),
                        "audit_confidence": parsed.get("audit_confidence", "HIGH"),
                    }
        except Exception as e:
            return self.get_fallback_audit(
                cve_id=cve_id,
                org_name=org_name,
                priority=risk_result.priority,
                risk_score=risk_result.risk_score,
                reason_msg=f"Featherless AI audit failed: {str(e)}."
            )

        return self.get_fallback_audit(
            cve_id=cve_id,
            org_name=org_name,
            priority=risk_result.priority,
            risk_score=risk_result.risk_score,
        )

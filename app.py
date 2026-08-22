"""ShieldLens Flask Web Application & REST API with Phase 7 Decision Intelligence Endpoints."""

import os
from flask import Flask, render_template, jsonify, request
from dotenv import load_dotenv

from engine.loader import DataLoader, ShieldLensDataError
from engine.ranker import Top5Ranker
from engine.evaluator import GoldSetEvaluator
from engine.matcher import ContextValidator
from engine.scorer import RiskScorer
from engine.explainer import FeatherlessExplainer
from engine.intelligence import DecisionIntelligenceEngine
from engine.models import SimulatedWeightInput, WeightModifiers

# Load environment variables
load_dotenv()

# Paths to authoritative datasets
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROFILES_PATH = os.path.join(BASE_DIR, "data", "profiles.json")
VULNS_PATH = os.path.join(BASE_DIR, "data", "vulnerabilities.csv")
GOLD_PATH = os.path.join(BASE_DIR, "data", "gold_set.csv")

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)
handler = app



@app.route("/")
def index():
    """Index page route rendering SOC Dashboard."""
    return render_template("index.html")


@app.route("/health", methods=["GET"])
def health_check():
    """Simple health-check endpoint."""
    return jsonify({
        "status": "ok",
        "app": "ShieldLens",
        "phase": 10,
        "featherless_configured": bool(os.getenv("FEATHERLESS_API_KEY", "").strip())
    }), 200


@app.route("/api/organizations", methods=["GET"])
def get_organizations():
    """API endpoint returning official organization profiles."""
    try:
        profiles = DataLoader.load_profiles(PROFILES_PATH)
        return jsonify([p.model_dump() for p in profiles]), 200
    except Exception as e:
        return jsonify({"error": f"Failed to load profiles: {str(e)}"}), 500


@app.route("/api/ranking/<org_id>", methods=["GET"])
def get_ranking(org_id):
    """API endpoint returning production Top-5 ranking candidates for an organization."""
    try:
        profiles = DataLoader.load_profiles(PROFILES_PATH)
        profile = next((p for p in profiles if p.org_id == org_id or p.profile_id == org_id), None)
        if not profile:
            return jsonify({"error": f"Organization '{org_id}' not found."}), 404

        vulns = DataLoader.load_vulnerabilities(VULNS_PATH)
        ranker = Top5Ranker()

        ranking = ranker.rank_vulnerabilities(vulns, profile, top_n=5)
        scorer = RiskScorer()
        all_eligible = scorer.score_profile_vulnerabilities(vulns, profile)

        return jsonify({
            "org_id": profile.org_id,
            "org_name": profile.name,
            "eligible_candidate_count": len(all_eligible),
            "top5_ranking": [r.model_dump() for r in ranking]
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to compute ranking: {str(e)}"}), 500


@app.route("/api/evaluation/<org_id>", methods=["GET"])
def get_evaluation(org_id):
    """API endpoint returning Gold-Set benchmark evaluation metrics for an organization."""
    try:
        profiles = DataLoader.load_profiles(PROFILES_PATH)
        profile = next((p for p in profiles if p.org_id == org_id or p.profile_id == org_id), None)
        if not profile:
            return jsonify({"error": f"Organization '{org_id}' not found."}), 404

        vulns = DataLoader.load_vulnerabilities(VULNS_PATH)
        gold_entries = DataLoader.load_gold_set(GOLD_PATH)

        ranker = Top5Ranker()
        ranking = ranker.rank_vulnerabilities(vulns, profile, top_n=5)

        metrics = GoldSetEvaluator.evaluate(ranking, gold_entries, profile.org_id)
        return jsonify(metrics.model_dump()), 200
    except Exception as e:
        return jsonify({"error": f"Failed to compute evaluation: {str(e)}"}), 500


@app.route("/api/explain", methods=["POST"])
def explain_vulnerability():
    """API endpoint invoking Featherless AI explanation for a vulnerability."""
    try:
        data = request.get_json() or {}
        cve_id = data.get("cve_id")
        org_id = data.get("org_id")

        if not cve_id or not org_id:
            return jsonify({"error": "Both 'cve_id' and 'org_id' are required."}), 400

        profiles = DataLoader.load_profiles(PROFILES_PATH)
        profile = next((p for p in profiles if p.org_id == org_id or p.profile_id == org_id), None)
        if not profile:
            return jsonify({"error": f"Organization '{org_id}' not found."}), 404

        vulns = DataLoader.load_vulnerabilities(VULNS_PATH)
        vuln = next((v for v in vulns if v.cve_id == cve_id), None)
        if not vuln:
            return jsonify({"error": f"Vulnerability '{cve_id}' not found."}), 404

        evidence_res = ContextValidator.validate_evidence(vuln, profile)
        scorer = RiskScorer()
        risk_res = scorer.score_vulnerability(vuln, profile, evidence_status=evidence_res.overall_evidence_status.value)

        explainer = FeatherlessExplainer()
        explanation = explainer.explain_vulnerability(vuln, profile, risk_res, evidence_res)

        return jsonify(explanation), 200
    except Exception as e:
        return jsonify({"error": f"Explanation endpoint failure: {str(e)}"}), 500


# ==================================================
# PHASE 7 DECISION INTELLIGENCE ENDPOINTS
# ==================================================

@app.route("/api/simulate/<org_id>", methods=["POST"])
def simulate_weights(org_id):
    """API endpoint executing Risk What-If Simulation with alternative weight modifiers."""
    try:
        profiles = DataLoader.load_profiles(PROFILES_PATH)
        profile = next((p for p in profiles if p.org_id == org_id or p.profile_id == org_id), None)
        if not profile:
            return jsonify({"error": f"Organization '{org_id}' not found."}), 404

        data = request.get_json() or {}
        try:
            sim_input = SimulatedWeightInput(
                cvss_weight=float(data.get("cvss_weight", 0.0)),
                cisa_kev_weight=float(data.get("cisa_kev_weight", 0.0)),
                first_epss_weight=float(data.get("first_epss_weight", 0.0)),
            )
        except (ValueError, TypeError) as val_err:
            return jsonify({"error": f"Invalid weight input: {str(val_err)}"}), 400

        vulns = DataLoader.load_vulnerabilities(VULNS_PATH)
        res = DecisionIntelligenceEngine.simulate_risk_weights(vulns, profile, sim_input)

        return jsonify(res.model_dump()), 200
    except ValueError as val_err:
        return jsonify({"error": str(val_err)}), 400
    except Exception as e:
        return jsonify({"error": f"Simulation endpoint failure: {str(e)}"}), 500


@app.route("/api/stability/<org_id>", methods=["GET"])
def get_stability(org_id):
    """API endpoint returning scenario-based decision stability analysis."""
    try:
        profiles = DataLoader.load_profiles(PROFILES_PATH)
        profile = next((p for p in profiles if p.org_id == org_id or p.profile_id == org_id), None)
        if not profile:
            return jsonify({"error": f"Organization '{org_id}' not found."}), 404

        vulns = DataLoader.load_vulnerabilities(VULNS_PATH)
        items = DecisionIntelligenceEngine.analyze_decision_stability(vulns, profile)

        return jsonify([it.model_dump() for it in items]), 200
    except Exception as e:
        return jsonify({"error": f"Stability analysis failure: {str(e)}"}), 500


@app.route("/api/verification/<org_id>", methods=["GET"])
def get_verification_queue(org_id):
    """API endpoint returning verification queue items requiring version/context verification."""
    try:
        profiles = DataLoader.load_profiles(PROFILES_PATH)
        profile = next((p for p in profiles if p.org_id == org_id or p.profile_id == org_id), None)
        if not profile:
            return jsonify({"error": f"Organization '{org_id}' not found."}), 404

        vulns = DataLoader.load_vulnerabilities(VULNS_PATH)
        queue = DecisionIntelligenceEngine.build_verification_queue(vulns, profile)

        return jsonify([item.model_dump() for item in queue]), 200
    except Exception as e:
        return jsonify({"error": f"Verification queue failure: {str(e)}"}), 500


@app.route("/api/audit", methods=["POST"])
def audit_decision_endpoint():
    """API endpoint invoking Featherless AI Decision Audit for an authoritative decision package."""
    try:
        data = request.get_json() or {}
        cve_id = data.get("cve_id")
        org_id = data.get("org_id")

        if not cve_id or not org_id:
            return jsonify({"error": "Both 'cve_id' and 'org_id' are required."}), 400

        profiles = DataLoader.load_profiles(PROFILES_PATH)
        profile = next((p for p in profiles if p.org_id == org_id or p.profile_id == org_id), None)
        if not profile:
            return jsonify({"error": f"Organization '{org_id}' not found."}), 404

        vulns = DataLoader.load_vulnerabilities(VULNS_PATH)
        vuln = next((v for v in vulns if v.cve_id == cve_id), None)
        if not vuln:
            return jsonify({"error": f"Vulnerability '{cve_id}' not found."}), 404

        evidence_res = ContextValidator.validate_evidence(vuln, profile)
        scorer = RiskScorer()
        risk_res = scorer.score_vulnerability(vuln, profile, evidence_status=evidence_res.overall_evidence_status.value)

        stability_items = DecisionIntelligenceEngine.analyze_decision_stability(vulns, profile)
        st_item = next((s for s in stability_items if s.cve_id == cve_id), None)

        explainer = FeatherlessExplainer()
        audit_res = explainer.audit_decision(vuln, profile, risk_res, evidence_res, st_item)

        return jsonify(audit_res), 200
    except Exception as e:
        return jsonify({"error": f"AI Audit endpoint failure: {str(e)}"}), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=True)

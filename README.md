# ShieldLens — Contextual Vulnerability Prioritization Engine

> **ShieldLens is an organization-aware deterministic vulnerability prioritization engine with AI-assisted explanation and decision auditing.**

---

## Problem Statement

Traditional vulnerability management relies on raw CVSS base scores, creating a "one-size-fits-all" model. A CVSS 9.8 vulnerability in an unexposed legacy system often displaces a CVSS 7.5 vulnerability in a mission-critical banking framework with active exploitation (CISA KEV) and high probability of breach (FIRST EPSS).

ShieldLens resolves this by contextualizing vulnerability signals against an organization's specific sector, risk appetite, mission-critical product inventory, and weight modifiers.

---

## System Architecture

```text
Official Hackathon Datasets (data/profiles.json, data/vulnerabilities.csv, data/gold_set.csv)
                                         │
                                         ▼
                     DataLoader & Normalizer (engine/loader.py, normalizer.py)
                                         │
                                         ▼
                     Context Matching Engine (engine/matcher.py)
                                         │
                                         ▼
                     Deterministic Risk Scorer (engine/scorer.py)
                                         │
                                         ▼
                     Top-5 Prioritization Ranker (engine/ranker.py)
                                         │
                 ┌───────────────────────┼───────────────────────┐
                 ▼                       ▼                       ▼
      Decision Intelligence    Gold-Set Evaluator      Featherless AI Explainer
     (engine/intelligence.py)  (engine/evaluator.py)    (engine/explainer.py)
      - Risk Simulator          - Relative Top-1/3/5    - Natural Language Rationale
      - Decision Stability      - Precision & Recall    - AI Decision Audit
      - Verification Queue      - Spearman Correlation  - Safe Fallback Mode
                 │                       │                       │
                 └───────────────────────┼───────────────────────┘
                                         ▼
                           Flask REST API (app.py)
                                         │
                                         ▼
                  Cybersecurity SOC Dashboard (templates/index.html)
```

---

## Core Engine & Scoring Methodology

### 1. Context Matching & Evidence Engine
- **Vendor & Product Normalization**: Handles case insensitivity, whitespace collapsing, and transparent alias resolutions (`postgres` $\rightarrow$ `postgresql`, `k8s` $\rightarrow$ `kubernetes`, `py` $\rightarrow$ `python`, etc.).
- **Product Evidence Validation**: Vulnerabilities affecting non-critical products are assigned status `EXCLUDE`.
- **Honest Version Evidence**: Official dataset does not contain explicit affected-version fields. Technology-matched items are assigned status `NEEDS_VERIFICATION` without inventing version ranges.

### 2. Profile-Specific Deterministic Scoring Formula
$$\text{risk\_score} = (\text{cvss\_norm} \times \text{cvss\_w}) + (\text{kev\_norm} \times \text{kev\_w}) + (\text{epss} \times \text{epss\_w})$$

- **CVSS Normalization**: `cvss_base_score / 10.0`
- **CISA KEV Normalization**: `1.0` if `cisa_kev == True` else `0.0`
- **EPSS**: `first_epss` probability ($0.0 \dots 1.0$)
- **Determinism**: 100% deterministic, zero random numbers.

### 3. Strict 5-Tier Tie-Breaking
1. `risk_score` descending
2. `cisa_kev` `True` before `False`
3. `first_epss` descending
4. `cvss_base_score` descending
5. `cve_id` ascending (lexicographical string sort)

---

## Decision Intelligence Layer

Sitting directly on top of the authoritative deterministic engine:

1. **Risk What-If Simulator**: Allows security teams to experiment with custom CVSS, KEV, and EPSS weight modifiers in memory. Does **not** modify `profiles.json` or official production results.
2. **Scenario Decision Stability**: Evaluates rank invariance across 5 deterministic scenario weight profiles (*Current*, *CVSS-Heavy*, *KEV-Heavy*, *EPSS-Heavy*, *Balanced*) and computes stability percentages (`HIGH`, `MEDIUM`, `LOW`).
3. **Verification Queue**: Collects `NEEDS_VERIFICATION` candidates and outlines 4-step manual asset registry verification procedures.

---

## Featherless AI Role & Boundaries

Featherless AI (`Qwen/Qwen2.5-7B-Instruct`) is used **strictly** as an explanation and auditing layer.

### Strict Safety Boundaries
- AI does **NOT** calculate risk scores.
- AI does **NOT** determine technology matching or candidate eligibility.
- AI does **NOT** override evidence statuses.
- AI does **NOT** access practitioner ranks.
- AI does **NOT** expose API keys to client code.
- If AI key is missing, times out, or fails, a safe deterministic fallback explanation is returned.

---

## Benchmark & Gold-Set Evaluation

Evaluates production rankings against practitioner ground-truth entries in `gold_set.csv`:
- **Practitioner Rank Isolation**: Practitioner ranks (`practitioner_rank_bank`, `practitioner_rank_startup`) are used **strictly** for offline evaluation in `GoldSetEvaluator` and **never** influence production risk scoring.
- **Organization-Relative Metrics**: Computes relative Top-1 Agreement, Top-3 Overlap, Top-5 Overlap, Precision@5, Recall@5, and Spearman Correlation ($\rho$) bounded by eligible candidate count ($N$).

---

## REST API Reference

| Endpoint | Method | Description |
| :--- | :---: | :--- |
| `/health` | `GET` | Application health check and Featherless API status. |
| `/api/organizations` | `GET` | Returns list of official organization profiles from `data/profiles.json`. |
| `/api/ranking/<org_id>` | `GET` | Returns production Top-5 ranking candidates for `org_id`. |
| `/api/evaluation/<org_id>` | `GET` | Returns Gold-Set benchmark evaluation metrics for `org_id`. |
| `/api/explain` | `POST` | Generates structured Featherless AI explanation for a vulnerability. |
| `/api/simulate/<org_id>` | `POST` | Executes What-If simulation with custom weight modifiers. |
| `/api/stability/<org_id>` | `GET` | Returns scenario-based decision stability metrics. |
| `/api/verification/<org_id>` | `GET` | Returns pending verification queue items. |
| `/api/audit` | `POST` | Generates an independent Featherless AI Decision Audit. |

---

## Quick Start & Installation

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Environment Configuration
Create a `.env` file in the project root:
```env
FEATHERLESS_API_KEY=your_featherless_api_key_here
PORT=5000
```
*(A placeholder `.env.example` is provided; `.env` is ignored by git).*

### 3. Run Automated Unit Test Suite
```bash
python -m pytest -v
```
*(All 101 unit tests should pass).*

### 4. Start the Application
```bash
python app.py
```
Open your browser at **`http://127.0.0.1:5000`**.

---

## 60–90 Second Hackathon Judge Demo Procedure

1. **Launch Dashboard**: Open `http://127.0.0.1:5000` in browser.
2. **Select Organization**: Select **Global Retail Bank (`ORG-001`)**. Observe Top-5 ranking: `#1 CVE-2025-1111` (Core Banking Framework, Score: `0.9815`, `CRITICAL`).
3. **Run What-If Simulation**: Navigate to **Simulator & Stability** tab. Adjust sliders to `CVSS=0.20, KEV=0.30, EPSS=0.50` and click **Run What-If Simulation**. View comparison table labeled `"SIMULATION — DOES NOT MODIFY PRODUCTION RESULTS"`.
4. **Check Decision Stability**: View Decision Stability panel showing `CVE-2025-1111` stability evaluated as `HIGH (80.0%)` across 5 scenario profiles.
5. **Inspect Verification Queue**: Switch to **Verification Queue** tab to view pending verification items and action steps.
6. **Trigger AI Decision Audit**: Select `CVE-2025-1111` and click **AI Decision Audit**. Review Featherless AI audit results clearly labeled `AI AUDIT — EXPLANATORY ONLY`.
7. **View Benchmark Metrics**: Switch to **Benchmark Evaluation** tab to demonstrate relative metrics (`Top-1 Agreement: True`, `Precision@5: 1.0`, `Recall@5: 1.0`, `Spearman: 1.0`).

---

## Known Limitations

- **Affected-Version Verification**: The official hackathon dataset does not provide explicit version ranges for vulnerabilities. Technology-matched items are assigned status `NEEDS_VERIFICATION`, requiring manual confirmation against organizational asset registries before patch deployment.

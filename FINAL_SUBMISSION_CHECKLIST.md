# ShieldLens — Final Hackathon Submission Checklist

> **"AI explains. Deterministic security logic decides."**

---

## Final Submission Verification Matrix

- [x] **Official Datasets Untouched**: `data/profiles.json`, `data/vulnerabilities.csv`, and `data/gold_set.csv` remain 100% intact with zero schema alterations or fake entries.
- [x] **Automated Unit Tests**: 101 / 101 unit tests passing cleanly (`python -m pytest -v`).
- [x] **Browser Console Status**: 0 errors, 0 warnings.
- [x] **API Key Security**: `FEATHERLESS_API_KEY` loaded strictly from environment (`os.getenv`). Zero hardcoded secrets in source files or API responses.
- [x] **Git Configuration**: `.env` is listed in `.gitignore`. `.env.example` contains only `FEATHERLESS_API_KEY=`.
- [x] **REST API Endpoints**: All 9 endpoints (`/health`, `/api/organizations`, `/api/ranking/<org_id>`, `/api/evaluation/<org_id>`, `/api/explain`, `/api/simulate/<org_id>`, `/api/stability/<org_id>`, `/api/verification/<org_id>`, `/api/audit`) return valid `200 OK` JSON responses.
- [x] **Organization Switching**: Tested and verified across `ORG-001` (Global Retail Bank), `ORG-002` (Agile Cloud Tech Startup), and `ORG-003` (Municipal Utility Provider).
- [x] **Production Risk Scoring**: 100% deterministic CVSS, CISA KEV, and FIRST EPSS weighted scoring with 5-tier tie-breaking.
- [x] **Context & Evidence Validation**: Product matching engine correctly filters `EXCLUDE` candidates and assigns `NEEDS_VERIFICATION` status without inventing version data.
- [x] **Organization-Aware Benchmark Evaluation**: Evaluates production rankings against ground truth gold set metrics (Top-1, Top-3, Top-5, Precision@5, Recall@5, Spearman correlation $\rho$). Spearman correlation displays `N/A — insufficient candidates` cleanly for $N=1$.
- [x] **Verification Queue**: Displays pending candidates with explicit missing dataset evidence reasons and analyst verification action steps.
- [x] **Risk What-If Simulator**: Allows in-memory weight scenario testing with prominent disclaimer: `"SIMULATION — DOES NOT MODIFY PRODUCTION RESULTS"`.
- [x] **Decision Stability Analysis**: Tests rank invariance across 5 deterministic scenario weight profiles (*Current*, *CVSS-Heavy*, *KEV-Heavy*, *EPSS-Heavy*, *Balanced*).
- [x] **Featherless AI Integration & Fallback**: AI layer provides natural-language reasoning and independent decision audits without altering authoritative risk scores. Safe fallback operates if API key is missing or service times out.
- [x] **Hackathon Demo Script**: `DEMO_SCRIPT.md` created with 60–90 second speaking script.
- [x] **Documentation**: `README.md` updated with full architecture, API documentation, installation instructions, and known limitations.

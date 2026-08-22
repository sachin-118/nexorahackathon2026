# ShieldLens — 60–90 Second Hackathon Presentation Script

> **Motto / Differentiator**: *"AI explains. Deterministic security logic decides."*

---

## Pitch & Speaking Flow

### 1. Problem Statement (0:00 – 0:15)
> "Good morning, judges. Security operations teams are drowning in thousands of vulnerabilities. Raw CVSS scores treat a legacy isolated server the same as a core banking framework. CVSS alone fails to prioritize what actually threatens an organization."

### 2. Solution & Core Architecture (0:15 – 0:30)
> "Meet **ShieldLens** — an organization-aware vulnerability prioritization engine. ShieldLens combines an organization's mission-critical product inventory with CISA KEV active exploitation data, FIRST EPSS breach probabilities, and custom risk appetite weights to compute profile-specific priority scores."

### 3. Live Dashboard Walkthrough — Production Prioritization (0:30 – 0:45)
> "Here on the SOC Dashboard, we select **Global Retail Bank (`ORG-001`)**. ShieldLens immediately ranks **`CVE-2025-1111`** as #1 Critical Priority (Score: `0.9815`). Expanding the deterministic score breakdown shows exact mathematical contributions: CVSS (`0.2940`), CISA KEV (`0.4500`), and FIRST EPSS (`0.2375`)."

### 4. Honest Evidence Validation & Verification Queue (0:45 – 1:00)
> "Because the official dataset does not supply explicit version range fields, ShieldLens honestly flags the candidate as **`NEEDS_VERIFICATION`**. Switching to the **Verification Queue** tab shows the 4-step analyst workflow guide required to verify build versions before patch deployment."

### 5. Risk What-If Simulator & Decision Stability (1:00 – 1:15)
> "Under **Simulator & Stability**, security leads can test alternative CVSS, KEV, or EPSS weight scenarios in memory. The UI explicitly confirms: *'SIMULATION — DOES NOT MODIFY PRODUCTION RESULTS'*. The Decision Stability panel proves `CVE-2025-1111` maintains `HIGH (80.0%)` stability across 5 deterministic scenario profiles."

### 6. Benchmark Evaluation & Featherless AI Audit (1:15 – 1:30)
> "Under **Benchmark Evaluation**, ShieldLens measures ranking agreement against practitioner ground truth (`Top-1 Agreement: True`, `Precision@5: 1.0`, `Recall@5: 1.0`, `Spearman: 1.0000`). Finally, clicking **AI Decision Audit** triggers Featherless AI (`Qwen/Qwen2.5-7B-Instruct`) to provide natural-language executive reasoning — without altering the authoritative score."

### 7. Closing Statement
> "**ShieldLens decides deterministically and explains intelligently.** Thank you!"

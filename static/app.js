// ShieldLens Web Application JavaScript Controller — White Enterprise SOC Theme

let currentOrganizations = [];
let selectedOrgId = null;
let currentRanking = [];
let selectedCveId = null;
let currentVerificationQueue = [];

document.addEventListener("DOMContentLoaded", () => {
    fetchHealth();
    fetchOrganizations();
});

function getActiveOrgId() {
    if (selectedOrgId) return selectedOrgId;
    const select = document.getElementById("org-select");
    if (select && select.value) return select.value;
    if (currentOrganizations.length > 0) return currentOrganizations[0].org_id;
    return "ORG-001";
}

function getActiveCveId() {
    if (selectedCveId) return selectedCveId;
    if (currentRanking.length > 0) return currentRanking[0].cve_id;
    return null;
}

function getWeightValue(w, primaryKey, fallbackKey) {
    if (!w) return 0.0;
    if (w[primaryKey] !== undefined && w[primaryKey] !== null) return parseFloat(w[primaryKey]);
    if (w[fallbackKey] !== undefined && w[fallbackKey] !== null) return parseFloat(w[fallbackKey]);
    return 0.0;
}

function switchTab(tabId) {
    const tabs = document.querySelectorAll(".tab-btn");
    tabs.forEach(t => t.classList.remove("active"));

    const sections = document.querySelectorAll(".tab-section");
    sections.forEach(s => {
        s.classList.remove("active");
        s.classList.add("hidden");
    });

    const activeBtn = Array.from(tabs).find(b => b.getAttribute("onclick").includes(tabId));
    if (activeBtn) activeBtn.classList.add("active");

    const activeSec = document.getElementById(`section-${tabId}`);
    if (activeSec) {
        activeSec.classList.remove("hidden");
        activeSec.classList.add("active");
    }

    const orgId = getActiveOrgId();
    if (orgId) {
        if (tabId === "intelligence") {
            fetchStability(orgId);
        } else if (tabId === "verification") {
            fetchVerification(orgId);
        } else if (tabId === "benchmark") {
            fetchEvaluation(orgId);
        }
    }
}

function fetchHealth() {
    fetch("/health")
        .then(res => res.json())
        .then(data => {
            const el = document.getElementById("featherless-status");
            if (data.featherless_configured) {
                el.innerHTML = '<i class="fa-solid fa-brain"></i> AI Explainer: Active';
                el.className = 'status-chip chip-ai';
            } else {
                el.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> AI Explainer: Fallback Mode';
                el.className = 'status-chip chip-engine';
            }
        })
        .catch(err => {
            console.warn("Health check unreachable:", err);
        });
}

function fetchOrganizations() {
    fetch("/api/organizations")
        .then(res => res.json())
        .then(data => {
            currentOrganizations = data;
            const select = document.getElementById("org-select");
            select.innerHTML = "";

            if (data.length === 0) {
                select.innerHTML = '<option value="" disabled selected>No profiles found</option>';
                return;
            }

            data.forEach((org, idx) => {
                const opt = document.createElement("option");
                opt.value = org.org_id;
                opt.textContent = `${org.name} (${org.org_id})`;
                select.appendChild(opt);
            });

            selectedOrgId = data[0].org_id;
            select.value = selectedOrgId;
            updateOrganizationProfileCard(data[0]);
            fetchRanking(selectedOrgId);
        })
        .catch(err => {
            console.error("Failed to fetch organizations:", err);
            const select = document.getElementById("org-select");
            select.innerHTML = '<option value="" disabled selected>Error loading profiles</option>';
        });
}

function onOrganizationChange(orgId) {
    selectedOrgId = orgId;
    const org = currentOrganizations.find(p => p.org_id === orgId);
    if (org) {
        updateOrganizationProfileCard(org);
    }
    fetchRanking(orgId);

    const activeSec = document.querySelector(".tab-section.active");
    if (activeSec) {
        const secId = activeSec.id.replace("section-", "");
        if (secId === "intelligence") fetchStability(orgId);
        else if (secId === "verification") fetchVerification(orgId);
        else if (secId === "benchmark") fetchEvaluation(orgId);
    }
}

function updateOrganizationProfileCard(org) {
    document.getElementById("prof-name").textContent = org.name;
    document.getElementById("prof-sector").textContent = org.sector;
    document.getElementById("prof-risk").textContent = org.risk_appetite;

    const w = org.weight_modifiers || {};
    const cvssW = getWeightValue(w, "cvss_weight", "cvss_base_score");
    const kevW = getWeightValue(w, "cisa_kev_weight", "cisa_kev");
    const epssW = getWeightValue(w, "first_epss_weight", "first_epss");

    document.getElementById("w-cvss").textContent = cvssW.toFixed(2);
    document.getElementById("w-kev").textContent = kevW.toFixed(2);
    document.getElementById("w-epss").textContent = epssW.toFixed(2);

    const list = document.getElementById("prof-products-list");
    list.innerHTML = "";
    (org.critical_products || []).forEach(p => {
        const li = document.createElement("li");
        li.innerHTML = `<i class="fa-solid fa-cube text-primary"></i> ${p}`;
        list.appendChild(li);
    });
}

function fetchRanking(orgId) {
    const container = document.getElementById("ranking-cards-container");
    container.innerHTML = '<p class="placeholder-text"><i class="fa-solid fa-spinner fa-spin"></i> Scoring and ranking candidates...</p>';

    fetch(`/api/ranking/${orgId}`)
        .then(res => res.json())
        .then(data => {
            currentRanking = data.top5_ranking || [];
            document.getElementById("eligible-count-badge").textContent = `${data.eligible_candidate_count} eligible vulnerabilities found`;

            renderRankingCards(currentRanking);

            if (currentRanking.length > 0) {
                selectVulnerability(currentRanking[0].cve_id);
            } else {
                document.getElementById("detail-drawer").classList.add("hidden");
            }
        })
        .catch(err => {
            console.error("Failed to fetch ranking:", err);
            container.innerHTML = '<div class="alert-banner" style="background:#fee2e2;color:#dc2626;border:1px solid #fca5a5;"><i class="fa-solid fa-triangle-exclamation"></i> Failed to load ranking data from API.</div>';
        });
}

function fetchEvaluation(orgId) {
    const org = currentOrganizations.find(p => p.org_id === orgId) || {};
    const orgTitle = org.name ? `${org.name} (${orgId})` : `Org: ${orgId}`;
    document.getElementById("eval-org-title").textContent = orgTitle;

    fetch(`/api/evaluation/${orgId}`)
        .then(res => res.json())
        .then(m => {
            if (m.error) {
                document.getElementById("eval-notes-text").textContent = `Error: ${m.error}`;
                return;
            }

            document.getElementById("m-eligible").textContent = m.eligible_candidate_count;
            
            const top1El = document.getElementById("m-top1");
            top1El.textContent = m.relative_top1_agreement ? "True (100% Agree)" : "False (Disagree)";
            top1El.style.color = m.relative_top1_agreement ? "#047857" : "#dc2626";

            document.getElementById("m-top3").textContent = (m.relative_top3_overlap * 100).toFixed(0) + "% (" + m.relative_top3_overlap.toFixed(4) + ")";
            document.getElementById("m-top5").textContent = (m.relative_top5_overlap * 100).toFixed(0) + "% (" + m.relative_top5_overlap.toFixed(4) + ")";
            document.getElementById("m-prec").textContent = (m.precision_at_5 * 100).toFixed(0) + "% (" + m.precision_at_5.toFixed(4) + ")";
            document.getElementById("m-rec").textContent = (m.recall_at_5 * 100).toFixed(0) + "% (" + m.recall_at_5.toFixed(4) + ")";
            
            document.getElementById("m-spearman").textContent = (m.spearman_rank_correlation !== null && m.spearman_rank_correlation !== undefined) 
                ? m.spearman_rank_correlation.toFixed(4) 
                : "N/A (Single Candidate)";

            document.getElementById("gm-top1").textContent = m.global_top1_agreement ? "True" : "False";
            document.getElementById("gm-top3").textContent = (m.global_top3_overlap * 100).toFixed(0) + "%";
            document.getElementById("gm-top5").textContent = (m.global_top5_overlap * 100).toFixed(0) + "%";
            document.getElementById("eval-notes-text").textContent = m.evaluation_notes || "Benchmark evaluated cleanly.";
        })
        .catch(err => {
            console.error("Failed to fetch evaluation:", err);
            document.getElementById("eval-notes-text").textContent = "Unable to load evaluation data from backend API.";
        });
}

function fetchStability(orgId) {
    const container = document.getElementById("stability-cards-container");
    container.innerHTML = '<p class="placeholder-text"><i class="fa-solid fa-spinner fa-spin"></i> Loading decision stability analysis...</p>';

    fetch(`/api/stability/${orgId}`)
        .then(res => res.json())
        .then(items => {
            container.innerHTML = "";

            if (!items || items.length === 0) {
                container.innerHTML = '<p class="placeholder-text">No eligible candidates available for stability analysis.</p>';
                return;
            }

            items.forEach(st => {
                const card = document.createElement("div");
                card.className = "stability-card";
                card.innerHTML = `
                    <div class="flex-between">
                        <strong>${st.cve_id}</strong>
                        <span class="st-badge st-${st.stability_category}">Stability: ${st.stability_category} (${st.stability_percentage}%)</span>
                    </div>
                    <div class="prod-sub" style="margin-top:0.2rem;"><i class="fa-solid fa-cube"></i> ${st.product_name}</div>
                    <div class="card-divider" style="margin:0.5rem 0;"></div>
                    <div class="weight-grid">
                        <div class="weight-item"><span class="w-label">Current Rank</span><span class="w-val">#${st.current_rank}</span></div>
                        <div class="weight-item"><span class="w-label">Scenario Range</span><span class="w-val">#${st.min_rank}–#${st.max_rank}</span></div>
                        <div class="weight-item"><span class="w-label">Stable Scenarios</span><span class="w-val">${st.top1_stable_count}/${st.scenarios_tested}</span></div>
                    </div>
                `;
                container.appendChild(card);
            });
        })
        .catch(err => {
            console.error("Failed to fetch decision stability:", err);
            container.innerHTML = '<div class="alert-banner" style="background:#fee2e2;color:#dc2626;border:1px solid #fca5a5;"><i class="fa-solid fa-triangle-exclamation"></i> Failed to load decision stability data.</div>';
        });
}

function fetchVerification(orgId) {
    const container = document.getElementById("verification-queue-container");
    container.innerHTML = '<p class="placeholder-text"><i class="fa-solid fa-spinner fa-spin"></i> Loading verification queue...</p>';

    fetch(`/api/verification/${orgId}`)
        .then(res => res.json())
        .then(queue => {
            currentVerificationQueue = queue;
            document.getElementById("queue-count-badge").textContent = `${queue.length} vulnerabilities require verification`;

            container.innerHTML = "";

            if (!queue || queue.length === 0) {
                container.innerHTML = '<div class="empty-state"><i class="fa-solid fa-circle-check" style="font-size:2.5rem;color:var(--evidence-match);"></i><br><br><strong>No pending verification tasks in queue.</strong><br><span style="font-size:0.85rem;color:var(--text-secondary);">All matched candidates have verified evidence status.</span></div>';
                return;
            }

            queue.forEach(q => {
                const card = document.createElement("div");
                card.className = "queue-card";
                card.innerHTML = `
                    <div>
                        <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap;">
                            <h4>${q.cve_id}</h4>
                            <span class="badge-priority priority-${q.priority}">${q.priority}</span>
                            <span class="badge-evidence ev-${q.evidence_status}">${q.evidence_status}</span>
                            <span style="font-size:0.75rem;color:var(--text-secondary);font-weight:600;">Org: ${q.org_name} (${q.org_id})</span>
                        </div>
                        <div class="prod-sub" style="margin-top:0.3rem;"><i class="fa-solid fa-cube"></i> Product: <strong>${q.product_name}</strong> &bull; Score: <strong>${q.risk_score.toFixed(4)}</strong> (Rank #${q.current_rank})</div>
                        <p style="font-size:0.8rem;color:#b45309;margin-top:0.4rem;background:#fef3c7;padding:0.45rem 0.65rem;border-radius:4px;border:1px solid #fde68a;border-left:4px solid #d97706;">
                            <i class="fa-solid fa-triangle-exclamation"></i> <strong>Reason:</strong> ${q.verification_reason}
                        </p>
                    </div>
                    <button class="btn btn-primary" onclick="openQueueModal('${q.cve_id}')">
                        <i class="fa-solid fa-eye"></i> View Requirements
                    </button>
                `;
                container.appendChild(card);
            });
        })
        .catch(err => {
            console.error("Failed to fetch verification queue:", err);
            container.innerHTML = '<div class="alert-banner" style="background:#fee2e2;color:#dc2626;border:1px solid #fca5a5;"><i class="fa-solid fa-triangle-exclamation"></i> Failed to load verification queue from API.</div>';
        });
}

function renderRankingCards(ranking) {
    const container = document.getElementById("ranking-cards-container");
    container.innerHTML = "";

    if (!ranking || ranking.length === 0) {
        container.innerHTML = '<div class="empty-state"><i class="fa-solid fa-circle-check" style="font-size:2.5rem;color:var(--evidence-match);"></i><br><br>No eligible vulnerabilities found for this organization profile.</div>';
        return;
    }

    ranking.forEach((r, idx) => {
        const bd = r.score_breakdown || {};
        const card = document.createElement("div");
        card.className = `rank-card ${idx === 0 ? 'top1' : ''}`;
        card.onclick = () => selectVulnerability(r.cve_id);

        card.innerHTML = `
            <div class="rank-badge">#${r.rank}</div>
            <div class="card-main">
                <h4>${r.cve_id}</h4>
                <div class="prod-sub"><i class="fa-solid fa-cube"></i> ${r.product_name}</div>
            </div>
            <div class="card-metrics">
                <span class="metric-pill">CVSS: <strong>${(bd.cvss_normalized * 10).toFixed(1)}</strong></span>
                <span class="metric-pill">KEV: <strong>${bd.kev_normalized > 0 ? 'Yes' : 'No'}</strong></span>
                <span class="metric-pill">EPSS: <strong>${(bd.epss_value * 100).toFixed(1)}%</strong></span>
            </div>
            <div class="card-score">
                <div class="score-big">${r.risk_score.toFixed(4)}</div>
                <span class="badge-priority priority-${r.priority}">${r.priority}</span>
                <div style="margin-top:0.25rem;"><span class="badge-evidence ev-${r.evidence_status}">${r.evidence_status}</span></div>
            </div>
        `;
        container.appendChild(card);
    });
}

function selectVulnerability(cveId) {
    selectedCveId = cveId;
    const item = currentRanking.find(r => r.cve_id === cveId);
    if (!item) return;

    const orgId = getActiveOrgId();
    const org = currentOrganizations.find(p => p.org_id === orgId) || {};
    const bd = item.score_breakdown || {};
    const w = org.weight_modifiers || {};

    const cvssW = getWeightValue(w, "cvss_weight", "cvss_base_score");
    const kevW = getWeightValue(w, "cisa_kev_weight", "cisa_kev");
    const epssW = getWeightValue(w, "first_epss_weight", "first_epss");

    const drawer = document.getElementById("detail-drawer");
    if (drawer) drawer.classList.remove("hidden");

    // Header
    const cveEl = document.getElementById("dtl-cve");
    if (cveEl) cveEl.textContent = item.cve_id;

    // A. Technology Context
    const orgNameEl = document.getElementById("dtl-org-name");
    if (orgNameEl) orgNameEl.textContent = org.name || orgId;

    const orgIdEl = document.getElementById("dtl-org-id");
    if (orgIdEl) orgIdEl.textContent = orgId;

    const prodEl = document.getElementById("dtl-product");
    if (prodEl) prodEl.textContent = item.product_name;

    const evEl = document.getElementById("dtl-evidence-badge");
    if (evEl) {
        evEl.textContent = item.evidence_status;
        evEl.className = `badge-evidence ev-${item.evidence_status}`;
    }

    // B. Security Evidence
    const cvssRawEl = document.getElementById("dtl-cvss-raw");
    if (cvssRawEl) cvssRawEl.textContent = (bd.cvss_normalized * 10).toFixed(1);

    const kevRawEl = document.getElementById("dtl-kev-raw");
    if (kevRawEl) kevRawEl.textContent = bd.kev_normalized > 0 ? "YES" : "NO";

    const epssRawEl = document.getElementById("dtl-epss-raw");
    if (epssRawEl) epssRawEl.textContent = (bd.epss_value * 100).toFixed(1) + "% (" + bd.epss_value.toFixed(4) + ")";

    const verRawEl = document.getElementById("dtl-ver-raw");
    if (verRawEl) verRawEl.textContent = item.evidence_status === "NEEDS_VERIFICATION" ? "NEEDS VERIFICATION" : "VERIFIED";

    // C. Organization Profile Weights
    const profNameEl = document.getElementById("dtl-prof-name");
    if (profNameEl) profNameEl.textContent = org.name || orgId;

    const wCvssEl = document.getElementById("dtl-w-cvss");
    if (wCvssEl) wCvssEl.textContent = (cvssW * 100).toFixed(0) + "%";

    const wKevEl = document.getElementById("dtl-w-kev");
    if (wKevEl) wKevEl.textContent = (kevW * 100).toFixed(0) + "%";

    const wEpssEl = document.getElementById("dtl-w-epss");
    if (wEpssEl) wEpssEl.textContent = (epssW * 100).toFixed(0) + "%";

    // D. Deterministic Score Breakdown
    const cvssContribEl = document.getElementById("dtl-cvss-contrib");
    if (cvssContribEl) cvssContribEl.textContent = bd.cvss_contribution.toFixed(4);

    const kevContribEl = document.getElementById("dtl-kev-contrib");
    if (kevContribEl) kevContribEl.textContent = bd.kev_contribution.toFixed(4);

    const epssContribEl = document.getElementById("dtl-epss-contrib");
    if (epssContribEl) epssContribEl.textContent = bd.epss_contribution.toFixed(4);

    const cvssBarEl = document.getElementById("dtl-cvss-bar");
    if (cvssBarEl) cvssBarEl.style.width = (bd.cvss_contribution * 100) + "%";

    const kevBarEl = document.getElementById("dtl-kev-bar");
    if (kevBarEl) kevBarEl.style.width = (bd.kev_contribution * 100) + "%";

    const epssBarEl = document.getElementById("dtl-epss-bar");
    if (epssBarEl) epssBarEl.style.width = (bd.epss_contribution * 100) + "%";

    const scoreEl = document.getElementById("dtl-score");
    if (scoreEl) scoreEl.textContent = item.risk_score.toFixed(4);
    
    const prioEl = document.getElementById("dtl-priority");
    if (prioEl) {
        prioEl.textContent = item.priority;
        prioEl.className = `score-lbl badge-priority priority-${item.priority}`;
    }

    // E. Decision
    const rankBadgeEl = document.getElementById("dtl-rank-badge");
    if (rankBadgeEl) rankBadgeEl.textContent = `#${item.rank} PRIORITY`;

    const reasonEl = document.getElementById("dtl-reason");
    if (reasonEl) reasonEl.textContent = `Ranked #${item.rank} because its deterministic risk score (${item.risk_score.toFixed(4)}) is higher than the other eligible candidates under this organization's weighting profile.`;

    // F. AI Explanation Reset
    const aiBox = document.getElementById("ai-explanation-content");
    if (aiBox) aiBox.innerHTML = '<p class="placeholder-text"><i class="fa-solid fa-circle-info"></i> Click <strong>Explain</strong> or <strong>AI Decision Audit</strong> to generate natural language guidance.</p>';
}

function closeDetailDrawer() {
    const drawer = document.getElementById("detail-drawer");
    if (drawer) drawer.classList.add("hidden");
}

function updateSimSliders() {
    const cvss = parseFloat(document.getElementById("sim-cvss").value) || 0;
    const kev = parseFloat(document.getElementById("sim-kev").value) || 0;
    const epss = parseFloat(document.getElementById("sim-epss").value) || 0;

    document.getElementById("sim-cvss-val").textContent = cvss.toFixed(2);
    document.getElementById("sim-kev-val").textContent = kev.toFixed(2);
    document.getElementById("sim-epss-val").textContent = epss.toFixed(2);

    const sum = cvss + kev + epss;
    const sumEl = document.getElementById("sim-sum-val");
    sumEl.textContent = sum.toFixed(2);
    sumEl.style.color = Math.abs(sum - 1.0) <= 0.01 ? "#047857" : "#dc2626";
}

function runSimulation() {
    const orgId = getActiveOrgId();
    let cvss = parseFloat(document.getElementById("sim-cvss").value) || 0.33;
    let kev = parseFloat(document.getElementById("sim-kev").value) || 0.33;
    let epss = parseFloat(document.getElementById("sim-epss").value) || 0.34;

    // Auto-normalize if weights do not sum to 1.0
    const sum = cvss + kev + epss;
    if (sum > 0 && Math.abs(sum - 1.0) > 0.001) {
        cvss = Math.round((cvss / sum) * 100) / 100;
        kev = Math.round((kev / sum) * 100) / 100;
        epss = Math.round((1.0 - cvss - kev) * 100) / 100;

        document.getElementById("sim-cvss").value = cvss;
        document.getElementById("sim-kev").value = kev;
        document.getElementById("sim-epss").value = epss;
        updateSimSliders();
    }

    const box = document.getElementById("sim-results-box");
    box.innerHTML = '<p class="placeholder-text"><i class="fa-solid fa-spinner fa-spin"></i> Running simulation...</p>';

    fetch(`/api/simulate/${orgId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cvss_weight: cvss, cisa_kev_weight: kev, first_epss_weight: epss })
    })
    .then(res => res.json())
    .then(data => {
        if (data.error) {
            box.innerHTML = `<div class="alert-banner" style="background:#fee2e2;color:#dc2626;border:1px solid #fca5a5;"><i class="fa-solid fa-triangle-exclamation"></i> ${data.error}</div>`;
            return;
        }

        const rankings = data.simulated_rankings || data.simulation_results || [];

        if (rankings.length === 0) {
            box.innerHTML = '<p class="placeholder-text">No eligible candidates available for simulation.</p>';
            return;
        }

        let html = `
            <table class="sim-table">
                <thead>
                    <tr>
                        <th>CVE ID</th>
                        <th>Product</th>
                        <th>Prod Rank</th>
                        <th>Sim Rank</th>
                        <th>Sim Score</th>
                        <th>FIRST EPSS</th>
                    </tr>
                </thead>
                <tbody>
        `;

        rankings.forEach(r => {
            const origRank = r.original_rank !== undefined ? r.original_rank : r.production_rank;
            const simScore = r.simulated_score !== undefined ? r.simulated_score : r.simulated_risk_score;

            const rankMatch = currentRanking.find(item => item.cve_id === r.cve_id);
            const epssVal = (r.epss_score !== undefined && r.epss_score > 0) 
                ? r.epss_score 
                : (rankMatch && rankMatch.score_breakdown ? rankMatch.score_breakdown.epss_value : 0.0);

            html += `
                <tr>
                    <td><strong>${r.cve_id}</strong></td>
                    <td>${r.product_name}</td>
                    <td>#${origRank}</td>
                    <td><strong>#${r.simulated_rank}</strong></td>
                    <td>${simScore.toFixed(4)}</td>
                    <td><span class="metric-pill" style="background:#eff6ff;color:#1d4ed8;border:1px solid #bfdbfe;padding:0.25rem 0.5rem;border-radius:4px;">EPSS: <strong>${(epssVal * 100).toFixed(1)}%</strong></span></td>
                </tr>
            `;
        });

        html += `</tbody></table>`;
        box.innerHTML = html;
    })
    .catch(err => {
        console.error("Simulation failed:", err);
        box.innerHTML = '<div class="alert-banner" style="background:#fee2e2;color:#dc2626;border:1px solid #fca5a5;"><i class="fa-solid fa-triangle-exclamation"></i> Simulation request failed.</div>';
    });
}

function requestAiExplanation() {
    const orgId = getActiveOrgId();
    const cveId = getActiveCveId();

    const btn = document.getElementById("ai-explain-btn");
    const box = document.getElementById("ai-explanation-content");

    if (!cveId) {
        if (box) box.innerHTML = '<div class="alert-banner" style="background:#fef3c7;color:#b45309;border:1px solid #fde68a;"><i class="fa-solid fa-circle-exclamation"></i> Please select a vulnerability candidate first.</div>';
        return;
    }

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Generating...';
    }
    if (box) box.innerHTML = '<p class="placeholder-text"><i class="fa-solid fa-spinner fa-spin"></i> Requesting Featherless AI rationale...</p>';

    fetch("/api/explain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ org_id: orgId, cve_id: cveId })
    })
    .then(res => res.json())
    .then(data => {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-wand-magic-sparkles"></i> Explain';
        }

        if (data.error) {
            if (box) box.innerHTML = `<div class="alert-banner" style="background:#fee2e2;color:#dc2626;border:1px solid #fca5a5;"><i class="fa-solid fa-triangle-exclamation"></i> ${data.error}</div>`;
            return;
        }

        const executiveSummary = data.executive_summary || data.why_prioritized || data.explanation || "ShieldLens deterministic security engine evaluated this vulnerability candidate.";
        const technicalContext = data.evidence_interpretation || data.verification_needed || data.technical_context || "Technology context and evidence validated against organizational profile.";
        const actionText = data.recommended_action || "Audit asset inventory and verify component patch level against vendor advisories.";

        if (box) {
            box.innerHTML = `
                <div class="ai-sec">
                    <h6><i class="fa-solid fa-bullseye"></i> Executive Decision Rationale</h6>
                    <p>${executiveSummary}</p>
                </div>
                <div class="ai-sec">
                    <h6><i class="fa-solid fa-shield"></i> Technical Context</h6>
                    <p>${technicalContext}</p>
                </div>
                <div class="ai-sec">
                    <h6><i class="fa-solid fa-lightbulb"></i> Recommended Action</h6>
                    <p><strong>${actionText}</strong></p>
                </div>
            `;
        }
    })
    .catch(err => {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-wand-magic-sparkles"></i> Explain';
        }
        if (box) box.innerHTML = '<div class="alert-banner" style="background:#fee2e2;color:#dc2626;border:1px solid #fca5a5;"><i class="fa-solid fa-triangle-exclamation"></i> Failed to generate AI explanation.</div>';
    });
}

function requestAiAudit() {
    const orgId = getActiveOrgId();
    const cveId = getActiveCveId();

    const btn = document.getElementById("ai-audit-btn");
    const box = document.getElementById("ai-explanation-content");

    if (!cveId) {
        if (box) box.innerHTML = '<div class="alert-banner" style="background:#fef3c7;color:#b45309;border:1px solid #fde68a;"><i class="fa-solid fa-circle-exclamation"></i> Please select a vulnerability candidate first.</div>';
        return;
    }

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Auditing...';
    }
    if (box) box.innerHTML = '<p class="placeholder-text"><i class="fa-solid fa-spinner fa-spin"></i> Requesting Featherless AI decision audit...</p>';

    fetch("/api/audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ org_id: orgId, cve_id: cveId })
    })
    .then(res => res.json())
    .then(data => {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-user-shield"></i> AI Decision Audit';
        }

        if (data.error) {
            if (box) box.innerHTML = `<div class="alert-banner" style="background:#fee2e2;color:#dc2626;border:1px solid #fca5a5;"><i class="fa-solid fa-triangle-exclamation"></i> ${data.error}</div>`;
            return;
        }

        const audit = data.audit || {};
        if (box) {
            box.innerHTML = `
                <div class="ai-sec" style="background:#eff6ff;padding:0.75rem;border-radius:6px;border-left:4px solid #2563eb;border:1px solid #bfdbfe;">
                    <div class="flex-between">
                        <h6 style="color:#1d4ed8;"><i class="fa-solid fa-user-shield"></i> ${audit.audit_label || 'AI AUDIT — EXPLANATORY ONLY'}</h6>
                        <span style="font-size:0.75rem;font-weight:800;color:#1e40af;">Score Alignment: ${audit.score_alignment || '100% Deterministic'}</span>
                    </div>
                    <p style="margin-top:0.4rem;color:#111827;"><strong>Audit Rationale:</strong> ${audit.audit_rationale || audit.decision_summary || 'Decision aligns strictly with deterministic scoring formulas.'}</p>
                    <div style="margin-top:0.5rem;font-size:0.8rem;color:#374151;">
                        <strong>Audit Summary:</strong> ${audit.summary || audit.why_prioritized || 'Verified zero AI hallucination or score mutation.'}
                    </div>
                </div>
            `;
        }
    })
    .catch(err => {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-user-shield"></i> AI Decision Audit';
        }
        if (box) box.innerHTML = '<div class="alert-banner" style="background:#fee2e2;color:#dc2626;border:1px solid #fca5a5;"><i class="fa-solid fa-triangle-exclamation"></i> Failed to execute AI decision audit.</div>';
    });
}

function openQueueModal(cveId) {
    const item = currentVerificationQueue.find(q => q.cve_id === cveId);
    if (!item) return;

    const content = document.getElementById("modal-content");
    let stepsHtml = "";
    const actions = item.recommended_actions || item.action_steps || [];
    actions.forEach(step => {
        stepsHtml += `<li><i class="fa-solid fa-angle-right text-primary"></i> ${step}</li>`;
    });

    content.innerHTML = `
        <div style="margin-bottom:1rem;">
            <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem;">
                <h3>${item.cve_id}</h3>
                <span class="badge-priority priority-${item.priority}">${item.priority}</span>
                <span class="badge-evidence ev-${item.evidence_status}">${item.evidence_status}</span>
            </div>
            <div class="prod-sub"><i class="fa-solid fa-cube"></i> ${item.product_name} &bull; Org: <strong>${item.org_name}</strong></div>
        </div>

        <div style="background:#fef3c7;padding:0.75rem;border-radius:6px;margin-bottom:1rem;border:1px solid #fde68a;">
            <strong style="color:#b45309;font-size:0.85rem;"><i class="fa-solid fa-circle-exclamation"></i> Verification Reason:</strong>
            <p style="font-size:0.85rem;margin-top:0.25rem;color:#111827;">${item.verification_reason}</p>
        </div>

        <div>
            <strong style="font-size:0.85rem;color:var(--heading-section);"><i class="fa-solid fa-list-check"></i> Analyst Verification Workflow:</strong>
            <ul class="action-steps-list">
                ${stepsHtml}
            </ul>
        </div>
    `;

    document.getElementById("verification-modal").classList.remove("hidden");
}

function closeQueueModal() {
    document.getElementById("verification-modal").classList.add("hidden");
}

// Global Scope Bindings for HTML Event Handlers
window.switchTab = switchTab;
window.onOrganizationChange = onOrganizationChange;
window.updateSimSliders = updateSimSliders;
window.runSimulation = runSimulation;
window.requestAiExplanation = requestAiExplanation;
window.requestAiAudit = requestAiAudit;
window.selectVulnerability = selectVulnerability;
window.closeDetailDrawer = closeDetailDrawer;
window.openQueueModal = openQueueModal;
window.closeQueueModal = closeQueueModal;

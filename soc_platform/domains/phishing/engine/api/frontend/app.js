/* ═══════════════════════════════════════════════════════════════
   SOC Analysis Hub — Shared Application Module v2.0
   ═══════════════════════════════════════════════════════════════ */

const AgentUI = (() => {
  const STORAGE_KEY = "soc_hub_auth_key";

  /* ── Auth Key (optional, only when API_AUTH_ENABLED=1) ── */
  function getApiKey() { return localStorage.getItem(STORAGE_KEY) || ""; }

  function setApiKey(value) {
    localStorage.setItem(STORAGE_KEY, value || "");
    _updateSettingsBtn();
  }

  function _buildHeaders(extra = {}) {
    const h = { ...extra };
    const key = getApiKey().trim();
    if (key) h["X-API-Key"] = key;
    return h;
  }

  async function apiFetch(path, options = {}) {
    const opts = { ...options };
    opts.headers = _buildHeaders(opts.headers || {});
    return fetch(path, opts);
  }

  /* ── Formatting ── */
  function jsonPretty(obj) { return JSON.stringify(obj, null, 2); }

  function verdictClass(verdict) {
    const v = String(verdict || "").toLowerCase();
    if (v === "malicious" || v === "high_risk") return "danger";
    if (v === "suspicious") return "suspicious";
    return "safe";
  }

  /* ── Status ── */
  function showStatus(el, msg, level) {
    el.className = `status-msg visible ${level || ""}`;
    el.textContent = msg;
  }
  function hideStatus(el) {
    el.className = "status-msg";
    el.textContent = "";
  }

  /* ── Settings Dropdown ── */
  function initSettingsDropdown() {
    const toggle = document.getElementById("settingsToggle");
    const dropdown = document.getElementById("settingsDropdown");
    const input = document.getElementById("authKeyInput");
    const saveBtn = document.getElementById("authKeySave");
    const clearBtn = document.getElementById("authKeyClear");
    if (!toggle || !dropdown) return;

    input.value = getApiKey();
    _updateSettingsBtn();

    toggle.addEventListener("click", (e) => {
      e.stopPropagation();
      dropdown.classList.toggle("open");
    });
    document.addEventListener("click", (e) => {
      if (!dropdown.contains(e.target) && e.target !== toggle)
        dropdown.classList.remove("open");
    });
    saveBtn.addEventListener("click", () => {
      setApiKey(input.value);
      dropdown.classList.remove("open");
    });
    clearBtn.addEventListener("click", () => {
      input.value = "";
      setApiKey("");
    });
  }

  function _updateSettingsBtn() {
    const toggle = document.getElementById("settingsToggle");
    if (!toggle) return;
    const has = !!getApiKey().trim();
    toggle.classList.toggle("has-key", has);
    toggle.textContent = has ? "🔐 Authenticated" : "⚙ Settings";
  }

  /* ── Agent Descriptions ── */
  const AGENT_DESC = {
    header_agent: "Validates SPF, DKIM, DMARC records and detects sender spoofing, routing anomalies, and header manipulation.",
    content_agent: "Runs NLP/SLM-based phishing intent analysis over the cleaned email body text to detect social engineering patterns.",
    url_agent: "Evaluates URL risk using lexical heuristics, ML model scoring, and optional reputation provider lookups.",
    attachment_agent: "Static metadata and signature inspection of email attachments without executing files.",
    sandbox_agent: "Dynamic behavioral analysis via detonation pipeline with executor-mode support and safe fallback paths.",
    threat_intel_agent: "Correlates IOCs (domains, IPs, hashes) against local store and external feeds (VirusTotal, OTX, etc.).",
    user_behavior_agent: "Assesses recipient susceptibility, applies context-aware risk amplification based on target profile.",
  };

  function getAgentDescription(name) {
    return AGENT_DESC[name] || "No description available.";
  }

  /* ── Topbar HTML ── */
  function topbarHTML(activePage) {
    const pages = [
      { href: "/ui", label: "🏠 Home", id: "overview" },
      { href: "/soc/dashboard", label: "📊 Dashboard", id: "dashboard" },
      { href: "/ui/analyze", label: "📤 Analyze", id: "analyze" },
      { href: "/ui/triage", label: "🔍 Triage", id: "triage" },
      { href: "/ui/campaigns", label: "🕸️ Campaigns", id: "campaigns" },
      { href: "/ui/agents", label: "🧪 Agents", id: "agents" },
    ];
    const links = pages
      .map(p => `<a href="${p.href}" class="${p.id === activePage ? "active" : ""}">${p.label}</a>`)
      .join("");

    return `
      <header class="topbar">
        <div class="brand"><span class="brand-icon">⬡</span> SOC Analysis Hub</div>
        <nav class="nav">
          ${links}
          <a href="/docs" target="_blank" rel="noreferrer">📄 API Docs</a>
          <div class="settings-toggle">
            <button id="settingsToggle" class="settings-btn" type="button">⚙ Settings</button>
            <div id="settingsDropdown" class="settings-dropdown">
              <div class="settings-title">🔑 Authentication Key</div>
              <div class="settings-hint">
                <strong>Only needed</strong> if your backend has <code>API_AUTH_ENABLED=1</code> in <code>.env</code>.<br/>
                For local development, leave this empty.
              </div>
              <input id="authKeyInput" type="password" placeholder="Paste your X-API-Key here…" />
              <div class="settings-actions">
                <button id="authKeySave" class="btn-ghost" type="button">💾 Save</button>
                <button id="authKeyClear" class="btn-ghost" type="button">🗑 Clear</button>
              </div>
            </div>
          </div>
        </nav>
      </header>`;
  }

  /* ── DOMContentLoaded ── */
  function onReady(fn) {
    if (document.readyState !== "loading") fn();
    else document.addEventListener("DOMContentLoaded", fn);
  }

  /* ── Live WebSocket Tracker ── */
  function initLivePipelineTracker(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;

    let wsUrl = (window.location.protocol === "https:" ? "wss://" : "ws://") + window.location.host + "/ws/orchestrator";
    // WebSocket handshakes can't carry custom headers, so pass the auth key
    // (when configured) as a query param to satisfy server-side auth.
    const wsKey = getApiKey().trim();
    if (wsKey) wsUrl += "?api_key=" + encodeURIComponent(wsKey);
    const ws = new WebSocket(wsUrl);

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === "agent_start" || data.type === "agent_complete") {
            let el = document.getElementById(`tracker-${data.agent}`);
            if (!el) {
                el = document.createElement("div");
                el.id = `tracker-${data.agent}`;
                el.className = "tracker-node pending";
                el.textContent = data.agent.replace('_agent', '');
                container.appendChild(el);
            }
            if (data.type === "agent_complete") {
                el.className = "tracker-node complete";
            } else {
                el.className = "tracker-node active";
            }
        }
      } catch (e) {
          console.error("WS Parse Error", e);
      }
    };
    
    ws.onclose = () => {
        setTimeout(() => initLivePipelineTracker(containerId), 5000);
    };
  }

  return {
    getApiKey, setApiKey, apiFetch,
    jsonPretty, verdictClass,
    showStatus, hideStatus,
    initSettingsDropdown,
    initLivePipelineTracker,
    getAgentDescription,
    topbarHTML, onReady,
    AGENT_DESCRIPTIONS: AGENT_DESC,
  };
})();

package api

const uiHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>bpfcompat UI</title>
  <style nonce="__CSP_NONCE__">
    :root { color-scheme: light dark; }
    body {
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background: #0f1115;
      color: #e8ebf1;
    }
    .preview-banner {
      border-bottom: 1px solid #2f3748;
      background: #1f2530;
      color: #ffdc8a;
      padding: 10px 14px;
      font-size: 12px;
      letter-spacing: 0;
    }
    .layout {
      display: grid;
      grid-template-columns: 420px 1fr;
      gap: 14px;
      height: calc(100vh - 44px);
      padding: 14px;
      box-sizing: border-box;
    }
    .panel {
      border: 1px solid #2c3340;
      border-radius: 8px;
      background: #151a22;
      overflow: auto;
      min-width: 0;
    }
    .panel h2 {
      margin: 0;
      padding: 12px 14px;
      font-size: 14px;
      border-bottom: 1px solid #2c3340;
    }
    .section { padding: 12px 14px; border-bottom: 1px solid #2c3340; }
    .section:last-child { border-bottom: 0; }
    label { display: block; font-size: 12px; color: #b5bfd1; margin: 8px 0 6px; }
    input, select, textarea, button {
      width: 100%;
      box-sizing: border-box;
      border-radius: 6px;
      border: 1px solid #3b4557;
      background: #0f131b;
      color: #edf1f8;
      padding: 8px 10px;
      font-size: 13px;
      letter-spacing: 0;
    }
    textarea { min-height: 120px; resize: vertical; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    button {
      background: #1d5bd8;
      border-color: #2d66d8;
      cursor: pointer;
      font-weight: 600;
    }
    button.secondary { background: #1c2431; border-color: #3b4557; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
    .profiles { max-height: 220px; overflow: auto; border: 1px solid #2f3748; border-radius: 6px; padding: 8px; }
    .profile {
      display: grid;
      grid-template-columns: 18px 1fr auto;
      align-items: center;
      gap: 8px;
      margin-bottom: 6px;
      font-size: 12px;
    }
    .profile .meta { color: #95a3bc; }
    .profile input[type="checkbox"] { width: 14px; height: 14px; margin: 0; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .status {
      font-size: 13px;
      margin-bottom: 8px;
      color: #9fd5a7;
    }
    .status.error { color: #f2a3a3; }
    .hint {
      margin-top: 8px;
      font-size: 12px;
      color: #c5d0e6;
      line-height: 1.35;
      white-space: pre-line;
    }
    .hint.error {
      color: #f2a3a3;
    }
    .results {
      padding: 12px 14px;
      display: grid;
      grid-template-rows: auto auto auto 1fr auto;
      gap: 10px;
      height: calc(100% - 52px);
      box-sizing: border-box;
    }
    .progress-wrap {
      border: 1px solid #2f3748;
      border-radius: 6px;
      background: #0d121a;
      padding: 8px;
      display: grid;
      gap: 6px;
    }
    .progress-track {
      height: 10px;
      border-radius: 999px;
      background: #1a2230;
      overflow: hidden;
    }
    .progress-fill {
      height: 100%;
      width: 0%;
      background: #2d66d8;
      transition: width 250ms ease;
    }
    .progress-meta {
      font-size: 12px;
      color: #b9c7df;
    }
    .progress-profiles {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      max-height: 90px;
      overflow: auto;
    }
    .progress-pill {
      font-size: 11px;
      padding: 2px 6px;
      border-radius: 999px;
      border: 1px solid #2f3748;
      background: #0f131b;
      color: #cfd9ec;
    }
    .progress-pill.running { border-color: #3863ab; color: #9fc1ff; }
    .progress-pill.pass { border-color: #2f7b58; color: #94d7b0; }
    .progress-pill.fail, .progress-pill.infra_error { border-color: #8b4a4a; color: #f3b1b1; }
    table {
      border-collapse: collapse;
      width: 100%;
      font-size: 12px;
    }
    th, td {
      border: 1px solid #2f3748;
      padding: 6px 7px;
      text-align: left;
      vertical-align: top;
    }
    th { background: #19202b; }
    pre {
      margin: 0;
      border: 1px solid #2f3748;
      border-radius: 6px;
      background: #0d121a;
      padding: 10px;
      overflow: auto;
      font-size: 12px;
      line-height: 1.35;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    .history-table-wrap { max-height: 240px; overflow: auto; border: 1px solid #2f3748; border-radius: 6px; }
    .badge { font-size: 11px; padding: 2px 6px; border: 1px solid #2f3748; border-radius: 6px; background: #111722; color: #c8d2e6; }
    .split-actions { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 8px; }
    .runtime-flow {
      border: 1px solid #2f3748;
      border-radius: 6px;
      padding: 10px;
      display: grid;
      gap: 8px;
    }
    .runtime-steps {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 6px;
    }
    .runtime-step {
      border: 1px solid #2f3748;
      border-radius: 6px;
      background: #0f131b;
      color: #95a3bc;
      font-size: 11px;
      padding: 5px 6px;
      text-align: center;
    }
    .runtime-step.active {
      border-color: #3863ab;
      color: #c8dbff;
      background: #122237;
    }
    .runtime-step.done {
      border-color: #2f7b58;
      color: #9bd9b4;
      background: #12231b;
    }
    .runtime-step.blocked {
      border-color: #8b4a4a;
      color: #f3b1b1;
      background: #2a1717;
    }
    .runtime-modes {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 8px;
    }
    .runtime-mode-btn.active {
      background: #1d5bd8;
      border-color: #2d66d8;
      color: #edf1f8;
    }
    .runtime-output > summary {
      cursor: pointer;
      font-size: 12px;
      color: #b5bfd1;
      margin-bottom: 6px;
      list-style: none;
    }
    .hidden { display: none; }
    .mt8 { margin-top: 8px; }
    .mt10 { margin-top: 10px; }
    .inline-checkbox { width: auto; margin-right: 6px; }
    .clickable-row { cursor: pointer; }
  </style>
</head>
<body>
  <div class="preview-banner">Technical Preview — VM-backed eBPF compatibility validation and runtime selection proof. Not for production runtime loading.</div>
  <div class="layout">
    <div class="panel">
      <h2>Validation Request</h2>
      <div class="section">
        <div class="row">
          <div>
            <label>Artifact Name</label>
            <input id="artifactName" placeholder="execsnoop">
          </div>
          <div>
            <label>Artifact Version</label>
            <input id="artifactVersion" placeholder="v1.0.0">
          </div>
        </div>
        <label>Artifact Variant</label>
        <input id="artifactVariant" placeholder="ringbuf-modern">
        <label>Artifact URI (optional)</label>
        <input id="artifactURI" placeholder="https://object-store.example.com/execsnoop-v1.0.0.bpf.o">
      </div>

      <div class="section">
        <label>Input Mode</label>
        <div class="row">
          <button type="button" class="secondary" id="modeArtifact">Artifact Upload</button>
          <button type="button" class="secondary" id="modeSource">Source Upload</button>
        </div>
        <div id="artifactMode">
          <label>artifact_file</label>
          <input id="artifactFile" type="file">
        </div>
        <div id="sourceMode" class="hidden">
          <label>source_file</label>
          <input id="sourceFile" type="file">
          <label>or source_code</label>
          <textarea id="sourceCode" placeholder="Paste .bpf.c source"></textarea>
          <label>clang_flags (optional)</label>
          <input id="clangFlags" placeholder="-I./include -DDEBUG=1">
        </div>
      </div>

      <div class="section">
        <label>manifest_file (optional)</label>
        <input id="manifestFile" type="file">
        <label>or manifest_text</label>
        <textarea id="manifestText" placeholder="name: demo
programs:
  - name: prog
    section: tracepoint/syscalls/sys_enter_execve"></textarea>
      </div>

      <div class="section">
        <div id="writeAuthSection" class="hidden">
          <input id="writeApiKey" type="hidden" autocomplete="off">
          <input id="writeIdentityToken" type="hidden" autocomplete="off">
        </div>
        <div id="authHint" class="hint"></div>
        <div class="row">
          <div>
            <label>timeout</label>
            <input id="timeout" value="8m">
          </div>
          <div>
            <label>concurrency</label>
            <input id="concurrency" value="2">
          </div>
        </div>
        <label>Profiles</label>
        <div id="profiles" class="profiles"></div>
        <div class="split-actions">
          <button type="button" class="secondary" id="selectAll">Select All</button>
          <button type="button" class="secondary" id="clearAll">Clear All</button>
        </div>
      </div>

      <div class="section">
        <button id="runBtn">Run Validation</button>
      </div>
    </div>

    <div class="panel">
      <h2>Results & History</h2>
      <div class="results">
        <div id="status" class="status">Ready</div>
        <div class="progress-wrap">
          <div class="progress-track"><div id="progressFill" class="progress-fill"></div></div>
          <div id="progressMeta" class="progress-meta">0%</div>
          <div id="progressProfiles" class="progress-profiles"></div>
        </div>
        <div id="summary"></div>
        <pre id="resultJson" class="mono">{}</pre>

        <div>
          <div class="row">
            <div>
              <label>Artifact Filter</label>
              <input id="historyArtifactName" placeholder="execsnoop">
            </div>
            <div>
              <label>History Limit</label>
              <input id="historyLimit" value="100">
            </div>
          </div>
          <div class="split-actions">
            <button type="button" class="secondary" id="refreshHistory">Refresh History</button>
            <button type="button" id="runCompare">Compare Versions</button>
          </div>
          <div class="row">
            <div>
              <label>Base Version</label>
              <select id="baseVersion"></select>
            </div>
            <div>
              <label>Head Version</label>
              <select id="headVersion"></select>
            </div>
          </div>
          <div class="history-table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Artifact</th>
                  <th>Version</th>
                  <th>Status</th>
                  <th>Req Pass/Fail</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody id="historyRows"></tbody>
            </table>
          </div>
          <pre id="compareJson" class="mono mt8">{}</pre>

          <div class="mt10">
            <div class="row">
              <div>
                <label>Runtime Decision Limit</label>
                <input id="decisionLimit" value="100">
              </div>
            </div>
            <div class="split-actions">
              <button type="button" class="secondary" id="refreshDecisions">Refresh Runtime Decisions</button>
            </div>
            <div class="history-table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Decision</th>
                    <th>Operation</th>
                    <th>Status</th>
                    <th>Artifact</th>
                    <th>Version</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody id="decisionRows"></tbody>
              </table>
            </div>
            <pre id="decisionJson" class="mono mt8">{}</pre>
          </div>

          <div class="runtime-flow mt10">
            <div class="runtime-steps">
              <div class="runtime-step" id="runtimeStepProbe">1. Probe</div>
              <div class="runtime-step" id="runtimeStepSelect">2. Select</div>
              <div class="runtime-step" id="runtimeStepFetch">3. Fetch</div>
              <div class="runtime-step hidden" id="runtimeStepExecute">4. Execute</div>
            </div>

            <div class="runtime-modes" role="tablist" aria-label="Runtime Operation Mode">
              <button type="button" class="secondary runtime-mode-btn" id="runtimeModeProbe" aria-pressed="true">Probe</button>
              <button type="button" class="secondary runtime-mode-btn" id="runtimeModeSelect" aria-pressed="false">Select</button>
              <button type="button" class="secondary runtime-mode-btn" id="runtimeModeFetch" aria-pressed="false">Fetch</button>
              <button type="button" class="secondary runtime-mode-btn hidden" id="runtimeModeExecute" aria-pressed="false">Execute</button>
            </div>

            <div id="runtimeHint" class="hint"></div>

            <div class="row">
              <div>
                <label>Runtime Artifact Name</label>
                <input id="runtimeArtifactName" list="runtimeArtifactNames" placeholder="defaults to Artifact Name">
                <datalist id="runtimeArtifactNames"></datalist>
              </div>
              <div>
                <label>Runtime Version (optional)</label>
                <input id="runtimeVersion" placeholder="v1.0.0">
              </div>
            </div>

            <div class="row">
              <div>
                <label>Runtime Target Profile (optional)</label>
                <input id="runtimeTargetProfile" placeholder="ubuntu-22.04-5.15">
              </div>
              <div id="runtimeAttachModeWrap" class="hidden">
                <label>Runtime Attach Mode (optional)</label>
                <input id="runtimeAttachMode" placeholder="best-effort">
              </div>
            </div>

            <div id="runtimeExecuteFields" class="hidden">
              <div class="row">
                <div>
                  <label>Runtime Tenant (required for execute)</label>
                  <input id="runtimeTenant" placeholder="acme">
                </div>
                <div>
                  <label>Runtime Project (required for execute)</label>
                  <input id="runtimeProject" placeholder="aegis-bpf">
                </div>
              </div>
              <div class="row">
                <div>
                  <label>Registry Bearer Token (required for execute)</label>
                  <input id="runtimeRegistryToken" type="password" placeholder="Authorization: Bearer ...">
                </div>
                <div>
                  <label>Execute Approval Token (required for execute)</label>
                  <input id="runtimeApprovalToken" type="password" placeholder="X-Execute-Approval-Token">
                </div>
              </div>
              <div class="row">
                <div>
                  <label>Approved By (optional)</label>
                  <input id="runtimeApprovedBy" placeholder="operator@example.com">
                </div>
              </div>
            </div>

            <div class="row">
              <div id="runtimeProbeFeaturesWrap" class="hidden">
                <label><input id="runtimeProbeFeatures" class="inline-checkbox" type="checkbox" checked>probe_features</label>
              </div>
              <div id="runtimeRequireVerifiedHistoryWrap" class="hidden">
                <label><input id="runtimeRequireVerifiedHistory" class="inline-checkbox" type="checkbox" checked>require_verified_history</label>
              </div>
            </div>

            <button type="button" id="runtimeActionBtn">Probe Host</button>

            <details class="runtime-output" open>
              <summary>Technical Output</summary>
              <pre id="runtimeJson" class="mono">{}</pre>
            </details>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script nonce="__CSP_NONCE__">
    let mode = "artifact";
    const state = { profiles: [], history: [], decisions: [] };
    let apiConfig = null;
    let runInFlight = false;

    const byId = (id) => document.getElementById(id);
    const statusEl = byId("status");
    const resultJsonEl = byId("resultJson");
    const compareJsonEl = byId("compareJson");
    const decisionJsonEl = byId("decisionJson");
    const runtimeJsonEl = byId("runtimeJson");
    const progressFillEl = byId("progressFill");
    const progressMetaEl = byId("progressMeta");
    const progressProfilesEl = byId("progressProfiles");
    const writeAuthSectionEl = byId("writeAuthSection");
    const authHintEl = byId("authHint");
    const runtimeHintEl = byId("runtimeHint");
    const runtimeArtifactNamesEl = byId("runtimeArtifactNames");
    const runtimeActionBtn = byId("runtimeActionBtn");
    const runtimeModeButtons = {
      probe: byId("runtimeModeProbe"),
      select: byId("runtimeModeSelect"),
      fetch: byId("runtimeModeFetch"),
      execute: byId("runtimeModeExecute")
    };
    const runtimeStepElements = {
      probe: byId("runtimeStepProbe"),
      select: byId("runtimeStepSelect"),
      fetch: byId("runtimeStepFetch"),
      execute: byId("runtimeStepExecute")
    };
    const runtimeStepsEl = document.querySelector(".runtime-steps");
    const runtimeModesEl = document.querySelector(".runtime-modes");
    const demoRuntimeExecuteDefaults = {
      tenant: "acme",
      project: "aegis-bpf",
      registryToken: "",
      approvalToken: "",
      approvedBy: "live-demo"
    };
    const exposeRuntimeExecuteInWebUI = false;
    let runtimeMode = "probe";
    const runtimeCompletedSteps = {
      probe: false,
      select: false,
      fetch: false,
      execute: false
    };

    function setStatus(text, error = false) {
      statusEl.textContent = text;
      statusEl.className = error ? "status error" : "status";
    }

    function setAuthHint(text, error = false) {
      authHintEl.textContent = text || "";
      authHintEl.className = error ? "hint error" : "hint";
    }

    function setRuntimeHint(text, error = false) {
      runtimeHintEl.textContent = text || "";
      runtimeHintEl.className = error ? "hint error" : "hint";
    }

    function deriveProfileHintFromProbe(probe) {
      const osID = String(probe && probe.os && probe.os.id || "").trim();
      const versionID = String(probe && probe.os && probe.os.version_id || "").trim();
      const release = String(probe && probe.kernel && probe.kernel.release || "").trim();
      const match = release.match(/^([0-9]+)\.([0-9]+)/);
      if (!osID || !versionID || !match) {
        return "";
      }
      return osID + "-" + versionID + "-" + match[1] + "." + match[2];
    }

    function modeLabel(mode) {
      switch (mode) {
        case "probe": return "Probe Host";
        case "select": return "Runtime Select";
        case "fetch": return "Runtime Fetch";
        case "execute": return "Runtime Execute";
        default: return "Run";
      }
    }

    function modeHelp(mode) {
      switch (mode) {
        case "probe":
          return "Detect host kernel and feature support; pre-fills target profile hint when possible.";
        case "select":
          return "Operator-only path: choose the best artifact variant from compatibility history.";
        case "fetch":
          return "Operator-only path: select and retrieve artifact payload with history verification.";
        case "execute":
          return "Operator-only path: controlled host load with explicit approval.";
        default:
          return "";
      }
    }

    function shouldApplyDemoRuntimeExecuteDefaults() {
      if (!apiConfig) {
        return false;
      }
      if (!exposeRuntimeExecuteInWebUI) {
        return false;
      }
      return !!apiConfig.allow_anonymous_write &&
        !!apiConfig.runtime_execute_enabled &&
        !apiConfig.write_api_key_configured &&
        !apiConfig.write_identity_verifier_enabled;
    }

    function setInputIfBlank(id, value) {
      const el = byId(id);
      if (!el) {
        return;
      }
      if (!el.value.trim()) {
        el.value = value;
      }
    }

    function applyDemoRuntimeExecuteDefaults() {
      if (!shouldApplyDemoRuntimeExecuteDefaults()) {
        return;
      }
      setInputIfBlank("runtimeTenant", demoRuntimeExecuteDefaults.tenant);
      setInputIfBlank("runtimeProject", demoRuntimeExecuteDefaults.project);
      setInputIfBlank("runtimeRegistryToken", demoRuntimeExecuteDefaults.registryToken);
      setInputIfBlank("runtimeApprovalToken", demoRuntimeExecuteDefaults.approvalToken);
      setInputIfBlank("runtimeApprovedBy", demoRuntimeExecuteDefaults.approvedBy);
    }

    function availableRuntimeArtifactNames() {
      const seen = new Set();
      const names = [];
      state.history.forEach((rec) => {
        const name = String(rec && rec.artifact_name || "").trim();
        if (!name || seen.has(name)) {
          return;
        }
        seen.add(name);
        names.push(name);
      });
      return names;
    }

    function refreshRuntimeArtifactSuggestions() {
      const names = availableRuntimeArtifactNames();
      runtimeArtifactNamesEl.innerHTML = "";
      names.forEach((name) => {
        const option = document.createElement("option");
        option.value = name;
        runtimeArtifactNamesEl.appendChild(option);
      });
      if (!byId("runtimeArtifactName").value.trim() && names.length > 0) {
        byId("runtimeArtifactName").value = names[0];
      }
    }

    function enhanceRuntimeErrorMessage(mode, message) {
      if ((mode === "select" || mode === "fetch") && message.includes("no artifact versions found for")) {
        const names = availableRuntimeArtifactNames();
        if (names.length > 0) {
          return message + ". Try one of: " + names.slice(0, 8).join(", ");
        }
      }
      return message;
    }

    function renderRuntimeSteps() {
      const order = ["probe", "select", "fetch", "execute"];
      order.forEach((step) => {
        const el = runtimeStepElements[step];
        if (!el) {
          return;
        }
        el.classList.remove("active", "done", "blocked");
        if (runtimeCompletedSteps[step]) {
          el.classList.add("done");
        }
        if (runtimeMode === step) {
          el.classList.add("active");
        }
      });
      if (!runtimeDeliveryActionsAvailable()) {
        if (runtimeStepElements.select) {
          runtimeStepElements.select.classList.add("blocked");
        }
        if (runtimeStepElements.fetch) {
          runtimeStepElements.fetch.classList.add("blocked");
        }
      }
      if (runtimeStepElements.execute && (!exposeRuntimeExecuteInWebUI || !apiConfig || !apiConfig.runtime_execute_enabled || !writeActionsAvailable())) {
        runtimeStepElements.execute.classList.add("blocked");
      }
    }

    function syncRuntimeModeUI() {
      const runtimeDeliveryAllowed = runtimeDeliveryActionsAvailable();
      const executeAllowed = exposeRuntimeExecuteInWebUI && !!apiConfig && !!apiConfig.runtime_execute_enabled && writeActionsAvailable();
      if (runtimeStepsEl) {
        runtimeStepsEl.style.gridTemplateColumns = exposeRuntimeExecuteInWebUI ? "repeat(4, minmax(0, 1fr))" : "repeat(3, minmax(0, 1fr))";
      }
      if (runtimeModesEl) {
        runtimeModesEl.style.gridTemplateColumns = exposeRuntimeExecuteInWebUI ? "repeat(4, minmax(0, 1fr))" : "repeat(3, minmax(0, 1fr))";
      }
      if (runtimeStepElements.execute) {
        runtimeStepElements.execute.style.display = exposeRuntimeExecuteInWebUI ? "block" : "none";
      }
      if (runtimeMode === "select" || runtimeMode === "fetch") {
        if (!runtimeDeliveryAllowed) {
          runtimeMode = "probe";
        }
      }
      if (runtimeMode === "execute" && !executeAllowed) {
        runtimeMode = "probe";
      }

      Object.entries(runtimeModeButtons).forEach(([modeKey, btn]) => {
        if (!btn) {
          return;
        }
        if (modeKey === "select" || modeKey === "fetch") {
          btn.disabled = !runtimeDeliveryAllowed;
          btn.title = runtimeDeliveryAllowed ? "" : "Runtime delivery is not open on this public demo";
        }
        if (modeKey === "execute") {
          btn.disabled = !executeAllowed;
          btn.style.display = executeAllowed ? "block" : "none";
          btn.title = executeAllowed ? "" : "Runtime execute is disabled on this public demo";
        }
        const active = runtimeMode === modeKey;
        btn.classList.toggle("active", active);
        btn.setAttribute("aria-pressed", active ? "true" : "false");
      });

      const showExecute = runtimeMode === "execute";
      byId("runtimeExecuteFields").style.display = showExecute ? "block" : "none";
      byId("runtimeAttachModeWrap").style.display = showExecute ? "block" : "none";
      byId("runtimeProbeFeaturesWrap").style.display = showExecute ? "block" : "none";
      byId("runtimeRequireVerifiedHistoryWrap").style.display =
        (runtimeMode === "fetch" || runtimeMode === "execute") ? "block" : "none";
      if (showExecute) {
        applyDemoRuntimeExecuteDefaults();
      }

      runtimeActionBtn.textContent = modeLabel(runtimeMode);
      runtimeActionBtn.disabled = false;
      runtimeActionBtn.title = "";

      if (!runtimeDeliveryAllowed && runtimeMode === "probe") {
        setRuntimeHint("Public demo mode: probe is available here. Selection, fetch, and execute are operator-only; see Results for prepared selection evidence.");
      } else {
        setRuntimeHint(modeHelp(runtimeMode), runtimeMode === "execute" && !executeAllowed);
      }
      renderRuntimeSteps();
    }

    function setRuntimeMode(nextMode) {
      if (!nextMode || !runtimeModeButtons[nextMode]) {
        return;
      }
      if ((nextMode === "select" || nextMode === "fetch") && !runtimeDeliveryActionsAvailable()) {
        setRuntimeHint("Runtime " + nextMode + " is not open on this public demo. Use the Results page for prepared selector evidence.", true);
        return;
      }
      if (nextMode === "execute" && (!exposeRuntimeExecuteInWebUI || !apiConfig || !apiConfig.runtime_execute_enabled || !writeActionsAvailable())) {
        setRuntimeHint("Runtime execute is disabled on this public demo.", true);
        return;
      }
      runtimeMode = nextMode;
      syncRuntimeModeUI();
    }

    function sleep(ms) {
      return new Promise((resolve) => setTimeout(resolve, ms));
    }

    function resetProgress() {
      progressFillEl.style.width = "0%";
      progressMetaEl.textContent = "0%";
      progressProfilesEl.innerHTML = "";
    }

    function renderProgress(job) {
      const percent = Math.max(0, Math.min(100, Number(job && job.percent) || 0));
      progressFillEl.style.width = percent + "%";

      const details = [];
      if (job && job.completed_profiles && job.total_profiles) {
        details.push(job.completed_profiles + "/" + job.total_profiles + " profiles");
      }
      if (job && job.stage) {
        details.push(job.stage);
      }
      if (job && job.message) {
        details.push(job.message);
      }
      progressMetaEl.textContent = percent + "%" + (details.length ? " • " + details.join(" • ") : "");

      progressProfilesEl.innerHTML = "";
      const statuses = (job && job.profile_statuses) || {};
      const ids = Object.keys(statuses).sort();
      ids.forEach((id) => {
        const pill = document.createElement("span");
        const state = String(statuses[id] || "").trim() || "pending";
        pill.className = "progress-pill " + state;
        pill.textContent = id + ": " + state;
        progressProfilesEl.appendChild(pill);
      });
    }

    async function decodeJSONResponse(res) {
      const raw = await res.text();
      if (!raw || !raw.trim()) {
        return { data: {}, raw: "" };
      }
      try {
        return { data: JSON.parse(raw), raw };
      } catch (err) {
        return { data: {}, raw };
      }
    }

    async function requestJSON(url, options) {
      const res = await fetch(url, options);
      const decoded = await decodeJSONResponse(res);
      if (!res.ok) {
        let message = "";
        if (decoded.data && typeof decoded.data.error === "string" && decoded.data.error.trim()) {
          message = decoded.data.error.trim();
        } else if (decoded.raw.trim()) {
          message = decoded.raw.trim();
        } else {
          message = res.statusText || "request failed";
        }
        throw new Error("HTTP " + res.status + ": " + message);
      }
      return decoded.data || {};
    }

    function buildWriteHeaders(baseHeaders = {}) {
      const headers = Object.assign({}, baseHeaders);
      const key = byId("writeApiKey").value.trim();
      if (key && apiConfig && apiConfig.write_api_key_configured) {
        headers["X-API-Key"] = key;
      }
      const identityToken = byId("writeIdentityToken").value.trim();
      if (identityToken && apiConfig && apiConfig.write_identity_verifier_enabled) {
        headers["X-API-Identity-Token"] = identityToken;
      }
      return headers;
    }

    function runtimeArtifactNameOrFallback() {
      const runtimeName = byId("runtimeArtifactName").value.trim();
      if (runtimeName) {
        return runtimeName;
      }
      return byId("artifactName").value.trim();
    }

    function runtimeCommonBody() {
      return {
        artifact_name: runtimeArtifactNameOrFallback(),
        version: byId("runtimeVersion").value.trim(),
        target_profile: byId("runtimeTargetProfile").value.trim()
      };
    }

    function buildRuntimeExecuteHeaders() {
      const headers = buildWriteHeaders({ "Content-Type": "application/json" });
      const registryToken = byId("runtimeRegistryToken").value.trim();
      if (registryToken) {
        headers["Authorization"] = "Bearer " + registryToken;
      }
      const approvalToken = byId("runtimeApprovalToken").value.trim();
      if (approvalToken) {
        headers["X-Execute-Approval-Token"] = approvalToken;
      }
      const approvedBy = byId("runtimeApprovedBy").value.trim();
      if (approvedBy) {
        headers["X-Execute-Approved-By"] = approvedBy;
      }
      return headers;
    }

    function hasWriteCredentials() {
      const key = byId("writeApiKey").value.trim();
      const identityToken = byId("writeIdentityToken").value.trim();
      return (!!key && apiConfig && apiConfig.write_api_key_configured) ||
        (!!identityToken && apiConfig && apiConfig.write_identity_verifier_enabled);
    }

    function writeActionsAvailable() {
      return !!apiConfig && (!!apiConfig.allow_anonymous_write || hasWriteCredentials());
    }

    function runtimeDeliveryActionsAvailable() {
      return writeActionsAvailable() || (!!apiConfig && !!apiConfig.allow_anonymous_runtime_delivery);
    }

    function requireWriteCredentials(actionLabel) {
      if (writeActionsAvailable()) {
        return;
      }
      if (!apiConfig) {
        throw new Error("Demo configuration is not loaded yet");
      }
      throw new Error(actionLabel + " is an operator-only action in this public demo.");
    }

    function requireRuntimeDeliveryAccess(actionLabel) {
      if (runtimeDeliveryActionsAvailable()) {
        return;
      }
      if (!apiConfig) {
        throw new Error("Demo configuration is not loaded yet");
      }
      throw new Error(actionLabel + " is not open on this public demo.");
    }

    function switchMode(nextMode) {
      mode = nextMode;
      byId("artifactMode").style.display = mode === "artifact" ? "block" : "none";
      byId("sourceMode").style.display = mode === "source" ? "block" : "none";
    }

    byId("modeArtifact").addEventListener("click", () => switchMode("artifact"));
    byId("modeSource").addEventListener("click", () => switchMode("source"));
    runtimeModeButtons.probe.addEventListener("click", () => setRuntimeMode("probe"));
    runtimeModeButtons.select.addEventListener("click", () => setRuntimeMode("select"));
    runtimeModeButtons.fetch.addEventListener("click", () => setRuntimeMode("fetch"));
    runtimeModeButtons.execute.addEventListener("click", () => setRuntimeMode("execute"));

    function refreshAuthHintFromConfig() {
      if (!apiConfig) {
        setAuthHint("Loading demo settings...");
        return;
      }
      writeAuthSectionEl.style.display = "none";
      const lines = [];
      let hasBlocking = false;
      if (apiConfig.allow_anonymous_write) {
        lines.push("Public demo mode: validation and protected demo actions run without credentials.");
      } else if (apiConfig.allow_anonymous_validate) {
        lines.push("Public demo mode: validation runs without credentials.");
        if (apiConfig.allow_anonymous_runtime_delivery) {
          lines.push("Runtime select/fetch are open for demo delivery proof.");
        } else if (!runtimeDeliveryActionsAvailable()) {
          lines.push("Operator-only actions are hidden in this UI.");
        }
      } else if (apiConfig.write_api_key_configured || apiConfig.write_identity_verifier_enabled) {
        lines.push("Protected server: validation requires operator credentials outside this public UI.");
        hasBlocking = !hasWriteCredentials();
      } else {
        lines.push("Validation is unavailable: server has no public validation mode configured.");
        hasBlocking = true;
      }
      if (!apiConfig.runtime_execute_enabled) {
        lines.push("Runtime execute is disabled on this server.");
      }
      if (lines.length == 0) {
        lines.push("Demo configuration loaded.");
      }
      setAuthHint(lines.join("\n"), hasBlocking);
      const compareButton = byId("runCompare");
      if (compareButton) {
        compareButton.disabled = !writeActionsAvailable();
        compareButton.title = writeActionsAvailable() ? "" : "Operator-only in this public demo";
      }
      syncRuntimeModeUI();
    }

    async function refreshAPIConfig() {
      apiConfig = await requestJSON("/api/config");
      applyDemoRuntimeExecuteDefaults();
      refreshAuthHintFromConfig();
    }

    function createProfileRow(profile) {
      const row = document.createElement("div");
      row.className = "profile";
      const include = document.createElement("input");
      include.type = "checkbox";
      include.checked = !!profile.transport_supported;
      include.dataset.kind = "include";
      include.dataset.id = profile.id;
      include.dataset.transportSupported = profile.transport_supported ? "true" : "false";

      const label = document.createElement("div");
      const title = document.createElement("div");
      const strong = document.createElement("strong");
      strong.textContent = profile.id;
      title.appendChild(strong);
      const meta = document.createElement("div");
      meta.className = "meta";
      meta.appendChild(document.createTextNode(
        profile.distro + " " + profile.version + " kernel " + profile.kernel_family + " "
      ));
      const badge = document.createElement("span");
      badge.className = "badge";
      badge.textContent = profile.image_cached ? "image cached" : "image missing";
      meta.appendChild(badge);
      const sourceBadge = document.createElement("span");
      sourceBadge.className = "badge";
      sourceBadge.textContent = profile.source_mode === "url" ? "url source" : "manual image";
      meta.appendChild(sourceBadge);
      const transportBadge = document.createElement("span");
      transportBadge.className = "badge";
      transportBadge.textContent = profile.transport_supported ? "transport: " + (profile.transport || "ssh") : "transport unsupported";
      meta.appendChild(transportBadge);
      label.append(title, meta);
      if (!profile.transport_supported && profile.transport_note) {
        const reason = document.createElement("div");
        reason.className = "meta";
        reason.textContent = profile.transport_note;
        label.appendChild(reason);
      }

      const required = document.createElement("input");
      required.type = "checkbox";
      required.checked = !!profile.required_default && !!profile.transport_supported;
      required.disabled = !profile.transport_supported;
      required.dataset.kind = "required";
      required.dataset.id = profile.id;

      include.addEventListener("change", () => {
        required.disabled = !include.checked || !profile.transport_supported;
        if (required.disabled) {
          required.checked = false;
        }
      });

      row.append(include, label, required);
      return row;
    }

    function appendCell(tr, value) {
      const td = document.createElement("td");
      td.textContent = String(value);
      tr.appendChild(td);
    }

    function formatProfileEnv(target) {
      const env = target && target.profile ? target.profile : null;
      if (!env) return "-";
      const parts = [];
      if (env.distro) parts.push(env.distro);
      if (env.version) parts.push(env.version);
      if (env.kernel_family) parts.push("kfamily=" + env.kernel_family);
      if (env.arch) parts.push("arch=" + env.arch);
      return parts.length ? parts.join(" ") : "-";
    }

    function formatHostKernel(target) {
      const env = target && target.host ? target.host : null;
      if (!env) return "-";
      const kernel = env.kernel || "-";
      if (env.arch) return kernel + " (" + env.arch + ")";
      return kernel;
    }

    async function loadProfiles() {
      const data = await requestJSON("/api/profiles");
      state.profiles = data.profiles || [];

      const container = byId("profiles");
      container.innerHTML = "";
      state.profiles.forEach((p) => container.appendChild(createProfileRow(p)));
    }

    function selectedProfiles() {
      const include = Array.from(document.querySelectorAll("input[data-kind='include']:checked"))
        .map((x) => x.dataset.id);
      const required = Array.from(document.querySelectorAll("input[data-kind='required']:checked"))
        .map((x) => x.dataset.id)
        .filter((id) => include.includes(id));
      return { include, required };
    }

    function renderSummary(report) {
      const container = byId("summary");
      if (!report || !report.targets) {
        container.replaceChildren();
        return;
      }
      const table = document.createElement("table");
      const thead = document.createElement("thead");
      const headRow = document.createElement("tr");
      ["Profile", "Profile Env", "Host Kernel", "Status", "Failed Stage", "Required", "Class"].forEach((name) => {
        const th = document.createElement("th");
        th.textContent = name;
        headRow.appendChild(th);
      });
      thead.appendChild(headRow);
      table.appendChild(thead);

      const tbody = document.createElement("tbody");
      report.targets.forEach((t) => {
        const tr = document.createElement("tr");
        appendCell(tr, t.profile_id || "-");
        appendCell(tr, formatProfileEnv(t));
        appendCell(tr, formatHostKernel(t));
        appendCell(tr, t.status || "-");
        appendCell(tr, t.failed_stage || "-");
        appendCell(tr, t.required ? "true" : "false");
        appendCell(tr, t.classification_code || "-");
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      container.replaceChildren(table);
    }

    byId("selectAll").addEventListener("click", () => {
      document.querySelectorAll("input[data-kind='include']").forEach((x) => {
        x.checked = x.dataset.transportSupported === "true";
      });
    });
    byId("clearAll").addEventListener("click", () => {
      document.querySelectorAll("input[data-kind='include']").forEach((x) => (x.checked = false));
    });

    async function runValidationJob(fd) {
      let startResp = null;
      try {
        startResp = await requestJSON("/api/validate/start", {
          method: "POST",
          headers: buildWriteHeaders(),
          body: fd
        });
      } catch (err) {
        if (String(err).includes("HTTP 404")) {
          setStatus("Server does not support async progress endpoint; running direct validation.");
          progressMetaEl.textContent = "Running without live progress (legacy server)";
          return await requestJSON("/api/validate", {
            method: "POST",
            headers: buildWriteHeaders(),
            body: fd
          });
        }
        throw err;
      }
      const jobID = String(startResp.job_id || "").trim();
      if (!jobID) {
        throw new Error("Validation job did not return job_id");
      }

      while (true) {
        const job = await requestJSON("/api/validate/status?job_id=" + encodeURIComponent(jobID));
        renderProgress(job);
        if (job.message) {
          setStatus(job.message);
        } else {
          setStatus("Running validation...");
        }

        if (job.state === "completed") {
          if (!job.result) {
            throw new Error("Validation completed without result payload");
          }
          return job.result;
        }
        if (job.state === "failed") {
          throw new Error(job.error || "Validation failed");
        }
        await sleep(1200);
      }
    }

    byId("runBtn").addEventListener("click", async () => {
      if (runInFlight) {
        setStatus("Validation already running. Please wait.");
        return;
      }
      runInFlight = true;
      byId("runBtn").disabled = true;
      try {
        refreshAuthHintFromConfig();
        if (apiConfig && !apiConfig.allow_anonymous_write && !apiConfig.allow_anonymous_validate && !hasWriteCredentials()) {
          throw new Error("Validation is not open on this server. Use the public Results page or run the CLI locally.");
        }
        resetProgress();
        setStatus("Starting validation...");
        const fd = new FormData();

        fd.append("artifact_name", byId("artifactName").value.trim());
        fd.append("artifact_version", byId("artifactVersion").value.trim());
        fd.append("artifact_variant", byId("artifactVariant").value.trim());
        fd.append("artifact_uri", byId("artifactURI").value.trim());
        fd.append("timeout", byId("timeout").value.trim());
        fd.append("concurrency", byId("concurrency").value.trim());

        if (mode === "artifact") {
          if (byId("artifactFile").files[0]) {
            fd.append("artifact_file", byId("artifactFile").files[0]);
          }
        } else {
          if (byId("sourceFile").files[0]) {
            fd.append("source_file", byId("sourceFile").files[0]);
          }
          if (byId("sourceCode").value.trim()) {
            fd.append("source_code", byId("sourceCode").value);
          }
          if (byId("clangFlags").value.trim()) {
            fd.append("clang_flags", byId("clangFlags").value.trim());
          }
        }

        if (byId("manifestFile").files[0]) {
          fd.append("manifest_file", byId("manifestFile").files[0]);
        }
        if (byId("manifestText").value.trim()) {
          fd.append("manifest_text", byId("manifestText").value);
        }

        const picks = selectedProfiles();
        picks.include.forEach((id) => fd.append("profiles", id));
        picks.required.forEach((id) => fd.append("required_profiles", id));
        if (picks.include.length === 0) {
          throw new Error("Select at least one profile");
        }

        const data = await runValidationJob(fd);

        setStatus("Completed. Exit code " + data.exit_code);
        resultJsonEl.textContent = JSON.stringify(data, null, 2);
        renderSummary(data.report);
        await refreshHistory();
      } catch (err) {
        setStatus(String(err), true);
      } finally {
        runInFlight = false;
        byId("runBtn").disabled = false;
      }
    });

    function refreshVersionSelectors() {
      const base = byId("baseVersion");
      const head = byId("headVersion");
      base.innerHTML = "";
      head.innerHTML = "";
      for (const rec of state.history) {
        const label = rec.artifact_name + "@" + rec.artifact_version + " (" + rec.summary_status + ")";
        const o1 = document.createElement("option");
        o1.value = rec.artifact_version;
        o1.textContent = label;
        base.appendChild(o1);

        const o2 = document.createElement("option");
        o2.value = rec.artifact_version;
        o2.textContent = label;
        head.appendChild(o2);
      }
      if (head.options.length > 0) {
        head.selectedIndex = 0;
      }
      if (base.options.length > 1) {
        base.selectedIndex = 1;
      }
    }

    async function refreshHistory() {
      const artifactName = byId("historyArtifactName").value.trim();
      const limit = byId("historyLimit").value.trim() || "100";
      const data = await requestJSON("/api/history/artifacts?artifact_name=" + encodeURIComponent(artifactName) + "&limit=" + encodeURIComponent(limit));
      state.history = data.records || [];

      const rows = byId("historyRows");
      rows.innerHTML = "";
      state.history.forEach((rec) => {
        const tr = document.createElement("tr");
        appendCell(tr, rec.artifact_name || "-");
        appendCell(tr, rec.artifact_version || "-");
        appendCell(tr, rec.summary_status || "-");
        appendCell(tr, String(rec.required_passed) + "/" + String(rec.required_failed));
        appendCell(tr, rec.created_at || "-");
        rows.appendChild(tr);
      });
      refreshVersionSelectors();
      refreshRuntimeArtifactSuggestions();
    }

    async function refreshDecisionHistory() {
      const limit = byId("decisionLimit").value.trim() || "100";
      const data = await requestJSON("/api/runtime/decisions?limit=" + encodeURIComponent(limit));
      state.decisions = data.records || [];

      const rows = byId("decisionRows");
      rows.innerHTML = "";
      state.decisions.forEach((rec) => {
        const tr = document.createElement("tr");
        appendCell(tr, rec.decision_id || "-");
        appendCell(tr, rec.operation || "-");
        appendCell(tr, rec.status || "-");
        appendCell(tr, rec.artifact_name || "-");
        appendCell(tr, rec.selected_version || rec.requested_version || "-");
        appendCell(tr, rec.created_at || "-");
        tr.classList.add("clickable-row");
        tr.addEventListener("click", () => {
          decisionJsonEl.textContent = JSON.stringify(rec, null, 2);
        });
        rows.appendChild(tr);
      });
      if (state.decisions.length === 0) {
        decisionJsonEl.textContent = "{}";
      } else {
        decisionJsonEl.textContent = JSON.stringify(state.decisions[0], null, 2);
      }
    }

    byId("refreshHistory").addEventListener("click", async () => {
      try {
        await refreshHistory();
        setStatus("History refreshed");
      } catch (err) {
        setStatus(String(err), true);
      }
    });

    byId("refreshDecisions").addEventListener("click", async () => {
      try {
        await refreshDecisionHistory();
        setStatus("Runtime decisions refreshed");
      } catch (err) {
        setStatus(String(err), true);
      }
    });

    byId("runCompare").addEventListener("click", async () => {
      try {
        requireWriteCredentials("Compare");
        const artifactName = byId("historyArtifactName").value.trim() || byId("artifactName").value.trim();
        if (!artifactName) {
          throw new Error("Artifact name is required for compare");
        }
        const body = {
          artifact_name: artifactName,
          base_version: byId("baseVersion").value,
          head_version: byId("headVersion").value
        };
        const data = await requestJSON("/api/compare", {
          method: "POST",
          headers: buildWriteHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify(body)
        });
        compareJsonEl.textContent = JSON.stringify(data, null, 2);
        setStatus("Compare completed");
      } catch (err) {
        setStatus(String(err), true);
      }
    });

    async function runRuntimeProbe() {
      const data = await requestJSON("/api/runtime/probe");
      runtimeJsonEl.textContent = JSON.stringify(data, null, 2);
      const hint = deriveProfileHintFromProbe(data.probe || {});
      if (!byId("runtimeTargetProfile").value.trim() && hint) {
        byId("runtimeTargetProfile").value = hint;
      }
      runtimeCompletedSteps.probe = true;
      setStatus("Runtime probe completed");
      if (runtimeDeliveryActionsAvailable()) {
        setRuntimeMode("select");
        setRuntimeHint("Host probe completed. Continue with Select.");
      } else {
        setRuntimeMode("probe");
        setRuntimeHint("Host probe completed. Selection and fetch are operator-only in this public demo.");
      }
      renderRuntimeSteps();
    }

    async function runRuntimeSelect() {
      requireRuntimeDeliveryAccess("Runtime select");
      const body = runtimeCommonBody();
      if (!body.artifact_name) {
        throw new Error("Runtime artifact name is required");
      }
      const data = await requestJSON("/api/runtime/select", {
        method: "POST",
        headers: buildWriteHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(body)
      });
      runtimeJsonEl.textContent = JSON.stringify(data, null, 2);
      if (!byId("runtimeVersion").value.trim() && data.selection && data.selection.selected && data.selection.selected.artifact_version) {
        byId("runtimeVersion").value = data.selection.selected.artifact_version;
      }
      if (!byId("runtimeTargetProfile").value.trim() && data.selection && data.selection.host_profile_hint) {
        byId("runtimeTargetProfile").value = data.selection.host_profile_hint;
      }
      runtimeCompletedSteps.select = true;
      await refreshDecisionHistory();
      setStatus("Runtime select completed");
      setRuntimeMode("fetch");
      setRuntimeHint("Selection completed. Continue with Fetch to retrieve the selected artifact.");
      renderRuntimeSteps();
    }

    async function runRuntimeFetch() {
      requireRuntimeDeliveryAccess("Runtime fetch");
      const body = runtimeCommonBody();
      if (!body.artifact_name) {
        throw new Error("Runtime artifact name is required");
      }
      body.require_verified_history = byId("runtimeRequireVerifiedHistory").checked;
      const data = await requestJSON("/api/runtime/fetch", {
        method: "POST",
        headers: buildWriteHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(body)
      });
      runtimeJsonEl.textContent = JSON.stringify(data, null, 2);
      if (!byId("runtimeVersion").value.trim() && data.selection && data.selection.selected && data.selection.selected.artifact_version) {
        byId("runtimeVersion").value = data.selection.selected.artifact_version;
      }
      runtimeCompletedSteps.fetch = true;
      await refreshDecisionHistory();
      setStatus("Runtime fetch completed");
      setRuntimeHint("Fetch completed. Technical output below includes selected version and fetch details.");
      renderRuntimeSteps();
    }

    async function runRuntimeExecute() {
      requireWriteCredentials("Runtime execute");
      const body = runtimeCommonBody();
      if (!body.artifact_name) {
        throw new Error("Runtime artifact name is required");
      }
      body.tenant = byId("runtimeTenant").value.trim();
      body.project = byId("runtimeProject").value.trim();
      body.attach_mode = byId("runtimeAttachMode").value.trim();
      body.probe_features = byId("runtimeProbeFeatures").checked;
      body.require_verified_history = byId("runtimeRequireVerifiedHistory").checked;
      body.allow_host_load = true;

      if (!body.tenant || !body.project) {
        throw new Error("Runtime execute requires tenant and project");
      }
      if (!byId("runtimeApprovalToken").value.trim()) {
        throw new Error("Runtime execute requires Execute Approval Token");
      }
      if (!byId("runtimeRegistryToken").value.trim()) {
        throw new Error("Runtime execute requires Registry Bearer Token");
      }
      if (body.require_verified_history !== true) {
        throw new Error("Runtime execute requires require_verified_history=true");
      }

      const data = await requestJSON("/api/runtime/execute", {
        method: "POST",
        headers: buildRuntimeExecuteHeaders(),
        body: JSON.stringify(body)
      });
      runtimeJsonEl.textContent = JSON.stringify(data, null, 2);
      runtimeCompletedSteps.execute = true;
      await refreshDecisionHistory();
      setStatus("Runtime execute completed");
      setRuntimeHint("Runtime execute completed.");
      renderRuntimeSteps();
    }

    runtimeActionBtn.addEventListener("click", async () => {
      try {
        if (runtimeMode === "probe") {
          await runRuntimeProbe();
          return;
        }
        if (runtimeMode === "select") {
          await runRuntimeSelect();
          return;
        }
        if (runtimeMode === "fetch") {
          await runRuntimeFetch();
          return;
        }
        if (runtimeMode === "execute") {
          await runRuntimeExecute();
          return;
        }
        throw new Error("Unknown runtime mode: " + runtimeMode);
      } catch (err) {
        const message = enhanceRuntimeErrorMessage(runtimeMode, String(err));
        setStatus(message, true);
        setRuntimeHint(message, true);
      }
    });

    (async () => {
      try {
        resetProgress();
        await refreshAPIConfig();
        await loadProfiles();
        await refreshHistory();
        await refreshDecisionHistory();
        setRuntimeMode("probe");
      } catch (err) {
        setStatus(String(err), true);
      }
    })();
  </script>
</body>
</html>`

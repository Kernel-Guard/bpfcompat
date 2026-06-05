package api

import (
	"net/http"
	"strings"
)

func (s *Server) handleDemoResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	nonce := generateCSPNonce(r)
	w.Header().Set("Content-Security-Policy", htmlCSPWithNonce(nonce))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(strings.ReplaceAll(demoResultHTML, "__CSP_NONCE__", nonce)))
}

const demoResultHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>bpfcompat Results</title>
  <style nonce="__CSP_NONCE__">
    :root {
      --bg: #0b1220;
      --surface: #111b2e;
      --line: #283247;
      --text: #e8edf5;
      --muted: #9eb0cf;
      --ok: #4ade80;
      --bad: #f87171;
      --warn: #fbbf24;
      --btn: #2563eb;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font: 14px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      color: var(--text);
      background: var(--bg);
      letter-spacing: 0;
    }
    .wrap { max-width: 980px; margin: 0 auto; padding: 16px; }
    h1 { font-size: 20px; margin: 0 0 8px; }
    .muted { color: var(--muted); }
    .grid { display: grid; gap: 12px; }
    .card {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
    }
    .row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
    .pill {
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 2px 10px;
      font-size: 12px;
      white-space: nowrap;
    }
    .ok { color: var(--ok); border-color: rgba(74,222,128,0.4); }
    .bad { color: var(--bad); border-color: rgba(248,113,113,0.4); }
    .warn { color: var(--warn); border-color: rgba(251,191,36,0.4); }
    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
      font-size: 13px;
    }
    th, td {
      border: 1px solid var(--line);
      padding: 7px;
      text-align: left;
      vertical-align: top;
      word-break: break-word;
    }
    th { color: var(--muted); font-weight: 600; }
    ul { margin: 8px 0 0; padding-left: 18px; }
    li { margin-bottom: 4px; }
    .btn {
      border: 1px solid #35518a;
      background: var(--btn);
      color: #fff;
      border-radius: 8px;
      padding: 8px 12px;
      font-weight: 600;
      cursor: pointer;
    }
    .mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      font-size: 12px;
      color: var(--muted);
    }
    .header-row { justify-content: space-between; align-items: flex-end; }
    .split-row { justify-content: space-between; }
    .mt8 { margin-top: 8px; }
    .mt6 { margin-top: 6px; }
    .table-scroll { overflow: auto; margin-top: 8px; }
    .col-profile { width: 24%; }
    .col-profile-env { width: 22%; }
    .col-kernel { width: 16%; }
    .col-status { width: 12%; }
    .col-class { width: 14%; }
    .col-stage { width: 12%; }
    .col-required { width: 10%; }
  </style>
</head>
<body>
  <div class="wrap grid">
    <div class="row header-row">
      <div>
        <h1>Artifact Compatibility Result</h1>
        <div class="muted">Mobile-friendly evidence snapshot: where this BPF object loads, where it fails, and why.</div>
      </div>
      <button class="btn" type="button" id="refreshBtn">Refresh</button>
    </div>

    <div class="card">
      <div class="row">
        <span id="summaryBadge" class="pill warn">loading</span>
        <span id="runIdBadge" class="pill">run: -</span>
        <span id="artifactBadge" class="pill">artifact: -</span>
      </div>
      <div id="summaryText" class="mt8">Loading latest compatibility run...</div>
    </div>

    <div class="card">
      <div class="row split-row">
        <strong>Kernel Compatibility Matrix</strong>
        <span class="muted">distro/kernel verdicts</span>
      </div>
      <div class="table-scroll">
        <table>
          <thead>
            <tr>
              <th class="col-profile">Profile</th>
              <th class="col-profile-env">Profile Env</th>
              <th class="col-kernel">Kernel</th>
              <th class="col-status">Status</th>
              <th class="col-class">Class</th>
              <th class="col-stage">Stage</th>
              <th class="col-required">Required</th>
            </tr>
          </thead>
          <tbody id="targetsBody"></tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <strong>Failure Reasons</strong>
      <ul id="failureList"></ul>
    </div>

    <div class="card">
      <strong>Fallback Guidance</strong>
      <ul id="fallbackList"></ul>
    </div>

    <div class="card">
      <strong>Runtime Selection Decision</strong>
      <div id="selectionText" class="mt8">Loading compatibility decision...</div>
      <div class="mono mt6" id="selectionMeta"></div>
    </div>
  </div>

  <script nonce="__CSP_NONCE__">
    function byId(id) { return document.getElementById(id); }
    function esc(s) {
      return String(s || "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;");
    }
    async function requestJSON(url, options) {
      const res = await fetch(url, options);
      const text = await res.text();
      let data = {};
      try { data = text ? JSON.parse(text) : {}; } catch (_) {}
      if (!res.ok) {
        throw new Error(data.error || ("HTTP " + res.status));
      }
      return data;
    }
    function badgeClass(status) {
      const s = String(status || "").toLowerCase();
      if (s === "pass" || s === "success") return "ok";
      if (s === "fail" || s === "failed" || s === "error") return "bad";
      return "warn";
    }
    function fallbackText(classCode) {
      const code = String(classCode || "");
      if (code === "MISSING_BTF") return "Use non-CO-RE fallback or provide usable kernel/external BTF for this target.";
      if (code === "CORE_RELOCATION_FAILURE") return "Ship a fallback object built for this kernel family or avoid unsupported CO-RE relocations.";
      if (code === "UNSUPPORTED_PROGRAM_TYPE") return "Use an older-kernel-compatible variant (for example avoid fentry/fexit on pre-5.5 kernels).";
		if (code === "UNSUPPORTED_MAP_TYPE") return "Use a fallback map strategy (for example perf-buffer/classic maps) for older kernels.";
		if (code === "UNSUPPORTED_ATTACH_TYPE") return "Switch to a supported attach path on this kernel/profile.";
		if (code === "UNSUPPORTED_TRANSPORT") return "This profile needs a different executor transport than the current SSH runner.";
		if (code === "POLICY_DENIED") return "Host policy blocked BPF on this target. Use approved policy settings or a restricted fallback deployment path.";
      return "Keep a compatible fallback artifact variant for this profile.";
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
    function renderTargets(targets) {
      const body = byId("targetsBody");
      body.textContent = "";
      if (!Array.isArray(targets) || targets.length === 0) {
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = 7;
        td.textContent = "No targets in report.";
        tr.appendChild(td);
        body.appendChild(tr);
        return;
      }
      targets.forEach((t) => {
        const tr = document.createElement("tr");
        const profile = document.createElement("td");
        const profileEnv = document.createElement("td");
        const kernel = document.createElement("td");
        const status = document.createElement("td");
        const klass = document.createElement("td");
        const stage = document.createElement("td");
        const req = document.createElement("td");
        profile.textContent = t.profile_id || "-";
        profileEnv.textContent = formatProfileEnv(t);
        kernel.textContent = formatHostKernel(t);
        status.textContent = t.status || "-";
        status.className = badgeClass(t.status);
        klass.textContent = t.classification_code || "-";
        stage.textContent = t.failed_stage || "-";
        req.textContent = t.required ? "required" : "optional";
        tr.appendChild(profile);
        tr.appendChild(profileEnv);
        tr.appendChild(kernel);
        tr.appendChild(status);
        tr.appendChild(klass);
        tr.appendChild(stage);
        tr.appendChild(req);
        body.appendChild(tr);
      });
    }
    function renderFailureAndFallbacks(targets) {
      const failures = byId("failureList");
      const fallbacks = byId("fallbackList");
      failures.textContent = "";
      fallbacks.textContent = "";
      const failed = (targets || []).filter((t) => String(t.status).toLowerCase() !== "pass");
      if (failed.length === 0) {
        const li = document.createElement("li");
        li.textContent = "No failures in this run.";
        failures.appendChild(li);
        const li2 = document.createElement("li");
        li2.textContent = "No fallback needed for this run.";
        fallbacks.appendChild(li2);
        return;
      }
      const seenFallback = new Set();
      failed.forEach((t) => {
        const li = document.createElement("li");
        const reason = t.classification_reason || t.classification_code || "failed";
        li.textContent = (t.profile_id || "profile") + ": " + reason;
        failures.appendChild(li);
        const code = t.classification_code || "UNKNOWN";
        if (!seenFallback.has(code)) {
          const lf = document.createElement("li");
          lf.textContent = code + ": " + fallbackText(code);
          fallbacks.appendChild(lf);
          seenFallback.add(code);
        }
      });
    }
    function countRequired(targets) {
      let pass = 0;
      let fail = 0;
      (targets || []).forEach((t) => {
        if (!t.required) return;
        if (String(t.status).toLowerCase() === "pass") pass++;
        else fail++;
      });
      return { pass, fail };
    }
    function countAll(targets) {
      let pass = 0;
      let fail = 0;
      (targets || []).forEach((t) => {
        if (String(t.status).toLowerCase() === "pass") pass++;
        else fail++;
      });
      return { pass, fail, total: pass + fail };
    }
    function outcomeText(status, counts, req) {
      const s = String(status || "").toLowerCase();
      if (s === "pass") {
        return "Compatibility finding: this artifact passed all selected targets. Matrix pass/fail: " +
          counts.pass + "/" + counts.fail + ". Required pass/fail: " + req.pass + "/" + req.fail + ".";
      }
      if (s === "fail") {
        return "Compatibility finding: this artifact has expected kernel-specific failures. This is evidence, not a service error. Matrix pass/fail: " +
          counts.pass + "/" + counts.fail + ". Required pass/fail: " + req.pass + "/" + req.fail + ".";
      }
      return "Compatibility finding: run status is " + (status || "unknown") + ". Matrix pass/fail: " +
        counts.pass + "/" + counts.fail + ". Required pass/fail: " + req.pass + "/" + req.fail + ".";
    }
    function pickArtifactName(runRecord, report) {
      if (runRecord && runRecord.artifact_name) return runRecord.artifact_name;
      const base = report && report.artifact && report.artifact.basename ? report.artifact.basename : "";
      return String(base || "")
        .replace(/\.bpf\.o$/i, "")
        .replace(/\.o$/i, "");
    }
    function isCompatibilityVerdict(runRecord) {
      const status = String((runRecord && runRecord.summary_status) || "").toLowerCase();
      return status === "pass" || status === "fail";
    }
    function renderSelectionDecision(artifactName, status, targets, targetProfileHint) {
      const selectionText = byId("selectionText");
      const selectionMeta = byId("selectionMeta");
      if (!artifactName) {
        selectionText.textContent = "Selection decision unavailable: artifact name not found in selected run.";
        selectionMeta.textContent = "";
        return;
      }
      const s = String(status || "").toLowerCase();
      const counts = countAll(targets);
      const req = countRequired(targets);
      const targetText = targetProfileHint ? " for host profile " + targetProfileHint : "";
      if (s === "pass") {
        selectionText.textContent = "Strict selector decision: this artifact is eligible" + targetText + " because the selected compatibility matrix passed.";
      } else if (s === "fail") {
        selectionText.textContent = "Strict selector decision: this artifact version is rejected for all-required-pass delivery. A fallback or newer compatible variant is required for failed kernels.";
      } else {
        selectionText.textContent = "Strict selector decision: this run is not eligible for delivery because it did not produce a pass/fail compatibility verdict.";
      }
      selectionMeta.textContent = "artifact=" + artifactName +
        " matrix_pass_fail=" + counts.pass + "/" + counts.fail +
        " required_pass_fail=" + req.pass + "/" + req.fail +
        " policy=require_summary_pass,max_required_failed=0";
    }
    async function loadPage() {
      byId("summaryBadge").textContent = "loading";
      byId("summaryBadge").className = "pill warn";
      byId("summaryText").textContent = "Loading latest compatibility run...";
      byId("runIdBadge").textContent = "run: -";
      byId("artifactBadge").textContent = "artifact: -";

      try {
        const runsData = await requestJSON("/api/history/runs?limit=50");
        const runs = Array.isArray(runsData.records) ? runsData.records : [];
        if (!runs.length) {
          byId("summaryText").textContent = "No runs found yet.";
          return;
        }

        const q = new URLSearchParams(location.search);
        const requestedRunID = (q.get("run_id") || "").trim();
        let run = runs.find(isCompatibilityVerdict) || runs[0];
        if (requestedRunID) {
          const match = runs.find((r) => String(r.run_id || "") === requestedRunID);
          if (match) run = match;
        }

        byId("runIdBadge").textContent = "run: " + (run.run_id || "-");
        byId("artifactBadge").textContent = "artifact: " + (run.artifact_name || "-");

        const rr = await requestJSON("/api/history/run-report?run_id=" + encodeURIComponent(run.run_id));
        const report = rr.report || {};
        const targets = Array.isArray(report.targets) ? report.targets : [];
        const status = String((report.summary && report.summary.status) || run.summary_status || "unknown");
        const req = countRequired(targets);
        byId("summaryBadge").textContent = "compatibility " + status;
        byId("summaryBadge").className = "pill " + badgeClass(status);
        byId("summaryText").textContent = outcomeText(status, countAll(targets), req);

        renderTargets(targets);
        renderFailureAndFallbacks(targets);

        const targetHint = targets.find((t) => String(t.status || "").toLowerCase() === "pass");
        const artifactName = pickArtifactName(run, report);
        renderSelectionDecision(artifactName, status, targets, targetHint ? targetHint.profile_id : "");
      } catch (e) {
        byId("summaryBadge").textContent = "error";
        byId("summaryBadge").className = "pill bad";
        byId("summaryText").textContent = "Failed to load result page: " + e.message;
      }
    }

    byId("refreshBtn").addEventListener("click", loadPage);
    loadPage();
  </script>
</body>
</html>`

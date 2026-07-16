package api

const uiHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>bpfcompat UI</title>
  <style nonce="__CSP_NONCE__">
    :root {
      color-scheme: dark;
      /* IBM Carbon tokens — matched to the kernelguard.net marketing site so the
         demo reads as the same product. */
      --bg: #161616;
      --layer: #262626;
      --layer-hover: #333333;
      --field: #393939;
      --border: #393939;
      --border-strong: #525252;
      --fg: #f4f4f4;
      --fg-muted: #c6c6c6;
      --fg-subtle: #8d8d8d;
      --primary: #4589ff;
      --primary-hover: #0f62fe;
      --primary-active-bg: #1c2a45;
      --info-text: #a6c8ff;
      --accent: #3ddc97;
      --success: #42be65;
      --success-text: #6fdc8c;
      --success-bg: #1a2c20;
      --danger: #fa4d56;
      --danger-text: #ff8389;
      --danger-bg: #2d1a1c;
      --warning: #f1c21b;
      --warning-text: #f1c21b;
      --warning-bg: #2a2410;
    }
    html[data-theme="light"] {
      color-scheme: light;
      --bg: #ffffff;
      --layer: #f4f4f4;
      --layer-hover: #e8e8e8;
      --field: #ffffff;
      --border: #d1d1d1;
      --border-strong: #a8a8a8;
      --fg: #161616;
      --fg-muted: #525252;
      --fg-subtle: #6f6f6f;
      --primary: #0f62fe;
      --primary-hover: #0043ce;
      --primary-active-bg: #d0e2ff;
      --info-text: #0043ce;
      --accent: #0ca678;
      --success: #24a148;
      --success-text: #198038;
      --success-bg: #defbe6;
      --danger: #da1e28;
      --danger-text: #da1e28;
      --danger-bg: #fff1f1;
      --warning: #f1c21b;
      --warning-text: #8e6a00;
      --warning-bg: #fcf4d6;
    }
    body {
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background: var(--bg);
      color: var(--fg);
    }
    .preview-banner {
      border-bottom: 1px solid var(--border);
      background: var(--warning-bg);
      color: var(--warning-text);
      padding: 10px 14px;
      font-size: 12px;
      letter-spacing: 0;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }
    .theme-toggle {
      width: auto;
      flex: none;
      border: 1px solid var(--border-strong);
      background: transparent;
      color: var(--warning-text);
      border-radius: 999px;
      padding: 2px 10px;
      font-size: 11px;
      font-weight: 600;
      cursor: pointer;
      white-space: nowrap;
    }
    .example-run-btn {
      width: auto;
      margin-top: 6px;
      padding: 5px 10px;
      font-size: 12px;
    }
    .banner-nav { display: flex; align-items: center; gap: 14px; flex: none; }
    .banner-nav a {
      color: var(--warning-text);
      text-decoration: none;
      font-size: 12px;
      font-weight: 600;
      white-space: nowrap;
    }
    .banner-nav a:hover { text-decoration: underline; }
    .site-footer {
      border-top: 1px solid var(--border);
      background: var(--layer);
      padding: 28px 16px;
      font-size: 13px;
      color: var(--fg-muted);
    }
    .footer-grid {
      max-width: 1100px;
      margin: 0 auto;
      display: grid;
      grid-template-columns: 1.2fr 1.4fr 1fr;
      gap: 28px;
    }
    .site-footer h3 {
      font-size: 12px;
      color: var(--fg);
      margin: 0 0 12px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .site-footer ol { margin: 0; padding-left: 18px; display: grid; gap: 7px; line-height: 1.4; }
    .site-footer a { color: var(--primary); text-decoration: none; }
    .site-footer a:hover { text-decoration: underline; }
    .footer-links { list-style: none; margin: 0; padding: 0; display: grid; gap: 9px; }
    .site-footer details { border-bottom: 1px solid var(--border); padding: 8px 0; }
    .site-footer summary { cursor: pointer; color: var(--fg); font-weight: 600; list-style: none; }
    .site-footer summary::-webkit-details-marker { display: none; }
    .site-footer details p { margin: 8px 0 0; line-height: 1.45; color: var(--fg-muted); }
    .footer-bottom {
      max-width: 1100px;
      margin: 24px auto 0;
      padding-top: 16px;
      border-top: 1px solid var(--border);
      font-size: 12px;
      color: var(--fg-subtle);
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      justify-content: space-between;
    }
    @media (max-width: 820px) { .footer-grid { grid-template-columns: 1fr; gap: 22px; } }
    @media (max-width: 640px) { .banner-nav a { display: none; } }
    .layout {
      display: grid;
      grid-template-columns: 420px 1fr;
      gap: 14px;
      height: calc(100vh - 44px);
      padding: 14px;
      box-sizing: border-box;
    }
    .panel {
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--layer);
      overflow: auto;
      min-width: 0;
    }
    .panel h2 {
      margin: 0;
      padding: 12px 14px;
      font-size: 14px;
      border-bottom: 1px solid var(--border);
    }
    .section { padding: 12px 14px; border-bottom: 1px solid var(--border); }
    .section:last-child { border-bottom: 0; }
    .advanced-settings {
      border-bottom: 1px solid var(--border);
    }
    .advanced-settings > summary {
      cursor: pointer;
      padding: 10px 14px;
      color: var(--fg-muted);
      font-size: 12px;
      font-weight: 600;
      list-style: none;
    }
    .advanced-settings[open] > summary {
      border-bottom: 1px solid var(--border);
    }
    .advanced-settings .section {
      border-bottom: 0;
    }
    .run-snapshot {
      position: sticky;
      top: 0;
      z-index: 4;
      border-bottom: 1px solid var(--border);
      background: var(--layer);
      padding: 10px 14px;
      display: grid;
      gap: 8px;
      box-shadow: 0 8px 18px rgba(0, 0, 0, 0.18);
    }
    .run-snapshot-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }
    .run-snapshot-top strong {
      font-size: 13px;
      color: var(--fg);
    }
    .run-snapshot-state {
      border: 1px solid var(--warning);
      border-radius: 999px;
      color: var(--warning-text);
      background: var(--warning-bg);
      padding: 2px 7px;
      font-size: 11px;
      font-weight: 700;
      white-space: nowrap;
    }
    .run-snapshot-state.ready {
      border-color: var(--success);
      color: var(--success-text);
      background: var(--success-bg);
    }
    .run-snapshot-grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 5px;
    }
    .step-title {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      margin-bottom: 8px;
    }
    .step-title strong {
      font-size: 13px;
      color: var(--fg);
    }
    .step-title span {
      color: var(--fg-subtle);
      font-size: 11px;
    }
    label { display: block; font-size: 12px; color: var(--fg-muted); margin: 8px 0 6px; }
    input, select, textarea, button {
      width: 100%;
      box-sizing: border-box;
      border-radius: 6px;
      border: 1px solid var(--border-strong);
      background: var(--field);
      color: var(--fg);
      padding: 8px 10px;
      font-size: 13px;
      letter-spacing: 0;
    }
    textarea { min-height: 120px; resize: vertical; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    button {
      background: var(--primary);
      border-color: var(--primary);
      cursor: pointer;
      font-weight: 600;
    }
    button.secondary { background: var(--layer); border-color: var(--border-strong); }
    button.secondary.active {
      background: var(--primary-active-bg);
      border-color: var(--primary);
      color: var(--fg);
    }
    button:disabled {
      cursor: not-allowed;
      opacity: 0.55;
    }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
    .segmented {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px;
      margin-bottom: 8px;
    }
    .target-presets {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px;
      margin-bottom: 8px;
    }
    .target-filter-row {
      display: grid;
      gap: 4px;
      align-items: center;
      margin-top: 8px;
    }
    .target-filter-count {
      color: var(--fg-muted);
      font-size: 12px;
      white-space: nowrap;
    }
    .quad-actions {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px;
      margin-top: 8px;
    }
    .profiles { max-height: 220px; overflow: auto; border: 1px solid var(--border); border-radius: 6px; padding: 8px; }
    .profile-header {
      display: grid;
      grid-template-columns: 18px 1fr auto;
      gap: 8px;
      align-items: center;
      color: var(--fg-subtle);
      font-size: 11px;
      margin: 8px 0 4px;
      padding: 0 8px;
    }
    .profile {
      display: grid;
      grid-template-columns: 18px 1fr auto;
      align-items: center;
      gap: 8px;
      margin-bottom: 6px;
      font-size: 12px;
    }
    .profile .meta { color: var(--fg-subtle); }
    .profile input[type="checkbox"] { width: 14px; height: 14px; margin: 0; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .status {
      font-size: 13px;
      margin-bottom: 8px;
      color: var(--success-text);
    }
    .status.error { color: var(--danger-text); }
    .gate-decision {
      border: 1px solid var(--border);
      border-radius: 6px;
      background: var(--bg);
      padding: 8px 10px;
      color: var(--fg-muted);
      font-size: 12px;
      font-weight: 700;
    }
    .gate-decision.pass {
      border-color: var(--success);
      background: var(--success-bg);
      color: var(--success-text);
    }
    .gate-decision.fail, .gate-decision.error {
      border-color: var(--danger);
      background: var(--danger-bg);
      color: var(--danger-text);
    }
    .gate-decision.check {
      border-color: var(--warning);
      background: var(--warning-bg);
      color: var(--warning-text);
    }
    .verdict-bar {
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--layer);
      padding: 12px;
      display: grid;
      gap: 4px;
    }
    .verdict-bar.pass { border-color: var(--success); background: var(--success-bg); }
    .verdict-bar.fail, .verdict-bar.error { border-color: var(--danger); background: var(--danger-bg); }
    .verdict-bar.check { border-color: var(--warning); background: var(--warning-bg); }
    .verdict-bar.running { border-color: var(--primary); background: var(--primary-active-bg); }
    .verdict-title {
      font-size: 16px;
      font-weight: 700;
      color: var(--fg);
    }
    .verdict-meta {
      font-size: 12px;
      color: var(--fg-muted);
      line-height: 1.4;
    }
    .hint {
      margin-top: 8px;
      font-size: 12px;
      color: var(--fg-muted);
      line-height: 1.35;
      white-space: pre-line;
    }
    .hint.error {
      color: var(--danger-text);
    }
    .results {
      padding: 12px 14px;
      display: grid;
      grid-template-rows: repeat(5, auto);
      gap: 10px;
      box-sizing: border-box;
    }
    .progress-wrap {
      border: 1px solid var(--border);
      border-radius: 6px;
      background: var(--bg);
      padding: 8px;
      display: grid;
      gap: 6px;
    }
    .progress-track {
      height: 10px;
      border-radius: 999px;
      background: var(--field);
      overflow: hidden;
    }
    .progress-fill {
      height: 100%;
      width: 0%;
      background: var(--primary);
      transition: width 250ms ease;
    }
    .progress-meta {
      font-size: 12px;
      color: var(--fg-muted);
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
      border: 1px solid var(--border);
      background: var(--field);
      color: var(--fg-muted);
    }
    .progress-pill.running { border-color: var(--primary); color: var(--info-text); }
    .progress-pill.pass { border-color: var(--success); color: var(--success-text); }
    .progress-pill.fail, .progress-pill.infra_error { border-color: var(--danger); color: var(--danger-text); }
    .intent-options {
      display: grid;
      gap: 8px;
    }
    .intent-card {
      border: 1px solid var(--border);
      border-radius: 6px;
      background: var(--bg);
      padding: 9px 10px;
      display: grid;
      grid-template-columns: 18px 1fr;
      gap: 8px;
      align-items: start;
      margin: 0;
    }
    .intent-card.active {
      border-color: var(--primary);
      background: var(--primary-active-bg);
    }
    .intent-card.disabled {
      opacity: 0.6;
    }
    .intent-card input {
      width: 14px;
      height: 14px;
      margin: 1px 0 0;
    }
    .intent-label strong {
      display: block;
      font-size: 13px;
      color: var(--fg);
    }
    .intent-label span {
      display: block;
      font-size: 12px;
      color: var(--fg-muted);
      line-height: 1.35;
      margin-top: 2px;
    }
    .matrix-wrap {
      overflow: auto;
      border: 1px solid var(--border);
      border-radius: 6px;
    }
    .matrix-wrap table {
      min-width: 760px;
    }
    .matrix-toolbar {
      border: 1px solid var(--border);
      border-radius: 6px;
      background: var(--bg);
      padding: 8px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      margin-bottom: 8px;
      flex-wrap: wrap;
    }
    .matrix-filter-buttons {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
    }
    .matrix-filter-buttons button {
      width: auto;
      min-width: 86px;
      padding: 6px 8px;
      font-size: 12px;
    }
    .matrix-toolbar-meta {
      color: var(--fg-muted);
      font-size: 12px;
    }
    .matrix-counts {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 8px;
      margin-bottom: 8px;
    }
    .matrix-count {
      border: 1px solid var(--border);
      border-radius: 6px;
      background: var(--bg);
      padding: 8px;
      display: grid;
      gap: 2px;
      min-width: 0;
    }
    .matrix-count strong {
      font-size: 16px;
      color: var(--fg);
    }
    .matrix-count span {
      font-size: 11px;
      color: var(--fg-muted);
    }
    .matrix-count.pass { border-color: var(--success); background: var(--success-bg); }
    .matrix-count.fail, .matrix-count.error { border-color: var(--danger); background: var(--danger-bg); }
    .matrix-count.check { border-color: var(--warning); background: var(--warning-bg); }
    .failure-summary {
      border: 1px solid var(--border);
      border-radius: 6px;
      background: var(--bg);
      padding: 8px 10px;
      display: grid;
      gap: 6px;
      margin-bottom: 8px;
    }
    .failure-summary strong {
      font-size: 12px;
      color: var(--fg);
    }
    .failure-summary ul {
      margin: 0;
      padding-left: 18px;
      display: grid;
      gap: 4px;
      color: var(--fg-muted);
      font-size: 12px;
      line-height: 1.35;
    }
    .matrix-required-fail td {
      background: rgba(250, 77, 86, 0.14);
    }
    .matrix-row-pass td:first-child {
      border-left: 3px solid var(--success);
    }
    .matrix-row-fail td:first-child,
    .matrix-row-error td:first-child,
    .matrix-row-infra_error td:first-child {
      border-left: 3px solid var(--danger);
    }
    .matrix-status-pill {
      display: inline-block;
      min-width: 66px;
      border: 1px solid var(--border-strong);
      border-radius: 999px;
      padding: 2px 8px;
      text-align: center;
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0;
    }
    .matrix-status-pill.pass {
      border-color: var(--success);
      background: var(--success-bg);
      color: var(--success-text);
    }
    .matrix-status-pill.fail,
    .matrix-status-pill.error,
    .matrix-status-pill.infra_error {
      border-color: var(--danger);
      background: var(--danger-bg);
      color: var(--danger-text);
    }
    .matrix-status-pill.running {
      border-color: var(--primary);
      background: var(--primary-active-bg);
      color: var(--info-text);
    }
    .matrix-status-pill.pending { color: var(--fg-subtle); }
    @keyframes bpfPulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.45; } }
    .matrix-status-pill.running { animation: bpfPulse 1.1s ease-in-out infinite; }
    @media (prefers-reduced-motion: reduce) { .matrix-status-pill.running { animation: none; } }
    .live-caption {
      font-size: 12px;
      color: var(--info-text);
      margin-bottom: 6px;
    }
    .example-panel {
      border: 1px dashed var(--border-strong);
      border-radius: 6px;
      padding: 10px;
      display: grid;
      gap: 8px;
    }
    .example-caption {
      font-size: 12px;
      color: var(--fg-subtle);
      line-height: 1.35;
    }
    .example-tag {
      display: inline-block;
      border: 1px solid var(--border-strong);
      border-radius: 999px;
      padding: 1px 7px;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      color: var(--fg-muted);
      margin-right: 6px;
    }
    .ci-mode-panel {
      border: 1px solid var(--border);
      border-radius: 6px;
      background: var(--bg);
      padding: 10px;
      display: grid;
      gap: 7px;
      margin-bottom: 10px;
    }
    .ci-mode-panel strong {
      font-size: 13px;
      color: var(--fg);
    }
    .ci-mode-panel p {
      margin: 0;
      color: var(--fg-muted);
      font-size: 12px;
      line-height: 1.35;
    }
    .ci-mode-pills {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }
    .target-warning {
      color: var(--warning-text);
      margin-top: 2px;
    }
    .gate-readiness {
      border: 1px solid var(--border);
      border-radius: 6px;
      background: var(--bg);
      display: grid;
      gap: 7px;
      padding: 9px;
      margin-bottom: 10px;
    }
    .readiness-item {
      display: grid;
      grid-template-columns: 12px minmax(44px, auto) minmax(0, 1fr);
      gap: 7px;
      align-items: center;
      min-width: 0;
      color: var(--fg-muted);
      font-size: 12px;
    }
    .readiness-item strong {
      color: var(--fg);
      font-size: 12px;
    }
    .readiness-item span:last-child {
      overflow-wrap: anywhere;
      line-height: 1.25;
    }
    .readiness-dot {
      width: 8px;
      height: 8px;
      border-radius: 999px;
      background: var(--warning);
      border: 1px solid var(--warning);
    }
    .readiness-item.ready .readiness-dot {
      background: var(--success);
      border-color: var(--success);
    }
    .readiness-item.blocked .readiness-dot {
      background: var(--danger);
      border-color: var(--danger);
    }
    .suite-preview {
      border: 1px solid var(--border);
      border-radius: 6px;
      background: var(--field);
      padding: 8px;
      margin-top: 8px;
      display: grid;
      gap: 8px;
    }
    .suite-preview table {
      margin-top: 2px;
    }
    .suite-stats {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 7px;
      margin: 8px 0;
    }
    .suite-stat {
      border: 1px solid var(--border);
      border-radius: 6px;
      background: var(--bg);
      padding: 8px;
      display: grid;
      gap: 2px;
      min-width: 0;
    }
    .suite-stat strong {
      font-size: 15px;
      color: var(--fg);
    }
    .suite-stat span {
      font-size: 11px;
      color: var(--fg-muted);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    table {
      border-collapse: collapse;
      width: 100%;
      font-size: 12px;
    }
    th, td {
      border: 1px solid var(--border);
      padding: 6px 7px;
      text-align: left;
      vertical-align: top;
    }
    th { background: var(--layer); }
    pre {
      margin: 0;
      border: 1px solid var(--border);
      border-radius: 6px;
      background: var(--bg);
      padding: 10px;
      overflow: auto;
      font-size: 12px;
      line-height: 1.35;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    .history-table-wrap { max-height: 240px; overflow: auto; border: 1px solid var(--border); border-radius: 6px; }
    .badge { font-size: 11px; padding: 2px 6px; border: 1px solid var(--border); border-radius: 6px; background: var(--layer); color: var(--fg-muted); }
    .split-actions { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 8px; }
    .runtime-flow {
      border: 1px solid var(--border);
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
      border: 1px solid var(--border);
      border-radius: 6px;
      background: var(--field);
      color: var(--fg-subtle);
      font-size: 11px;
      padding: 5px 6px;
      text-align: center;
    }
    .runtime-step.active {
      border-color: var(--primary);
      color: var(--info-text);
      background: var(--primary-active-bg);
    }
    .runtime-step.done {
      border-color: var(--success);
      color: var(--success-text);
      background: var(--success-bg);
    }
    .runtime-step.blocked {
      border-color: var(--danger);
      color: var(--danger-text);
      background: var(--danger-bg);
    }
    .runtime-modes {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 8px;
    }
    .runtime-mode-btn.active {
      background: var(--primary);
      border-color: var(--primary);
      color: var(--fg);
    }
    .runtime-output > summary {
      cursor: pointer;
      font-size: 12px;
      color: var(--fg-muted);
      margin-bottom: 6px;
      list-style: none;
    }
    .result-drilldown {
      border: 1px solid var(--border);
      border-radius: 6px;
      background: var(--layer);
      overflow: hidden;
    }
    .result-drilldown > summary {
      cursor: pointer;
      padding: 9px 10px;
      color: var(--fg-muted);
      font-size: 12px;
      font-weight: 600;
      list-style: none;
      border-bottom: 1px solid var(--border);
    }
    .result-drilldown:not([open]) > summary { border-bottom: 0; }
    .result-drilldown > pre { border: 0; border-radius: 0; }
    .summary-cell-pass { color: var(--success-text); font-weight: 700; }
    .summary-cell-fail, .summary-cell-error, .summary-cell-infra_error { color: var(--danger-text); font-weight: 700; }
    .summary-cell-running { color: var(--info-text); font-weight: 700; }
    .hidden { display: none; }
    .mt8 { margin-top: 8px; }
    .mt10 { margin-top: 10px; }
    .inline-checkbox { width: auto; margin-right: 6px; }
    .clickable-row { cursor: pointer; }
    @media (max-width: 980px) {
      .layout {
        grid-template-columns: 1fr;
        height: auto;
        min-height: calc(100vh - 44px);
      }
      .panel {
        overflow: visible;
      }
      .results {
        height: auto;
        grid-template-rows: auto;
      }
      .matrix-counts {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
      .runtime-steps,
      .runtime-modes {
        grid-template-columns: repeat(2, minmax(0, 1fr)) !important;
      }
    }
    @media (max-width: 560px) {
      .preview-banner {
        padding: 8px 10px;
      }
      .layout {
        padding: 8px;
        gap: 8px;
      }
      .section {
        padding: 10px;
      }
      .run-snapshot-grid,
      .suite-stats,
      .row,
      .segmented,
      .target-presets,
      .quad-actions,
      .matrix-counts,
      .runtime-steps,
      .runtime-modes,
      .split-actions {
        grid-template-columns: 1fr !important;
      }
      .step-title {
        align-items: flex-start;
        flex-direction: column;
        gap: 3px;
      }
      .matrix-wrap table {
        min-width: 620px;
      }
      .verdict-title {
        font-size: 15px;
      }
    }
  
    button:not(.secondary):not(:disabled):hover { background: var(--primary-hover); border-color: var(--primary-hover); }
    button.secondary:not(:disabled):hover { background: var(--layer-hover); border-color: var(--border-strong); }
    input:focus, select:focus, textarea:focus { outline: 2px solid var(--primary); outline-offset: -2px; border-color: var(--primary); }
    a { color: var(--primary); }
</style>
</head>
<body>
  <div class="preview-banner">
    <span>Technical Preview — test your eBPF across real kernels, locally or in CI. Production runtime loading remains disabled in the public demo.</span>
    <nav class="banner-nav">
      <a href="#how-it-works">How it works</a>
      <a href="#faq">FAQ</a>
      <a href="https://github.com/Kernel-Guard/bpfcompat" target="_blank" rel="noopener noreferrer">Source &#8599;</a>
      <button type="button" id="themeToggle" class="theme-toggle" aria-label="Toggle light/dark theme">Light</button>
    </nav>
  </div>
  <div class="layout">
    <div class="panel">
      <h2>BPF Compatibility Gate</h2>
      <div class="run-snapshot">
        <div class="run-snapshot-top">
          <strong>Gate Snapshot</strong>
          <span id="runSnapshotState" class="run-snapshot-state">not ready</span>
        </div>
        <div id="gateReadiness" class="run-snapshot-grid">
          <div id="readyTargets" class="readiness-item">
            <span class="readiness-dot"></span>
            <strong>Targets</strong>
            <span id="readyTargetsText">No targets selected</span>
          </div>
          <div id="readyBPF" class="readiness-item">
            <span class="readiness-dot"></span>
            <strong>BPF</strong>
            <span id="readyBPFText">No object or suite selected</span>
          </div>
          <div id="readyOutput" class="readiness-item">
            <span class="readiness-dot"></span>
            <strong>Gate</strong>
            <span id="readyOutputText">Pass/fail matrix after run</span>
          </div>
        </div>
      </div>
      <div class="section">
        <div class="step-title">
          <strong>1. Select Targets</strong>
          <span>release scope</span>
        </div>
        <div class="target-presets" id="targetPresets">
          <button type="button" class="secondary" data-preset="enterprise-broad">Enterprise</button>
          <button type="button" class="secondary" data-preset="ubuntu-lts">Ubuntu LTS</button>
          <button type="button" class="secondary" data-preset="rhel-like">RHEL / EL</button>
          <button type="button" class="secondary" data-preset="aws">Cloud</button>
          <button type="button" class="secondary" data-preset="custom">Custom</button>
        </div>
        <div id="targetPresetHint" class="hint">Loading target catalog...</div>
        <div class="target-filter-row">
          <input id="targetFilter" placeholder="Filter targets by distro, kernel, or arch">
          <div id="targetFilterCount" class="target-filter-count">0 targets</div>
        </div>
        <div class="profile-header">
          <span>Run</span>
          <span>Kernel / distro profile</span>
          <span>Required</span>
        </div>
        <div id="profiles" class="profiles"></div>
        <div class="quad-actions">
          <button type="button" class="secondary" id="selectAll">Select All</button>
          <button type="button" class="secondary" id="clearAll">Clear All</button>
          <button type="button" class="secondary" id="requireSelected">Require Selected</button>
          <button type="button" class="secondary" id="clearRequired">Clear Required</button>
        </div>
      </div>

      <div class="section">
        <div class="step-title">
          <strong>2. Provide BPF</strong>
          <span>object or collection</span>
        </div>
        <div class="segmented">
          <button type="button" class="secondary active" id="modeSingle">Single object</button>
          <button type="button" class="secondary" id="modeSuite">Object collection</button>
        </div>

        <div id="singleInputMode">
          <label>Artifact Name</label>
          <input id="artifactName" placeholder="execsnoop">
          <label>BPF Input</label>
          <div class="row">
            <button type="button" class="secondary active" id="modeArtifact">Upload .bpf.o</button>
            <button type="button" class="secondary" id="modeSource">Compile Source</button>
          </div>
          <div id="artifactMode">
            <label>Artifact File</label>
            <input id="artifactFile" type="file">
            <div class="hint" id="trySampleHint">
              Don't have a <code>.bpf.o</code>?
              <button type="button" class="secondary" id="trySampleBtn">Try our aegis sample &rarr;</button>
            </div>
          </div>
          <div id="sourceMode" class="hidden">
            <label>Source File</label>
            <input id="sourceFile" type="file">
            <label>Paste Source Code</label>
            <textarea id="sourceCode" placeholder="Paste .bpf.c source"></textarea>
            <label>Clang Flags (optional)</label>
            <input id="clangFlags" placeholder="-DDEBUG=1">
          </div>
        </div>

        <div id="suiteInputMode" class="hidden">
          <div class="ci-mode-panel">
            <strong>Object collection gate</strong>
            <p>Recommended for product releases: one suite lists every BPF object/program, its manifest, gate mode, and optional behavior assertion. CI runs the suite and returns one collection matrix first, then per-object evidence.</p>
            <div class="ci-mode-pills">
              <span class="badge">collection matrix</span>
              <span class="badge">per-object reports</span>
              <span class="badge">self-hosted KVM CI</span>
            </div>
          </div>
          <div id="suiteStats" class="suite-stats"></div>
          <label>Suite YAML File</label>
          <input id="suiteFile" type="file" accept=".yaml,.yml,text/yaml">
          <label>or Paste Suite YAML</label>
          <textarea id="suiteText" placeholder="name: my-bpf-suite
defaults:
  matrix: matrices/dev-one.yaml
  validation_mode: load_attach
cases:
  - name: exec-tracepoint
    artifact: build/exec_tracepoint.bpf.o
    manifest: manifests/exec_tracepoint.yaml
  - name: network-xdp
    artifact: build/network_xdp.bpf.o
    validation_mode: load_only
  - name: exec-behavior
    artifact: build/exec_tracepoint.bpf.o
    test:
      mode: behavior
      command: ./scripts/smoke-exec.sh
      expect:
        exit_code: 0"></textarea>
          <label>Suite Path in CI</label>
          <input id="suitePath" value="suites/project.yaml">
          <div id="suitePreview" class="suite-preview">
            <div class="hint">Paste a suite YAML to preview collection cases and generate GitHub Action configuration.</div>
          </div>
          <label>Local CLI Preview</label>
          <pre id="suiteCliCommand" class="mono">Paste a suite YAML to generate a local suite command.</pre>
          <button type="button" class="secondary mt8" id="copySuiteCli">Copy CLI Command</button>
          <label>GitHub Action Preview</label>
          <pre id="suiteActionYaml" class="mono">Paste a suite YAML to generate a CI snippet.</pre>
          <button type="button" class="secondary mt8" id="copyActionYaml">Copy GitHub Action YAML</button>
        </div>
      </div>

      <details class="advanced-settings">
        <summary>Advanced single-object metadata</summary>
        <div class="section">
          <div class="row">
            <div>
              <label>Artifact Version</label>
              <input id="artifactVersion" placeholder="v1.0.0">
            </div>
            <div>
              <label>Artifact Variant</label>
              <input id="artifactVariant" placeholder="ringbuf-modern">
            </div>
          </div>
          <label>Artifact URI (optional)</label>
          <input id="artifactURI" placeholder="https://object-store.example.com/execsnoop-v1.0.0.bpf.o">
        </div>
      </details>

      <div class="section">
        <div class="step-title">
          <strong>3. Gate Mode</strong>
          <span>load evidence level</span>
        </div>
        <div class="intent-options">
          <label class="intent-card active" id="intentLoadAttach">
            <input type="radio" name="testIntent" value="load_attach" checked>
            <span class="intent-label">
              <strong>Load + attach</strong>
              <span>Default web path: libbpf load plus best-effort attach evidence.</span>
            </span>
          </label>
          <label class="intent-card" id="intentLoadOnly">
            <input type="radio" name="testIntent" value="load_only">
            <span class="intent-label">
              <strong>Load only</strong>
              <span>libbpf load and verifier evidence only; attach and behavior commands are skipped.</span>
            </span>
          </label>
          <label class="intent-card disabled" id="intentBehavior">
            <input type="radio" name="testIntent" value="behavior" disabled>
            <span class="intent-label">
              <strong>Load + attach + behavior command</strong>
              <span>Use suite mode in CI when a collection needs Falco-style event or smoke-test assertions.</span>
            </span>
          </label>
        </div>
        <div id="testIntentHint" class="hint">Load-only checks verifier/kernel compatibility. Load + attach adds hook evidence. Behavior assertions belong in suite manifests and CI.</div>
      </div>

      <details class="advanced-settings">
        <summary>Advanced manifest and run settings</summary>
        <div class="section">
          <label>Manifest File (optional)</label>
          <input id="manifestFile" type="file">
          <label>or Manifest Text</label>
          <textarea id="manifestText" placeholder="name: demo
programs:
  - name: prog
    section: tracepoint/syscalls/sys_enter_execve"></textarea>
          <div id="writeAuthSection" class="hidden">
            <input id="writeApiKey" type="hidden" autocomplete="off">
            <input id="writeIdentityToken" type="hidden" autocomplete="off">
          </div>
          <div id="authHint" class="hint"></div>
          <div class="row">
            <div>
              <label>Timeout</label>
              <input id="timeout" value="8m">
            </div>
            <div>
              <label>Concurrency</label>
              <input id="concurrency" value="2">
            </div>
          </div>
        </div>
      </details>

      <div class="section">
        <div class="step-title">
          <strong>4. Run</strong>
          <span>gate selected targets</span>
        </div>
        <button id="runBtn">Run Compatibility Gate</button>
        <div id="runHint" class="hint">Single-object mode runs here. Collection mode generates CI configuration.</div>
      </div>
    </div>

    <div class="panel">
      <h2>Result Matrix</h2>
      <div class="results">
        <div id="verdictBar" class="verdict-bar neutral">
          <div id="verdictTitle" class="verdict-title">No validation run yet</div>
          <div id="verdictMeta" class="verdict-meta">Select targets, provide a BPF object, then run the gate.</div>
        </div>
        <div id="gateDecision" class="gate-decision">Gate decision will appear after validation.</div>
        <div id="status" class="status">Select target kernels and run validation.</div>
        <div class="progress-wrap">
          <div class="progress-track"><div id="progressFill" class="progress-fill"></div></div>
          <div id="progressMeta" class="progress-meta">0%</div>
          <div id="progressProfiles" class="progress-profiles"></div>
        </div>
        <div id="summary"></div>
        <details class="result-drilldown">
          <summary>Technical JSON report</summary>
          <pre id="resultJson" class="mono">{}</pre>
        </details>

        <details class="result-drilldown" id="evidenceDrilldown">
          <summary>Advanced evidence and history</summary>
          <div class="section">
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
        </details>
      </div>
    </div>
  </div>

  <footer class="site-footer">
    <div class="footer-grid">
      <section id="how-it-works">
        <h3>How it works</h3>
        <ol>
          <li>Provide compiled BPF object(s) and the kernel matrix you ship to.</li>
          <li>Each profile boots as a throwaway QEMU/KVM VM from a clean cloud image — nothing touches a shared host.</li>
          <li>A libbpf validator loads (and optionally attaches) your object inside the guest — real evidence, not a static guess.</li>
          <li>Results roll into a pass/fail matrix with classified reasons; in CI a regression exits non-zero.</li>
        </ol>
      </section>
      <section id="faq">
        <h3>FAQ</h3>
        <details><summary>What does a "pass" mean?</summary><p>The object loaded — and attached, if you chose load+attach — inside a real VM running that exact kernel. It is not a static or heuristic check.</p></details>
        <details><summary>Is my BPF object uploaded or stored?</summary><p>On this public demo it is processed in a disposable VM and only a sanitized report is kept. In your own CI via the GitHub Action, the artifact never leaves your runner.</p></details>
        <details><summary>Which kernels and architectures are covered?</summary><p>A multi-distro 5.x–6.x matrix (Ubuntu, Debian, and more) on x86_64 and ARM64. Each profile records kernel version and BTF availability.</p></details>
        <details><summary>What do classifications like MISSING_BTF mean?</summary><p>They name why an object failed on a kernel — missing BTF, unsupported map/program type, or a CO-RE relocation mismatch — so you know exactly what to fix or fall back to.</p></details>
        <details><summary>Is it open source? Can I self-host?</summary><p>Yes — Apache-2.0. Run it locally with the CLI or in CI with the GitHub Action; no account required.</p></details>
      </section>
      <section>
        <h3>Project</h3>
        <ul class="footer-links">
          <li><a href="https://github.com/Kernel-Guard/bpfcompat" target="_blank" rel="noopener noreferrer">View source on GitHub &#8599;</a></li>
          <li><a href="https://github.com/Kernel-Guard/bpfcompat/tree/main/docs" target="_blank" rel="noopener noreferrer">Documentation &#8599;</a></li>
          <li><a href="https://github.com/marketplace/actions/bpfcompat-ebpf-compatibility-gate" target="_blank" rel="noopener noreferrer">GitHub Action &#8599;</a></li>
          <li><a href="/api/openapi.yaml" target="_blank" rel="noopener noreferrer">OpenAPI spec</a></li>
          <li><a href="https://kernelguard.net/projects/bpfcompat/" target="_blank" rel="noopener noreferrer">kernelguard.net &#8599;</a></li>
        </ul>
      </section>
    </div>
    <div class="footer-bottom">
      <span>bpfcompat — Apache-2.0 · boots real kernels, proves your eBPF loads.</span>
      <span>Technical Preview</span>
    </div>
  </footer>

  <script nonce="__CSP_NONCE__">
    let mode = "artifact";
    let bpfInputMode = "single";
    let selectedPreset = "ubuntu-lts";
    let testIntent = "load_attach";
    const state = { profiles: [], history: [], decisions: [], suite: { name: "", cases: [] }, matrixFilter: "all" };
    let apiConfig = null;
    let runInFlight = false;
    let evidenceLoaded = false;

    const byId = (id) => document.getElementById(id);
    const statusEl = byId("status");
    const verdictBarEl = byId("verdictBar");
    const verdictTitleEl = byId("verdictTitle");
    const verdictMetaEl = byId("verdictMeta");
    const gateDecisionEl = byId("gateDecision");
    const resultJsonEl = byId("resultJson");
    const compareJsonEl = byId("compareJson");
    const decisionJsonEl = byId("decisionJson");
    const runtimeJsonEl = byId("runtimeJson");
    const progressFillEl = byId("progressFill");
    const progressMetaEl = byId("progressMeta");
    const progressProfilesEl = byId("progressProfiles");
    const runBtnEl = byId("runBtn");
    const runHintEl = byId("runHint");
    const targetPresetHintEl = byId("targetPresetHint");
    const targetFilterEl = byId("targetFilter");
    const targetFilterCountEl = byId("targetFilterCount");
    const readyTargetsEl = byId("readyTargets");
    const readyTargetsTextEl = byId("readyTargetsText");
    const readyBPFEl = byId("readyBPF");
    const readyBPFTextEl = byId("readyBPFText");
    const readyOutputEl = byId("readyOutput");
    const readyOutputTextEl = byId("readyOutputText");
    const runSnapshotStateEl = byId("runSnapshotState");
    const suitePreviewEl = byId("suitePreview");
    const suiteActionYamlEl = byId("suiteActionYaml");
    const suiteCliCommandEl = byId("suiteCliCommand");
    const suiteStatsEl = byId("suiteStats");
    const evidenceDrilldownEl = byId("evidenceDrilldown");
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

    function setVerdict(kind, title, meta) {
      verdictBarEl.className = "verdict-bar " + (kind || "neutral");
      verdictTitleEl.textContent = title || "No validation run yet";
      verdictMetaEl.textContent = meta || "";
    }

    function setGateDecision(kind, text) {
      gateDecisionEl.className = "gate-decision " + (kind || "neutral");
      gateDecisionEl.textContent = text || "Gate decision will appear after validation.";
    }

    function setAuthHint(text, error = false) {
      authHintEl.textContent = text || "";
      authHintEl.className = error ? "hint error" : "hint";
    }

    function setRuntimeHint(text, error = false) {
      runtimeHintEl.textContent = text || "";
      runtimeHintEl.className = error ? "hint error" : "hint";
    }

    function setReadinessItem(itemEl, textEl, ready, text) {
      itemEl.classList.remove("ready", "blocked");
      itemEl.classList.add(ready ? "ready" : "blocked");
      textEl.textContent = text;
    }

    function artifactInputStatus() {
      const name = byId("artifactName").value.trim();
      if (mode === "artifact") {
        const file = byId("artifactFile").files[0];
        if (file) {
          return { ready: true, text: (name || file.name.replace(/\.bpf\.o$/i, "")) + " • " + file.name };
        }
        return { ready: false, text: "Upload a compiled .bpf.o" };
      }
      const sourceFile = byId("sourceFile").files[0];
      const sourceText = byId("sourceCode").value.trim();
      if (sourceFile || sourceText) {
        return { ready: true, text: (name || (sourceFile ? sourceFile.name : "source")) + " • source compile" };
      }
      return { ready: false, text: "Add source file or pasted source" };
    }

    function suiteInputStatus() {
      const count = state.suite && state.suite.cases ? state.suite.cases.length : 0;
      if (count > 0) {
        const name = state.suite.name || "collection";
        return { ready: true, text: name + " • " + count + " object case(s)" };
      }
      return { ready: false, text: "Paste collection suite YAML" };
    }

    function updateGateReadiness() {
      const picks = selectedProfiles();
      setReadinessItem(
        readyTargetsEl,
        readyTargetsTextEl,
        picks.include.length > 0,
        picks.include.length + " selected • " + picks.required.length + " required"
      );
      const bpfStatus = bpfInputMode === "suite" ? suiteInputStatus() : artifactInputStatus();
      setReadinessItem(readyBPFEl, readyBPFTextEl, bpfStatus.ready, bpfStatus.text);
      const outputReady = picks.include.length > 0 && bpfStatus.ready;
      const outputText = bpfInputMode === "suite" ? "CI suite summary + matrix" :
        testIntent === "load_only" ? "VM-backed load/verifier matrix" : "VM-backed load + attach matrix";
      setReadinessItem(
        readyOutputEl,
        readyOutputTextEl,
        outputReady,
        outputText
      );
      runSnapshotStateEl.classList.toggle("ready", outputReady);
      runSnapshotStateEl.textContent = outputReady ? "ready" : "not ready";
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
      if (percent > 0 && percent < 100) {
        setVerdict("running", "Running compatibility gate", progressMetaEl.textContent);
      }

      progressProfilesEl.innerHTML = "";
      const statuses = (job && job.profile_statuses) || {};
      renderLiveMatrix(statuses);
    }

    // "Watch it boot": render the per-kernel statuses as a live matrix that
    // fills in cell-by-cell as each disposable VM boots and loads the object.
    // Running cells pulse. Replaced by the full report on completion.
    function renderLiveMatrix(statuses) {
      const container = byId("summary");
      if (!container) return;
      const ids = Object.keys(statuses || {}).sort();
      if (ids.length === 0) return;

      const cap = document.createElement("div");
      cap.className = "live-caption";
      const running = ids.filter((id) => normalizeStatus(statuses[id]) === "running").length;
      const done = ids.filter((id) => ["pass", "fail", "error", "infra_error"].includes(normalizeStatus(statuses[id]))).length;
      cap.textContent = "Booting real kernels in disposable VMs — " + done + "/" + ids.length + " done" + (running ? ", " + running + " loading now…" : "…");

      const wrap = document.createElement("div");
      wrap.className = "matrix-wrap";
      const table = document.createElement("table");
      const thead = document.createElement("thead");
      const headRow = document.createElement("tr");
      ["Target", "Status"].forEach((name) => {
        const th = document.createElement("th");
        th.textContent = name;
        headRow.appendChild(th);
      });
      thead.appendChild(headRow);
      table.appendChild(thead);

      const order = { running: 0, pending: 1, fail: 2, error: 2, infra_error: 2, pass: 3 };
      const tbody = document.createElement("tbody");
      ids.slice().sort((a, b) => {
        const sa = order[normalizeStatus(statuses[a])] ?? 1;
        const sb = order[normalizeStatus(statuses[b])] ?? 1;
        return sa !== sb ? sa - sb : a.localeCompare(b);
      }).forEach((id) => {
        const st = String(statuses[id] || "pending").trim() || "pending";
        const tr = document.createElement("tr");
        tr.classList.add("matrix-row-" + normalizeStatus(st));
        appendCell(tr, id);
        appendStatusCell(tr, st);
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      wrap.appendChild(table);
      container.replaceChildren(cap, wrap);
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

    function setButtonActive(id, active) {
      const el = byId(id);
      if (el) {
        el.classList.toggle("active", !!active);
      }
    }

    function switchMode(nextMode) {
      mode = nextMode;
      byId("artifactMode").style.display = mode === "artifact" ? "block" : "none";
      byId("sourceMode").style.display = mode === "source" ? "block" : "none";
      setButtonActive("modeArtifact", mode === "artifact");
      setButtonActive("modeSource", mode === "source");
      updateGateReadiness();
    }

    function switchTestIntent(nextIntent) {
      if (nextIntent === "behavior") {
        return;
      }
      testIntent = nextIntent === "load_only" ? "load_only" : "load_attach";
      document.querySelectorAll("input[name='testIntent']").forEach((input) => {
        input.checked = input.value === testIntent;
        const card = input.closest(".intent-card");
        if (card) {
          card.classList.toggle("active", input.value === testIntent);
        }
      });
      if (testIntent === "load_only") {
        byId("testIntentHint").textContent = "Load-only mode proves libbpf/verifier compatibility and skips attach attempts and behavior commands.";
      } else {
        byId("testIntentHint").textContent = "Load + attach mode proves libbpf/verifier compatibility plus hook attach evidence.";
      }
      updateGateReadiness();
    }

    function switchBPFInputMode(nextMode) {
      bpfInputMode = nextMode;
      byId("singleInputMode").style.display = bpfInputMode === "single" ? "block" : "none";
      byId("suiteInputMode").style.display = bpfInputMode === "suite" ? "block" : "none";
      setButtonActive("modeSingle", bpfInputMode === "single");
      setButtonActive("modeSuite", bpfInputMode === "suite");
      if (bpfInputMode === "suite") {
        runBtnEl.textContent = "Generate CI Gate";
        runHintEl.textContent = "Collection mode generates the GitHub Action configuration.";
        setStatus("Collection mode selected. Paste suite YAML to preview the BPF object set.");
        setVerdict("neutral", "Collection preview mode", "Use the generated GitHub Action on a self-hosted Linux/KVM runner for real suite execution.");
        setGateDecision("neutral", "CI suite gate preview.");
        updateSuitePreview();
        renderSuiteGatePreview(state.suite);
      } else {
        runBtnEl.textContent = "Run Compatibility Gate";
        runHintEl.textContent = "Single-object mode runs here. Collection mode generates CI configuration.";
        setStatus("Single-object mode selected. Upload or compile one BPF object.");
        setVerdict("neutral", "No validation run yet", "Select targets, provide a BPF object, then run the gate.");
        setGateDecision("neutral", "Gate decision will appear after validation.");
        byId("summary").replaceChildren();
      }
      updateGateReadiness();
    }

    byId("modeSingle").addEventListener("click", () => switchBPFInputMode("single"));
    byId("modeSuite").addEventListener("click", () => switchBPFInputMode("suite"));
    byId("modeArtifact").addEventListener("click", () => switchMode("artifact"));
    byId("modeSource").addEventListener("click", () => switchMode("source"));
    byId("intentLoadAttach").addEventListener("click", () => switchTestIntent("load_attach"));
    byId("intentLoadOnly").addEventListener("click", () => switchTestIntent("load_only"));

    // Inline note under the sample button (created on demand, cleared with "").
    function setTrySampleNote(text) {
      let note = byId("trySampleNote");
      if (!text) {
        if (note) note.remove();
        return;
      }
      if (!note) {
        note = document.createElement("div");
        note.id = "trySampleNote";
        note.className = "meta";
        byId("trySampleHint").appendChild(note);
      }
      note.textContent = text;
    }

    // "Try our aegis sample": load the bundled artifact into the form and run a
    // real validation across a kernel spread that crosses aegis's 5.16 boundary
    // (it uses a bloom-filter map). One click -> artifact filled below -> run.
    byId("trySampleBtn").addEventListener("click", async () => {
      const btn = byId("trySampleBtn");
      const original = btn.textContent;
      btn.disabled = true;
      btn.textContent = "Loading aegis sample...";
      try {
        const res = await fetch("/api/v1/sample/aegis/artifact");
        if (!res.ok) throw new Error("sample unavailable (HTTP " + res.status + ")");
        const blob = await res.blob();
        const file = new File([blob], "aegis.bpf.o", { type: "application/octet-stream" });
        const dt = new DataTransfer();
        dt.items.add(file);
        const input = byId("artifactFile");
        input.files = dt.files;
        input.dispatchEvent(new Event("change", { bubbles: true }));
        byId("artifactName").value = "aegis";

        // Honor an explicit target selection: the curated boundary spread is
        // a teaching default, not an override. Only apply it when the target
        // list is still the untouched default preset (or nothing is checked).
        const picks = selectedProfiles();
        const userCustomizedTargets = selectedPreset !== "ubuntu-lts" && picks.include.length > 0;
        if (userCustomizedTargets) {
          setTrySampleNote("Running the aegis sample on your selected targets. aegis uses a bloom-filter map (kernel >= 5.16), so older kernels are expected to fail - include a 6.x target to see it pass.");
        } else {
          setTrySampleNote("");
          // Reset to a clean slate so only the boundary spread runs (no arm64 /
          // kernel-sweep variants from the default selection).
          document.querySelectorAll("input[data-kind='include']").forEach((x) => { x.checked = false; });
          document.querySelectorAll("input[data-kind='required']").forEach((x) => { x.checked = false; x.disabled = true; });

          // Boundary spread: 5.4/5.15 fail (no bloom map), 6.1/6.8 pass (required).
          const include = ["ubuntu-20.04-5.4", "ubuntu-22.04-5.15", "debian-12-6.1", "ubuntu-24.04-6.8"];
          const required = ["debian-12-6.1", "ubuntu-24.04-6.8"];
          include.forEach((id) => {
            const inc = document.querySelector("input[data-kind='include'][data-id='" + id + "']");
            if (!inc || inc.disabled) return;
            inc.checked = true;
            inc.dispatchEvent(new Event("change", { bubbles: true }));
            if (required.includes(id)) {
              const req = document.querySelector("input[data-kind='required'][data-id='" + id + "']");
              if (req) {
                req.disabled = false;
                req.checked = true;
                req.dispatchEvent(new Event("change", { bubbles: true }));
              }
            }
          });
        }

        btn.textContent = original;
        btn.disabled = false;
        byId("runBtn").click();
      } catch (e) {
        btn.textContent = original;
        btn.disabled = false;
        alert("Could not load the aegis sample: " + e.message);
      }
    });
    runtimeModeButtons.probe.addEventListener("click", () => setRuntimeMode("probe"));
    runtimeModeButtons.select.addEventListener("click", () => setRuntimeMode("select"));
    runtimeModeButtons.fetch.addEventListener("click", () => setRuntimeMode("fetch"));
    runtimeModeButtons.execute.addEventListener("click", () => setRuntimeMode("execute"));

    byId("suiteText").addEventListener("input", updateSuitePreview);
    byId("suitePath").addEventListener("input", updateSuitePreview);
    ["artifactName", "artifactFile", "sourceFile", "sourceCode"].forEach((id) => {
      const el = byId(id);
      if (!el) {
        return;
      }
      el.addEventListener("input", updateGateReadiness);
      el.addEventListener("change", updateGateReadiness);
    });
    byId("suiteFile").addEventListener("change", () => {
      const file = byId("suiteFile").files[0];
      if (!file) {
        return;
      }
      const reader = new FileReader();
      reader.onload = () => {
        byId("suiteText").value = String(reader.result || "");
        updateSuitePreview();
      };
      reader.onerror = () => setStatus("Failed to read suite file", true);
      reader.readAsText(file);
    });
    byId("copyActionYaml").addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(suiteActionYamlEl.textContent || "");
        setStatus("GitHub Action YAML copied");
      } catch (err) {
        setStatus("Copy failed; select the generated YAML manually.", true);
      }
    });
    byId("copySuiteCli").addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(suiteCliCommandEl.textContent || "");
        setStatus("Suite CLI command copied");
      } catch (err) {
        setStatus("Copy failed; select the generated command manually.", true);
      }
    });

    document.querySelectorAll("input[name='testIntent']").forEach((input) => {
      input.addEventListener("change", () => {
        document.querySelectorAll(".intent-card").forEach((card) => card.classList.remove("active"));
        const card = input.closest(".intent-card");
        if (card) {
          card.classList.add("active");
        }
      });
    });

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
      row.dataset.profileSearch = [
        profile.id,
        profile.distro,
        profile.version,
        profile.kernel_family,
        profile.arch,
        profile.transport_note
      ].filter(Boolean).join(" ").toLowerCase();
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
      const profileParts = [];
      if (profile.distro) profileParts.push(profile.distro);
      if (profile.version) profileParts.push(profile.version);
      if (profile.kernel_family) profileParts.push("kernel " + profile.kernel_family);
      if (profile.arch) profileParts.push(profile.arch);
      meta.textContent = profileParts.length > 0 ? profileParts.join(" • ") : "kernel target";
      label.append(title, meta);
      if (!profile.transport_supported || profile.image_cached === false) {
        const reason = document.createElement("div");
        reason.className = "meta target-warning";
        reason.textContent = !profile.transport_supported ? (profile.transport_note || "Unavailable for this run") : "VM image not cached yet";
        label.appendChild(reason);
      }

      const required = document.createElement("input");
      required.type = "checkbox";
      required.checked = !!profile.required_default && !!profile.transport_supported;
      required.disabled = !profile.transport_supported;
      required.dataset.kind = "required";
      required.dataset.id = profile.id;

      include.addEventListener("change", () => {
        selectedPreset = "custom";
        syncTargetPresetButtons();
        required.disabled = !include.checked || !profile.transport_supported;
        if (required.disabled) {
          required.checked = false;
        }
        updateTargetPresetHint();
      });
      required.addEventListener("change", () => {
        selectedPreset = "custom";
        syncTargetPresetButtons();
        updateTargetPresetHint();
      });

      row.append(include, label, required);
      return row;
    }

    function syncTargetPresetButtons() {
      document.querySelectorAll("button[data-preset]").forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.preset === selectedPreset);
      });
    }

    function updateTargetFilter() {
      const filter = targetFilterEl.value.trim().toLowerCase();
      let visible = 0;
      document.querySelectorAll("#profiles .profile").forEach((row) => {
        const match = filter === "" || String(row.dataset.profileSearch || "").includes(filter);
        row.classList.toggle("hidden", !match);
        if (match) {
          visible++;
        }
      });
      const picks = selectedProfiles();
      const total = state.profiles.length;
      const selectedLabel = picks.include.length === 1 ? "selected target" : "selected targets";
      targetFilterCountEl.textContent = visible + "/" + total + " visible • " + picks.include.length + " " + selectedLabel;
    }

    function scrollFirstSelectedProfileIntoView() {
      const firstSelected = document.querySelector("input[data-kind='include']:checked");
      const row = firstSelected ? firstSelected.closest(".profile") : null;
      if (row) {
        const list = byId("profiles");
        const targetTop = row.offsetTop - list.offsetTop - Math.max(0, Math.floor((list.clientHeight - row.clientHeight) / 2));
        list.scrollTop = Math.max(0, targetTop);
      }
    }

    function profileMatchesPreset(profile, preset) {
      const id = String(profile.id || "").toLowerCase();
      const distro = String(profile.distro || "").toLowerCase();
      const version = String(profile.version || "").toLowerCase();
      if (!profile.transport_supported) {
        return false;
      }
      switch (preset) {
        case "ubuntu-lts":
          return distro === "ubuntu" && ["18.04", "20.04", "22.04", "24.04"].includes(version) && !id.includes("minimal");
        case "rhel-like":
          return ["rhel", "rocky", "almalinux", "centos", "centos-stream"].includes(distro);
        case "aws":
          return distro.includes("amazon") || id.includes("amazonlinux") || id.includes("bottlerocket");
        case "enterprise-broad":
          if (distro === "ubuntu") {
            return ["20.04", "22.04", "24.04"].includes(version) && !id.includes("minimal");
          }
          if (distro === "debian") {
            return ["12", "13"].includes(version);
          }
          if (["rhel", "rocky", "almalinux", "centos", "centos-stream"].includes(distro)) {
            return ["8", "9", "10"].includes(version);
          }
          return ["oracle", "oraclelinux", "sles", "opensuse"].includes(distro) || distro.includes("amazon");
        default:
          return false;
      }
    }

    function requiredForPreset(profile, preset, selectedCount) {
      if (!profile.transport_supported) {
        return false;
      }
      if (profile.required_default) {
        return true;
      }
      return selectedCount <= 12;
    }

    function applyTargetPreset(preset) {
      if (preset === "custom") {
        selectedPreset = "custom";
        syncTargetPresetButtons();
        updateTargetPresetHint();
        return;
      }
      selectedPreset = preset;
      targetFilterEl.value = "";
      const selected = state.profiles.filter((profile) => profileMatchesPreset(profile, preset));
      const selectedIDs = new Set(selected.map((profile) => profile.id));
      document.querySelectorAll("input[data-kind='include']").forEach((input) => {
        input.checked = selectedIDs.has(input.dataset.id);
      });
      document.querySelectorAll("input[data-kind='required']").forEach((input) => {
        const profile = state.profiles.find((p) => p.id === input.dataset.id);
        const include = selectedIDs.has(input.dataset.id);
        input.disabled = !include || !profile || !profile.transport_supported;
        input.checked = include && !!profile && requiredForPreset(profile, preset, selected.length);
      });
      syncTargetPresetButtons();
      updateTargetPresetHint();
      scrollFirstSelectedProfileIntoView();
    }

    function updateTargetPresetHint() {
      const picks = selectedProfiles();
      const label = selectedPreset === "enterprise-broad" ? "Enterprise Broad" :
        selectedPreset === "ubuntu-lts" ? "Ubuntu LTS" :
        selectedPreset === "rhel-like" ? "RHEL-like" :
        selectedPreset === "aws" ? "AWS" : "Custom";
      targetPresetHintEl.textContent = label + ": " + picks.include.length + " target(s) selected, " + picks.required.length + " required for the gate.";
      updateTargetFilter();
      updateGateReadiness();
    }

    function appendCell(tr, value, className = "") {
      const td = document.createElement("td");
      td.textContent = String(value);
      if (className) {
        td.className = className;
      }
      tr.appendChild(td);
    }

    function normalizeStatus(status) {
      const normalized = String(status || "").trim().toLowerCase().replace(/[^a-z0-9_]+/g, "_");
      return normalized || "unknown";
    }

    function appendStatusCell(tr, status) {
      const td = document.createElement("td");
      const normalized = normalizeStatus(status);
      const pill = document.createElement("span");
      pill.className = "matrix-status-pill " + normalized;
      pill.textContent = String(status || "-").toUpperCase();
      td.appendChild(pill);
      tr.appendChild(td);
    }

    function appendMatrixCount(container, label, value, className = "") {
      const item = document.createElement("div");
      item.className = "matrix-count" + (className ? " " + className : "");
      const strong = document.createElement("strong");
      strong.textContent = String(value);
      const span = document.createElement("span");
      span.textContent = label;
      item.append(strong, span);
      container.appendChild(item);
    }

    function summaryStatusClass(status) {
      return "summary-cell-" + normalizeStatus(status);
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

    function formatTargetReason(target) {
      if (!target) return "-";
      if (String(target.status || "").toLowerCase() === "pass") return "-";
      if (target.classification_code) return target.classification_code;
      if (target.failed_stage) return target.failed_stage;
      if (target.classification_reason) return target.classification_reason;
      return "failed";
    }

    function formatTargetFailureDetail(target) {
      if (!target) return "failed";
      const code = formatTargetReason(target);
      const reason = String(target.classification_reason || "").trim();
      if (reason && reason !== code) {
        return code + ": " + reason;
      }
      return code;
    }

    function renderFailureSummary(targets) {
      const failures = targets.filter((target) => normalizeStatus(target.status) !== "pass");
      if (failures.length === 0) {
        return null;
      }
      const panel = document.createElement("div");
      panel.className = "failure-summary";
      const title = document.createElement("strong");
      title.textContent = "Failure reasons";
      const list = document.createElement("ul");
      failures.slice(0, 6).forEach((target) => {
        const item = document.createElement("li");
        const required = target.required ? "required" : "optional";
        item.textContent = (target.profile_id || "target") + " (" + required + "): " + formatTargetFailureDetail(target);
        list.appendChild(item);
      });
      if (failures.length > 6) {
        const item = document.createElement("li");
        item.textContent = String(failures.length - 6) + " more failure(s) in the matrix.";
        list.appendChild(item);
      }
      panel.append(title, list);
      return panel;
    }

    function targetMatchesMatrixFilter(target, filter) {
      const status = normalizeStatus(target && target.status);
      switch (filter) {
        case "failures":
          return status !== "pass";
        case "required":
          return !!(target && target.required);
        case "passes":
          return status === "pass";
        default:
          return true;
      }
    }

    function renderMatrixRows(tbody, targets, filter) {
      tbody.replaceChildren();
      const visible = targets.filter((target) => targetMatchesMatrixFilter(target, filter));
      if (visible.length === 0) {
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = 5;
        td.textContent = "No targets match this filter.";
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
      }
      visible.forEach((t) => {
        const tr = document.createElement("tr");
        tr.classList.add("matrix-row-" + normalizeStatus(t.status));
        if (t.required && t.status !== "pass") {
          tr.classList.add("matrix-required-fail");
        }
        appendCell(tr, t.profile_id || "-");
        appendCell(tr, formatProfileEnv(t) + " • " + formatHostKernel(t));
        appendStatusCell(tr, t.status || "-");
        appendCell(tr, t.required ? "yes" : "optional");
        appendCell(tr, formatTargetReason(t));
        tbody.appendChild(tr);
      });
    }

    function renderMatrixToolbar(targets, tbody) {
      const toolbar = document.createElement("div");
      toolbar.className = "matrix-toolbar";
      const buttons = document.createElement("div");
      buttons.className = "matrix-filter-buttons";
      const filters = [
        ["all", "All"],
        ["failures", "Failures"],
        ["required", "Required"],
        ["passes", "Passes"]
      ];
      filters.forEach(([filter, label]) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "secondary";
        button.textContent = label;
        button.classList.toggle("active", state.matrixFilter === filter);
        button.addEventListener("click", () => {
          state.matrixFilter = filter;
          buttons.querySelectorAll("button").forEach((btn) => btn.classList.remove("active"));
          button.classList.add("active");
          renderMatrixRows(tbody, targets, state.matrixFilter);
          meta.textContent = visibleMatrixCount(targets, state.matrixFilter) + "/" + targets.length + " target(s)";
        });
        buttons.appendChild(button);
      });
      const meta = document.createElement("div");
      meta.className = "matrix-toolbar-meta";
      meta.textContent = visibleMatrixCount(targets, state.matrixFilter) + "/" + targets.length + " target(s)";
      toolbar.append(buttons, meta);
      return toolbar;
    }

    function visibleMatrixCount(targets, filter) {
      return targets.filter((target) => targetMatchesMatrixFilter(target, filter)).length;
    }

    function cleanYAMLValue(raw) {
      let value = String(raw || "").trim();
      if ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      return value.trim();
    }

    function suiteSlug(name) {
      const slug = String(name || "bpfcompat-suite").trim().toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
      return slug || "bpfcompat-suite";
    }

    function suiteModeForCase(suite, c) {
      if (c.testMode === "behavior") {
        return "behavior";
      }
      return c.validationMode || suite.defaultMode || "load_attach";
    }

    function suiteCounts(suite) {
      const counts = { cases: 0, loadOnly: 0, loadAttach: 0, behavior: 0, manifests: 0 };
      if (!suite || !suite.cases) {
        return counts;
      }
      counts.cases = suite.cases.length;
      suite.cases.forEach((c) => {
        const mode = suiteModeForCase(suite, c);
        if (mode === "load_only") {
          counts.loadOnly++;
        } else if (mode === "behavior") {
          counts.behavior++;
        } else {
          counts.loadAttach++;
        }
        if (c.manifest) {
          counts.manifests++;
        }
      });
      return counts;
    }

    function appendSuiteStat(label, value) {
      const item = document.createElement("div");
      item.className = "suite-stat";
      const strong = document.createElement("strong");
      strong.textContent = String(value);
      const span = document.createElement("span");
      span.textContent = label;
      item.append(strong, span);
      suiteStatsEl.appendChild(item);
    }

    function renderSuiteStats(suite) {
      suiteStatsEl.replaceChildren();
      const counts = suiteCounts(suite);
      appendSuiteStat("object cases", counts.cases);
      appendSuiteStat("load only", counts.loadOnly);
      appendSuiteStat("load + attach", counts.loadAttach);
      appendSuiteStat("behavior", counts.behavior);
    }

    function parseSuitePreview(text) {
      const suite = { name: "", defaultMode: "", cases: [] };
      let current = null;
      String(text || "").split(/\r?\n/).forEach((line) => {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) {
          return;
        }
        let match = trimmed.match(/^name:\s*(.+)$/);
        if (match && !current && !suite.name) {
          suite.name = cleanYAMLValue(match[1]);
          return;
        }
        match = line.match(/^\s+validation_mode:\s*(.+)$/);
        if (match && !current) {
          suite.defaultMode = cleanYAMLValue(match[1]);
          return;
        }
        match = line.match(/^\s*-\s+name:\s*(.+)$/);
        if (match) {
          current = { name: cleanYAMLValue(match[1]), artifact: "", manifest: "", artifactName: "", validationMode: "", testMode: "", testCommand: "" };
          suite.cases.push(current);
          return;
        }
        if (!current) {
          return;
        }
        match = line.match(/^\s+(artifact|manifest|artifact_name|validation_mode|mode|command):\s*(.+)$/);
        if (!match) {
          return;
        }
        const key = match[1];
        const value = cleanYAMLValue(match[2]);
        if (key === "artifact") {
          current.artifact = value;
        } else if (key === "manifest") {
          current.manifest = value;
        } else if (key === "artifact_name") {
          current.artifactName = value;
        } else if (key === "validation_mode") {
          current.validationMode = value;
        } else if (key === "mode") {
          current.testMode = value;
        } else if (key === "command") {
          current.testCommand = value;
        }
      });
      return suite;
    }

    function generateSuiteActionYAML(suite) {
      const suitePath = byId("suitePath").value.trim() || "suites/project.yaml";
      const suiteName = suite && suite.name ? suite.name : "bpf-compatibility";
      return [
        "name: BPF compatibility",
        "",
        "on:",
        "  pull_request:",
        "  push:",
        "    branches: [main]",
        "",
        "jobs:",
        "  bpfcompat:",
        "    name: " + suiteName,
        "    runs-on: [self-hosted, linux, x64, kvm]",
        "    steps:",
        "      - uses: actions/checkout@v4",
        "      - uses: Kernel-Guard/bpfcompat@v0.1.3",
        "        with:",
        "          suite: " + suitePath,
        "          suite-out: reports/bpfcompat-suite.json",
        "          suite-markdown: reports/bpfcompat-suite.md",
        "          timeout: 8m",
        "          concurrency: \"1\""
      ].join("\n");
    }

    function generateSuiteCLICommand(suite) {
      const suitePath = byId("suitePath").value.trim() || "suites/project.yaml";
      const slug = suiteSlug(suite && suite.name);
      return [
        "make validator-static",
        "",
        "./bin/bpfcompat suite \\",
        "  --suite " + suitePath + " \\",
        "  --out reports/suites/" + slug + "/suite.json \\",
        "  --markdown reports/suites/" + slug + "/suite.md \\",
        "  --timeout 8m \\",
        "  --concurrency 1"
      ].join("\n");
    }

    function renderSuiteGatePreview(suite) {
      const container = byId("summary");
      const counts = suiteCounts(suite);
      const countCards = document.createElement("div");
      countCards.className = "matrix-counts";
      appendMatrixCount(countCards, "object cases", counts.cases);
      appendMatrixCount(countCards, "load only", counts.loadOnly);
      appendMatrixCount(countCards, "load + attach", counts.loadAttach);
      appendMatrixCount(countCards, "behavior", counts.behavior);

      if (!suite || !suite.cases || suite.cases.length === 0) {
        const note = document.createElement("div");
        note.className = "failure-summary";
        const title = document.createElement("strong");
        title.textContent = "Collection gate";
        const list = document.createElement("ul");
        const item = document.createElement("li");
        item.textContent = "Paste suite YAML with cases[].name and cases[].artifact to preview the BPF object collection.";
        list.appendChild(item);
        note.append(title, list);
        container.replaceChildren(countCards, note);
        return;
      }

      const wrap = document.createElement("div");
      wrap.className = "matrix-wrap";
      const table = document.createElement("table");
      const thead = document.createElement("thead");
      const headRow = document.createElement("tr");
      ["Case", "Mode", "Artifact", "Manifest", "Behavior"].forEach((name) => {
        const th = document.createElement("th");
        th.textContent = name;
        headRow.appendChild(th);
      });
      thead.appendChild(headRow);
      table.appendChild(thead);
      const tbody = document.createElement("tbody");
      suite.cases.forEach((c) => {
        const tr = document.createElement("tr");
        appendCell(tr, c.artifactName || c.name || "-");
        appendCell(tr, suiteModeForCase(suite, c));
        appendCell(tr, c.artifact || "-");
        appendCell(tr, c.manifest || "-");
        appendCell(tr, suiteModeForCase(suite, c) === "behavior" ? (c.testCommand || "behavior command") : "-");
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      wrap.appendChild(table);
      container.replaceChildren(countCards, wrap);
    }

    function updateSuitePreview() {
      const suite = parseSuitePreview(byId("suiteText").value);
      state.suite = suite;
      renderSuiteStats(suite);
      suitePreviewEl.replaceChildren();
      const title = document.createElement("div");
      title.className = "hint";
      if (suite.cases.length === 0) {
        title.textContent = "No suite cases detected yet. Paste a suite YAML with cases[].name and cases[].artifact.";
        suitePreviewEl.appendChild(title);
      } else {
        title.textContent = "Suite " + (suite.name || "unnamed") + ": " + suite.cases.length + " BPF object case(s).";
        suitePreviewEl.appendChild(title);
        const table = document.createElement("table");
        const thead = document.createElement("thead");
        const headRow = document.createElement("tr");
        ["Case", "Mode", "Artifact", "Manifest", "Behavior"].forEach((name) => {
          const th = document.createElement("th");
          th.textContent = name;
          headRow.appendChild(th);
        });
        thead.appendChild(headRow);
        table.appendChild(thead);
        const tbody = document.createElement("tbody");
        suite.cases.forEach((c) => {
          const tr = document.createElement("tr");
          const mode = suiteModeForCase(suite, c);
          appendCell(tr, c.artifactName || c.name || "-");
          appendCell(tr, mode);
          appendCell(tr, c.artifact || "-");
          appendCell(tr, c.manifest || "-");
          appendCell(tr, c.testMode === "behavior" ? (c.testCommand || "behavior command") : "-");
          tbody.appendChild(tr);
        });
        table.appendChild(tbody);
        suitePreviewEl.appendChild(table);
      }
      suiteActionYamlEl.textContent = generateSuiteActionYAML(suite);
      suiteCliCommandEl.textContent = generateSuiteCLICommand(suite);
      if (bpfInputMode === "suite") {
        renderSuiteGatePreview(suite);
      }
      updateGateReadiness();
    }

    async function loadProfiles() {
      const data = await requestJSON("/api/profiles");
      state.profiles = data.profiles || [];

      const container = byId("profiles");
      container.innerHTML = "";
      state.profiles.forEach((p) => container.appendChild(createProfileRow(p)));
      applyTargetPreset("ubuntu-lts");
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
      const targetCount = report.targets.length;
      const requiredFailed = report.targets.filter((t) => t.required && t.status !== "pass").length;
      const requiredPassed = report.targets.filter((t) => t.required && t.status === "pass").length;
      const optionalFailed = report.targets.filter((t) => !t.required && t.status !== "pass").length;
      let verdictKind = "pass";
      let verdictTitle = "PASS: all required targets passed";
      if (requiredFailed > 0) {
        verdictKind = "fail";
        verdictTitle = "FAIL: " + requiredFailed + " required target(s) failed";
      } else if (optionalFailed > 0) {
        verdictKind = "check";
        verdictTitle = "CHECK: optional target failure(s) found";
      }
      const verdictMeta = targetCount + " target(s) checked. Required pass/fail: " + requiredPassed + "/" + requiredFailed + ". Optional failures: " + optionalFailed + ".";
      setVerdict(verdictKind, verdictTitle, verdictMeta);
      if (requiredFailed > 0) {
        setGateDecision("fail", "Do not ship: " + requiredFailed + " required target(s) failed.");
      } else if (optionalFailed > 0) {
        setGateDecision("check", "Required targets passed. Review " + optionalFailed + " optional failure(s).");
      } else {
        setGateDecision("pass", "Ship candidate: all selected targets passed.");
      }

      const counts = document.createElement("div");
      counts.className = "matrix-counts";
      appendMatrixCount(counts, "required passed", requiredPassed, "pass");
      appendMatrixCount(counts, "required failed", requiredFailed, requiredFailed > 0 ? "fail" : "pass");
      appendMatrixCount(counts, "optional failed", optionalFailed, optionalFailed > 0 ? "check" : "pass");
      appendMatrixCount(counts, "targets checked", targetCount);

      const wrap = document.createElement("div");
      wrap.className = "matrix-wrap";
      const table = document.createElement("table");
      const thead = document.createElement("thead");
      const headRow = document.createElement("tr");
      ["Target", "Distro / kernel", "Pass/Fail", "Required", "Reason"].forEach((name) => {
        const th = document.createElement("th");
        th.textContent = name;
        headRow.appendChild(th);
      });
      thead.appendChild(headRow);
      table.appendChild(thead);

      const tbody = document.createElement("tbody");
      const targets = Array.from(report.targets).sort((a, b) => {
        const aRequiredFail = a.required && a.status !== "pass";
        const bRequiredFail = b.required && b.status !== "pass";
        if (aRequiredFail !== bRequiredFail) return aRequiredFail ? -1 : 1;
        const aFail = a.status !== "pass";
        const bFail = b.status !== "pass";
        if (aFail !== bFail) return aFail ? -1 : 1;
        return String(a.profile_id || "").localeCompare(String(b.profile_id || ""));
      });
      renderMatrixRows(tbody, targets, state.matrixFilter);
      table.appendChild(tbody);
      wrap.appendChild(table);
      const failureSummary = renderFailureSummary(targets);
      if (failureSummary) {
        container.replaceChildren(counts, failureSummary, renderMatrixToolbar(targets, tbody), wrap);
      } else {
        container.replaceChildren(counts, renderMatrixToolbar(targets, tbody), wrap);
      }
    }

    // Empty-state hero: before any run, show a clearly-labelled example matrix so
    // first-time visitors immediately see the payoff (the actual deliverable).
    // Mirrors the real Falco modern_bpf boundary (5.4 ringbuf) so it doubles as
    // honest, representative output. Cleared as soon as a real run starts.
    function renderExampleMatrix() {
      const container = byId("summary");
      if (!container || container.children.length) return;
      const rows = [
        { p: "ubuntu-24.04-6.8", e: "ubuntu 24.04 • 6.8.0", s: "pass", r: true, why: "loaded + attached" },
        { p: "debian-12-6.1", e: "debian 12 • 6.1.0", s: "pass", r: true, why: "loaded + attached" },
        { p: "ubuntu-22.04-5.15", e: "ubuntu 22.04 • 5.15.0", s: "pass", r: true, why: "loaded + attached" },
        { p: "debian-11-5.10", e: "debian 11 • 5.10.0", s: "partial", r: false, why: "loaded; attach limited" },
        { p: "ubuntu-20.04-5.4", e: "ubuntu 20.04 • 5.4.0", s: "fail", r: false, why: "UNSUPPORTED_MAP_TYPE: ringbuf needs ≥ 5.8" }
      ];

      const panel = document.createElement("div");
      panel.className = "example-panel";

      const cap = document.createElement("div");
      cap.className = "example-caption";
      const tag = document.createElement("span");
      tag.className = "example-tag";
      tag.textContent = "Example output";
      cap.appendChild(tag);
      cap.appendChild(document.createTextNode("This is what a gate run produces. Pick targets, drop a .bpf.o, and run to generate your own — or run this live in one click:"));
      const runLive = document.createElement("button");
      runLive.type = "button";
      runLive.className = "secondary example-run-btn";
      runLive.textContent = "Run this example live ▸";
      runLive.addEventListener("click", () => {
        const b = byId("trySampleBtn");
        if (b) b.click();
      });
      cap.appendChild(document.createElement("br"));
      cap.appendChild(runLive);

      const counts = document.createElement("div");
      counts.className = "matrix-counts";
      appendMatrixCount(counts, "required passed", 3, "pass");
      appendMatrixCount(counts, "required failed", 0, "pass");
      appendMatrixCount(counts, "optional failed", 1, "check");
      appendMatrixCount(counts, "targets checked", 5);

      const wrap = document.createElement("div");
      wrap.className = "matrix-wrap";
      const table = document.createElement("table");
      const thead = document.createElement("thead");
      const headRow = document.createElement("tr");
      ["Target", "Distro / kernel", "Pass/Fail", "Required", "Reason"].forEach((name) => {
        const th = document.createElement("th");
        th.textContent = name;
        headRow.appendChild(th);
      });
      thead.appendChild(headRow);
      table.appendChild(thead);

      const tbody = document.createElement("tbody");
      rows.forEach((t) => {
        const tr = document.createElement("tr");
        tr.classList.add("matrix-row-" + normalizeStatus(t.s));
        if (t.r && t.s !== "pass") {
          tr.classList.add("matrix-required-fail");
        }
        appendCell(tr, t.p);
        appendCell(tr, t.e);
        appendStatusCell(tr, t.s);
        appendCell(tr, t.r ? "yes" : "optional");
        appendCell(tr, t.why);
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      wrap.appendChild(table);

      panel.replaceChildren(cap, counts, wrap);
      container.replaceChildren(panel);
    }

    document.querySelectorAll("button[data-preset]").forEach((btn) => {
      btn.addEventListener("click", () => applyTargetPreset(btn.dataset.preset));
    });
    targetFilterEl.addEventListener("input", updateTargetFilter);

    byId("selectAll").addEventListener("click", () => {
      selectedPreset = "custom";
      syncTargetPresetButtons();
      document.querySelectorAll("input[data-kind='include']").forEach((x) => {
        x.checked = x.dataset.transportSupported === "true";
      });
      document.querySelectorAll("input[data-kind='required']").forEach((x) => {
        const include = document.querySelector("input[data-kind='include'][data-id='" + x.dataset.id + "']");
        x.disabled = !include || !include.checked;
      });
      updateTargetPresetHint();
    });
    byId("clearAll").addEventListener("click", () => {
      selectedPreset = "custom";
      syncTargetPresetButtons();
      document.querySelectorAll("input[data-kind='include']").forEach((x) => (x.checked = false));
      document.querySelectorAll("input[data-kind='required']").forEach((x) => {
        x.checked = false;
        x.disabled = true;
      });
      updateTargetPresetHint();
    });
    byId("requireSelected").addEventListener("click", () => {
      selectedPreset = "custom";
      syncTargetPresetButtons();
      const picks = selectedProfiles();
      document.querySelectorAll("input[data-kind='required']").forEach((x) => {
        if (picks.include.includes(x.dataset.id) && !x.disabled) {
          x.checked = true;
        }
      });
      updateTargetPresetHint();
    });
    byId("clearRequired").addEventListener("click", () => {
      selectedPreset = "custom";
      syncTargetPresetButtons();
      document.querySelectorAll("input[data-kind='required']").forEach((x) => (x.checked = false));
      updateTargetPresetHint();
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
      if (bpfInputMode === "suite") {
        updateSuitePreview();
        const count = state.suite.cases.length;
        if (count === 0) {
        setStatus("Paste a suite YAML before generating a CI gate.", true);
        setVerdict("error", "Collection needs object cases", "Add cases with name and artifact fields, then use the generated GitHub Action.");
          setGateDecision("error", "Blocked: suite has no cases.");
          return;
        }
        setStatus("Suite preview ready. Run this collection through the generated GitHub Action.");
        setVerdict("neutral", "CI suite gate generated", count + " BPF object case(s) ready for self-hosted Linux/KVM execution.");
        setGateDecision("neutral", "Ready for CI: " + count + " object case(s).");
        renderSuiteGatePreview(state.suite);
        return;
      }
      if (runInFlight) {
        setStatus("Validation already running. Please wait.");
        return;
      }
      runInFlight = true;
      runBtnEl.disabled = true;
      try {
        refreshAuthHintFromConfig();
        if (apiConfig && !apiConfig.allow_anonymous_write && !apiConfig.allow_anonymous_validate && !hasWriteCredentials()) {
          throw new Error("Validation is not open on this server. Use the public Results page or run the CLI locally.");
        }
        resetProgress();
        byId("summary").replaceChildren();
        setStatus("Starting validation...");
        setVerdict("running", "Running compatibility gate", "Validating selected targets. Required failures will be shown first.");
        setGateDecision("neutral", "Running selected target matrix.");
        const fd = new FormData();

        fd.append("artifact_name", byId("artifactName").value.trim());
        fd.append("artifact_version", byId("artifactVersion").value.trim());
        fd.append("artifact_variant", byId("artifactVariant").value.trim());
        fd.append("artifact_uri", byId("artifactURI").value.trim());
        fd.append("validation_mode", testIntent);
        fd.append("timeout", byId("timeout").value.trim());
        fd.append("concurrency", byId("concurrency").value.trim());

        if (mode === "artifact") {
          if (byId("artifactFile").files[0]) {
            fd.append("artifact_file", byId("artifactFile").files[0]);
          } else {
            throw new Error("Choose a compiled BPF object (.bpf.o) to validate, or switch to the source tab.");
          }
        } else {
          if (byId("sourceFile").files[0]) {
            fd.append("source_file", byId("sourceFile").files[0]);
          }
          if (byId("sourceCode").value.trim()) {
            fd.append("source_code", byId("sourceCode").value);
          }
          if (!byId("sourceFile").files[0] && !byId("sourceCode").value.trim()) {
            throw new Error("Provide BPF source (upload a .c file or paste source code) before running.");
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
        if (evidenceDrilldownEl.open) {
          try {
            await refreshHistory();
          } catch (historyErr) {
            compareJsonEl.textContent = JSON.stringify({ warning: String(historyErr) }, null, 2);
          }
        }
      } catch (err) {
        setStatus(String(err), true);
        setVerdict("error", "Validation could not complete", String(err));
        setGateDecision("error", "Blocked: validation did not complete.");
      } finally {
        runInFlight = false;
        runBtnEl.disabled = false;
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

    async function loadEvidenceIfNeeded() {
      if (!evidenceDrilldownEl.open || evidenceLoaded) {
        return;
      }
      evidenceLoaded = true;
      try {
        await refreshHistory();
      } catch (historyErr) {
        compareJsonEl.textContent = JSON.stringify({ warning: String(historyErr) }, null, 2);
      }
      try {
        await refreshDecisionHistory();
      } catch (decisionErr) {
        decisionJsonEl.textContent = JSON.stringify({ warning: String(decisionErr) }, null, 2);
      }
    }

    byId("refreshHistory").addEventListener("click", async () => {
      try {
        evidenceLoaded = true;
        await refreshHistory();
        setStatus("History refreshed");
      } catch (err) {
        setStatus(String(err), true);
      }
    });

    byId("refreshDecisions").addEventListener("click", async () => {
      try {
        evidenceLoaded = true;
        await refreshDecisionHistory();
        setStatus("Runtime decisions refreshed");
      } catch (err) {
        setStatus(String(err), true);
      }
    });
    evidenceDrilldownEl.addEventListener("toggle", loadEvidenceIfNeeded);

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

    function setTheme(theme) {
      const light = theme === "light";
      if (light) {
        document.documentElement.setAttribute("data-theme", "light");
      } else {
        document.documentElement.removeAttribute("data-theme");
      }
      try { localStorage.setItem("bpfcompat-theme", light ? "light" : "dark"); } catch (e) {}
      const btn = byId("themeToggle");
      if (btn) btn.textContent = light ? "Dark" : "Light";
    }
    function initTheme() {
      let stored = "dark";
      try { stored = localStorage.getItem("bpfcompat-theme") || "dark"; } catch (e) {}
      setTheme(stored);
      const btn = byId("themeToggle");
      if (btn) {
        btn.addEventListener("click", () => {
          const isLight = document.documentElement.getAttribute("data-theme") === "light";
          setTheme(isLight ? "dark" : "light");
        });
      }
    }

    (async () => {
      try {
        initTheme();
        resetProgress();
        await refreshAPIConfig();
        await loadProfiles();
        updateSuitePreview();
        switchMode("artifact");
        switchBPFInputMode("single");
        setRuntimeMode("probe");
        renderExampleMatrix();
      } catch (err) {
        setStatus(String(err), true);
      }
    })();
  </script>
</body>
</html>`

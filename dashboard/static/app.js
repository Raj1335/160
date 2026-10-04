const tabs = [...document.querySelectorAll(".source-tab")];
const demoSelect = document.querySelector("#demo-select");
const demoMeta = document.querySelector("#demo-meta");
const fileInput = document.querySelector("#capture-file");
const dropZone = document.querySelector("#drop-zone");
const dropTitle = document.querySelector("#drop-title");
const dropSubtitle = document.querySelector("#drop-subtitle");
const analyzeButton = document.querySelector("#analyze-button");
const errorMessage = document.querySelector("#error-message");
const loadingState = document.querySelector("#loading-state");
const results = document.querySelector("#results");
let activeSource = "demo";
let reportContents = "";

async function loadDemoCaptures() {
  try {
    const response = await fetch("/api/demo-captures");
    if (!response.ok) throw new Error("Could not load bundled demo captures.");
    const { captures } = await response.json();
    demoSelect.replaceChildren();
    if (!captures.length) {
      const empty = new Option("No verified demo captures available", "");
      demoSelect.add(empty);
      demoMeta.lastElementChild.textContent = "Upload a capture to get started";
      updateButtonState();
      return;
    }
    for (const capture of captures) {
      const option = new Option(
        `${capture.traffic_type.toUpperCase()}  /  ${capture.profile.replaceAll("-", " ")}`,
        capture.name,
      );
      demoSelect.add(option);
    }
    updateButtonState();
  } catch (error) {
    showError(error.message);
    demoSelect.replaceChildren(new Option("Demo captures unavailable", ""));
    updateButtonState();
  }
}

function updateButtonState() {
  analyzeButton.disabled = activeSource === "demo"
    ? !demoSelect.value
    : !fileInput.files.length;
}

function showError(message) {
  errorMessage.textContent = message;
  errorMessage.classList.remove("hidden");
}

function clearError() {
  errorMessage.textContent = "";
  errorMessage.classList.add("hidden");
}

function setBusy(isBusy) {
  analyzeButton.disabled = isBusy;
  analyzeButton.classList.toggle("busy", isBusy);
  analyzeButton.querySelector("span:first-child").textContent = isBusy
    ? "Analyzing capture…"
    : "Analyze capture";
  loadingState.classList.toggle("hidden", !isBusy);
  if (isBusy) results.classList.add("hidden");
}

function displayFact(label, value, source) {
  const item = document.createElement("div");
  item.className = "fact-item";
  const heading = document.createElement("span");
  heading.className = "fact-label";
  heading.textContent = label.replaceAll("_", " ");
  const content = document.createElement("span");
  content.className = "fact-value";
  content.textContent = value === null || value === undefined || value === ""
    ? "Not observable"
    : String(value);
  item.append(heading, content);
  if (source) {
    const provenance = document.createElement("span");
    provenance.className = "fact-source";
    provenance.textContent = source;
    item.append(provenance);
  }
  return item;
}

function renderFindings(findings) {
  const container = document.querySelector("#findings-list");
  const count = document.querySelector("#finding-count");
  container.replaceChildren();
  count.textContent = String(findings.length);
  if (!findings.length) {
    const empty = document.createElement("div");
    empty.className = "empty-findings";
    empty.innerHTML = '<span class="empty-check" aria-hidden="true">✓</span><span>No configured rules were triggered by the observed evidence.</span>';
    container.append(empty);
    return;
  }
  for (const finding of findings) {
    const card = document.createElement("article");
    card.className = "finding-card";
    const indicator = document.createElement("span");
    indicator.className = `finding-indicator ${finding.severity || ""}`;
    const content = document.createElement("div");
    const title = document.createElement("p");
    title.className = "finding-title";
    const id = document.createElement("span");
    id.textContent = finding.id;
    const severity = document.createElement("span");
    severity.className = `severity-label ${finding.severity || ""}`;
    severity.textContent = (finding.severity || "unknown").toUpperCase();
    title.append(id, severity);
    const message = document.createElement("p");
    message.className = "finding-message";
    message.textContent = finding.message;
    content.append(title, message);
    card.append(indicator, content);
    container.append(card);
  }
}

function renderCoverage(coverage, rules) {
  const segments = document.querySelector("#coverage-segments");
  const legend = document.querySelector("#coverage-legend");
  segments.replaceChildren();
  legend.replaceChildren();
  const pass = coverage.pass || 0;
  const fail = coverage.fail || 0;
  const unknown = coverage.not_observable || 0;
  document.querySelector("#coverage-value").textContent =
    `${coverage.observed || 0} / ${coverage.total || 0} observed`;
  for (const rule of rules) {
    const segment = document.createElement("span");
    segment.className = `coverage-segment ${rule.status === "PASS" ? "pass" : rule.status === "FAIL" ? "fail" : ""}`;
    segment.title = `${rule.id}: ${rule.status}`;
    segments.append(segment);
  }
  for (const [name, value, style] of [
    ["Pass", pass, "pass"],
    ["Findings", fail, "fail"],
    ["Unknown", unknown, ""],
  ]) {
    const item = document.createElement("span");
    item.className = "legend-item";
    const dot = document.createElement("i");
    dot.className = `legend-dot ${style}`;
    const text = document.createElement("span");
    text.textContent = `${name} ${value}`;
    item.append(dot, text);
    legend.append(item);
  }
}

function renderResults(data) {
  document.querySelector("#result-title").textContent = data.label;
  document.querySelector("#score-value").textContent = String(data.security_score ?? "—");
  const score = Number(data.security_score ?? 0);
  const grade = data.grade || "—";
  const badge = document.querySelector("#grade-badge");
  badge.textContent = grade;
  badge.className = `grade-badge grade-${grade.toLowerCase()}`;
  const fill = document.querySelector("#score-fill");
  fill.style.width = `${Math.min(100, Math.max(0, score))}%`;
  fill.className = score < 40 ? "score-low" : score <= 70 ? "score-mid" : "";
  renderFindings(data.findings || []);
  renderCoverage(data.coverage || {}, data.rule_results || []);

  const facts = data.ike_facts || {};
  document.querySelector("#ike-version").textContent = facts.ike_version || "IKE —";
  const factFields = [
    ["Exchange mode", "ike_exchange_mode"],
    ["Tunnel mode", "mode"],
    ["IKE cipher", "encryption_algorithm"],
    ["ESP cipher", "esp_encryption_algorithm"],
    ["Integrity", "esp_integrity_algorithm"],
    ["Key exchange", "dh_group"],
    ["PFS", "pfs_enabled"],
    ["SA lifetime", "sa_lifetime_seconds"],
  ];
  const grid = document.querySelector("#facts-grid");
  grid.replaceChildren();
  for (const [label, key] of factFields) {
    grid.append(displayFact(label, facts[key], facts.fact_sources?.[key]));
  }

  const warnings = document.querySelector("#warnings-box");
  warnings.replaceChildren();
  const warningList = facts.parse_warnings || [];
  if (warningList.length) {
    const heading = document.createElement("strong");
    heading.textContent = "PARSER NOTES";
    const list = document.createElement("ul");
    for (const warning of warningList) {
      const item = document.createElement("li");
      item.textContent = warning;
      list.append(item);
    }
    warnings.append(heading, list);
    warnings.classList.remove("hidden");
  } else {
    warnings.classList.add("hidden");
  }
  reportContents = data.report_html || "";
  results.classList.remove("hidden");
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function analyzeCapture() {
  clearError();
  setBusy(true);
  try {
    let response;
    if (activeSource === "demo") {
      response = await fetch(`/api/demo/${encodeURIComponent(demoSelect.value)}`, {
        method: "POST",
      });
    } else {
      const formData = new FormData();
      formData.append("file", fileInput.files[0]);
      response = await fetch("/api/analyze", { method: "POST", body: formData });
    }
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || "Analysis failed.");
    renderResults(result);
  } catch (error) {
    showError(error.message || "Could not reach the analysis service. Please try again.");
  } finally {
    setBusy(false);
    updateButtonState();
  }
}

for (const tab of tabs) {
  tab.addEventListener("click", () => {
    activeSource = tab.id === "tab-demo" ? "demo" : "upload";
    for (const item of tabs) {
      const active = item === tab;
      item.classList.toggle("active", active);
      item.setAttribute("aria-selected", String(active));
    }
    document.querySelector("#panel-demo").classList.toggle("hidden", activeSource !== "demo");
    document.querySelector("#panel-upload").classList.toggle("hidden", activeSource !== "upload");
    clearError();
    updateButtonState();
  });
}

demoSelect.addEventListener("change", () => {
  const name = demoSelect.value;
  if (name) demoMeta.lastElementChild.textContent = `${name} · SHA-256-bound testbed capture`;
  updateButtonState();
});
fileInput.addEventListener("change", () => {
  const file = fileInput.files[0];
  if (file) {
    dropTitle.textContent = file.name;
    dropSubtitle.textContent = `${(file.size / (1024 * 1024)).toFixed(2)} MB · ready to analyze`;
  }
  updateButtonState();
});
for (const eventName of ["dragenter", "dragover"]) {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.add("dragging");
  });
}
for (const eventName of ["dragleave", "drop"]) {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.remove("dragging");
  });
}
dropZone.addEventListener("drop", (event) => {
  const files = event.dataTransfer?.files;
  if (!files?.length) return;
  const transfer = new DataTransfer();
  transfer.items.add(files[0]);
  fileInput.files = transfer.files;
  fileInput.dispatchEvent(new Event("change", { bubbles: true }));
});
analyzeButton.addEventListener("click", analyzeCapture);
document.querySelector("#download-report").addEventListener("click", () => {
  if (!reportContents) return;
  const blob = new Blob([reportContents], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "ipsec-analysis-report.html";
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
});

loadDemoCaptures();

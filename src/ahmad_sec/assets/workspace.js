"use strict";

const byId = (id) => document.getElementById(id);
const SVG_NS = "http://www.w3.org/2000/svg";
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const LIMIT_BYTES = 10 * 1024 * 1024;
const LIMIT_FINDINGS = 5000;
let report = null;
let findings = [];
let selected = null;

const asText = (value, max = 3000) => {
  if (value === null || value === undefined) return "";
  if (typeof value !== "string" && typeof value !== "number") return "";
  return String(value).slice(0, max);
};
const setText = (id, value) => { byId(id).textContent = value; };
const severityClass = (severity) => SEVERITIES.includes(severity) ? severity.toLowerCase() : "info";

function notify(message, error = false) {
  const notice = byId("notice");
  notice.textContent = message;
  notice.classList.toggle("error", error);
}
function empty(element, text) {
  element.replaceChildren();
  const div = document.createElement("div");
  div.className = "empty-state";
  div.textContent = text;
  element.append(div);
}
function normalizeFinding(item, index) {
  const severity = asText(item.severity, 20).toUpperCase();
  const evidence = item.evidence && typeof item.evidence === "object" ? item.evidence : {};
  const score = Number(item.risk_score);
  return {
    index,
    id: asText(item.instance_id || item.rule_id, 100),
    rule: asText(item.rule_id, 100),
    title: asText(item.title, 400) || "Untitled observation",
    severity: SEVERITIES.includes(severity) ? severity : "INFO",
    confidence: asText(item.confidence, 40),
    score: Number.isFinite(score) ? score : 0,
    component: asText(item.component, 500),
    source: asText(item.source_file, 500),
    cwe: asText(item.cwe, 50),
    status: asText(item.validation_status, 100),
    observation: asText(evidence.observation, 3000),
    method: asText(evidence.collection_method, 100),
    assessment: asText(item.assessment, 3000),
  };
}
function compareFindings(a, b) {
  return SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) ||
    b.score - a.score || a.title.localeCompare(b.title);
}
function loadReport(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw) ||
      raw.tool !== "ahmad-sec" || raw.schema_version !== "1.0" ||
      !raw.target || typeof raw.target !== "object" ||
      !Array.isArray(raw.findings) || raw.findings.length > LIMIT_FINDINGS) {
    throw new Error("Unsupported report. Choose an ahmad-sec evidence JSON file (schema 1.0, up to 5,000 findings).");
  }
  report = raw;
  findings = raw.findings.filter(item => item && typeof item === "object" && !Array.isArray(item))
    .map(normalizeFinding).sort(compareFindings);
  selected = null;
  const components = new Set(findings.map(item => item.component).filter(Boolean));
  const elevated = findings.filter(item => ["HIGH", "CRITICAL"].includes(item.severity)).length;
  setText("stat-total", findings.length.toLocaleString());
  setText("stat-high", elevated.toLocaleString());
  setText("stat-components", components.size.toLocaleString());
  setText("stat-status", findings.length ? "REVIEW REQUIRED" : "NO OBSERVATIONS");
  setText("target-package", asText(raw.target.package, 500) || "Unknown package");
  setText("target-filename", asText(raw.target.filename, 500) || "Unnamed artifact");
  setText("target-sha", asText(raw.target.sha256, 128) || "Not supplied");
  setText("target-sdk", asText(raw.target.target_sdk, 32) || "Not supplied");
  setText("target-mode", asText(raw.assessment_type, 80) || "Not supplied");
  setText("target-schema", asText(raw.schema_version, 20));
  byId("finding-search").disabled = false;
  byId("severity-filter").disabled = false;
  byId("clear-button").disabled = false;
  byId("finding-search").value = "";
  byId("severity-filter").value = "ALL";
  notify("Evidence loaded locally. " + findings.length + " observations available for inspection. Findings are not automatically verified vulnerabilities.");
  renderFindings();
  renderGraph();
  renderEvidence();
}
function reset() {
  report = null;
  findings = [];
  selected = null;
  ["stat-total","stat-high","stat-components","target-sha","target-sdk","target-mode","target-schema"].forEach(id => setText(id, "—"));
  setText("stat-status", "NO REPORT");
  setText("target-package", "No report loaded");
  setText("target-filename", "Import a local evidence report");
  setText("finding-count", "0 DISPLAYED");
  byId("finding-search").value = "";
  byId("severity-filter").value = "ALL";
  byId("finding-search").disabled = true;
  byId("severity-filter").disabled = true;
  byId("clear-button").disabled = true;
  byId("report-file").value = "";
  empty(byId("findings-list"), "No findings to display.");
  empty(byId("graph-container"), "No graph data yet. Import an evidence report.");
  empty(byId("evidence-content"), "Select a finding to inspect its evidence and assessment.");
  setText("graph-caption", "Nodes represent data present in the report, not verified exploit paths.");
  notify("Import an evidence report generated with ahmad-sec apk scan --json-out.");
}
function selectFinding(finding) {
  selected = finding;
  renderFindings();
  renderEvidence();
  renderGraph();
}
function renderFindings() {
  const query = byId("finding-search").value.trim().toLowerCase();
  const severity = byId("severity-filter").value;
  const visible = findings.filter(item =>
    (severity === "ALL" || item.severity === severity) &&
    [item.title,item.rule,item.component,item.source].some(field => field.toLowerCase().includes(query))
  );
  setText("finding-count", visible.length + " DISPLAYED");
  const list = byId("findings-list");
  list.replaceChildren();
  if (!report) { empty(list, "No findings to display."); return; }
  if (!visible.length) { empty(list, "No observations match the current filters."); return; }
  const fragment = document.createDocumentFragment();
  visible.slice(0, 500).forEach(item => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "finding" + (selected && selected.index === item.index ? " selected" : "");
    button.setAttribute("aria-label", item.severity + ": " + item.title);
    const badge = document.createElement("span");
    badge.className = "severity " + severityClass(item.severity);
    badge.textContent = item.severity;
    const center = document.createElement("span");
    const title = document.createElement("strong");
    title.textContent = item.title;
    const note = document.createElement("small");
    note.textContent = item.component || item.rule || "Uncategorized";
    center.append(title, note);
    const score = document.createElement("span");
    score.className = "score";
    score.textContent = String(item.score);
    score.title = "Contextual risk score";
    button.append(badge, center, score);
    button.addEventListener("click", () => selectFinding(item));
    fragment.append(button);
  });
  list.append(fragment);
  if (visible.length > 500) {
    const note = document.createElement("p");
    note.className = "graph-caption";
    note.textContent = "Showing the first 500 matching observations. Narrow the search to view more.";
    list.append(note);
  }
}
function detailRow(label, value) {
  const row = document.createElement("div");
  row.className = "evidence-row";
  const dt = document.createElement("dt");
  dt.textContent = label;
  const dd = document.createElement("dd");
  dd.textContent = value || "Not provided";
  row.append(dt, dd);
  return row;
}
function renderEvidence() {
  const pane = byId("evidence-content");
  pane.replaceChildren();
  if (!selected) {
    empty(pane, findings.length ? "Choose a finding or a node in the graph to inspect it." : "Select a finding to inspect its evidence and assessment.");
    return;
  }
  const heading = document.createElement("div");
  heading.className = "evidence-title";
  const severity = document.createElement("span");
  severity.className = "severity " + severityClass(selected.severity);
  severity.textContent = selected.severity;
  const title = document.createElement("strong");
  title.textContent = selected.title;
  heading.append(severity, title);
  const details = document.createElement("dl");
  details.append(
    detailRow("Rule", selected.rule),
    detailRow("Instance", selected.id),
    detailRow("Component", selected.component),
    detailRow("Source file", selected.source),
    detailRow("Confidence", selected.confidence),
    detailRow("Risk score", String(selected.score)),
    detailRow("CWE", selected.cwe),
    detailRow("Validation", selected.status || "Requires manual validation"),
    detailRow("Method", selected.method),
    detailRow("Observation", selected.observation),
    detailRow("Assessment", selected.assessment)
  );
  pane.append(heading, details);
}
function svg(tag, attrs) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs)) el.setAttribute(key, String(value));
  return el;
}
function drawLine(svgRoot, from, to, color) {
  svgRoot.append(svg("line", {x1:from.x,y1:from.y,x2:to.x,y2:to.y,stroke:color,"stroke-width":1.2,"stroke-opacity":0.48}));
}
function drawNode(svgRoot, point, radius, color, label, onSelect) {
  const group = svg("g", {class:"graph-node",tabindex:"0",role:"button","aria-label":label});
  const circle = svg("circle", {cx:point.x,cy:point.y,r:radius,fill:"#132738",stroke:color,"stroke-width":2});
  const title = svg("title",{});
  title.textContent = label;
  group.append(circle,title);
  if (onSelect) {
    group.addEventListener("click", onSelect);
    group.addEventListener("keydown", event => {
      if (event.key === "Enter" || event.key === " ") {event.preventDefault();onSelect();}
    });
  }
  svgRoot.append(group);
}
function pointAt(center, radius, index, total, offset = -Math.PI / 2) {
  const angle = offset + index * Math.PI * 2 / Math.max(total, 1);
  return {x:center.x + radius * Math.cos(angle),y:center.y + radius * Math.sin(angle)};
}
function renderGraph() {
  const container = byId("graph-container");
  container.replaceChildren();
  if (!report) {empty(container, "No graph data yet. Import an evidence report.");return;}
  const root = svg("svg",{viewBox:"0 0 600 265",role:"img","aria-label":"Interactive radial map of reported components and observations"});
  const origin = {x:300,y:132};
  const sample = findings.slice(0, 24);
  const componentNames = [...new Set(sample.map(f => f.component).filter(Boolean))].slice(0, 8);
  const comp = componentNames.map((name,i) => ({name,...pointAt(origin,75,i,componentNames.length)}));
  const graphItems = sample.map((finding,i) => ({finding,...pointAt(origin,117,i,sample.length, -Math.PI / 2 + .13)}));
  comp.forEach(c => drawLine(root,origin,c,"#26b9e3"));
  graphItems.forEach(c => {
    const parent = comp.find(item => item.name === c.finding.component) || origin;
    drawLine(root,parent,c,c.finding.severity === "CRITICAL" || c.finding.severity === "HIGH" ? "#ff6c76" : "#427ea5");
  });
  comp.forEach(c => drawNode(root,c,8,"#38c5ea","Reported component: " + c.name,null));
  graphItems.forEach(c => {
    const color = ["CRITICAL","HIGH"].includes(c.finding.severity) ? "#ff7d86" : "#53abd5";
    drawNode(root,c,selected && selected.index === c.finding.index ? 8 : 5,color,
      c.finding.severity + " observation: " + c.finding.title,() => selectFinding(c.finding));
  });
  drawNode(root,origin,15,"#ebbd70","Target: " + asText(report.target.package,100),null);
  const centerLabel = svg("text",{x:300,y:163,"text-anchor":"middle","font-size":11,fill:"#cde5f1"});
  centerLabel.textContent = asText(report.target.package,35) || "Android APK";
  root.append(centerLabel);
  container.append(root);
  setText("graph-caption", "Showing " + sample.length + " of " + findings.length +
    " observations and " + comp.length + " linked components. Graph edges indicate report association, not exploitation.");
}
byId("import-button").addEventListener("click", () => byId("report-file").click());
byId("report-file").addEventListener("change", async event => {
  const file = event.target.files && event.target.files[0];
  if (!file) return;
  try {
    if (!file.name.toLowerCase().endsWith(".json") || file.size > LIMIT_BYTES) {
      throw new Error("Select a .json evidence report smaller than 10 MB.");
    }
    const raw = JSON.parse(await file.text());
    loadReport(raw);
  } catch (error) {
    notify(error instanceof SyntaxError ? "This file is not valid JSON." :
      error instanceof Error ? error.message : "Cannot load this report.", true);
  } finally {
    event.target.value = "";
  }
});
byId("clear-button").addEventListener("click", reset);
byId("finding-search").addEventListener("input", renderFindings);
byId("severity-filter").addEventListener("change", renderFindings);
document.querySelectorAll(".nav-item").forEach(link => {
  link.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach(item => item.classList.remove("active"));
    link.classList.add("active");
  });
});

"use strict";

/* AHMAD-IB: four-pane, offline security research IDE.
 * Every value shown is read from an explicitly imported evidence report.
 * No code execution, network calls, uploads or fabricated scan events.
 */
const $ = (id) => document.getElementById(id);
const SVG_NS = "http://www.w3.org/2000/svg";
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const MAX_FILE_BYTES = 10 * 1024 * 1024;
const MAX_FINDINGS = 5000;
const MAX_RENDER_LINES = 440;
let report = null;
let findings = [];
let selected = null;
let selectedComponent = null;
let sourceView = "manifest";

const safe = (value, limit = 400) =>
  (typeof value === "string" || typeof value === "number") ?
    String(value).slice(0, limit) : "";
const setText = (id, text) => { $(id).textContent = text; };
const severityClass = (level) => SEVERITIES.includes(level) ? level.toLowerCase() : "info";
const shape = (tag, attrs = {}) => {
  const element = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs)) element.setAttribute(key, String(value));
  return element;
};
const textElement = (tag, text, className) => {
  const element = document.createElement(tag);
  element.textContent = text;
  if (className) element.className = className;
  return element;
};
function notice(message, error = false) {
  $("notice").textContent = message;
  $("notice").classList.toggle("error", error);
}
function clean(element, message, className = "results-empty") {
  element.replaceChildren(textElement("div", message, className));
}
function normalize(item, index) {
  const evidence = item && typeof item.evidence === "object" && !Array.isArray(item.evidence) ?
    item.evidence : {};
  const level = safe(item.severity, 20).toUpperCase();
  const score = Number(item.risk_score);
  return {
    index,
    id: safe(item.instance_id, 100),
    rule: safe(item.rule_id, 100),
    title: safe(item.title, 300) || "Unspecified observation",
    severity: SEVERITIES.includes(level) ? level : "INFO",
    confidence: safe(item.confidence, 50),
    score: Number.isFinite(score) ? score : 0,
    component: safe(item.component, 300),
    file: safe(item.source_file, 300),
    state: safe(item.validation_status, 60),
    cwe: safe(item.cwe, 80),
    observation: safe(evidence.observation, 4000),
    collection: safe(evidence.collection_method, 80),
    assessment: safe(item.assessment, 4000),
    original: item,
  };
}
function validate(raw) {
  if (!raw || Array.isArray(raw) || typeof raw !== "object" ||
      raw.tool !== "ahmad-sec" || raw.schema_version !== "1.0" ||
      !raw.target || typeof raw.target !== "object" || Array.isArray(raw.target) ||
      !Array.isArray(raw.findings) || raw.findings.length > MAX_FINDINGS) {
    throw new Error("Expected an ahmad-sec version 1.0 evidence JSON report (max 5,000 observations).");
  }
  if (raw.surface !== undefined) {
    const graph = raw.surface;
    if (!graph || typeof graph !== "object" || !Array.isArray(graph.nodes) ||
        graph.nodes.length > 8000 || !Array.isArray(graph.edges) ||
        graph.edges.length > 15000 || !Array.isArray(graph.components) ||
        graph.components.length > 1000 ||
        graph.components.some(c => !c || typeof c.name !== "string" ||
          typeof c.kind !== "string" || !Array.isArray(c.filters) ||
          c.filters.some(f => !f || !Array.isArray(f.actions) ||
            !Array.isArray(f.data)))) {
      throw new Error("Invalid manifest relationship graph in evidence report.");
    }
  }
}
function selectSource(view) {
  sourceView = view;
  for (const button of document.querySelectorAll("[data-source-view]")) {
    const active = button.dataset.sourceView === view;
    button.classList.toggle("active", active);
    if (button.getAttribute("role") === "tab") button.setAttribute("aria-selected", active ? "true" : "false");
  }
  renderSource();
}
function visibleSourceData() {
  if (!report) return null;
  if (sourceView === "target") {
    return {target: report.target, assessment_type: report.assessment_type,
      schema_version: report.schema_version, summary: report.summary, limitations: report.limitations};
  }
  if (sourceView === "findings") {
    return {count: findings.length, truncated_for_view: findings.length > 80,
      observations: findings.slice(0, 80).map(item => item.original)};
  }
  if (sourceView === "selected") {
    return selectedComponent ? {source:"AndroidManifest.xml", component:selectedComponent} :
      selected ? selected.original : {message:"Select an observation or component to view its source record."};
  }
  return report.surface ? {
    source: "AndroidManifest.xml (normalized declarations, not raw source code)",
    package: report.surface.package,
    target_sdk: report.surface.target_sdk,
    summary: report.surface.summary,
    truncated: report.surface.truncated,
    components: report.surface.components.slice(0, 90),
    limitations: report.surface.limitations,
  } : {notice:"No manifest graph in this report. Scan again with the current CLI to generate one.",
    target:report.target};
}
function appendCodeTokens(container, line) {
  const expression = /"(?:\\.|[^"\\])*"(?=\s*:)|"(?:\\.|[^"\\])*"|\b(?:true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|[{}\[\],:]/g;
  let last = 0, match;
  while ((match = expression.exec(line)) !== null) {
    if (match.index > last) container.append(document.createTextNode(line.slice(last, match.index)));
    const token = match[0];
    let category = "token-punc";
    if (token.startsWith('"')) category = /^\s*:/.test(line.slice(match.index + token.length)) ? "token-key" : "token-string";
    else if (/^(true|false|null)$/.test(token)) category = "token-bool";
    else if (/^-?\d/.test(token)) category = "token-number";
    container.append(textElement("span", token, category));
    last = match.index + token.length;
  }
  if (last < line.length) container.append(document.createTextNode(line.slice(last)));
}
function renderSource() {
  const view = $("source-view");
  view.replaceChildren();
  const filename = sourceView === "manifest" ? "manifest.json" :
    sourceView === "target" ? "target.json" :
    sourceView === "findings" ? "findings.json" : "selected.json";
  $("editor-breadcrumb").replaceChildren(document.createTextNode("assessment / " + filename + "  "),
    textElement("span", "READ ONLY"));
  if (!report) {
    view.append(textElement("div",
      "No analysis loaded.\n\nRun: ahmad-sec apk scan authorized.apk --json-out evidence.json\nThen import evidence.json from this workstation.",
      "code-placeholder"));
    return;
  }
  const json = JSON.stringify(visibleSourceData(), null, 2);
  const lines = json.slice(0, 160000).split("\n");
  const fragment = document.createDocumentFragment();
  const length = Math.min(lines.length, MAX_RENDER_LINES);
  for (let i=0; i<length; i++) {
    const row = document.createElement("div");
    row.className = "code-line";
    row.append(textElement("span", String(i+1).padStart(3, "0"), "line-number"));
    const code = document.createElement("span");
    code.className = "line-text";
    appendCodeTokens(code, lines[i].slice(0,1000));
    row.append(code);
    fragment.append(row);
  }
  if (lines.length > length || json.length > 160000)
    fragment.append(textElement("div", "Output truncated in editor. Export contains the full report.", "code-placeholder"));
  view.append(fragment);
}
function selectFinding(item) {
  selected = item;
  selectedComponent = null;
  renderFindings();
  renderInspector();
  selectSource("selected");
  setText("graph-selection", "OBSERVATION / " + safe(item.rule, 38));
}
function selectComponent(component) {
  selectedComponent = component;
  selected = null;
  renderFindings();
  renderInspector();
  selectSource("selected");
  setText("graph-selection", "COMPONENT / " + safe(component.name, 42));
}
function renderFindings() {
  const list = $("findings-list");
  list.replaceChildren();
  if (!report) { clean(list, "No findings imported."); return; }
  const term = $("finding-search").value.trim().toLowerCase();
  const severity = $("severity-filter").value;
  const chosen = findings.filter(item =>
    (severity === "ALL" || item.severity === severity) &&
    [item.title,item.rule,item.component,item.file].some(v => v.toLowerCase().includes(term))
  );
  setText("finding-count", chosen.length + " RESULTS");
  if (!chosen.length) { clean(list, "No observations match this filter."); return; }
  const fragment = document.createDocumentFragment();
  for (const item of chosen.slice(0, 300)) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "finding-row" + (selected && selected.index === item.index ? " active" : "");
    button.setAttribute("aria-label", item.severity + " observation: " + item.title);
    const flag = textElement("span", item.severity, "severity " + severityClass(item.severity));
    const text = document.createElement("span");
    text.append(textElement("span", item.title, "finding-title"),
      textElement("span", item.component || item.rule, "finding-details"));
    button.append(flag, text);
    button.addEventListener("click", () => selectFinding(item));
    fragment.append(button);
  }
  list.append(fragment);
  if (chosen.length > 300)
    list.append(textElement("div", "Showing first 300. Narrow the filters for more.", "results-empty"));
}
function detail(label, value) {
  const row = document.createElement("div");
  row.className = "evidence-row";
  const dt = textElement("dt", label);
  const dd = textElement("dd", value === null || value === undefined || value === "" ? "—" : safe(value, 6500));
  row.append(dt, dd);
  return row;
}
function renderInspector() {
  const pane = $("evidence-content");
  pane.replaceChildren();
  if (selectedComponent) {
    const c = selectedComponent;
    pane.append(textElement("div", c.kind.toUpperCase() + "  /  " + c.name, "evidence-title"));
    pane.append(detail("Enabled", String(c.enabled)),detail("Exported", String(c.exported)),
      detail("Basis", safe(c.export_basis)),detail("Permission",safe(c.permission)),
      detail("Read perm.",safe(c.read_permission)),detail("Write perm.",safe(c.write_permission)),
      detail("Authorities",safe(c.authorities)),
      detail("Intent filters",JSON.stringify(c.filters || [],null,2).slice(0,5000)));
    return;
  }
  if (selected) {
    const f=selected;
    pane.append(textElement("div", f.severity+" / "+f.title,"evidence-title"));
    pane.append(detail("Rule",f.rule),detail("Instance",f.id),detail("Component",f.component),
      detail("Source",f.file),detail("Confidence",f.confidence),detail("Risk",String(f.score)),
      detail("CWE",f.cwe),detail("Validation",f.state || "requires manual validation"),
      detail("Collection",f.collection),detail("Evidence",f.observation),detail("Assessment",f.assessment));
    return;
  }
  clean(pane, findings.length ?
    "Select a finding in the list or a component in the graph to see its evidence." :
    "No evidence selected. Import an authorized report.");
}
function renderConsole() {
  const log = $("event-feed"), gutter = $("console-gutter");
  log.replaceChildren();
  gutter.textContent = "";
  if (!report) {
    const empty = document.createElement("div");
    empty.className = "console-placeholder";
    empty.append(
      document.createTextNode("[LOCAL] Workstation ready. No scan data imported."),
      textElement("div", "ahmad-sec apk scan authorized.apk --json-out evidence.json"),
      textElement("div", "Import the exported file. This is not a live device terminal.")
    );
    log.append(empty);
    setText("event-count", "0 ENTRIES");
    setText("console-footnote", "NO REPORT");
    return;
  }
  const lines = [
    {level:"INFO", code:"IMPORT", message:"Loaded offline evidence: "+safe(report.target.filename,130)},
    {level:"INFO", code:"FORMAT", message:"Schema "+safe(report.schema_version)+" / "+safe(report.assessment_type,45)},
    {level:"INFO", code:"PACKAGE", message:safe(report.target.package,160)+" / SDK "+safe(report.target.target_sdk,20)},
  ];
  if (report.surface) {
    lines.push({level:"INFO",code:"SURFACE",message:
      String(report.surface.components.length)+" manifest components / "+
      String(report.surface.edges.length)+" recorded declarations"});
    if (report.surface.truncated)
      lines.push({level:"MEDIUM",code:"LIMIT",message:"Manifest inventory truncated at safety limit"});
  }
  for (const item of findings.slice(0,600)) {
    lines.push({level:item.severity,code:item.rule || "FINDING",
      message:item.title+(item.component ? "  ::  "+item.component : ""),item});
  }
  const rows = document.createDocumentFragment();
  const numbers = [];
  lines.forEach((entry,index) => {
    numbers.push(String(index + 1).padStart(2,"0"));
    const row = document.createElement(entry.item ? "button":"div");
    if (entry.item) { row.type="button"; row.style.width="100%";row.style.textAlign="left";
      row.style.border="0";row.style.cursor="pointer"; }
    row.className = "console-line";
    row.append(textElement("span",safe(entry.code,15),"console-stamp"),
      textElement("span","["+entry.level+"]","console-level "+severityClass(entry.level)),
      textElement("span",safe(entry.message,600),"console-message"));
    if (entry.item) row.addEventListener("click",() => selectFinding(entry.item));
    rows.append(row);
  });
  log.append(rows);
  gutter.textContent = numbers.join("\n");
  setText("event-count",lines.length+" ENTRIES");
  setText("console-footnote",findings.length+" REPORTED OBSERVATIONS / NOT LIVE LOGS");
}
function drawNode(canvas, node, point, index, type, onSelect) {
  const isRoot = type==="app";
  const radius = isRoot ? 23 : type==="component" ? 15 : 12;
  const color = isRoot ? "#f15055" : type==="component" ? "#00a9ee" :
    type==="permission" ? "#e3b45a" : "#72caa8";
  const group=shape("g", onSelect ?
    {class:"graph-node",tabindex:"0",role:"button","aria-label":safe(node.label,160)} :
    {class:"graph-label","aria-label":safe(node.label,160)});
  const circle=shape("circle",{cx:point.x,cy:point.y,r:radius,fill:isRoot?"#c83239":"#133447",
    stroke:color,"stroke-width":isRoot?2:1.7,class:"node-core"});
  const glow=shape("circle",{cx:point.x,cy:point.y,r:radius+4,fill:"none",
    stroke:color,"stroke-width":0.65,"stroke-opacity":0.32});
  const title=shape("title");title.textContent=safe(node.label,240);
  const label=shape("text",{x:point.x,y:point.y+(isRoot?3:2.4),
    "text-anchor":"middle",fill:"#e5f4fb","font-weight":700,
    "font-size":isRoot?7.3:8,"pointer-events":"none"});
  label.textContent=isRoot ? "ANDROID" :
    type==="permission" ? "P" : type==="intent_action" ? "I" : type==="uri_host" ? "H" :
    type==="uri_scheme" ? "U" : String(index+1);
  group.append(glow,circle,label,title);
  if (onSelect) {
    group.addEventListener("click",onSelect);
    group.addEventListener("keydown",event=>{
      if (event.key==="Enter" || event.key===" ") {event.preventDefault();onSelect();}
    });
  }
  canvas.append(group);
}
function coords(radius,index,total,origin={x:280,y:137}) {
  const theta=-Math.PI/2 + 2*Math.PI*index/Math.max(total,1);
  return {x:origin.x+radius*Math.cos(theta),y:origin.y+radius*Math.sin(theta)};
}
function emptyGraph() {
  $("graph-container").replaceChildren();
  const div = document.createElement("div");
  div.className="graph-empty";
  div.append(textElement("div","◎","graph-ghost"),textElement("strong","NO TOPOLOGY LOADED"),
    textElement("span","Import evidence to display actual Android relationships."));
  $("graph-container").append(div);
  for (const id of ["graph-readout","layer-target","layer-components","layer-observations"]) {
    setText(id,id==="graph-readout"?"0 NODES / 0 EDGES":"0");
  }
  setText("graph-selection","NO SELECTION");
}
function renderGraph() {
  if (!report) {emptyGraph();return;}
  const graph=$("graph-container");graph.replaceChildren();
  const surface=report.surface;
  let root, components, remainder, edges=[];
  const componentDetails=new Map();
  if (surface && Array.isArray(surface.nodes)) {
    const nodes=surface.nodes.filter(node=>node && typeof node.id==="string" && typeof node.type==="string");
    root=nodes.find(node=>node.type==="app");
    if (!root) {emptyGraph();return;}
    for (const c of surface.components)
      componentDetails.set("component:"+c.kind+":"+c.name,c);
    components=nodes.filter(node=>componentDetails.has(node.id)).slice(0,15);
    const wanted=new Set([root.id,...components.map(node=>node.id)]);
    remainder=[];
    for (const edge of surface.edges) {
      if (remainder.length>=17)break;
      if (!wanted.has(edge.source) || wanted.has(edge.target))continue;
      const child=nodes.find(n=>n.id===edge.target);
      if (child) { remainder.push(child);wanted.add(child.id); }
    }
    edges=surface.edges.filter(edge=>wanted.has(edge.source)&&wanted.has(edge.target));
  } else {
    root={id:"app:target",type:"app",label:safe(report.target.package,80)};
    components=findings.slice(0,17).map(item=>({id:"finding:"+item.index,type:"observation",
      label:item.title,finding:item}));
    remainder=[];
    edges=components.map(item=>({source:root.id,target:item.id,relation:"reported_by"}));
  }
  const svg=shape("svg",{viewBox:"0 0 560 275",role:"img",
    "aria-label":"Interactive graph of reported Android manifest components or evidence observations"});
  const position=new Map([[root.id,{x:280,y:137}]]);
  components.forEach((node,index)=>position.set(node.id,coords(86,index,components.length)));
  remainder.forEach((node,index)=>position.set(node.id,coords(123,index,remainder.length)));
  for (const link of edges) {
    const a=position.get(link.source),b=position.get(link.target);
    if (!a || !b)continue;
    svg.append(shape("line",{x1:a.x,y1:a.y,x2:b.x,y2:b.y,stroke:
      link.relation==="declares_component"?"#0876bc":"#366c8e",
      "stroke-width":0.9,"stroke-opacity":0.72}));
  }
  const clickFor=(node)=>componentDetails.has(node.id)?
    ()=>selectComponent(componentDetails.get(node.id)):node.finding?
    ()=>selectFinding(node.finding):null;
  for (const [i,node] of remainder.entries())
    drawNode(svg,node,position.get(node.id),i,node.type,clickFor(node));
  for (const [i,node] of components.entries())
    drawNode(svg,node,position.get(node.id),i,componentDetails.has(node.id)?"component":node.type,clickFor(node));
  drawNode(svg,root,position.get(root.id),0,"app",null);
  graph.append(svg);
  const size=1+components.length+remainder.length;
  setText("graph-readout",size+" NODES / "+edges.length+" EDGES");
  setText("layer-target","1");
  setText("layer-components",String(components.length));
  setText("layer-observations",String(remainder.length));
  setText("graph-selection",selectedComponent? "COMPONENT / "+safe(selectedComponent.name,30) :
    selected ? "OBSERVATION / "+safe(selected.rule,30) : "SELECT A NODE");
}
function load(raw) {
  validate(raw);
  report=raw;
  findings=raw.findings.filter(item=>item && typeof item==="object" && !Array.isArray(item))
    .map(normalize).sort((a,b)=>SEVERITIES.indexOf(a.severity)-SEVERITIES.indexOf(b.severity)||
      b.score-a.score || a.title.localeCompare(b.title));
  selected=null;selectedComponent=null;
  setText("session-indicator","● REPORT LOADED / LOCAL");
  setText("context-target",safe(raw.target.package,120)||"UNKNOWN");
  setText("context-sha",safe(raw.target.sha256,18)||"—");
  setText("context-count",String(findings.length));
  setText("source-filename",safe(raw.target.filename,70)||"unknown.apk");
  setText("source-scope",safe(raw.target.package,120)||"Unknown package");
  setText("source-schema","SCHEMA "+safe(raw.schema_version,15));
  const counts=Object.fromEntries(SEVERITIES.map(s=>[s,0]));
  findings.forEach(f=>{counts[f.severity]++;});
  setText("severity-summary","CRIT "+counts.CRITICAL+" / HIGH "+counts.HIGH+
    " / MED "+counts.MEDIUM+" / LOW "+counts.LOW+" / INFO "+counts.INFO);
  $("finding-search").value="";
  $("severity-filter").value="ALL";
  $("finding-search").disabled=false;
  $("severity-filter").disabled=false;
  $("clear-button").disabled=false;
  selectSource("manifest");
  renderConsole();renderGraph();renderFindings();renderInspector();
  notice("Imported "+findings.length+" observations. Offline evidence only; manual validation remains necessary.");
}
function reset() {
  report=null;findings=[];selected=null;selectedComponent=null;
  setText("session-indicator","● LOCAL / NO REPORT");
  setText("context-target","NOT LOADED");setText("context-sha","—");setText("context-count","—");
  setText("source-filename","untitled.apk");setText("source-scope","No report imported");
  setText("source-schema","SCHEMA —");setText("severity-summary","CRIT 0 / HIGH 0 / MED 0 / LOW 0 / INFO 0");
  setText("finding-count","0 RESULTS");
  $("finding-search").value="";$("severity-filter").value="ALL";
  $("finding-search").disabled=true;$("severity-filter").disabled=true;
  $("clear-button").disabled=true;$("report-file").value="";
  selectSource("manifest");renderConsole();renderGraph();renderFindings();renderInspector();
  notice("Import exported JSON from an authorized APK scan.");
}
for (const button of document.querySelectorAll("[data-source-view]"))
  button.addEventListener("click",()=>selectSource(button.dataset.sourceView));
$("import-button").addEventListener("click",()=>$("report-file").click());
$("clear-button").addEventListener("click",reset);
$("finding-search").addEventListener("input",renderFindings);
$("severity-filter").addEventListener("change",renderFindings);
$("report-file").addEventListener("change",async(event)=>{
  const file=event.target.files && event.target.files[0];
  if (!file)return;
  try {
    if (!file.name.toLowerCase().endsWith(".json") || file.size>MAX_FILE_BYTES)
      throw new Error("Choose a local JSON evidence report smaller than 10 MB.");
    load(JSON.parse(await file.text()));
  } catch(error) {
    notice(error instanceof SyntaxError?"This file is not valid JSON.":
      error instanceof Error?error.message:"Unable to load this evidence report.",true);
  } finally {
    event.target.value="";
  }
});
reset();

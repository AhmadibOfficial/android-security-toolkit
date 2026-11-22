"""Static integration contracts for the four-pane research workstation.

The UI must not silently regress into the old metric-card dashboard, and
its script must reference IDs that actually exist in the bundled HTML.
"""
from __future__ import annotations

import re
from importlib.resources import files


def asset(name):
    return files("ahmad_sec").joinpath("assets", name).read_text(encoding="utf-8")


def test_workstation_has_exactly_four_primary_panes():
    html = asset("index.html")
    ids = re.findall(r'<section class="pane [^"]+" id="([^"]+)"', html)
    assert ids == ["source-panel", "graph-panel", "events-panel", "results-panel"]
    assert 'class="ide-grid"' in html
    assert 'class="metrics"' not in html
    assert 'class="metric"' not in html
    assert 'class="sidebar"' not in html


def test_workstation_id_bindings_match_html():
    html = asset("index.html")
    script = asset("workspace.js")
    defined = set(re.findall(r'\bid="([^"]+)"', html))
    used = set(re.findall(r'\$\("([a-z][a-z0-9-]+)"\)', script))
    used.update(re.findall(r'setText\("([a-z][a-z0-9-]+)"', script))
    assert used - defined == set(), f"JS references missing DOM IDs: {used - defined}"


def test_workstation_supports_real_report_navigation():
    html = asset("index.html")
    js = asset("workspace.js")
    css = asset("workspace.css")
    for name in ("manifest", "target", "findings", "selected"):
        assert f'data-source-view="{name}"' in html
    assert "raw.tool !== \"ahmad-sec\"" in js
    assert "Array.isArray(graph.components)" in js
    assert "document.createElementNS" in js
    assert "graph-node" in js
    assert "grid-template-columns:minmax(0,1fr) minmax(0,1fr)" in css
    assert "grid-template-rows:minmax(0,1fr) minmax(0,1fr)" in css
